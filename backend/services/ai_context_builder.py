"""AI context builder: bounded, deterministic evidence selection.

NEVER sends the whole repository to the model. Instead it deterministically
selects relevant context in priority order:

    1. deterministic security findings + surrounding source (±N lines)
    2. entry-point-like files (main.py, app.py, routes/, handlers/, ...)
    3. files imported by finding-bearing files (parsed import symbols)
    4. (nothing else — the budget, not curiosity, decides)

Hard budgets (from Settings) cap total characters, file count, per-file
characters, and finding count. Anything cut is reported in budget flags so
callers can observe what the model did NOT see. Selection is fully
deterministic: same repository -> same context, which keeps tests hermetic
and results reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import Settings, settings
from models.schemas import Finding, ParsedFile, RepositoryMetadata
from services.prompts.analysis_system import CODEAUDIT_SECURITY_PROMPT_V1
from services.repository_scanner import ScanResult

ENTRYPOINT_FILENAMES = frozenset(
    {
        "main.py",
        "__main__.py",
        "app.py",
        "wsgi.py",
        "asgi.py",
        "manage.py",
        "server.py",
        "run.py",
        "cli.py",
    }
)

ENTRYPOINT_DIR_HINTS = frozenset(
    {"routes", "views", "handlers", "controllers", "api", "endpoints"}
)


@dataclass(frozen=True)
class AIContextBlock:
    path: str
    start_line: int
    end_line: int
    text: str  # line-numbered excerpt, never truncated mid-line
    truncated: bool


@dataclass
class AIContext:
    repo_owner: str
    repo_name: str
    prompt_version: str = CODEAUDIT_SECURITY_PROMPT_V1
    language_distribution: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    finding_context: dict[str, str] = field(default_factory=dict)
    file_blocks: list[AIContextBlock] = field(default_factory=list)
    symbols_of_interest: list[str] = field(default_factory=list)
    budget: dict = field(default_factory=dict)
    # Phase 3 upgrade: agents may override the message builder (e.g. the
    # evidence agent's review prompt) while reusing the same provider
    # contract. None keeps the default investigation messages.
    message_builder: Any = field(default=None, repr=False)


def _numbered(lines: list[str], start: int) -> str:
    return "\n".join(f"{start + i} | {line}" for i, line in enumerate(lines))


def _head_excerpt(lines: list[str], max_chars: int) -> tuple[str, int, bool]:
    """First up-to-max_chars of a file, cut at a line boundary."""
    text = "\n".join(lines)
    if len(text) <= max_chars:
        return _numbered(lines, 1), len(lines), False
    cut = text.rfind("\n", 0, max_chars)
    cut = cut if cut > 0 else max_chars
    kept = text[:cut].split("\n")
    return _numbered(kept, 1), len(kept), True


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _is_entrypoint(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    name = lowered.rsplit("/", 1)[-1]
    if name in ENTRYPOINT_FILENAMES:
        return True
    parts = set(lowered.split("/"))
    return bool(parts & ENTRYPOINT_DIR_HINTS)


def _resolve_import(module: str, contents: dict[str, str]) -> str | None:
    """Best-effort: 'pkg.mod' -> 'pkg/mod.py' if present in scanned contents."""
    rel = module.replace(".", "/") + ".py"
    if rel in contents:
        return rel
    init = module.replace(".", "/") + "/__init__.py"
    if init in contents:
        return init
    return None


def build_ai_context(
    scan: ScanResult,
    parsed: list[ParsedFile],
    findings: list[Finding],
    repository: RepositoryMetadata,
    cfg: Settings | None = None,
) -> AIContext:
    """Build the bounded evidence context for one Nemotron investigation."""
    cfg = cfg or settings
    ctx_lines = max(0, cfg.ai_context_lines)
    max_chars = max(1, cfg.ai_context_chars)
    max_files = max(1, cfg.ai_max_context_files)
    per_file = max(64, cfg.ai_max_file_chars)

    context = AIContext(repo_owner=repository.owner, repo_name=repository.name)

    # Language distribution over scanned files.
    dist: dict[str, int] = {}
    for analyzed in scan.files:
        dist[analyzed.language or "unknown"] = dist.get(analyzed.language or "unknown", 0) + 1
    context.language_distribution = dist

    in_scope = list(findings)[: max(0, cfg.ai_max_findings)]
    context.findings = in_scope

    chars_used = 0
    files_used = 0
    truncated = False

    def fits(n: int) -> bool:
        return chars_used + n <= max_chars and files_used < max_files

    def add_block(block: AIContextBlock) -> bool:
        nonlocal chars_used, files_used, truncated
        if not fits(len(block.text)):
            truncated = True
            return False
        context.file_blocks.append(block)
        chars_used += len(block.text)
        files_used += 1
        if block.truncated:
            truncated = True
        return True

    # --- Priority 1: surrounding source for each deterministic finding ------
    ranges_by_file: dict[str, list[tuple[int, int]]] = {}
    for finding in in_scope:
        content = scan.contents.get(finding.file)
        if not content:
            continue
        lines = content.splitlines()
        start = max(1, finding.line - ctx_lines)
        end = min(len(lines), finding.line + ctx_lines)
        ranges_by_file.setdefault(finding.file, []).append((start, end))

    for path in sorted(ranges_by_file):
        lines = scan.contents[path].splitlines()
        for start, end in _merge_ranges(ranges_by_file[path]):
            excerpt_lines = lines[start - 1 : end]
            # The finding's own line must always survive truncation: keep
            # every line up to the last finding line in this block, then
            # fill further lines only while the per-file budget allows.
            last_finding_line = max(
                f.line for f in in_scope if f.file == path and start <= f.line <= end
            )
            kept: list[str] = []
            chars = 0
            for i, line in enumerate(excerpt_lines):
                lineno = start + i
                entry = f"{lineno} | {line}"
                if lineno <= last_finding_line or chars + len(entry) + 1 <= per_file:
                    kept.append(entry)
                    chars += len(entry) + 1
                else:
                    break
            text = "\n".join(kept)
            was_truncated = len(kept) < len(excerpt_lines)
            block = AIContextBlock(
                path=path, start_line=start, end_line=end,
                text=text, truncated=was_truncated,
            )
            if add_block(block):
                for finding in in_scope:
                    if finding.file == path and start <= finding.line <= end:
                        context.finding_context.setdefault(finding.id, text)

    # --- Priority 2: entry-point-like files --------------------------------
    for analyzed in sorted(scan.files, key=lambda a: a.relative_path):
        path = analyzed.relative_path
        if path in ranges_by_file or not _is_entrypoint(path):
            continue
        content = scan.contents.get(path)
        if not content:
            continue
        text, end_line, was_truncated = _head_excerpt(content.splitlines(), per_file)
        if add_block(AIContextBlock(path, 1, end_line, text, was_truncated)):
            _collect_symbols(context, parsed, path)

    # --- Priority 3: files imported by finding-bearing files ----------------
    import_targets: list[str] = []
    parsed_by_path = {p.relative_path: p for p in parsed}
    for path in sorted(ranges_by_file):
        parsed_file = parsed_by_path.get(path)
        if not parsed_file:
            continue
        for symbol in parsed_file.symbols:
            if symbol.kind != "import":
                continue
            target = _resolve_import(symbol.name.split(" ")[0], scan.contents)
            if target and target not in ranges_by_file:
                import_targets.append(target)
    for target in sorted(set(import_targets)):
        content = scan.contents.get(target)
        if not content:
            continue
        text, end_line, was_truncated = _head_excerpt(content.splitlines(), per_file)
        if add_block(AIContextBlock(target, 1, end_line, text, was_truncated)):
            _collect_symbols(context, parsed, target)

    context.budget = {
        "chars_used": chars_used,
        "chars_limit": max_chars,
        "files_included": files_used,
        "files_limit": max_files,
        "findings_included": len(in_scope),
        "findings_total": len(findings),
        "truncated": truncated,
    }
    return context


def _collect_symbols(context: AIContext, parsed: list[ParsedFile], path: str) -> None:
    for parsed_file in parsed:
        if parsed_file.relative_path != path:
            continue
        for symbol in parsed_file.symbols:
            if symbol.kind in ("function", "class") and len(context.symbols_of_interest) < 40:
                context.symbols_of_interest.append(
                    f"{symbol.kind} {symbol.name} ({path}:{symbol.line})"
                )
