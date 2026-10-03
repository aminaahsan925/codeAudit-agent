"""Fix context builder: the smallest useful evidence for one remediation.

For a single finding, prepares a bounded FixContext: the finding itself,
a numbered source window around the evidence line (the evidence line is
always present, never truncated mid-line), and the enclosing function/class
when the parser identified one. The whole repository is never sent.

Budgets (all from Settings, all hard caps):
    CODEAUDIT_FIX_CONTEXT_LINES      ±lines around the evidence line
    CODEAUDIT_FIX_MAX_FILE_CHARS     max chars of the source window
    CODEAUDIT_FIX_MAX_CONTEXT_CHARS  max chars of the assembled context
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Settings, settings
from models.schemas import CodeSymbol, Finding, ParsedFile
from services.knowledge import KnowledgeHit, retrieve_for_finding


@dataclass
class FixContext:
    finding: Finding
    file_path: str
    evidence_window: str  # numbered source lines; evidence line always present
    window_start: int
    window_end: int
    enclosing_symbol: str = ""  # e.g. "function get_user (lines 4-12)"
    budget: dict = field(default_factory=dict)
    # Phase 5: curated knowledge hits for this finding (knowledge-only:
    # guidance for the fix proposal, never evidence). Empty for sensitive
    # findings — retrieval returns nothing for them by construction.
    knowledge: list["KnowledgeHit"] = field(default_factory=list)


def _numbered(lines: list[str], start: int) -> str:
    return "\n".join(f"{start + i} | {line}" for i, line in enumerate(lines))


def _enclosing_symbol(symbols: list[CodeSymbol], line: int) -> str:
    """Smallest function/class range containing the line, if any."""
    best: CodeSymbol | None = None
    for sym in symbols:
        if sym.kind not in ("function", "class"):
            continue
        end = sym.end_line if sym.end_line is not None else sym.line
        if sym.line <= line <= end:
            span = end - sym.line
            if best is None or span < (
                (best.end_line or best.line) - best.line
            ):
                best = sym
    if best is None:
        return ""
    end = best.end_line if best.end_line is not None else best.line
    return f"{best.kind} {best.name} (lines {best.line}-{end})"


def build_fix_context(
    finding: Finding,
    contents: dict[str, str],
    parsed: list[ParsedFile] | None = None,
    cfg: Settings | None = None,
) -> FixContext:
    """Build the bounded evidence context for remediating one finding."""
    cfg = cfg or settings
    ctx_lines = max(0, cfg.fix_context_lines)
    per_file = max(64, cfg.fix_max_file_chars)

    content = contents.get(finding.file, "")
    lines = content.splitlines()
    total = len(lines)

    # Expand outward from the evidence line so it can never be cut,
    # and never split a line in half.
    lo = hi = min(max(finding.line, 1), total) if total else 1
    window = [lines[lo - 1]] if total else []
    used = len(window[0]) if window else 0
    # Alternate expansion, bounded by ctx_lines each side and per_file chars.
    for dist in range(1, ctx_lines + 1):
        grown = False
        if hi < total and hi < finding.line + ctx_lines:
            candidate = lines[hi]
            if used + 1 + len(candidate) <= per_file:
                window.append(candidate)
                used += 1 + len(candidate)
                hi += 1
                grown = True
        if lo > 1 and lo > finding.line - ctx_lines:
            candidate = lines[lo - 2]
            if used + 1 + len(candidate) <= per_file:
                window.insert(0, candidate)
                used += 1 + len(candidate)
                lo -= 1
                grown = True
        if not grown:
            break

    truncated = (lo > 1) or (hi < total)
    # Phase 4: a sensitive finding's evidence window must not carry the raw
    # secret to the AI provider. Redact known token shapes on every window
    # line, and force the evidence line itself to the finding's redacted
    # evidence (the raw value never appears in a finding).
    if finding.sensitive:
        from services.supplychain.secrets import redact_known_tokens_in_text

        window = [redact_known_tokens_in_text(w) for w in window]
        evidence_idx = finding.line - lo
        if 0 <= evidence_idx < len(window):
            window[evidence_idx] = finding.evidence
    context = FixContext(
        finding=finding,
        file_path=finding.file,
        evidence_window=_numbered(window, lo),
        window_start=lo,
        window_end=hi,
        budget={
            "context_lines": ctx_lines,
            "window_chars": used,
            "window_truncated": truncated,
        },
    )

    if parsed:
        for pf in parsed:
            if pf.relative_path == finding.file and not pf.parse_error:
                context.enclosing_symbol = _enclosing_symbol(pf.symbols, finding.line)
                break

    # Phase 5: curated knowledge for the fix proposal (knowledge-only,
    # deterministic, no AI call). Retrieval returns [] for sensitive
    # findings, so secret material can never gain a knowledge section.
    knowledge = retrieve_for_finding(finding, cfg)
    context.knowledge = knowledge
    context.budget["knowledge_chunks"] = len(knowledge)
    context.budget["knowledge_ids"] = [h.entry.id for h in knowledge]

    return context
