"""Tests for the AI context builder: budgets, determinism, prioritization."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from models.schemas import (
    Category,
    CodeSymbol,
    Confidence,
    Finding,
    FindingSource,
    ParsedFile,
    RepositoryMetadata,
    Severity,
)
from services.ai_context_builder import AIContext, build_ai_context
from services.repository_scanner import ScanResult


def _finding(fid: str, path: str, line: int) -> Finding:
    return Finding(
        id=fid,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="T",
        description="D",
        file=path,
        line=line,
        evidence="evidence",
        confidence=Confidence.HIGH,
        source=FindingSource.DETERMINISTIC,
        detector="det",
    )


def _scan(files: dict[str, str]) -> ScanResult:
    scan = ScanResult()
    for path in sorted(files):
        scan.files.append(
            SimpleNamespace(relative_path=path, language="python", size_bytes=len(files[path]))
        )
        scan.contents[path] = files[path]
    return scan


def _repo() -> RepositoryMetadata:
    return RepositoryMetadata(owner="o", name="r", url="https://github.com/o/r")


APP_PY = "\n".join(f"line{i} = {i}" for i in range(1, 101))
MAIN_PY = "\n".join(f"mainline{i} = {i}" for i in range(1, 51))


def _cfg(**overrides):
    defaults = dict(
        ai_context_lines=2,
        ai_context_chars=10_000,
        ai_max_context_files=12,
        ai_max_file_chars=6_000,
        ai_max_findings=25,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_finding_excerpt_has_line_numbers_and_finding_line():
    scan = _scan({"app.py": APP_PY})
    ctx = build_ai_context(scan, [], [_finding("f1", "app.py", 50)], _repo(), _cfg())
    assert ctx.findings[0].id == "f1"
    snippet = ctx.finding_context["f1"]
    assert "50 | line50 = 50" in snippet
    assert "48 | line48 = 48" in snippet  # ±2 context lines
    assert "52 | line52 = 52" in snippet


def test_total_budget_enforced_and_flagged():
    scan = _scan({"app.py": APP_PY, "main.py": MAIN_PY})
    ctx = build_ai_context(
        scan, [], [_finding("f1", "app.py", 50)], _repo(), _cfg(ai_context_chars=200)
    )
    assert ctx.budget["chars_used"] <= 200
    assert ctx.budget["truncated"] is True


def test_file_count_budget_enforced():
    files = {f"mod{i}.py": APP_PY for i in range(5)}
    scan = _scan(files)
    ctx = build_ai_context(scan, [], [], _repo(), _cfg(ai_max_context_files=2))
    assert len(ctx.file_blocks) <= 2
    assert ctx.budget["files_included"] <= 2


def test_entrypoint_files_included():
    scan = _scan({"main.py": MAIN_PY, "utils.py": APP_PY})
    ctx = build_ai_context(scan, [], [], _repo(), _cfg())
    paths = [b.path for b in ctx.file_blocks]
    assert "main.py" in paths
    assert "utils.py" not in paths  # not entrypoint, not finding-related


def test_import_targets_resolved():
    app = "import helpers\n\nx = helpers.run(1)\n"
    helpers = "def run(v):\n    return v\n"
    scan = _scan({"app.py": app, "helpers.py": helpers})
    parsed = [
        ParsedFile(
            relative_path="app.py",
            language="python",
            symbols=[CodeSymbol(kind="import", name="helpers", line=1)],
        )
    ]
    ctx = build_ai_context(
        scan, parsed, [_finding("f1", "app.py", 3)], _repo(), _cfg()
    )
    paths = [b.path for b in ctx.file_blocks]
    assert "helpers.py" in paths


def test_deterministic_same_input_same_context():
    scan = _scan({"app.py": APP_PY, "main.py": MAIN_PY})
    findings = [_finding("f1", "app.py", 50), _finding("f2", "main.py", 10)]
    first = build_ai_context(scan, [], findings, _repo(), _cfg())
    second = build_ai_context(scan, [], findings, _repo(), _cfg())
    assert [b.path for b in first.file_blocks] == [b.path for b in second.file_blocks]
    assert [b.text for b in first.file_blocks] == [b.text for b in second.file_blocks]


def test_language_distribution_recorded():
    scan = _scan({"app.py": APP_PY})
    scan.files.append(
        SimpleNamespace(relative_path="app.js", language="javascript", size_bytes=10)
    )
    ctx = build_ai_context(scan, [], [], _repo(), _cfg())
    assert ctx.language_distribution == {"python": 1, "javascript": 1}


def test_missing_content_skipped_gracefully():
    scan = _scan({})
    ctx = build_ai_context(scan, [], [_finding("f1", "ghost.py", 3)], _repo(), _cfg())
    assert ctx.finding_context == {}
    assert ctx.budget["truncated"] is False


def test_prompt_version_stamp():
    ctx = build_ai_context(_scan({}), [], [], _repo(), _cfg())
    assert ctx.prompt_version == "codeaudit-security-v1"


def test_per_file_cap_truncates_tail_not_finding_line():
    scan = _scan({"app.py": APP_PY})
    ctx = build_ai_context(
        scan,
        [],
        [_finding("f1", "app.py", 2)],
        _repo(),
        _cfg(ai_context_lines=10, ai_max_file_chars=120),
    )
    block = next(b for b in ctx.file_blocks if b.path == "app.py")
    assert block.truncated is True
    assert "2 | line2 = 2" in block.text  # the finding's own line survives
