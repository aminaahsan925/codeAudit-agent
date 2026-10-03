"""Tests for the multi-language analysis layer: registry + JavaScript/TypeScript.

All hermetic — no network. Fixtures live in tests/fixtures/js_vulnerable,
ts_vulnerable, js_safe, and js_invalid.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from models.schemas import (
    Category,
    Confidence,
    Finding,
    FindingSource,
    FixChange,
    FixDecision,
    FixProposal,
    RemediationStatus,
    Severity,
    VerificationStatus,
)
from services import finding_validator
from services.ai_provider import StubAIProvider
from services.languages.javascript_analyzer import JavaScriptAnalyzer
from services.languages.python_analyzer import PythonAnalyzer
from services.languages.registry import get_analyzer, supported_languages
from services.orchestrator import AnalysisOrchestrator
from services.remediation_engine import RemediationEngine
from services.repository_scanner import supports_deep_analysis
from services.static_analyzer import analyze_content as analyze_python_content
from tests.fakes import FakeAIProvider


@pytest.fixture()
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def _read(fixture: Path, name: str) -> tuple[str, str]:
    content = (fixture / name).read_text(encoding="utf-8")
    return name, content


# --- Registry ------------------------------------------------------------


def test_registry_resolves_python():
    analyzer = get_analyzer("python")
    assert isinstance(analyzer, PythonAnalyzer)
    assert analyzer.language == "python"


def test_registry_resolves_javascript_and_typescript():
    js = get_analyzer("javascript")
    ts = get_analyzer("typescript")
    assert isinstance(js, JavaScriptAnalyzer)
    assert isinstance(ts, JavaScriptAnalyzer)
    assert js.language == "javascript"
    assert ts.language == "typescript"
    # Distinct instances, each bound to its own grammar.
    assert js is not ts


def test_registry_unknown_language_returns_none():
    assert get_analyzer("java") is None
    assert get_analyzer("go") is None
    assert get_analyzer(None) is None
    assert get_analyzer("") is None


def test_supported_languages_matches_deep_analysis_set():
    assert supported_languages() == frozenset({"python", "javascript", "typescript"})


def test_supports_deep_analysis_uses_registry():
    assert supports_deep_analysis("python")
    assert supports_deep_analysis("javascript")
    assert supports_deep_analysis("typescript")
    assert not supports_deep_analysis("java")
    assert not supports_deep_analysis(None)


def test_javascript_analyzer_rejects_other_languages():
    with pytest.raises(ValueError):
        JavaScriptAnalyzer("python")


# --- Python adapter: zero behavior change ----------------------------------


def test_python_analyzer_matches_legacy_pipeline(fixtures_dir: Path):
    """Same findings and IDs as static_analyzer.analyze_content, plus language."""
    content = (fixtures_dir / "sql_injection_example" / "users.py").read_text()
    legacy = analyze_python_content("users.py", content)
    adapted = PythonAnalyzer().analyze_file("users.py", content)
    assert [f.id for f in adapted] == [f.id for f in legacy]
    assert [(f.detector, f.line, f.evidence) for f in adapted] == [
        (f.detector, f.line, f.evidence) for f in legacy
    ]
    assert all(f.language == "python" for f in adapted)


def test_python_analyzer_parse_matches_code_parser(fixtures_dir: Path):
    content = (fixtures_dir / "sql_injection_example" / "users.py").read_text()
    parsed = PythonAnalyzer().parse_source(content, "users.py")
    assert parsed.language == "python"
    assert parsed.parse_error is None
    assert any(s.kind == "function" for s in parsed.symbols)


def test_python_analyzer_parse_error_structural():
    parsed = PythonAnalyzer().parse_source("def broken(:\n", "broken.py")
    assert parsed.parse_error is not None
    assert "SyntaxError" in parsed.parse_error


# --- JavaScript detectors ----------------------------------------------------


def _js_findings(fixtures_dir: Path) -> list[Finding]:
    name, content = _read(fixtures_dir / "js_vulnerable", "app.js")
    return get_analyzer("javascript").analyze_file(name, content)  # type: ignore[union-attr]


def test_all_nine_detectors_fire_on_vulnerable_fixture(fixtures_dir: Path):
    detectors = {f.detector for f in _js_findings(fixtures_dir)}
    assert detectors == {
        "js_dangerous_eval",
        "js_function_constructor",
        "js_command_injection",
        "js_xss_dom_sink",
        "js_react_dangerous_html",
        "js_hardcoded_secret",
        "js_sql_string_construction",
        "js_weak_crypto",
        "js_implied_eval",
    }


def test_js_finding_ids_evidence_and_attribution(fixtures_dir: Path):
    findings = _js_findings(fixtures_dir)
    by_detector = {f.detector: f for f in findings}
    eval_finding = by_detector["js_dangerous_eval"]
    assert eval_finding.id == "js_dangerous_eval:app.js:5"
    assert eval_finding.evidence == "const result = eval(userInput);"
    assert eval_finding.line == 5
    assert eval_finding.file == "app.js"
    assert eval_finding.language == "javascript"
    assert eval_finding.source == FindingSource.DETERMINISTIC
    assert eval_finding.category == Category.SECURITY
    assert eval_finding.severity == Severity.HIGH
    assert eval_finding.confidence == Confidence.HIGH
    assert eval_finding.suggested_fix

    secret = by_detector["js_hardcoded_secret"]
    # Phase 4: sensitive findings carry redacted evidence (the raw secret
    # never appears in a finding).
    assert secret.evidence == 'const apiKey = "[REDACTED]";'
    assert secret.sensitive is True

    sql = [f for f in findings if f.detector == "js_sql_string_construction"]
    assert len(sql) == 2  # template literal + concatenation
    assert all(f.confidence == Confidence.MEDIUM for f in sql)

    assert by_detector["js_weak_crypto"].severity == Severity.MEDIUM
    assert by_detector["js_implied_eval"].severity == Severity.MEDIUM


def test_js_command_injection_variants(fixtures_dir: Path):
    findings = _js_findings(fixtures_dir)
    injections = [f for f in findings if f.detector == "js_command_injection"]
    assert len(injections) == 2
    lines = sorted(f.line for f in injections)
    assert lines == [11, 13]  # shell:true and non-literal command


def test_js_does_not_flag_literal_commands_and_static_strings():
    analyzer = JavaScriptAnalyzer("javascript")
    content = (
        'const { execFile } = require("child_process");\n'
        'execFile("ls", ["-la"], (e, o) => console.log(o));\n'
        'const cp = require("child_process");\n'
        'cp.exec("uptime");\n'
        'el.innerHTML = "<b>static</b>";\n'
    )
    findings = analyzer.analyze_file("ok.js", content)
    assert findings == []


def test_typescript_fixture_detectors(fixtures_dir: Path):
    name, content = _read(fixtures_dir / "ts_vulnerable", "app.ts")
    findings = get_analyzer("typescript").analyze_file(name, content)  # type: ignore[union-attr]
    detectors = {f.detector for f in findings}
    assert detectors == {
        "js_dangerous_eval",
        "js_react_dangerous_html",
        "js_sql_string_construction",
    }
    assert all(f.language == "typescript" for f in findings)
    react = next(f for f in findings if f.detector == "js_react_dangerous_html")
    assert "dangerouslySetInnerHTML" in react.evidence


def test_safe_fixture_yields_zero_findings(fixtures_dir: Path):
    name, content = _read(fixtures_dir / "js_safe", "app.js")
    findings = get_analyzer("javascript").analyze_file(name, content)  # type: ignore[union-attr]
    assert findings == []


def test_invalid_js_does_not_crash_and_yields_no_garbage(fixtures_dir: Path):
    name, content = _read(fixtures_dir / "js_invalid", "broken.js")
    analyzer = get_analyzer("javascript")
    assert analyzer is not None
    parsed = analyzer.parse_source(content, name)
    # tree-sitter is error-tolerant: a partial tree, never an exception.
    assert parsed.parse_error is None
    findings = analyzer.analyze_file(name, content)
    assert findings == []


def test_js_analysis_is_deterministic(fixtures_dir: Path):
    name, content = _read(fixtures_dir / "js_vulnerable", "app.js")
    analyzer = JavaScriptAnalyzer("javascript")
    first = analyzer.analyze_file(name, content)
    second = analyzer.analyze_file(name, content)
    assert [(f.id, f.evidence) for f in first] == [(f.id, f.evidence) for f in second]


def test_js_parse_extracts_symbols():
    parsed = JavaScriptAnalyzer("javascript").parse_source(
        "function foo() {}\nclass Bar {}\n", "x.js"
    )
    kinds = {(s.kind, s.name) for s in parsed.symbols}
    assert ("function", "foo") in kinds
    assert ("class", "Bar") in kinds


# --- Orchestrator end-to-end --------------------------------------------------


def _copy_fixture_tree(fixtures_dir: Path, dest: Path) -> Path:
    for fixture in ("js_vulnerable", "ts_vulnerable", "js_safe", "js_invalid"):
        shutil.copytree(fixtures_dir / fixture, dest / fixture)
    (dest / "notes.txt").write_text("hello\n")  # unsupported language
    return dest


def test_orchestrator_end_to_end_over_js_fixtures(tmp_path: Path, fixtures_dir: Path):
    repo = _copy_fixture_tree(fixtures_dir, tmp_path / "repo")
    orch = AnalysisOrchestrator(ai_provider=StubAIProvider())
    result = orch.run_on_local_path(repo)
    s = result.summary

    # 4 fixture dirs + notes.txt = 5 discovered; 4 deep (js/ts), 1 unsupported.
    assert s.files_discovered == 5
    assert s.files_scanned == 5
    assert s.files_deep_analyzed == 4
    assert s.files_unsupported == 1
    assert s.files_failed_parse == 0
    assert s.files_skipped == 0

    # Accounting invariant: every discovered file in exactly one bucket.
    assert s.files_discovered == (
        s.files_deep_analyzed
        + s.files_unsupported
        + s.files_skipped
        + s.files_failed_parse
    )

    detectors = {f.detector for f in result.findings}
    assert "js_dangerous_eval" in detectors
    assert "js_sql_string_construction" in detectors
    # Python findings still flow through the same pipeline.
    assert all(f.language in ("javascript", "typescript") for f in result.findings)
    assert result.risk.score >= 0


# --- Evidence validator hard gate ----------------------------------------------


def test_validator_gate_accepts_real_js_finding(tmp_path: Path, fixtures_dir: Path):
    shutil.copytree(fixtures_dir / "js_vulnerable", tmp_path / "repo")
    orch = AnalysisOrchestrator(ai_provider=StubAIProvider())
    result = orch.run_on_local_path(tmp_path / "repo")
    # Every surviving finding passed the evidence hard gate.
    assert result.findings, "expected JS findings to survive validation"
    assert all(isinstance(f.detector, str) and f.detector.startswith("js_") for f in result.findings)


def test_validator_gate_drops_fabricated_js_finding():
    contents = {"app.js": "const result = eval(userInput);\n"}

    def _finding(**overrides):
        base = dict(
            id="js_dangerous_eval:app.js:1",
            category=Category.SECURITY,
            severity=Severity.HIGH,
            title="Dangerous eval() call",
            description="fabricated",
            file="app.js",
            line=1,
            evidence="const result = eval(userInput);",
            confidence=Confidence.HIGH,
            source=FindingSource.DETERMINISTIC,
            detector="js_dangerous_eval",
            language="javascript",
        )
        base.update(overrides)
        return Finding(**base)

    gate = finding_validator.validate_findings([_finding()], contents)
    assert len(gate.validated) == 1
    assert gate.dropped == []

    # Wrong line: dropped.
    gate = finding_validator.validate_findings(
        [_finding(id="js_dangerous_eval:app.js:99", line=99, evidence="eval(x)")],
        contents,
    )
    assert gate.validated == []
    assert len(gate.dropped) == 1

    # Evidence does not match the cited line: dropped.
    gate = finding_validator.validate_findings(
        [_finding(evidence="const result = JSON.parse(userInput);")],
        contents,
    )
    assert gate.validated == []
    assert len(gate.dropped) == 1


# --- Remediation round-trip on a JS finding ----------------------------------------


def test_js_finding_remediation_round_trip(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    original = "const result = eval(userInput);\nconsole.log(result);\n"
    (repo / "app.js").write_text(original)

    before = AnalysisOrchestrator(ai_provider=StubAIProvider()).run_on_local_path(repo)
    finding_id = "js_dangerous_eval:app.js:1"
    assert finding_id in [f.id for f in before.findings]

    proposal = FixProposal(
        finding_id=finding_id,
        decision=FixDecision.FIX,
        reasoning="replace eval with JSON.parse",
        changes=[
            FixChange(
                file="app.js",
                start_line=1,
                end_line=1,
                old_text="const result = eval(userInput);",
                new_text="const result = JSON.parse(userInput);",
                rationale="eliminate eval",
            )
        ],
        expected_effect="finding eliminated",
        verification_notes="rerun the analyzer",
    )
    engine = RemediationEngine(ai_provider=FakeAIProvider(fix_proposal=proposal))
    result = engine.remediate_finding(finding_id, repo, before)

    assert result.status == RemediationStatus.VERIFIED
    assert result.verification.verified is True
    # The original repository was never modified.
    assert (repo / "app.js").read_text() == original
