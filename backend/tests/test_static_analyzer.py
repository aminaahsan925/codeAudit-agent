"""Tests for the deterministic static analyzer.

Each vulnerable fixture must produce the expected findings with exact
evidence; the safe fixture must produce none (no false positives).
"""

from services.static_analyzer import DETECTORS, analyze_content


def _detectors_for(findings):
    return {f.detector for f in findings}


def test_detector_count_is_thin_slice():
    # Phase 1 is a thin slice: ~10 focused detectors, not a rule zoo.
    assert 8 <= len(DETECTORS) <= 12


def test_safe_python_has_no_findings(fixtures_dir):
    content = (fixtures_dir / "safe_python" / "app.py").read_text()
    assert analyze_content("app.py", content) == []


def test_sql_injection_detected_with_evidence(fixtures_dir):
    content = (fixtures_dir / "sql_injection_example" / "users.py").read_text()
    findings = analyze_content("users.py", content)
    sql = [f for f in findings if f.detector == "sql_string_construction"]
    assert len(sql) == 2
    for finding in sql:
        assert finding.severity.value == "high"
        assert finding.source.value == "deterministic"
        # Evidence is the exact source line.
        assert finding.evidence in content.splitlines()
        assert "cursor.execute" in finding.evidence
    # The parameterized query must NOT be flagged.
    assert all(f.line != 13 for f in sql)


def test_hardcoded_secrets_detected(fixtures_dir):
    content = (fixtures_dir / "hardcoded_secret_example" / "config.py").read_text()
    findings = analyze_content("config.py", content)
    secrets = [f for f in findings if f.detector == "hardcoded_secret"]
    assert len(secrets) == 2
    assert {f.line for f in secrets} == {7, 8}
    # os.environ.get(...) must NOT be flagged.
    assert all("environ" not in f.evidence for f in secrets)


def test_xss_detected(fixtures_dir):
    content = (fixtures_dir / "xss_example" / "views.py").read_text()
    findings = analyze_content("views.py", content)
    xss = [f for f in findings if f.detector == "unsafe_html_render"]
    assert len(xss) == 2
    assert xss[0].severity.value == "high"


def test_eval_exec_detected(fixtures_dir):
    content = (fixtures_dir / "dangerous_eval_example" / "calc.py").read_text()
    findings = analyze_content("calc.py", content)
    assert _detectors_for(findings) == {"dangerous_eval", "dangerous_exec"}
    # Dynamic (non-constant) args -> high severity.
    assert all(f.severity.value == "high" for f in findings)


def test_subprocess_shell_true():
    code = 'import subprocess\nsubprocess.run("ls " + user_input, shell=True)\n'
    findings = analyze_content("s.py", code)
    assert [f.detector for f in findings] == ["subprocess_shell_true"]
    assert findings[0].severity.value == "high"


def test_subprocess_without_shell_true_is_clean():
    code = 'import subprocess\nsubprocess.run(["ls", "-la"], shell=False)\n'
    assert analyze_content("s.py", code) == []


def test_os_system_and_weak_crypto():
    code = "import os, hashlib\nos.system('ls ' + d)\nh = hashlib.md5(b'x')\n"
    findings = analyze_content("s.py", code)
    assert _detectors_for(findings) == {"os_system", "weak_crypto"}


def test_long_function_and_bare_except(monkeypatch):
    from dataclasses import replace

    from app import config

    # detect_long_function reads settings at call time; patch the module attr.
    monkeypatch.setattr(
        config, "settings", replace(config.settings, max_function_lines=5)
    )
    code = (
        "def big():\n"
        "    a = 1\n    b = 2\n    c = 3\n    d = 4\n    e = 5\n    f = 6\n"
        "    return a\n"
        "try:\n    pass\nexcept:\n    pass\n"
    )
    findings = analyze_content("s.py", code)
    assert _detectors_for(findings) == {"long_function", "bare_except"}


def test_invalid_python_yields_no_findings(fixtures_dir):
    content = (fixtures_dir / "invalid_python" / "broken.py").read_text()
    assert analyze_content("broken.py", content) == []


def test_findings_have_stable_sorted_order(fixtures_dir):
    content = (fixtures_dir / "dangerous_eval_example" / "calc.py").read_text()
    first = [f.id for f in analyze_content("calc.py", content)]
    second = [f.id for f in analyze_content("calc.py", content)]
    assert first == second == sorted(first)
