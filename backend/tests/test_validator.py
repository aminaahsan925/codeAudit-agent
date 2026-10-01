"""Tests for the finding validator (the evidence hard gate)."""

from models.schemas import Category, Confidence, Finding, FindingSource, Severity
from services.finding_validator import validate_findings


def _finding(**overrides):
    base = dict(
        id="test:file.py:1",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="T",
        description="D",
        file="app.py",
        line=2,
        evidence='x = eval(user_input)',
        confidence=Confidence.HIGH,
        source=FindingSource.DETERMINISTIC,
        detector="dangerous_eval",
    )
    base.update(overrides)
    return Finding(**base)


CONTENTS = {"app.py": "import os\nx = eval(user_input)\nprint(x)\n"}


def test_valid_finding_passes():
    result = validate_findings([_finding()], CONTENTS)
    assert len(result.validated) == 1
    assert result.validated[0].validation == "passed"
    assert result.dropped == []


def test_missing_file_dropped():
    result = validate_findings([_finding(file="nope.py")], CONTENTS)
    assert result.validated == []
    assert len(result.dropped) == 1
    assert result.drop_reasons["file_not_found"] == 1


def test_out_of_range_line_dropped():
    result = validate_findings([_finding(line=99)], CONTENTS)
    assert result.validated == []
    assert result.drop_reasons["line_out_of_range"] == 1


def test_evidence_mismatch_dropped():
    result = validate_findings([_finding(evidence="totally different code")], CONTENTS)
    assert result.validated == []
    assert result.drop_reasons["evidence_mismatch"] == 1


def test_evidence_substring_of_long_line_passes():
    long_line = "x = eval(user_input)  # " + "padding " * 50
    contents = {"app.py": f"import os\n{long_line}\n"}
    result = validate_findings([_finding(evidence="x = eval(user_input)")], contents)
    assert len(result.validated) == 1


def test_whitespace_insensitive_match():
    contents = {"app.py": "import os\n    x   =   eval(user_input)\n"}
    result = validate_findings([_finding(evidence="x = eval(user_input)")], contents)
    assert len(result.validated) == 1
