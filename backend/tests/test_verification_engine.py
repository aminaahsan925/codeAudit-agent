"""Tests for the deterministic verification engine.

verify_fix() compares BEFORE and AFTER deterministic findings using only
repository content — never model claims. Covers the five deterministic
outcomes: VERIFIED, NOT_VERIFIED, PARTIALLY_VERIFIED, NEW_ISSUE_INTRODUCED,
CANNOT_VERIFY.
"""

from __future__ import annotations

from models.schemas import (
    Category,
    Confidence,
    Finding,
    FindingSource,
    Severity,
    VerificationStatus,
)
from services import verification_engine

APP = "app.py"
SQLI_ID = "sql_string_construction:app.py:9"
SQLI_LINE = (
    '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
)
SAFE_LINE = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
EVAL_LINE = '    eval("fetch_user_" + user_id)'


def _finding(
    *,
    finding_id: str = SQLI_ID,
    detector: str = "sql_string_construction",
    file: str = APP,
    line: int = 9,
    evidence: str = SQLI_LINE,
    confidence: Confidence = Confidence.MEDIUM,
) -> Finding:
    return Finding(
        id=finding_id,
        detector=detector,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=confidence,
        source=FindingSource.DETERMINISTIC,
        title="t",
        description="d",
        suggested_fix="s",
        file=file,
        line=line,
        evidence=evidence,
        references=[],
    )


def _contents(line_no: int = 9, content_line: str = SQLI_LINE) -> dict:
    """File contents with the given line at line_no (evidence is matched
    near the claimed line, mirroring the hard gate)."""
    lines = ["pass"] * (line_no - 1) + [content_line]
    return {APP: "\n".join(lines) + "\n"}


def _verify(**kwargs):
    defaults = dict(
        finding=_finding(),
        before_findings=[_finding()],
        before_contents=_contents(),
        after_findings=[],
        after_contents=_contents(9, SAFE_LINE),
        changed_files=[APP],
    )
    defaults.update(kwargs)
    return verification_engine.verify_fix(**defaults)


# --- VERIFIED ------------------------------------------------------------


def test_verified_when_finding_and_evidence_gone():
    result = _verify()
    assert result.status == VerificationStatus.VERIFIED
    assert result.verified is True
    assert result.finding_present_after is False
    assert result.original_evidence_present_after is False


def test_verified_when_new_findings_are_in_unchanged_files():
    other = _finding(
        finding_id="hardcoded_secret:other.py:2",
        detector="hardcoded_secret",
        file="other.py",
        line=2,
        evidence='KEY = "abc"',
    )
    result = _verify(after_findings=[other], changed_files=[APP])
    assert result.status == VerificationStatus.VERIFIED


# --- NOT_VERIFIED --------------------------------------------------------


def test_not_verified_when_finding_persists():
    result = _verify(
        after_findings=[_finding()],
        after_contents=_contents(),
    )
    assert result.status == VerificationStatus.NOT_VERIFIED
    assert result.verified is False
    assert result.finding_present_after is True


def test_not_verified_when_line_shifts_within_tolerance():
    """(Q) A finding that moved <= 2 lines is still the same finding."""
    moved = _finding(line=11, finding_id="sql_string_construction:app.py:11")
    result = _verify(after_findings=[moved])
    assert result.status == VerificationStatus.NOT_VERIFIED


def test_not_verified_when_finding_id_matches_despite_content_change():
    result = _verify(
        after_findings=[_finding()],
        after_contents={APP: f"x\n{SAFE_LINE}\n"},
    )
    # Identity match on the detector output wins over evidence matching.
    assert result.status == VerificationStatus.NOT_VERIFIED


# --- PARTIALLY_VERIFIED ---------------------------------------------------


def test_partially_verified_when_same_detector_fires_nearby():
    """The same detector fires on the same file within 10 lines while the
    original evidence text is still present — the issue moved, not fixed."""
    nearby = _finding(line=14, finding_id="sql_string_construction:app.py:14")
    result = _verify(
        after_findings=[nearby],
        after_contents=_contents(),  # original evidence still at line 9
    )
    assert result.status == VerificationStatus.PARTIALLY_VERIFIED
    assert result.verified is False


# --- NEW_ISSUE_INTRODUCED -------------------------------------------------


def test_new_issue_introduced_when_eval_appears():
    new_issue = _finding(
        finding_id="dangerous_eval:app.py:9",
        detector="dangerous_eval",
        line=9,
        evidence=EVAL_LINE,
        confidence=Confidence.HIGH,
    )
    result = _verify(
        after_findings=[new_issue],
        after_contents=_contents(9, EVAL_LINE),
    )
    assert result.status == VerificationStatus.NEW_ISSUE_INTRODUCED
    assert result.verified is False
    assert result.new_findings_introduced == ["dangerous_eval:app.py:9"]


def test_preexisting_findings_are_not_new_issues():
    preexisting = _finding(
        finding_id="hardcoded_secret:app.py:1",
        detector="hardcoded_secret",
        line=1,
        evidence='KEY = "abc"',
    )
    result = _verify(
        before_findings=[_finding(), preexisting],
        after_findings=[preexisting],
    )
    assert result.status == VerificationStatus.VERIFIED
    assert result.new_findings_introduced == []


# --- CANNOT_VERIFY --------------------------------------------------------


def test_cannot_verify_when_patched_file_missing_from_after():
    result = _verify(after_contents={"other.py": "x\n"})
    assert result.status == VerificationStatus.CANNOT_VERIFY
    assert result.verified is False


def test_cannot_verify_when_evidence_present_but_detector_silent():
    """Evidence text survived while the detector no longer fires — the
    verifier refuses to claim success on a possible parser gap."""
    result = _verify(after_findings=[], after_contents=_contents())
    assert result.status == VerificationStatus.CANNOT_VERIFY


def test_result_carries_traceability_fields():
    result = _verify()
    assert result.original_finding_id == SQLI_ID
    assert result.finding_present_before is True
    assert result.original_evidence_present_before is True
    assert result.reason
