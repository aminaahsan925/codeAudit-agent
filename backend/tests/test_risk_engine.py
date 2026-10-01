"""Tests for the risk engine: deterministic, transparent, auditable."""

from models.schemas import Category, Confidence, Finding, FindingSource, Severity
from services.risk_engine import DIVISOR, calculate_risk, finding_score
from utils.constants import CONFIDENCE_FACTORS, SEVERITY_WEIGHTS


def _finding(severity, confidence):
    return Finding(
        id=f"t:{severity}:{confidence}",
        category=Category.SECURITY,
        severity=severity,
        title="T",
        description="D",
        file="a.py",
        line=1,
        evidence="e",
        confidence=confidence,
        source=FindingSource.DETERMINISTIC,
        detector="d",
    )


def test_finding_score_formula_is_transparent():
    f = _finding(Severity.HIGH, Confidence.HIGH)
    assert finding_score(f) == SEVERITY_WEIGHTS["high"] * CONFIDENCE_FACTORS["high"]
    f2 = _finding(Severity.MEDIUM, Confidence.LOW)
    assert finding_score(f2) == SEVERITY_WEIGHTS["medium"] * CONFIDENCE_FACTORS["low"]


def test_empty_findings_score_zero():
    risk = calculate_risk([])
    assert risk.score == 0
    assert risk.level == "low"
    assert risk.breakdown.findings_counted == 0


def test_score_is_deterministic_and_capped():
    findings = [_finding(Severity.CRITICAL, Confidence.HIGH) for _ in range(50)]
    first = calculate_risk(findings)
    second = calculate_risk(findings)
    assert first.score == second.score == 100  # capped, not unbounded
    assert first.level == "critical"


def test_breakdown_exposes_formula_and_weights():
    findings = [_finding(Severity.HIGH, Confidence.HIGH)]
    risk = calculate_risk(findings)
    b = risk.breakdown
    assert "severity_weight" in b.formula
    assert "not scientifically validated" in b.formula
    assert b.severity_weights == SEVERITY_WEIGHTS
    assert b.confidence_factors == CONFIDENCE_FACTORS
    assert b.findings_counted == 1
    assert b.total_weighted_points == SEVERITY_WEIGHTS["high"] * 1.0
    # score = min(100, round(total / DIVISOR))
    assert risk.score == min(100, round(b.total_weighted_points / DIVISOR))


def test_risk_bands():
    assert calculate_risk([_finding(Severity.INFO, Confidence.LOW)]).level == "low"
    many_medium = [_finding(Severity.MEDIUM, Confidence.HIGH) for _ in range(10)]
    assert calculate_risk(many_medium).level == "medium"
