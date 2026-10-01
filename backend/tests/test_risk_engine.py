"""Tests for the risk engine: deterministic, transparent, auditable."""

from models.schemas import Category, Confidence, Finding, FindingSource, Severity
from services.risk_engine import SCORE_DIVISOR, calculate_risk, finding_score, reachability_factor
from utils.constants import CONFIDENCE_FACTORS, REACHABILITY_FACTORS, SEVERITY_WEIGHTS


def _finding(severity, confidence, file="a.py"):
    return Finding(
        id=f"t:{severity}:{confidence}:{file}",
        category=Category.SECURITY,
        severity=severity,
        title="T",
        description="D",
        file=file,
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
    assert first.score == second.score == 10  # capped, not unbounded
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
    # score = min(10, round(total / SCORE_DIVISOR)) on the 0-10 scale
    assert risk.score == min(10, round(b.total_weighted_points / SCORE_DIVISOR))


def test_reachability_factor_web_exposed_paths():
    assert reachability_factor("views.py") == REACHABILITY_FACTORS["exposed"]
    assert reachability_factor("app/api/routes.py") == REACHABILITY_FACTORS["exposed"]
    assert reachability_factor("utils/helpers.py") == REACHABILITY_FACTORS["internal"]
    assert reachability_factor("models.py") == REACHABILITY_FACTORS["internal"]


def test_exposed_finding_scores_higher():
    internal = _finding(Severity.HIGH, Confidence.HIGH, file="utils.py")
    exposed = _finding(Severity.HIGH, Confidence.HIGH, file="views.py")
    assert finding_score(exposed) > finding_score(internal)
    assert finding_score(exposed) == finding_score(internal) * REACHABILITY_FACTORS["exposed"]


def test_breakdown_exposes_reachability():
    risk = calculate_risk([_finding(Severity.HIGH, Confidence.HIGH, file="views.py")])
    assert risk.breakdown.reachability_factors == REACHABILITY_FACTORS
    assert "reachability" in risk.breakdown.formula


def test_risk_bands():
    assert calculate_risk([_finding(Severity.INFO, Confidence.LOW)]).level == "low"
    many_medium = [_finding(Severity.MEDIUM, Confidence.HIGH) for _ in range(10)]
    assert calculate_risk(many_medium).level == "medium"


def _critical_high_findings(n):
    # Each: 100 (critical) x 1.0 (high confidence) x 1.0 (internal path) = 100 pts.
    return [_finding(Severity.CRITICAL, Confidence.HIGH, file=f"mod{i}.py") for i in range(n)]


def test_score_scale_is_zero_to_ten():
    assert calculate_risk([]).score == 0
    # A single critical finding (100 pts) maps to 1, not 10: the scale is 0-10.
    assert calculate_risk(_critical_high_findings(1)).score == 1
    # Heavy load caps at 10, never beyond.
    assert calculate_risk(_critical_high_findings(50)).score == 10
    assert calculate_risk(_critical_high_findings(500)).score == 10
    for n in (0, 1, 3, 5, 8, 10, 50, 500):
        assert 0 <= calculate_risk(_critical_high_findings(n)).score <= 10


def test_risk_bands_new_scale():
    # score = min(10, round(total / 100)); bands: 8 critical, 5 high, 3 medium.
    assert calculate_risk(_critical_high_findings(1)).level == "low"      # 100 -> 1
    assert calculate_risk(_critical_high_findings(2)).level == "low"      # 200 -> 2
    assert calculate_risk(_critical_high_findings(3)).level == "medium"   # 300 -> 3
    assert calculate_risk(_critical_high_findings(4)).level == "medium"   # 400 -> 4
    assert calculate_risk(_critical_high_findings(5)).level == "high"     # 500 -> 5
    assert calculate_risk(_critical_high_findings(7)).level == "high"     # 700 -> 7
    assert calculate_risk(_critical_high_findings(8)).level == "critical"  # 800 -> 8
    assert calculate_risk(_critical_high_findings(10)).level == "critical"  # capped


def test_formula_text_documents_zero_to_ten_scale():
    risk = calculate_risk(_critical_high_findings(1))
    assert "min(10" in risk.breakdown.formula
    assert "0-10" in risk.breakdown.formula
    assert "not scientifically validated" in risk.breakdown.formula
