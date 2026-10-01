"""Risk engine: deterministic, transparent, auditable scoring.

Formula (heuristic — NOT scientifically validated, and the output says so):

    per_finding_score = severity_weight * confidence_factor
    repository_score  = min(100, round(sum(per_finding_score) / 10))

The weights, the per-finding contributions, and the formula itself are
returned in the RiskResult breakdown so anyone can audit the score.
An LLM never dictates the score.
"""

from __future__ import annotations

from models.schemas import (
    Confidence,
    Finding,
    RiskBreakdown,
    RiskResult,
    Severity,
)
from utils.constants import CONFIDENCE_FACTORS, RISK_BANDS, SEVERITY_WEIGHTS

DIVISOR = 10


def _level_for(score: int) -> str:
    for threshold, level in RISK_BANDS:
        if score >= threshold:
            return level
    return "low"


def finding_score(finding: Finding) -> float:
    severity_weight = SEVERITY_WEIGHTS[finding.severity.value]
    confidence_factor = CONFIDENCE_FACTORS[finding.confidence.value]
    return severity_weight * confidence_factor


def calculate_risk(findings: list[Finding]) -> RiskResult:
    points = [finding_score(f) for f in findings]
    total = round(sum(points), 2)
    score = min(100, round(total / DIVISOR))
    breakdown = RiskBreakdown(
        severity_weights=dict(SEVERITY_WEIGHTS),
        confidence_factors=dict(CONFIDENCE_FACTORS),
        findings_counted=len(findings),
        total_weighted_points=total,
    )
    return RiskResult(score=score, level=_level_for(score), breakdown=breakdown)


# Re-export for tests and introspection.
__all__ = [
    "DIVISOR",
    "calculate_risk",
    "finding_score",
    "Severity",
    "Confidence",
]
