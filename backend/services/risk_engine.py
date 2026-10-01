"""Risk engine: deterministic, transparent, auditable scoring.

Public contract: the repository score is an integer on a 0-10 scale.

Formula (heuristic — NOT scientifically validated, and the output says so):

    per_finding_score = severity_weight * confidence_factor * reachability_factor
    repository_score  = min(10, round(sum(per_finding_score) / 100))

Reachability is a path-based heuristic: findings in plausibly web-exposed
code (views, routes, handlers, controllers, APIs) get a 1.25 multiplier.
This is documented path-substring matching, not data-flow analysis.

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
from utils.constants import (
    CONFIDENCE_FACTORS,
    REACHABILITY_FACTORS,
    REACHABILITY_PATH_HINTS,
    RISK_BANDS,
    SEVERITY_WEIGHTS,
)

# Divisor mapping total weighted points onto the public 0-10 score scale.
# Per-finding raw points (severity_weight * confidence_factor *
# reachability_factor) are unchanged; only the aggregate is rescaled.
SCORE_DIVISOR = 100


def _level_for(score: int) -> str:
    for threshold, level in RISK_BANDS:
        if score >= threshold:
            return level
    return "low"


def reachability_factor(relative_path: str) -> float:
    """1.25 for web-exposed-looking paths, 1.0 otherwise (documented heuristic)."""
    lowered = (relative_path or "").lower()
    if any(hint in lowered for hint in REACHABILITY_PATH_HINTS):
        return REACHABILITY_FACTORS["exposed"]
    return REACHABILITY_FACTORS["internal"]


def finding_score(finding: Finding) -> float:
    severity_weight = SEVERITY_WEIGHTS[finding.severity.value]
    confidence_factor = CONFIDENCE_FACTORS[finding.confidence.value]
    return severity_weight * confidence_factor * reachability_factor(finding.file)


def calculate_risk(findings: list[Finding]) -> RiskResult:
    points = [finding_score(f) for f in findings]
    total = round(sum(points), 2)
    score = min(10, round(total / SCORE_DIVISOR))
    breakdown = RiskBreakdown(
        severity_weights=dict(SEVERITY_WEIGHTS),
        confidence_factors=dict(CONFIDENCE_FACTORS),
        reachability_factors=dict(REACHABILITY_FACTORS),
        findings_counted=len(findings),
        total_weighted_points=total,
    )
    return RiskResult(score=score, level=_level_for(score), breakdown=breakdown)


# Re-export for tests and introspection.
__all__ = [
    "SCORE_DIVISOR",
    "calculate_risk",
    "finding_score",
    "reachability_factor",
    "Severity",
    "Confidence",
]
