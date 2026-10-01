"""AI result processor: deterministic handling of model output.

Pure, side-effect-free functions that turn an AIInvestigationResult into
pipeline-ready findings. No network, no model calls here — which makes the
rules fully unit-testable and hermetic.

Rules (documented, deterministic):

ASSESSMENT APPLICATION (enrichment of deterministic findings):
  * An assessment must reference a known deterministic finding id;
    unknown ids and duplicate assessments are ignored (counted).
  * verdict "confirmed" -> attach ai_reasoning + suggested_fix (if given).
  * verdict "uncertain"  -> attach reasoning, demote confidence ONE step.
  * verdict "unlikely"   -> attach reasoning, demote confidence to low.
  * NEVER changed by AI: id, file, line, evidence, severity, detector,
    source. AI enriches; it never rewrites the evidence anchor and never
    deletes a deterministic finding (fail-closed).

DEDUPLICATION (AI candidates vs deterministic findings):
  * Match key: same normalized file + same category + |line diff| <= 2.
  * A candidate matching a deterministic finding is merged INTO it (its
    reasoning/suggested_fix enrich the anchor when not already set) and
    counted as a duplicate — never shown as a second card.
  * Candidates matching each other: first wins, rest counted as duplicates.
  * Non-matching candidates are converted to Findings with source="ai"
    and detector="nemotron_security_v1". They still face the evidence hard
    gate downstream; nothing here bypasses it.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

from models.schemas import (
    AIAssessment,
    AIFindingCandidate,
    AIVerdict,
    Confidence,
    Finding,
    FindingSource,
)

from services.ai_provider import AIInvestigationResult

logger = logging.getLogger(__name__)

AI_DETECTOR_NAME = "nemotron_security_v1"

# Lines within this distance, same file + category, are considered the same
# underlying issue for deduplication purposes.
DEDUP_LINE_TOLERANCE = 2

_CONFIDENCE_ORDER = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]


def _demote_one_step(confidence: Confidence) -> Confidence:
    idx = _CONFIDENCE_ORDER.index(confidence)
    return _CONFIDENCE_ORDER[min(idx + 1, len(_CONFIDENCE_ORDER) - 1)]


def _normalize_path(path: str) -> str:
    return (path or "").replace("\\", "/").strip().lower()


@dataclass
class MergedAIResults:
    enriched: list[Finding] = field(default_factory=list)
    new_candidates: list[Finding] = field(default_factory=list)
    enriched_count: int = 0
    duplicates_merged: int = 0
    ignored_assessments: int = 0


def _apply_one_assessment(finding: Finding, assessment: AIAssessment) -> Finding:
    updates: dict = {
        "ai_reasoning": assessment.reasoning,
        "prompt_version": finding.prompt_version,
    }
    if assessment.suggested_fix:
        updates["suggested_fix"] = assessment.suggested_fix
    if assessment.verdict == AIVerdict.UNCERTAIN:
        updates["confidence"] = _demote_one_step(finding.confidence)
    elif assessment.verdict == AIVerdict.UNLIKELY:
        updates["confidence"] = Confidence.LOW
    return finding.model_copy(update=updates)


def apply_assessments(
    findings: list[Finding],
    assessments: list[AIAssessment],
    *,
    provider_name: str,
    prompt_version: str,
) -> tuple[list[Finding], int, int]:
    """Attach AI verdicts to deterministic findings. Returns (enriched, enriched_count, ignored)."""
    by_id = {f.id: f for f in findings}
    seen: set[str] = set()
    # Work on copies so the caller's list is untouched.
    enriched = [f.model_copy() for f in findings]
    by_id = {f.id: f for f in enriched}
    enriched_count = 0
    ignored = 0
    for assessment in assessments:
        target = by_id.get(assessment.finding_id)
        if target is None or assessment.finding_id in seen:
            ignored += 1
            continue
        seen.add(assessment.finding_id)
        idx = enriched.index(target)
        updated = _apply_one_assessment(target, assessment)
        updated = updated.model_copy(
            update={"enriched_by": provider_name, "prompt_version": prompt_version}
        )
        enriched[idx] = updated
        enriched_count += 1
    return enriched, enriched_count, ignored


def _candidate_id(candidate: AIFindingCandidate) -> str:
    digest = hashlib.sha1(
        f"{candidate.category.value}|{candidate.title}|{candidate.evidence}".encode(
            "utf-8"
        )
    ).hexdigest()[:8]
    return f"ai:{_normalize_path(candidate.file)}:{candidate.line}:{digest}"


def candidate_to_finding(
    candidate: AIFindingCandidate,
    *,
    provider_name: str,
    prompt_version: str,
) -> Finding:
    """Convert a validated AI candidate into a Finding (source="ai")."""
    return Finding(
        id=_candidate_id(candidate),
        category=candidate.category,
        severity=candidate.severity,
        title=candidate.title,
        description=candidate.description,
        file=_normalize_path(candidate.file),
        line=candidate.line,
        evidence=candidate.evidence,
        suggested_fix=candidate.suggested_fix,
        confidence=candidate.confidence,
        source=FindingSource.AI,
        detector=AI_DETECTOR_NAME,
        ai_reasoning=candidate.reasoning,
        enriched_by=provider_name,
        prompt_version=prompt_version,
    )


def _is_duplicate(candidate: AIFindingCandidate, existing: Finding) -> bool:
    return (
        _normalize_path(candidate.file) == _normalize_path(existing.file)
        and candidate.category == existing.category
        and abs(candidate.line - existing.line) <= DEDUP_LINE_TOLERANCE
    )


def merge_ai_results(
    deterministic: list[Finding],
    result: AIInvestigationResult,
) -> MergedAIResults:
    """Apply assessments and deduplicate candidates. Pure function."""
    merged = MergedAIResults()
    enriched, enriched_count, ignored = apply_assessments(
        deterministic,
        result.assessments,
        provider_name=result.provider_name,
        prompt_version=result.prompt_version,
    )
    merged.enriched = enriched
    merged.enriched_count = enriched_count
    merged.ignored_assessments = ignored

    for candidate in result.candidates:
        anchor = next((f for f in merged.enriched if _is_duplicate(candidate, f)), None)
        if anchor is not None:
            # Merge into the deterministic anchor: fill gaps only.
            updates: dict = {}
            if not anchor.ai_reasoning:
                updates["ai_reasoning"] = candidate.reasoning
            if not anchor.suggested_fix and candidate.suggested_fix:
                updates["suggested_fix"] = candidate.suggested_fix
            if updates:
                idx = merged.enriched.index(anchor)
                merged.enriched[idx] = anchor.model_copy(update=updates)
            merged.duplicates_merged += 1
            continue
        if any(_is_duplicate(candidate, f) for f in merged.new_candidates):
            merged.duplicates_merged += 1
            continue
        merged.new_candidates.append(
            candidate_to_finding(
                candidate,
                provider_name=result.provider_name,
                prompt_version=result.prompt_version,
            )
        )
    return merged
