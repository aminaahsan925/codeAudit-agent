"""Evidence agent: Nemotron review of the specialists' deterministic output.

The main reasoning-heavy agent. It receives the security, performance, and
quality specialists' triaged outputs plus bounded repository excerpts, and
asks Nemotron to challenge suspicious findings, identify relationships,
flag false positives, and prioritize — all from the supplied evidence.

Hard boundaries (never violated):
  * It does NOT create final findings. Its output flows through Pydantic
    validation -> deduplication (merge_ai_results) -> the FindingValidator
    evidence hard gate, exactly like Phase 2.
  * It NEVER overrides deterministic evidence: the deterministic anchor
    (id/file/line/evidence/detector) is preserved; AI only attaches
    reasoning or proposes candidates that must pass the gate.
  * Every call is cache-checked, then budget-checked via
    budget_manager.allow_call("evidence_agent"). On exhaustion it degrades
    with AI_BUDGET_EXHAUSTED and makes no provider call.
"""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, ConfigDict, Field

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
    SpecialistAgentResult,
)
from agents.registry import EVIDENCE_AGENT
from app.config import settings
from models.schemas import Finding, Severity, ValidatedFinding
from services import finding_validator
from services.ai_budget_manager import AI_BUDGET_EXHAUSTED, AIBudgetManager
from services.ai_call_cache import AICallCache, make_cache_key
from services.ai_context_builder import AIContext, AIContextBlock
from services.ai_errors import AIError
from services.ai_provider import AIInvestigationResult, AIProvider
from services.ai_result_processor import merge_ai_results
from services.prompts.evidence_review import (
    CODEAUDIT_EVIDENCE_AGENT_PROMPT_V1,
    build_evidence_review_messages,
    wrap_untrusted,
)

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class EvidenceAgentResult(BaseModel):
    """What the evidence review produced (advisory; fusion decides finals)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    agent_name: str = EVIDENCE_AGENT
    # Deterministic findings with AI assessments attached (anchors preserved).
    enriched: list[Finding] = Field(default_factory=list)
    # AI-discovered candidates that passed the evidence hard gate.
    accepted: list[ValidatedFinding] = Field(default_factory=list)
    ai_findings_dropped: int = 0
    assessments_applied: int = 0
    duplicates_merged: int = 0
    # Review judgments derived from the model output + deterministic grouping.
    relationships: list[str] = Field(default_factory=list)
    priorities: list[str] = Field(default_factory=list)
    false_positive_flags: list[str] = Field(default_factory=list)
    # Raw model output, for the supervisor's AI status accounting.
    raw_result: AIInvestigationResult | None = Field(default=None, exclude=True)
    status: str = "disabled"  # enabled | disabled | failed | unavailable | budget_exhausted
    cached: bool = False
    execution_metadata: AgentExecutionMetadata


def _specialist_brief(specialists: list[SpecialistAgentResult]) -> str:
    lines: list[str] = []
    for spec in specialists:
        summary = spec.evidence_summary
        lines.append(
            f"- {spec.agent_name}: {summary.get('total', 0)} findings; "
            f"priority targets: {', '.join(spec.priority_targets[:5]) or 'none'}; "
            f"by detector: {summary.get('by_detector', {})}"
        )
        review = summary.get("needs_ai_review")
        if review:
            lines.append(f"  flagged for review: {', '.join(review[:10])}")
    return "\n".join(lines) or "No specialist output."


def _select_review_scope(
    ctx: AgentContext, specialists: list[SpecialistAgentResult]
) -> list[ValidatedFinding]:
    """Bounded, deterministic review scope: priority targets first."""
    max_findings = max(1, settings.ai_max_findings)
    priority_files: list[str] = []
    for spec in specialists:
        priority_files.extend(spec.priority_targets)
    priority_set = set(priority_files)

    def _rank(f: ValidatedFinding) -> tuple[int, int, str, int, str]:
        in_priority = 0 if f.file in priority_set else 1
        return (
            in_priority,
            _SEVERITY_RANK.get(f.severity, 4),
            f.file,
            f.line,
            f.detector,
        )

    return sorted(ctx.validated_findings, key=_rank)[:max_findings]


class EvidenceAgent:
    """Nemotron evidence review behind a strict agent boundary."""

    name = EVIDENCE_AGENT

    def __init__(
        self,
        provider: AIProvider | None = None,
        budget: AIBudgetManager | None = None,
        cache: AICallCache | None = None,
    ) -> None:
        self._provider = provider
        self._budget = budget
        self._cache = cache or AICallCache()

    def _degraded(
        self,
        status: str,
        error: str,
        started: float,
        scope: list[ValidatedFinding],
    ) -> EvidenceAgentResult:
        return EvidenceAgentResult(
            enriched=list(scope),
            status=status,
            execution_metadata=AgentExecutionMetadata(
                agent_name=self.name,
                status=AgentStatus.DEGRADED if status != "disabled" else AgentStatus.SKIPPED,
                duration_ms=int((time.monotonic() - started) * 1000),
                findings_count=len(scope),
                errors=[error] if error else [],
            ),
        )

    def run(
        self,
        ctx: AgentContext,
        specialists: list[SpecialistAgentResult],
    ) -> EvidenceAgentResult:
        started = time.monotonic()
        provider = self._provider or ctx.provider
        scope = _select_review_scope(ctx, specialists)

        if provider is None:
            return self._degraded(
                "unavailable", "no AI provider configured", started, scope
            )

        brief = _specialist_brief(specialists)
        excerpts = (ctx.shared.excerpts_for_findings(scope)
                    if ctx.shared else {})
        findings_block = "\n".join(
            f"[{f.id}] {f.severity.value.upper()} {f.title}\n"
            f"File: {f.file}:{f.line} (detector: {f.detector}, "
            f"confidence: {f.confidence.value})\n"
            f"Description: {f.description}\n"
            f"Evidence: {f.evidence}"
            + (f"\nSource excerpt:\n{wrap_untrusted(excerpts[f.id])}"
               if f.id in excerpts else "")
            for f in scope
        )
        # Cross-specialist file excerpts for priority targets (bounded).
        target_blocks: list[str] = []
        seen_files: set[str] = set()
        for spec in specialists:
            for path in spec.priority_targets[:3]:
                if path in seen_files or not ctx.shared:
                    continue
                seen_files.add(path)
                excerpt = ctx.shared.file_excerpt(path)
                if excerpt:
                    target_blocks.append(
                        f"--- {path} ---\n{wrap_untrusted(excerpt)}"
                    )
        excerpts_block = "\n".join(target_blocks)

        prompt_version = CODEAUDIT_EVIDENCE_AGENT_PROMPT_V1
        messages = build_evidence_review_messages(
            brief, findings_block, excerpts_block, prompt_version
        )
        context_chars = len(messages[1]["content"])

        repo_id = f"{ctx.repository.owner}/{ctx.repository.name}"
        cache_key = make_cache_key(
            repo_id,
            [f.id for f in scope],
            messages[1]["content"],
            prompt_version,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            logger.info("Evidence agent: cache hit, no model call made")
            return self._from_result(
                cached, scope, ctx, started,
                cached=True, context_chars=context_chars,
                prompt_version=prompt_version,
            )

        budget = self._budget or ctx.budget
        if budget is not None and not budget.allow_call(self.name, "analysis"):
            logger.warning("Evidence agent: AI budget exhausted, skipping model call")
            degraded = self._degraded(
                "budget_exhausted", AI_BUDGET_EXHAUSTED, started, scope
            )
            degraded.execution_metadata.context_chars = context_chars
            degraded.execution_metadata.prompt_version = prompt_version
            return degraded

        ai_context = AIContext(
            repo_owner=ctx.repository.owner,
            repo_name=ctx.repository.name,
            prompt_version=prompt_version,
            findings=list(scope),
            message_builder=lambda _c: messages,
        )
        try:
            result = provider.investigate(list(scope), ai_context)
        except AIError as exc:
            logger.warning("Evidence agent AI call failed: %s", exc.code)
            degraded = self._degraded("failed", exc.code, started, scope)
            degraded.execution_metadata.context_chars = context_chars
            degraded.execution_metadata.prompt_version = prompt_version
            return degraded
        except Exception:  # noqa: BLE001 - AI bugs must not kill the run
            logger.exception("Evidence agent: unexpected provider failure")
            degraded = self._degraded("failed", "AI_UPSTREAM_ERROR", started, scope)
            degraded.execution_metadata.context_chars = context_chars
            degraded.execution_metadata.prompt_version = prompt_version
            return degraded

        if result.status in ("failed", "unavailable"):
            degraded = self._degraded(result.status, result.error_code or result.status, started, scope)
            degraded.execution_metadata.context_chars = context_chars
            degraded.execution_metadata.prompt_version = prompt_version
            degraded.execution_metadata.model_used = result.model or None
            return degraded
        if result.status == "disabled":
            return self._degraded("disabled", "", started, scope)

        self._cache.put(cache_key, result)
        return self._from_result(
            result, scope, ctx, started,
            cached=False, context_chars=context_chars,
            prompt_version=prompt_version,
        )

    def _from_result(
        self,
        result: AIInvestigationResult,
        scope: list[ValidatedFinding],
        ctx: AgentContext,
        started: float,
        *,
        cached: bool,
        context_chars: int,
        prompt_version: str,
    ) -> EvidenceAgentResult:
        # Deterministic handling, identical discipline to Phase 2:
        # apply assessments, dedup candidates, gate everything.
        merged = merge_ai_results(list(scope), result)
        gate = finding_validator.validate_findings(
            merged.new_candidates, ctx.scan.contents
        )

        # Review judgments derived deterministically from model output.
        verdict_by_id = {a.finding_id: a.verdict.value for a in result.assessments}
        false_positives = sorted(
            fid for fid, verdict in verdict_by_id.items() if verdict == "unlikely"
        )
        priorities = sorted(
            [f.id for f in merged.enriched],
            key=lambda fid: next(
                (
                    _SEVERITY_RANK.get(f.severity, 4)
                    for f in merged.enriched
                    if f.id == fid
                ),
                4,
            ),
        )
        # Relationships: findings sharing a file form a candidate cluster.
        by_file: dict[str, list[str]] = {}
        for f in merged.enriched:
            by_file.setdefault(f.file, []).append(f.id)
        relationships = sorted(
            f"{path}: {', '.join(sorted(ids))}"
            for path, ids in by_file.items()
            if len(ids) > 1
        )

        duration_ms = int((time.monotonic() - started) * 1000)
        return EvidenceAgentResult(
            enriched=list(merged.enriched),
            accepted=list(gate.validated),
            ai_findings_dropped=len(gate.dropped),
            assessments_applied=merged.enriched_count,
            duplicates_merged=merged.duplicates_merged,
            relationships=relationships,
            priorities=priorities,
            false_positive_flags=false_positives,
            raw_result=result,
            status="enabled",
            cached=cached,
            execution_metadata=AgentExecutionMetadata(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                duration_ms=duration_ms,
                model_used=result.model or None,
                model_calls=0 if cached else result.model_calls,
                context_chars=context_chars,
                prompt_version=result.prompt_version or prompt_version,
                findings_count=len(merged.enriched) + len(gate.validated),
            ),
        )


__all__ = ["EvidenceAgent", "EvidenceAgentResult"]
