"""Fix agent: Nemotron fix proposals behind a proper agent boundary.

This is the existing remediation capability moved behind an agent
boundary. Responsibilities:

  * receive ONE validated finding
  * construct the bounded fix context from real repository evidence
  * request a minimal structured remediation from the provider
  * stamp traceability deterministically (finding_id/provider/model/prompt)
  * NEVER write to files, NEVER execute code

The proposal goes to the Patch Guard (services/patch_engine.py), never
directly to the filesystem. Every provider call is cache-checked, then
budget-checked against the REMEDIATION budget.
"""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, ConfigDict, Field

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
)
from agents.registry import FIX_AGENT
from models.schemas import FixDecision, FixProposal, ValidatedFinding
from services.ai_budget_manager import AI_BUDGET_EXHAUSTED, AIBudgetManager
from services.ai_call_cache import AICallCache, make_cache_key
from services.ai_errors import AIError, AIOutputInvalid, AIProviderNotConfigured
from services.ai_provider import AIProvider, FixProposalResult
from services.fix_context_builder import FixContext, build_fix_context
from services.prompts import CODEAUDIT_REMEDIATION_PROMPT_V1

logger = logging.getLogger(__name__)


class FixAgentResult(BaseModel):
    """Outcome of one fix-proposal request."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    agent_name: str = FIX_AGENT
    # ok | unavailable | failed | cannot_fix | budget_exhausted
    status: str = "unavailable"
    proposal: FixProposal | None = None
    error_code: str | None = None
    cached: bool = False
    fix_context: FixContext | None = Field(default=None, exclude=True)
    execution_metadata: AgentExecutionMetadata


class FixAgent:
    """Proposes structured remediations for single validated findings."""

    name = FIX_AGENT

    def __init__(
        self,
        provider: AIProvider | None = None,
        budget: AIBudgetManager | None = None,
        cache: AICallCache | None = None,
    ) -> None:
        self._provider = provider
        self._budget = budget
        self._cache = cache or AICallCache()

    def _failed(
        self,
        status: str,
        error_code: str | None,
        started: float,
        context_chars: int = 0,
        prompt_version: str = "",
        model: str = "",
    ) -> FixAgentResult:
        return FixAgentResult(
            status=status,
            error_code=error_code,
            execution_metadata=AgentExecutionMetadata(
                agent_name=self.name,
                status=AgentStatus.DEGRADED,
                duration_ms=int((time.monotonic() - started) * 1000),
                model_used=model or None,
                context_chars=context_chars,
                prompt_version=prompt_version or None,
                errors=[error_code] if error_code else [],
            ),
        )

    def propose(
        self,
        finding: ValidatedFinding,
        ctx: AgentContext,
        contents: dict[str, str] | None = None,
    ) -> FixAgentResult:
        """Request a fix proposal for one validated finding. Never writes."""
        started = time.monotonic()
        provider = self._provider or ctx.provider
        repo_contents = contents if contents is not None else (
            ctx.shared.contents if ctx.shared else ctx.scan.contents
        )

        if provider is None:
            return self._failed(
                "unavailable", AIProviderNotConfigured.code, started
            )

        parsed = ctx.parsed
        fix_context = build_fix_context(finding, repo_contents, parsed)

        # Phase 5: knowledge shown to the model for this finding (system
        # truth — stamped onto the proposal below). Deterministic per
        # finding, so the KB version joins the cache key: KB edits must
        # invalidate cached proposals.
        from services.knowledge import load_knowledge_base

        shown_knowledge_ids = [h.entry.id for h in fix_context.knowledge]
        kb_version = load_knowledge_base().version

        # Cache check BEFORE the budget check: a cached proposal costs nothing.
        repo_id = f"{ctx.repository.owner}/{ctx.repository.name}"
        # The context text is the bounded evidence the model would see.
        context_text = (
            f"{fix_context.finding.id}:{fix_context.evidence_window}"
            f":kb={kb_version}:{','.join(shown_knowledge_ids)}"
        )
        cache_key = make_cache_key(
            repo_id, [finding.id], context_text, CODEAUDIT_REMEDIATION_PROMPT_V1
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            result = self._from_provider_result(
                cached, finding, provider, started,
                cached=True, knowledge_used=shown_knowledge_ids,
            )
            return result

        budget = self._budget or ctx.budget
        if budget is not None and not budget.allow_call(self.name, "remediation"):
            logger.warning("Fix agent: remediation AI budget exhausted")
            return self._failed(
                "budget_exhausted",
                AI_BUDGET_EXHAUSTED,
                started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=CODEAUDIT_REMEDIATION_PROMPT_V1,
            )

        try:
            provider_result = provider.propose_fix(finding, fix_context)
        except AIProviderNotConfigured as exc:
            return self._failed(
                "unavailable", exc.code, started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=CODEAUDIT_REMEDIATION_PROMPT_V1,
            )
        except AIError as exc:
            return self._failed(
                "failed", exc.code, started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=CODEAUDIT_REMEDIATION_PROMPT_V1,
            )
        except Exception:  # noqa: BLE001 - AI bugs must not break remediation
            logger.exception("Fix agent: unexpected provider failure")
            return self._failed(
                "failed", "AI_UPSTREAM_ERROR", started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=CODEAUDIT_REMEDIATION_PROMPT_V1,
            )

        if provider_result.status == "disabled":
            return self._failed(
                "unavailable", AIProviderNotConfigured.code, started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=CODEAUDIT_REMEDIATION_PROMPT_V1,
            )
        if provider_result.status in ("failed", "unavailable"):
            return self._failed(
                provider_result.status,
                provider_result.error_code or "AI_UPSTREAM_ERROR",
                started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=provider_result.prompt_version,
                model=provider_result.model,
            )
        if provider_result.proposal is None:
            return self._failed(
                "failed", AIOutputInvalid.code, started,
                context_chars=len(fix_context.evidence_window),
                prompt_version=provider_result.prompt_version,
                model=provider_result.model,
            )

        self._cache.put(cache_key, provider_result)
        return self._from_provider_result(
            provider_result, finding, provider, started,
            cached=False, knowledge_used=shown_knowledge_ids,
        )

    def _from_provider_result(
        self,
        provider_result: FixProposalResult,
        finding: ValidatedFinding,
        provider: AIProvider,
        started: float,
        *,
        cached: bool,
        knowledge_used: list[str] | None = None,
    ) -> FixAgentResult:
        assert provider_result.proposal is not None
        shown = list(knowledge_used or [])
        # knowledge_used is system truth (what was shown). knowledge_cited
        # is the model's claim, validated: only ids that were actually
        # shown survive — invented citations are dropped, never trusted.
        cited = [
            cid for cid in (provider_result.proposal.knowledge_cited or [])
            if cid in shown
        ]
        # Traceability is stamped by the system, never trusted from the model.
        proposal = provider_result.proposal.model_copy(
            update={
                "finding_id": finding.id,
                "provider": provider_result.provider_name
                or getattr(provider, "name", ""),
                "model": provider_result.model or "",
                "prompt_version": provider_result.prompt_version or "",
                "knowledge_used": shown,
                "knowledge_cited": cited,
            }
        )
        status = (
            "cannot_fix"
            if proposal.decision == FixDecision.CANNOT_FIX
            else "ok"
        )
        return FixAgentResult(
            status=status,
            proposal=proposal,
            cached=cached,
            execution_metadata=AgentExecutionMetadata(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                duration_ms=int((time.monotonic() - started) * 1000),
                model_used=provider_result.model or None,
                model_calls=0 if cached else provider_result.model_calls,
                context_chars=provider_result.context_chars,
                prompt_version=provider_result.prompt_version or None,
            ),
        )


__all__ = ["FixAgent", "FixAgentResult"]
