"""Supervisor agent: coordinates the multi-agent backend.

The Supervisor does NOT inspect every source file, modify repository files,
apply patches, or decide deterministic verification itself. It coordinates:

  analysis:
      build plan -> scan/parse (orchestrator tools) -> deterministic
      detection (static analyzer + perf/quality AST rules) -> evidence hard
      gate -> shared context -> security/performance/quality in PARALLEL ->
      [full mode] budgeted specialist AI reviews -> evidence agent (budgeted)
      -> fusion -> risk -> consolidated AnalysisResult

  remediation (explicit user request only):
      locate finding -> fix agent (budgeted) -> patch guard ->
      isolated temp workspace -> deterministic AFTER analysis ->
      verification agent -> consolidated RemediationResult

Every Nemotron call passes through the request-scoped AIBudgetManager;
in "free" mode the provider is forced to StubAIProvider so zero Nebius
calls are possible by construction.
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentExecutionPlan,
    AgentStatus,
    SpecialistAgentResult,
)
from agents.evidence_agent import EvidenceAgent, EvidenceAgentResult
from agents.finding_fusion_agent import FindingFusionAgent
from agents.fix_agent import FixAgent
from agents.performance_agent import PerformanceAgent
from agents.quality_agent import QualityAgent
from agents.registry import (
    EVIDENCE_AGENT,
    FIX_AGENT,
    PATCH_GUARD,
    PERFORMANCE_AGENT,
    QUALITY_AGENT,
    SECURITY_AGENT,
    SUPERVISOR_AGENT,
    VERIFICATION_AGENT,
    agents_for_analysis,
)
from agents.security_agent import SecurityAgent
from agents.shared_context import SharedRepositoryContext
from agents.verification_agent import VerificationAgent
from app.config import (
    _AGENT_ANALYSIS_CALL_DEFAULTS,
    _AGENT_REMEDIATION_CALL_DEFAULTS,
    settings,
)
from models.schemas import (
    AgentInfo,
    AgentRunSummary,
    AIStatus,
    AIStatusValue,
    AnalysisResult,
    AnalysisSummary,
    Finding,
    FindingProvenance,
    RemediationResult,
    RepositoryMetadata,
)
from services.ai_budget_manager import AIBudgetManager
from services.ai_call_cache import AICallCache, make_cache_key
from services.ai_context_builder import AIContext
from services.ai_errors import AIError
from services.ai_provider import AIProvider, StubAIProvider
from services.ai_result_processor import apply_assessments
from services.provider_factory import build_ai_provider
from services.orchestrator import AnalysisOrchestrator
from services.prompts.specialist_review import (
    CODEAUDIT_SPECIALIST_REVIEW_PROMPT_V1,
    build_specialist_review_messages,
)
from services.remediation_engine import RemediationEngine
from services import repository_scanner

logger = logging.getLogger(__name__)


class SupervisorAgent:
    """Coordinates specialist agents, budgets, and final consolidation."""

    name = SUPERVISOR_AGENT

    def __init__(
        self,
        orchestrator: AnalysisOrchestrator | None = None,
        ai_provider: AIProvider | None = None,
        default_mode: str | None = None,
    ) -> None:
        self._orchestrator = orchestrator or AnalysisOrchestrator(
            ai_provider=StubAIProvider()
        )
        # Explicitly injected provider (tests / explicit callers). In free
        # mode it is never used — the supervisor forces the stub instead.
        self._injected_provider = ai_provider
        # Mode used when callers don't pass one explicitly. Defaults to the
        # runtime configuration; tests may override it (e.g. "economy" with
        # a fake provider) without touching process env.
        self._default_mode = default_mode or settings.agent_mode
        self._security_agent = SecurityAgent()
        self._performance_agent = PerformanceAgent()
        self._quality_agent = QualityAgent()
        self._fusion_agent = FindingFusionAgent()
        self._verification_agent = VerificationAgent()

    # -- planning ------------------------------------------------------

    def build_plan(
        self, repository: RepositoryMetadata, mode: str | None = None
    ) -> AgentExecutionPlan:
        mode = mode or self._default_mode
        agents = agents_for_analysis(mode)
        ai_budget = self._analysis_budget_for(mode)
        if mode == "free":
            reason = (
                "Free mode: deterministic specialists only (security, "
                "performance, quality), deterministic fusion. Zero Nebius "
                "calls by construction."
            )
        elif mode == "economy":
            reason = (
                "Economy mode: deterministic specialists plus a single "
                "budgeted Nemotron evidence-review call; remediation calls "
                "Nemotron only on explicit user request."
            )
        else:
            reason = (
                "Full mode: deterministic specialists, selective budgeted "
                "Nemotron specialist reviews, then evidence review — all "
                "within the hard per-analysis call cap."
            )
        return AgentExecutionPlan(
            repository=f"{repository.owner}/{repository.name}",
            agents_requested=list(agents),
            ai_budget=ai_budget,
            reason=reason,
            mode=mode,
        )

    # -- provider / budget resolution ----------------------------------

    def _resolve_provider(self, mode: str) -> AIProvider | None:
        # Free mode: no AI provider at all — zero Nebius calls, even if a
        # provider was injected. This is the cost guarantee.
        if mode == "free":
            return StubAIProvider()
        if self._injected_provider is not None:
            return self._injected_provider
        # Auto: configured provider (Nebius default, Groq opt-in) when
        # available; otherwise deterministic-only. The agent MODE is the
        # explicit control here (it supersedes the legacy
        # CODEAUDIT_AI_ENABLED kill-switch for supervisor runs).
        service = build_ai_provider()
        if service is not None:
            return service
        logger.info("Supervisor: no AI provider configured; deterministic-only")
        return None

    @staticmethod
    def _analysis_budget_for(mode: str) -> int:
        if settings.max_ai_calls_per_analysis is not None:
            return max(0, settings.max_ai_calls_per_analysis)
        return _AGENT_ANALYSIS_CALL_DEFAULTS.get(mode, 0)

    @staticmethod
    def _remediation_budget_for(mode: str) -> int:
        if settings.max_ai_calls_per_remediation is not None:
            return max(0, settings.max_ai_calls_per_remediation)
        return _AGENT_REMEDIATION_CALL_DEFAULTS.get(mode, 0)

    def _new_budget(self, mode: str) -> AIBudgetManager:
        # Limits follow the RUN's mode, not the frozen import-time mode:
        # explicit env overrides win, otherwise the mode defaults apply.
        return AIBudgetManager(
            mode=mode,
            analysis_limit=self._analysis_budget_for(mode),
            remediation_limit=self._remediation_budget_for(mode),
        )

    # -- analysis ------------------------------------------------------

    def run_analysis(
        self,
        repo_dir,
        repository: RepositoryMetadata,
        mode: str | None = None,
    ) -> AnalysisResult:
        """Run the full multi-agent analysis pipeline on a local directory."""
        from pathlib import Path

        repo_dir = Path(repo_dir)
        mode = mode or self._default_mode
        started = time.monotonic()
        execution_id = uuid.uuid4().hex[:12]
        plan = self.build_plan(repository, mode)
        budget = self._new_budget(mode)
        cache = AICallCache()
        provider = self._resolve_provider(mode)

        agent_infos: list[AgentInfo] = []
        ai_calls_made = 0

        def _record(metadata: AgentExecutionMetadata) -> None:
            agent_infos.append(
                AgentInfo(
                    agent_name=metadata.agent_name,
                    status=metadata.status.value,
                    duration_ms=metadata.duration_ms,
                    model_used=metadata.model_used,
                    model_calls=metadata.model_calls,
                    context_chars=metadata.context_chars,
                    prompt_version=metadata.prompt_version,
                    findings_count=metadata.findings_count,
                    errors=list(metadata.errors),
                )
            )

        orch = self._orchestrator
        scan = orch.scan_files(repo_dir)
        parsed, failed_parse = orch.parse(scan)

        # Deterministic detection: existing static analyzer plus the
        # specialists' conservative AST rules. Everything is gated below.
        prelim_ctx = AgentContext(
            execution_id=execution_id,
            repository=repository,
            mode=mode,
            scan=scan,
            parsed=parsed,
        )
        raw_findings: list[Finding] = orch.analyze_static(scan)
        raw_findings.extend(self._performance_agent.detect(prelim_ctx))
        raw_findings.extend(self._quality_agent.detect(prelim_ctx))
        validated, dropped = orch.validate_findings(raw_findings, scan)

        shared = SharedRepositoryContext.build(scan.contents, parsed, validated)
        ctx = AgentContext(
            execution_id=execution_id,
            repository=repository,
            mode=mode,
            scan=scan,
            parsed=parsed,
            validated_findings=validated,
            shared=shared,
            budget=budget,
            cache=cache,
            provider=provider,
        )

        # Specialists are independent: run them concurrently.
        with ThreadPoolExecutor(max_workers=3) as pool:
            fut_sec = pool.submit(self._security_agent.run, ctx)
            fut_perf = pool.submit(self._performance_agent.run, ctx)
            fut_qual = pool.submit(self._quality_agent.run, ctx)
            security_result = fut_sec.result()
            performance_result = fut_perf.result()
            quality_result = fut_qual.result()
        specialists = [security_result, performance_result, quality_result]
        for spec in specialists:
            _record(spec.execution_metadata)

        # Full mode: one budgeted Nemotron review per specialist that has
        # findings (selective reasoning, hard-capped).
        ai_status = AIStatus(status=AIStatusValue.DISABLED)
        specialist_reviews = 0
        if mode == "full" and provider is not None and not isinstance(
            provider, StubAIProvider
        ):
            specialist_reviews = self._specialist_reviews(
                ctx, specialists, provider, budget, cache
            )
            # Refresh the recorded specialist metadata: reviews may have
            # attached AI reasoning and model-call counts.
            agent_infos.clear()
            for spec in specialists:
                _record(spec.execution_metadata)

        # Evidence review (economy: the single AI call; full: after reviews).
        evidence_agent = EvidenceAgent(provider=provider, budget=budget, cache=cache)
        evidence_result: EvidenceAgentResult | None = None
        if EVIDENCE_AGENT in plan.agents_requested:
            evidence_result = evidence_agent.run(ctx, specialists)
            _record(evidence_result.execution_metadata)
            ai_calls_made += evidence_result.execution_metadata.model_calls
        else:
            _record(
                AgentExecutionMetadata(
                    agent_name=EVIDENCE_AGENT,
                    status=AgentStatus.SKIPPED,
                    findings_count=0,
                )
            )

        ai_calls_made += specialist_reviews
        ai_status = self._ai_status(
            mode,
            evidence_result,
            specialist_reviews,
            len(validated),
            provider_name=getattr(provider, "name", "") or "",
        )

        # Deterministic fusion with provenance.
        fusion = self._fusion_agent.fuse(ctx, specialists, evidence_result)
        _record(fusion.execution_metadata)
        _record(
            AgentExecutionMetadata(
                agent_name=SUPERVISOR_AGENT,
                status=AgentStatus.COMPLETED,
                duration_ms=int((time.monotonic() - started) * 1000),
                findings_count=len(fusion.findings),
            )
        )

        findings = fusion.findings
        risk = orch.score_risk(findings)

        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
            by_category[finding.category.value] = by_category.get(finding.category.value, 0) + 1

        deep_analyzed = sum(1 for p in parsed if p.parse_error is None)
        unsupported = sum(
            1 for a in scan.files if not repository_scanner.supports_deep_analysis(a.language)
        )
        summary = AnalysisSummary(
            files_discovered=len(scan.files) + scan.skipped,
            files_scanned=len(scan.files),
            files_deep_analyzed=deep_analyzed,
            files_unsupported=unsupported,
            files_skipped=scan.skipped,
            files_failed_parse=failed_parse,
            findings_total=len(findings),
            findings_dropped=dropped
            + (evidence_result.ai_findings_dropped if evidence_result else 0),
            findings_by_severity=by_severity,
            findings_by_category=by_category,
            skip_reasons=dict(scan.skipped_reasons),
        )

        budget_report = budget.report("analysis")
        completed = sum(1 for i in agent_infos if i.status == "completed")
        agents_summary = AgentRunSummary(
            execution_id=execution_id,
            mode=mode,
            completed=completed,
            ai_calls=ai_calls_made,
            agents=agent_infos,
            budget=budget_report,
        )
        logger.info(
            "Supervisor analysis done: mode=%s execution=%s findings=%d "
            "ai_calls=%d/%d agents=%d",
            mode,
            execution_id,
            len(findings),
            ai_calls_made,
            budget_report.limit,
            len(agent_infos),
        )
        return AnalysisResult(
            repository=repository,
            summary=summary,
            findings=findings,
            risk=risk,
            ai=ai_status,
            agents=agents_summary,
            ai_budget=budget_report,
        )

    def _specialist_reviews(
        self,
        ctx: AgentContext,
        specialists: list[SpecialistAgentResult],
        provider: AIProvider,
        budget: AIBudgetManager,
        cache: AICallCache,
    ) -> int:
        """Full-mode selective reasoning: one budgeted call per specialist
        with findings. Attaches AI reasoning to the specialist's findings
        (anchors preserved) and stamps reviewed_by provenance."""
        calls = 0
        role_by_agent = {
            SECURITY_AGENT: "security",
            PERFORMANCE_AGENT: "performance",
            QUALITY_AGENT: "quality",
        }
        for spec in specialists:
            role = role_by_agent.get(spec.agent_name)
            if role is None or not spec.findings:
                continue
            started = time.monotonic()
            findings = spec.findings
            excerpts = (
                ctx.shared.excerpts_for_findings(findings) if ctx.shared else {}
            )
            findings_block = "\n".join(
                f"[{f.id}] {f.severity.value.upper()} {f.title}\n"
                f"File: {f.file}:{f.line} (detector: {f.detector})\n"
                f"Evidence: {f.evidence}"
                for f in findings
            )
            excerpts_block = "\n".join(
                f"--- {fid} ---\n{excerpt}"
                for fid, excerpt in excerpts.items()
            )
            prompt_version = CODEAUDIT_SPECIALIST_REVIEW_PROMPT_V1
            messages = build_specialist_review_messages(
                role, findings_block, excerpts_block, prompt_version
            )
            repo_id = f"{ctx.repository.owner}/{ctx.repository.name}"
            key = make_cache_key(
                repo_id, [f.id for f in findings],
                messages[1]["content"], prompt_version,
            )
            result = cache.get(key)
            called_provider = False
            if result is None:
                if not budget.allow_call(f"{spec.agent_name}_review", "analysis"):
                    logger.warning(
                        "Specialist review budget exhausted at %s", spec.agent_name
                    )
                    spec.execution_metadata.errors.append("AI_BUDGET_EXHAUSTED")
                    continue
                ai_context = AIContext(
                    repo_owner=ctx.repository.owner,
                    repo_name=ctx.repository.name,
                    prompt_version=prompt_version,
                    findings=list(findings),
                    message_builder=lambda _c, m=messages: m,
                )
                try:
                    result = provider.investigate(list(findings), ai_context)
                except AIError as exc:
                    logger.warning("Specialist review failed (%s): %s", role, exc.code)
                    spec.execution_metadata.errors.append(exc.code)
                    continue
                except Exception:  # noqa: BLE001
                    logger.exception("Specialist review failed unexpectedly")
                    spec.execution_metadata.errors.append("AI_UPSTREAM_ERROR")
                    continue
                if result.status != "enabled":
                    spec.execution_metadata.errors.append(
                        result.error_code or result.status
                    )
                    continue
                cache.put(key, result)
                called_provider = True
                calls += 1
            # Attach assessments deterministically (anchors preserved).
            enriched, enriched_count, _ignored = apply_assessments(
                [f.model_copy() for f in findings],
                result.assessments,
                provider_name=result.provider_name,
                prompt_version=result.prompt_version or prompt_version,
            )
            by_id = {f.id: f for f in enriched}
            updated: list[Finding] = []
            for original in ctx.validated_findings:
                reviewed = by_id.get(original.id)
                if reviewed is not None and reviewed.ai_reasoning:
                    provenance = original.provenance or FindingProvenance(
                        detected_by=[spec.agent_name]
                    )
                    if spec.agent_name not in provenance.reviewed_by:
                        provenance.reviewed_by.append(spec.agent_name)
                    updated.append(
                        reviewed.model_copy(update={"provenance": provenance})
                    )
                else:
                    updated.append(original)
            ctx.validated_findings = updated
            # Keep the specialist's own view in sync.
            spec.findings = [by_id.get(f.id, f) for f in findings]
            if called_provider:
                spec.execution_metadata.model_calls += 1
            spec.execution_metadata.model_used = result.model or None
            spec.execution_metadata.prompt_version = (
                result.prompt_version or prompt_version
            )
            spec.execution_metadata.duration_ms += int(
                (time.monotonic() - started) * 1000
            )
        return calls

    def _ai_status(
        self,
        mode: str,
        evidence: EvidenceAgentResult | None,
        specialist_reviews: int,
        deterministic_count: int,
        provider_name: str = "",
    ) -> AIStatus:
        if mode == "free" or evidence is None:
            return AIStatus(
                status=AIStatusValue.DISABLED,
                deterministic_findings=deterministic_count,
            )
        meta = evidence.execution_metadata
        status_map = {
            "enabled": AIStatusValue.ENABLED,
            "failed": AIStatusValue.FAILED,
            "unavailable": AIStatusValue.UNAVAILABLE,
            "disabled": AIStatusValue.DISABLED,
            "budget_exhausted": AIStatusValue.UNAVAILABLE,
        }
        total_calls = meta.model_calls + specialist_reviews
        # Attribute the result to the provider that actually ran, never a
        # hardcoded default: "nemotron" is only the legacy fallback.
        resolved_provider = (
            provider_name
            or ("nemotron" if evidence.status == "enabled" else (meta.model_used or ""))
        )
        ai_status = AIStatus(
            status=status_map.get(evidence.status, AIStatusValue.DISABLED),
            provider=resolved_provider,
            model=meta.model_used,
            prompt_version=meta.prompt_version,
            model_calls=total_calls,
            context_chars=meta.context_chars,
            deterministic_findings=deterministic_count,
            findings_enriched=evidence.assessments_applied,
            ai_findings_accepted=len(evidence.accepted),
            ai_findings_dropped=evidence.ai_findings_dropped,
            duplicates_merged=evidence.duplicates_merged,
            duration_ms=meta.duration_ms,
        )
        if evidence.status == "budget_exhausted":
            ai_status.error_code = "AI_BUDGET_EXHAUSTED"
            ai_status.error_message = (
                "AI budget exhausted for this analysis; deterministic "
                "results kept, no Nebius call made."
            )
        elif meta.errors:
            ai_status.error_code = meta.errors[0]
        return ai_status

    # -- local/remote entry points (mirror the orchestrator) -------------

    def run(self, repository_url: str, repo_dir) -> AnalysisResult:
        """Run the multi-agent pipeline against an already-cloned repo."""
        from services import github_service

        ref = github_service.validate_github_url(repository_url)
        metadata = github_service.fetch_metadata(ref)
        return self.run_analysis(
            repo_dir,
            RepositoryMetadata(
                owner=ref.owner,
                name=ref.name,
                url=ref.url,
                default_branch=metadata.get("default_branch"),
                description=metadata.get("description"),
            ),
        )

    def run_on_local_path(
        self, repo_dir, owner: str = "local", name: str = "fixture"
    ) -> AnalysisResult:
        """Same pipeline against a local directory (no network)."""
        from pathlib import Path

        return self.run_analysis(
            Path(repo_dir),
            RepositoryMetadata(owner=owner, name=name, url=f"file://{repo_dir}"),
        )

    # -- remediation -----------------------------------------------------

    def remediate_finding(
        self,
        finding_id: str,
        repo_dir,
        before: AnalysisResult,
        mode: str | None = None,
    ) -> RemediationResult:
        """Coordinate one FIND -> FIX -> VERIFY cycle for an explicit request.

        The Fix agent proposes (budgeted), the Patch Guard validates, the
        patch applies only in an isolated temp workspace, and the
        Verification agent coordinates deterministic verification. The
        original repository is never modified.
        """
        from pathlib import Path

        from services.remediation_errors import RemediationFindingNotFound

        repo_dir = Path(repo_dir)
        mode = mode or self._default_mode
        execution_id = uuid.uuid4().hex[:12]
        budget = self._new_budget(mode)
        cache = AICallCache()
        provider = self._resolve_provider(mode)

        target = next((f for f in before.findings if f.id == finding_id), None)
        if target is None:
            raise RemediationFindingNotFound(
                f"finding {finding_id!r} is not in the analysis result"
            )

        # The engine drives the guarded cycle; the agents provide the AI
        # boundaries. The fix agent is cache-backed, so the engine's single
        # propose call is the only model call on this path.
        fix_agent = FixAgent(provider=provider, budget=budget, cache=cache)
        engine = RemediationEngine(
            ai_provider=provider,
            fix_agent=fix_agent,
            verification_agent=self._verification_agent,
        )
        result = engine.remediate_finding(
            finding_id,
            repo_dir,
            before,
            agent_mode=mode,
            execution_id=execution_id,
        )

        # Record the agents that genuinely participated.
        trail = [SUPERVISOR_AGENT, FIX_AGENT]
        if result.changes_applied or result.changes_rejected:
            trail.append(PATCH_GUARD)
        if result.verification is not None:
            trail.append(VERIFICATION_AGENT)
        result.agent_trail = trail
        return result

    def remediate_findings(
        self,
        finding_ids: list[str],
        repo_dir,
        before: AnalysisResult,
        mode: str | None = None,
    ) -> list[RemediationResult]:
        cap = max(0, settings.max_remediations_per_request)
        return [
            self.remediate_finding(fid, repo_dir, before, mode)
            for fid in finding_ids[:cap]
        ]


__all__ = ["SupervisorAgent"]
