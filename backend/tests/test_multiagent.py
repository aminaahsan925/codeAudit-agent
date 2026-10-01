"""Tests for the Phase 3 multi-agent upgrade (hermetic, no network).

Covers: agent contracts/registry/plans, the AI budget manager, supervisor
coordination across FREE/ECONOMY/FULL modes, specialist independence and
determinism, the evidence agent's anchor guarantees, deterministic fusion
with provenance, graceful AI degradation, fix-on-explicit-request, the patch
guard's authority, verification non-override, the never-modify-the-repo
guarantee, metadata accuracy, cache dedup, and the end-to-end demo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.contracts import AgentContext, AgentStatus
from agents.evidence_agent import EvidenceAgent
from agents.finding_fusion_agent import FindingFusionAgent
from agents.fix_agent import FixAgent
from agents.performance_agent import PerformanceAgent
from agents.quality_agent import QualityAgent
from agents.registry import (
    AGENT_REGISTRY,
    EVIDENCE_AGENT,
    FIX_AGENT,
    FUSION_AGENT,
    PERFORMANCE_AGENT,
    QUALITY_AGENT,
    SECURITY_AGENT,
    SUPERVISOR_AGENT,
    VERIFICATION_AGENT,
    agents_for_analysis,
    agents_for_remediation,
)
from agents.security_agent import SecurityAgent
from agents.shared_context import SharedRepositoryContext
from agents.supervisor_agent import SupervisorAgent
from agents.verification_agent import VerificationAgent
from models.schemas import (
    AIAssessment,
    AIFindingCandidate,
    AIStatusValue,
    AIVerdict,
    Category,
    Confidence,
    FindingProvenance,
    FindingSource,
    FixChange,
    FixDecision,
    FixProposal,
    RemediationStatus,
    RepositoryMetadata,
    Severity,
    ValidatedFinding,
    VerificationStatus,
)
from services import verification_engine
from services.ai_budget_manager import AI_BUDGET_EXHAUSTED, AIBudgetManager
from services.ai_call_cache import AICallCache
from services.ai_errors import AIProviderNotConfigured, AIUpstreamError
from services.ai_provider import StubAIProvider
from services.orchestrator import AnalysisOrchestrator
from services.remediation_engine import RemediationEngine
from tests.fakes import FakeAIProvider

DEMO = Path(__file__).parent / "fixtures" / "multiagent_demo"
REPO = RepositoryMetadata(owner="demo", name="multiagent_demo", url="file://demo")

SQLI_ID = "sql_string_construction:app.py:23"
SQLI_LINE = '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
SQLI_FIX = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'


def _supervisor(mode: str, provider=None) -> SupervisorAgent:
    return SupervisorAgent(ai_provider=provider, default_mode=mode)


def _sqli_proposal(*, old_text: str = SQLI_LINE) -> FixProposal:
    return FixProposal(
        finding_id=SQLI_ID,
        decision=FixDecision.FIX,
        reasoning="parameterize the query",
        changes=[
            FixChange(
                file="app.py",
                start_line=23,
                end_line=23,
                old_text=old_text,
                new_text=SQLI_FIX,
                rationale="use a bound parameter",
            )
        ],
        expected_effect="finding eliminated",
        verification_notes="rerun the analyzer",
    )


def _assessment(finding_id: str, **overrides) -> AIAssessment:
    params = dict(
        finding_id=finding_id,
        verdict=AIVerdict.CONFIRMED,
        confidence=Confidence.HIGH,
        reasoning="evidence matches the finding",
    )
    params.update(overrides)
    return AIAssessment(**params)


def _validated_finding(**overrides) -> ValidatedFinding:
    params = dict(
        id="sql_string_construction:app.py:23",
        detector="sql_string_construction",
        title="SQL string construction",
        description="d",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="app.py",
        line=23,
        evidence=SQLI_LINE,
        source=FindingSource.DETERMINISTIC,
    )
    params.update(overrides)
    return ValidatedFinding(**params)


def _agent_ctx(**overrides) -> AgentContext:
    # Mirrors the supervisor's deterministic pipeline: static analysis plus
    # the specialists' AST detections, all through the evidence hard gate.
    orch = AnalysisOrchestrator(ai_provider=StubAIProvider())
    scan = orch.scan_files(DEMO)
    parsed, _ = orch.parse(scan)
    prelim = AgentContext(
        execution_id="test-prelim",
        repository=REPO,
        mode="economy",
        scan=scan,
        parsed=parsed,
    )
    raw = orch.analyze_static(scan)
    raw.extend(PerformanceAgent().detect(prelim))
    raw.extend(QualityAgent().detect(prelim))
    validated, _ = orch.validate_findings(raw, scan)
    ctx = AgentContext(
        execution_id="test-exec",
        repository=REPO,
        mode="economy",
        scan=scan,
        parsed=parsed,
        validated_findings=validated,
        shared=SharedRepositoryContext.build(scan.contents, parsed, validated),
        budget=AIBudgetManager(mode="economy", analysis_limit=2, remediation_limit=1),
        cache=AICallCache(),
        provider=FakeAIProvider(),
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


# ---------------------------------------------------------------------------
# 1. Contracts, registry, plans
# ---------------------------------------------------------------------------


def test_analysis_plan_free_is_deterministic_only():
    assert agents_for_analysis("free") == [
        SECURITY_AGENT,
        PERFORMANCE_AGENT,
        QUALITY_AGENT,
        FUSION_AGENT,
    ]
    assert EVIDENCE_AGENT not in agents_for_analysis("free")


def test_analysis_plan_economy_adds_evidence():
    plan = agents_for_analysis("economy")
    assert plan == [
        SECURITY_AGENT,
        PERFORMANCE_AGENT,
        QUALITY_AGENT,
        EVIDENCE_AGENT,
        FUSION_AGENT,
    ]


def test_analysis_plan_full_adds_everything():
    plan = agents_for_analysis("full")
    assert plan == [
        SECURITY_AGENT,
        PERFORMANCE_AGENT,
        QUALITY_AGENT,
        EVIDENCE_AGENT,
        FUSION_AGENT,
    ]
    assert set(plan) == {
        SECURITY_AGENT,
        PERFORMANCE_AGENT,
        QUALITY_AGENT,
        EVIDENCE_AGENT,
        FUSION_AGENT,
    }
    assert SUPERVISOR_AGENT not in plan
    assert FIX_AGENT not in plan
    assert VERIFICATION_AGENT not in plan


def test_remediation_plan_is_fix_then_verify():
    assert agents_for_remediation("economy") == [
        FIX_AGENT,
        "patch_guard",
        VERIFICATION_AGENT,
    ]
    assert agents_for_remediation("full") == [
        FIX_AGENT,
        "patch_guard",
        VERIFICATION_AGENT,
    ]
    # No fix agent in free mode: Nemotron is never called there.
    assert FIX_AGENT not in agents_for_remediation("free")


def test_registry_kinds_are_honest():
    # Specialists are hybrid: deterministic triage always, with an optional
    # budgeted AI review in full mode. They never claim to be pure AI.
    assert AGENT_REGISTRY[SECURITY_AGENT].kind == "hybrid"
    assert AGENT_REGISTRY[PERFORMANCE_AGENT].kind == "hybrid"
    assert AGENT_REGISTRY[QUALITY_AGENT].kind == "hybrid"
    assert AGENT_REGISTRY[EVIDENCE_AGENT].kind == "ai"
    assert AGENT_REGISTRY[FUSION_AGENT].kind == "deterministic"
    assert AGENT_REGISTRY[FIX_AGENT].kind == "ai"
    assert AGENT_REGISTRY[VERIFICATION_AGENT].kind == "deterministic"
    assert AGENT_REGISTRY[SUPERVISOR_AGENT].kind == "deterministic"


def test_supervisor_build_plan():
    sup = _supervisor("economy")
    plan = sup.build_plan(REPO)
    assert plan.mode == "economy"
    assert plan.agents_requested == agents_for_analysis("economy")
    assert plan.ai_budget == 1
    assert plan.reason  # human-readable rationale is required

    free_plan = _supervisor("free").build_plan(REPO)
    assert free_plan.ai_budget == 0


def test_unknown_mode_yields_empty_plan():
    assert agents_for_analysis("bogus") == []
    assert agents_for_remediation("bogus") == []


# ---------------------------------------------------------------------------
# 2. AI budget manager
# ---------------------------------------------------------------------------


def test_budget_free_mode_always_denies():
    budget = AIBudgetManager(mode="free", analysis_limit=0, remediation_limit=0)
    assert budget.allow_call("evidence_agent", "analysis") is False
    assert budget.allow_call("fix_agent", "remediation") is False
    report = budget.report("analysis")
    assert report.limit == 0 and report.used == 0 and report.remaining == 0


def test_budget_economy_allows_exactly_one_analysis_call():
    budget = AIBudgetManager(mode="economy", analysis_limit=1, remediation_limit=1)
    assert budget.allow_call("evidence_agent", "analysis") is True
    assert budget.allow_call("evidence_agent", "analysis") is False
    report = budget.report("analysis")
    assert report.used == 1 and report.limit == 1 and report.remaining == 0


def test_budget_analysis_and_remediation_are_separate():
    budget = AIBudgetManager(mode="economy", analysis_limit=1, remediation_limit=1)
    assert budget.allow_call("evidence_agent", "analysis") is True
    # Exhausting the analysis budget does not touch the remediation budget.
    assert budget.allow_call("fix_agent", "remediation") is True
    assert budget.allow_call("fix_agent", "remediation") is False


def test_budget_exhausted_constant():
    assert AI_BUDGET_EXHAUSTED == "AI_BUDGET_EXHAUSTED"


# ---------------------------------------------------------------------------
# 3. Free mode: deterministic only, zero AI calls
# ---------------------------------------------------------------------------


def test_free_mode_makes_zero_ai_calls_even_with_injected_provider():
    fake = FakeAIProvider(assessments=[_assessment(SQLI_ID)])
    result = _supervisor("free", provider=fake).run_on_local_path(DEMO)
    assert fake.investigate_calls == 0
    assert fake.propose_fix_calls == 0
    assert result.agents.ai_calls == 0
    assert result.ai_budget.used == 0
    assert result.ai_budget.limit == 0
    assert result.ai.status == AIStatusValue.DISABLED
    assert result.summary.findings_total == 6


def test_free_mode_specialists_complete_and_evidence_skipped():
    result = _supervisor("free").run_on_local_path(DEMO)
    by_name = {a.agent_name: a for a in result.agents.agents}
    for name in (SECURITY_AGENT, PERFORMANCE_AGENT, QUALITY_AGENT, FUSION_AGENT):
        assert by_name[name].status == "completed", name
    assert by_name[EVIDENCE_AGENT].status == "skipped"
    assert by_name[SUPERVISOR_AGENT].status == "completed"


def test_free_mode_every_finding_has_provenance():
    result = _supervisor("free").run_on_local_path(DEMO)
    for finding in result.findings:
        assert finding.provenance is not None
        assert finding.provenance.detected_by, finding.id


def test_free_analysis_is_deterministic():
    runs = [
        _supervisor("free").run_on_local_path(DEMO) for _ in range(2)
    ]
    first = [(f.id, f.severity, f.category, f.evidence) for f in runs[0].findings]
    second = [(f.id, f.severity, f.category, f.evidence) for f in runs[1].findings]
    assert first == second


def test_specialists_are_independent_of_each_other():
    """Each specialist triages only its own category; none sees another's."""
    ctx = _agent_ctx()
    security = SecurityAgent().run(ctx)
    performance = PerformanceAgent().run(ctx)
    quality = QualityAgent().run(ctx)
    assert {f.category for f in security.findings} == {Category.SECURITY}
    assert {f.category for f in performance.findings} == {Category.PERFORMANCE}
    assert {f.category for f in quality.findings} == {Category.QUALITY}
    assert security.execution_metadata.agent_name == SECURITY_AGENT
    assert performance.execution_metadata.agent_name == PERFORMANCE_AGENT
    assert quality.execution_metadata.agent_name == QUALITY_AGENT


# ---------------------------------------------------------------------------
# 4. Economy mode: exactly one AI call
# ---------------------------------------------------------------------------


def test_economy_mode_makes_exactly_one_analysis_call():
    fake = FakeAIProvider(assessments=[_assessment(SQLI_ID)])
    sup = _supervisor("economy", provider=fake)
    result = sup.run_on_local_path(DEMO)
    assert fake.investigate_calls == 1
    assert result.agents.ai_calls == 1
    assert result.ai_budget.used == 1
    assert result.ai_budget.limit == 1
    assert result.ai_budget.remaining == 0
    assert result.ai.status == AIStatusValue.ENABLED
    # The assessment was attached as reasoning on the deterministic finding.
    target = next(f for f in result.findings if f.id == SQLI_ID)
    assert target.ai_reasoning is not None
    assert target.enriched_by == "fake"
    assert "evidence matches" in target.ai_reasoning


def test_economy_evidence_agent_receives_specialist_outputs():
    fake = FakeAIProvider()
    _supervisor("economy", provider=fake).run_on_local_path(DEMO)
    received_ids = {f.id for f in fake.received_findings}
    # The evidence review scope covers every specialist finding.
    assert received_ids == {
        "hardcoded_secret:app.py:14",
        SQLI_ID,
        "subprocess_shell_true:app.py:29",
        "nested_loop:app.py:36",
        "long_function:app.py:42",
        "bare_except:app.py:98",
    }


def test_evidence_agent_never_overrides_deterministic_anchors():
    """A rogue assessment claiming LOW severity must not move the anchor."""
    ctx = _agent_ctx()
    specialists = [
        SecurityAgent().run(ctx),
        PerformanceAgent().run(ctx),
        QualityAgent().run(ctx),
    ]
    fake = FakeAIProvider(
        assessments=[
            _assessment(
                SQLI_ID,
                verdict=AIVerdict.UNLIKELY,
                reasoning="looks fine to me",
            )
        ]
    )
    agent = EvidenceAgent(provider=fake, budget=ctx.budget, cache=ctx.cache)
    outcome = agent.run(ctx, specialists)
    assert outcome.status == "enabled"
    target = next(f for f in outcome.enriched if f.id == SQLI_ID)
    assert target.severity == Severity.HIGH
    assert target.category == Category.SECURITY
    assert target.line == 23
    assert target.ai_reasoning is not None  # reasoning attached, anchor kept


def test_ai_candidate_without_evidence_is_dropped():
    ctx = _agent_ctx()
    specialists = [
        SecurityAgent().run(ctx),
        PerformanceAgent().run(ctx),
        QualityAgent().run(ctx),
    ]
    fake = FakeAIProvider(
        candidates=[
            AIFindingCandidate(
                title="Fabricated issue",
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                file="app.py",
                line=1,
                evidence="this string appears nowhere in the repository",
                description="no evidence",
                reasoning="fabricated",
                confidence=Confidence.LOW,
            )
        ]
    )
    agent = EvidenceAgent(provider=fake, budget=ctx.budget, cache=ctx.cache)
    outcome = agent.run(ctx, specialists)
    assert outcome.ai_findings_dropped == 1
    assert outcome.accepted == []
    assert all(f.id != "evidence_agent:app.py:1" for f in outcome.enriched)


# ---------------------------------------------------------------------------
# 5. Full mode: selective reasoning within the hard cap
# ---------------------------------------------------------------------------


def test_full_mode_respects_max_budget():
    fake = FakeAIProvider(
        assessments=[_assessment(SQLI_ID), _assessment("nested_loop:app.py:36")]
    )
    sup = _supervisor("full", provider=fake)
    result = sup.run_on_local_path(DEMO)
    # 3 specialist reviews + 1 evidence call at most; hard cap is 4.
    assert fake.investigate_calls <= 4
    assert result.ai_budget.used <= 4
    assert result.ai_budget.limit == 4
    assert result.ai.status == AIStatusValue.ENABLED


def test_full_mode_specialist_review_attaches_provenance():
    fake = FakeAIProvider(assessments=[_assessment(SQLI_ID)])
    result = _supervisor("full", provider=fake).run_on_local_path(DEMO)
    target = next(f for f in result.findings if f.id == SQLI_ID)
    assert target.ai_reasoning is not None
    assert SECURITY_AGENT in (target.provenance.reviewed_by if target.provenance else [])


# ---------------------------------------------------------------------------
# 6. Fusion: deterministic, dedup, provenance
# ---------------------------------------------------------------------------


def test_fusion_dedupes_on_file_line_detector():
    ctx = _agent_ctx()
    dupes = [
        _validated_finding(),
        _validated_finding(title="same finding, second copy"),
    ]
    ctx.validated_findings = dupes
    fused = FindingFusionAgent().fuse(ctx)
    assert len(fused.findings) == 1
    assert fused.findings[0].provenance.detected_by == [SECURITY_AGENT]


def test_fusion_stamps_category_provenance():
    ctx = _agent_ctx()
    fused = FindingFusionAgent().fuse(ctx)
    by_id = {f.id: f for f in fused.findings}
    assert by_id[SQLI_ID].provenance.detected_by == [SECURITY_AGENT]
    assert by_id["nested_loop:app.py:36"].provenance.detected_by == [PERFORMANCE_AGENT]
    assert by_id["long_function:app.py:42"].provenance.detected_by == [QUALITY_AGENT]


# ---------------------------------------------------------------------------
# 7. Graceful degradation
# ---------------------------------------------------------------------------


def test_ai_failure_degrades_to_deterministic():
    fake = FakeAIProvider(exc=AIUpstreamError("boom"))
    result = _supervisor("economy", provider=fake).run_on_local_path(DEMO)
    assert result.summary.findings_total == 6
    assert result.ai.status == AIStatusValue.FAILED
    by_name = {a.agent_name: a for a in result.agents.agents}
    # The evidence agent reports "degraded" (not failed): deterministic
    # results were kept and the run completed.
    assert by_name[EVIDENCE_AGENT].status == "degraded"
    assert by_name[FUSION_AGENT].status == "completed"


def test_no_provider_degrades_to_unavailable():
    result = _supervisor("economy", provider=None).run_on_local_path(DEMO)
    assert result.summary.findings_total == 6
    assert result.ai.status == AIStatusValue.UNAVAILABLE


# ---------------------------------------------------------------------------
# 8. Cache dedup
# ---------------------------------------------------------------------------


def test_evidence_cache_dedupes_repeat_calls():
    ctx = _agent_ctx()  # analysis_limit=2 so a second call *could* happen
    specialists = [
        SecurityAgent().run(ctx),
        PerformanceAgent().run(ctx),
        QualityAgent().run(ctx),
    ]
    agent = EvidenceAgent(provider=ctx.provider, budget=ctx.budget, cache=ctx.cache)
    first = agent.run(ctx, specialists)
    second = agent.run(ctx, specialists)
    assert first.status == "enabled"
    assert second.status == "enabled"
    assert ctx.provider.investigate_calls == 1  # second run was a cache hit
    assert ctx.budget.report("analysis").used == 1


# ---------------------------------------------------------------------------
# 9. Remediation: fix only on explicit request, patch guard, verification
# ---------------------------------------------------------------------------


def test_analysis_never_remediates_by_itself():
    before_bytes = (DEMO / "app.py").read_bytes()
    _supervisor("economy", provider=FakeAIProvider()).run_on_local_path(DEMO)
    assert (DEMO / "app.py").read_bytes() == before_bytes


def test_supervised_remediation_happy_path():
    fake = FakeAIProvider(fix_proposal=_sqli_proposal())
    sup = _supervisor("economy", provider=fake)
    before = sup.run_on_local_path(DEMO)
    before_bytes = (DEMO / "app.py").read_bytes()

    result = sup.remediate_finding(SQLI_ID, DEMO, before)

    assert result.status == RemediationStatus.VERIFIED
    assert result.verification is not None and result.verification.verified is True
    assert len(result.changes_applied) == 1
    assert result.agent_trail == [
        SUPERVISOR_AGENT,
        FIX_AGENT,
        "patch_guard",
        VERIFICATION_AGENT,
    ]
    # Exactly one remediation AI call; the original repo is untouched.
    assert fake.propose_fix_calls == 1
    assert (DEMO / "app.py").read_bytes() == before_bytes


def test_patch_guard_rejects_bad_old_text():
    fake = FakeAIProvider(fix_proposal=_sqli_proposal(old_text="not the real line"))
    sup = _supervisor("economy", provider=fake)
    before = sup.run_on_local_path(DEMO)
    before_bytes = (DEMO / "app.py").read_bytes()

    result = sup.remediate_finding(SQLI_ID, DEMO, before)

    assert result.status == RemediationStatus.PATCH_REJECTED
    assert result.changes_applied == []
    assert "patch_guard" in result.agent_trail
    assert (DEMO / "app.py").read_bytes() == before_bytes


def test_free_mode_remediation_is_unavailable_and_makes_no_calls():
    fake = FakeAIProvider(fix_proposal=_sqli_proposal())
    sup = _supervisor("free", provider=fake)
    before = sup.run_on_local_path(DEMO)
    result = sup.remediate_finding(SQLI_ID, DEMO, before)
    assert result.status == RemediationStatus.UNAVAILABLE
    assert fake.propose_fix_calls == 0


def test_remediation_budget_exhaustion_maps_to_unavailable():
    sup = _supervisor("free")
    before = sup.run_on_local_path(DEMO)
    zero_budget = AIBudgetManager(mode="economy", analysis_limit=1, remediation_limit=0)
    fix_agent = FixAgent(
        provider=FakeAIProvider(fix_proposal=_sqli_proposal()), budget=zero_budget
    )
    engine = RemediationEngine(
        ai_provider=FakeAIProvider(fix_proposal=_sqli_proposal()),
        fix_agent=fix_agent,
        verification_agent=VerificationAgent(),
    )
    result = engine.remediate_finding(SQLI_ID, DEMO, before, agent_mode="economy")
    assert result.status == RemediationStatus.UNAVAILABLE
    assert result.error_code == AI_BUDGET_EXHAUSTED


def test_fix_agent_stamps_proposal_and_never_writes():
    fake = FakeAIProvider(fix_proposal=_sqli_proposal())
    ctx = _agent_ctx()
    target = next(f for f in ctx.validated_findings if f.id == SQLI_ID)
    before_bytes = (DEMO / "app.py").read_bytes()

    outcome = FixAgent(provider=fake, budget=ctx.budget, cache=ctx.cache).propose(
        target, ctx, ctx.scan.contents
    )

    assert outcome.status == "ok"
    assert outcome.proposal.finding_id == SQLI_ID
    assert outcome.proposal.provider == "fake"
    assert outcome.proposal.prompt_version == "fake-fix-prompt-v1"
    assert outcome.proposal.decision == FixDecision.FIX
    assert (DEMO / "app.py").read_bytes() == before_bytes


def test_fix_agent_budget_exhaustion_is_graceful():
    fake = FakeAIProvider(fix_proposal=_sqli_proposal())
    budget = AIBudgetManager(mode="economy", analysis_limit=1, remediation_limit=0)
    ctx = _agent_ctx()
    target = next(f for f in ctx.validated_findings if f.id == SQLI_ID)
    outcome = FixAgent(provider=fake, budget=budget).propose(
        target, ctx, ctx.scan.contents
    )
    assert outcome.status == "budget_exhausted"
    assert outcome.error_code == AI_BUDGET_EXHAUSTED
    assert fake.propose_fix_calls == 0


def test_verification_agent_never_overrides_deterministic_verdict():
    orch = AnalysisOrchestrator(ai_provider=StubAIProvider())
    scan = orch.scan_files(DEMO)
    before_findings = [
        f for f in orch.validate_findings(orch.analyze_static(scan), scan)[0]
    ]
    target = next(f for f in before_findings if f.id == SQLI_ID)
    expected = verification_engine.verify_fix(
        finding=target,
        before_findings=before_findings,
        before_contents=scan.contents,
        after_findings=[f for f in before_findings if f.id != SQLI_ID],
        after_contents=scan.contents,
        changed_files=["app.py"],
    )
    agent_outcome = VerificationAgent().verify(
        finding=target,
        before_findings=before_findings,
        before_contents=scan.contents,
        after_findings=[f for f in before_findings if f.id != SQLI_ID],
        after_contents=scan.contents,
        changed_files=["app.py"],
    )
    assert agent_outcome.verification.status == expected.status
    assert agent_outcome.verification.verified == expected.verified
    assert agent_outcome.explanation  # deterministic explanation attached


# ---------------------------------------------------------------------------
# 10. Metadata accuracy
# ---------------------------------------------------------------------------


def test_agent_metadata_is_accurate():
    fake = FakeAIProvider(assessments=[_assessment(SQLI_ID)])
    result = _supervisor("economy", provider=fake).run_on_local_path(DEMO)
    summary = result.agents
    assert summary.mode == "economy"
    assert len(summary.execution_id) == 12
    assert summary.ai_calls == 1
    assert summary.budget.used == 1
    assert summary.budget.limit == 1
    assert summary.budget.remaining == 0
    assert summary.budget.mode == "economy"
    names = [a.agent_name for a in summary.agents]
    assert names == [
        SECURITY_AGENT,
        PERFORMANCE_AGENT,
        QUALITY_AGENT,
        EVIDENCE_AGENT,
        FUSION_AGENT,
        SUPERVISOR_AGENT,
    ]
    for info in summary.agents:
        assert info.duration_ms >= 0
        assert info.findings_count >= 0
        assert info.status in {"completed", "failed", "skipped"}
    assert result.ai_budget.used == summary.budget.used
    # AIStatus mirrors the run.
    assert result.ai.model_calls == 1
    assert result.ai.deterministic_findings == result.summary.findings_total


def test_ai_provider_not_configured_code_exists():
    assert AIProviderNotConfigured.code == "AI_PROVIDER_NOT_CONFIGURED"


# ---------------------------------------------------------------------------
# 11. End-to-end demo across modes
# ---------------------------------------------------------------------------


def test_demo_free_mode_finding_breakdown():
    result = _supervisor("free").run_on_local_path(DEMO)
    by_detector = {f.detector for f in result.findings}
    assert by_detector == {
        "hardcoded_secret",
        "sql_string_construction",
        "subprocess_shell_true",
        "nested_loop",
        "long_function",
        "bare_except",
    }
    by_category = {f.category for f in result.findings}
    assert by_category == {Category.SECURITY, Category.PERFORMANCE, Category.QUALITY}


def test_demo_economy_then_remediate_one_finding():
    fake = FakeAIProvider(
        assessments=[_assessment(SQLI_ID)], fix_proposal=_sqli_proposal()
    )
    sup = _supervisor("economy", provider=fake)
    before = sup.run_on_local_path(DEMO)
    assert fake.investigate_calls == 1

    result = sup.remediate_finding(SQLI_ID, DEMO, before)
    assert result.status == RemediationStatus.VERIFIED
    assert fake.propose_fix_calls == 1
    # Analysis and remediation budgets stayed independent.
    assert fake.investigate_calls == 1
