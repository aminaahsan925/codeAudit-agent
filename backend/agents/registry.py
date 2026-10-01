"""Agent registry: the single source of truth for agent names.

Do not hardcode agent names across the codebase — import them from here.
Each registration records the agent's dependencies, whether it is
deterministic or AI-driven, and in which AI operating modes it runs.
"""

from __future__ import annotations

from dataclasses import dataclass

# Canonical agent names. Everything else references these constants.
SUPERVISOR_AGENT = "supervisor"
SECURITY_AGENT = "security"
PERFORMANCE_AGENT = "performance"
QUALITY_AGENT = "quality"
EVIDENCE_AGENT = "evidence"
FUSION_AGENT = "fusion"
FIX_AGENT = "fix"
VERIFICATION_AGENT = "verification"
PATCH_GUARD = "patch_guard"  # NOT an LLM: services/patch_engine.py

ALL_AGENTS = (
    SUPERVISOR_AGENT,
    SECURITY_AGENT,
    PERFORMANCE_AGENT,
    QUALITY_AGENT,
    EVIDENCE_AGENT,
    FUSION_AGENT,
    FIX_AGENT,
    VERIFICATION_AGENT,
    PATCH_GUARD,
)

# Execution order for a full analysis run. The supervisor enforces the
# real data dependencies (evidence waits for specialists; fusion waits
# for evidence; fix waits for validated findings; verification waits
# for the patch) — this order is the canonical plan, not a strict
# sequence: security/performance/quality run concurrently.
ANALYSIS_PLAN = (
    SECURITY_AGENT,
    PERFORMANCE_AGENT,
    QUALITY_AGENT,
    EVIDENCE_AGENT,
    FUSION_AGENT,
)

# Execution order for one remediation cycle.
REMEDIATION_PLAN = (
    FIX_AGENT,
    PATCH_GUARD,
    VERIFICATION_AGENT,
)


@dataclass(frozen=True)
class AgentRegistration:
    name: str
    description: str
    dependencies: tuple[str, ...]
    # "deterministic": no model calls, ever. "ai": reasons via Nemotron.
    # "hybrid": deterministic core with optional budgeted AI reasoning.
    kind: str
    # AI operating modes in which the agent participates.
    modes: frozenset[str]


AGENT_REGISTRY: dict[str, AgentRegistration] = {
    SUPERVISOR_AGENT: AgentRegistration(
        name=SUPERVISOR_AGENT,
        description="Builds the execution plan, enforces AI budgets, "
        "coordinates specialists, and consolidates the final result.",
        dependencies=(),
        kind="deterministic",
        modes=frozenset({"free", "economy", "full"}),
    ),
    SECURITY_AGENT: AgentRegistration(
        name=SECURITY_AGENT,
        description="Deterministic security triage: groups validated security "
        "findings, ranks priority targets, flags ambiguous evidence for AI "
        "review. Orchestration layer around static_analyzer, not a copy of it.",
        dependencies=(),
        kind="hybrid",
        modes=frozenset({"free", "economy", "full"}),
    ),
    PERFORMANCE_AGENT: AgentRegistration(
        name=PERFORMANCE_AGENT,
        description="Deterministic performance rules over the AST "
        "(nested loops, repeated expensive operations). Never claims "
        "measured runtime performance.",
        dependencies=(),
        kind="hybrid",
        modes=frozenset({"free", "economy", "full"}),
    ),
    QUALITY_AGENT: AgentRegistration(
        name=QUALITY_AGENT,
        description="Deterministic maintainability triage: wraps the "
        "analyzer's quality detectors plus conservative AST rules "
        "(complexity, parameter counts).",
        dependencies=(),
        kind="hybrid",
        modes=frozenset({"free", "economy", "full"}),
    ),
    EVIDENCE_AGENT: AgentRegistration(
        name=EVIDENCE_AGENT,
        description="Nemotron evidence review: challenges suspicious findings, "
        "finds relationships, flags false positives, prioritizes. Advisory "
        "only — every output passes validation, dedup, and the evidence "
        "hard gate. Never overrides deterministic evidence.",
        dependencies=(SECURITY_AGENT, PERFORMANCE_AGENT, QUALITY_AGENT),
        kind="ai",
        modes=frozenset({"economy", "full"}),
    ),
    FUSION_AGENT: AgentRegistration(
        name=FUSION_AGENT,
        description="Deterministic fusion: merges specialist outputs, "
        "deduplicates, preserves deterministic anchors, records provenance.",
        dependencies=(SECURITY_AGENT, PERFORMANCE_AGENT, QUALITY_AGENT, EVIDENCE_AGENT),
        kind="deterministic",
        modes=frozenset({"free", "economy", "full"}),
    ),
    FIX_AGENT: AgentRegistration(
        name=FIX_AGENT,
        description="Nemotron fix proposal behind an agent boundary: one "
        "validated finding in, structured proposal out. Never writes files; "
        "the proposal goes to the Patch Guard, not the filesystem.",
        dependencies=(),
        kind="ai",
        modes=frozenset({"economy", "full"}),
    ),
    VERIFICATION_AGENT: AgentRegistration(
        name=VERIFICATION_AGENT,
        description="Coordinates deterministic BEFORE/AFTER verification via "
        "verification_engine. Reports the verdict; AI may explain but never "
        "override it.",
        dependencies=(PATCH_GUARD,),
        kind="deterministic",
        modes=frozenset({"free", "economy", "full"}),
    ),
    PATCH_GUARD: AgentRegistration(
        name=PATCH_GUARD,
        description="Authoritative deterministic patch validation "
        "(services/patch_engine.py). Not an LLM.",
        dependencies=(),
        kind="deterministic",
        modes=frozenset({"free", "economy", "full"}),
    ),
}


def is_registered(name: str) -> bool:
    return name in AGENT_REGISTRY


def agents_for_analysis(mode: str) -> list[str]:
    """Ordered agent names for an analysis run in the given mode."""
    return [
        name
        for name in ANALYSIS_PLAN
        if mode in AGENT_REGISTRY[name].modes
    ]


def agents_for_remediation(mode: str) -> list[str]:
    """Ordered agent names for a remediation run in the given mode."""
    return [
        name
        for name in REMEDIATION_PLAN
        if mode in AGENT_REGISTRY[name].modes
    ]


def is_deterministic(name: str) -> bool:
    return AGENT_REGISTRY[name].kind == "deterministic"


def uses_ai(name: str) -> bool:
    return AGENT_REGISTRY[name].kind in ("ai", "hybrid")


__all__ = [
    "AGENT_REGISTRY",
    "ALL_AGENTS",
    "ANALYSIS_PLAN",
    "REMEDIATION_PLAN",
    "AgentRegistration",
    "EVIDENCE_AGENT",
    "FUSION_AGENT",
    "FIX_AGENT",
    "PATCH_GUARD",
    "PERFORMANCE_AGENT",
    "QUALITY_AGENT",
    "SECURITY_AGENT",
    "SUPERVISOR_AGENT",
    "VERIFICATION_AGENT",
    "agents_for_analysis",
    "agents_for_remediation",
    "is_deterministic",
    "is_registered",
    "uses_ai",
]
