"""Typed contracts for the multi-agent backend.

Every agent receives a structured AgentContext (never a loose dict) and
returns a typed result carrying execution metadata: agent name, status,
duration, model usage, findings, errors, and provenance. These contracts
are what make the system "multi-agent" rather than "multi-function":
each agent has explicit inputs, outputs, and responsibility boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from models.schemas import Finding, ParsedFile, RepositoryMetadata, ValidatedFinding

if TYPE_CHECKING:  # typing only; avoids import cycles at runtime
    from services.ai_budget_manager import AIBudgetManager
    from services.ai_call_cache import AICallCache
    from services.ai_provider import AIProvider
    from services.repository_scanner import ScanResult
    from agents.shared_context import SharedRepositoryContext


class AgentStatus(str, Enum):
    """Lifecycle state of one agent execution."""

    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # e.g. AI agent with no budget in free mode
    DEGRADED = "degraded"  # ran, but a non-fatal problem occurred (e.g. AI failed)


@dataclass
class AgentContext:
    """Structured input every agent receives.

    Heavy, shareable data (scan results, parsed files, validated findings)
    is referenced, not copied: agents read from the shared context and
    return new result objects. budget/cache/provider are request-scoped.
    """

    execution_id: str
    repository: RepositoryMetadata
    mode: str  # "free" | "economy" | "full"
    scan: "ScanResult"
    parsed: list["ParsedFile"] = field(default_factory=list)
    # Native parse trees keyed by relative path (ast.Module for Python,
    # tree-sitter Tree for JavaScript/TypeScript), shared so specialist
    # agents can run AST rules without re-parsing. Internal to the analysis
    # stage: never serialized, read-only for agents. Empty when the caller
    # did not retain trees.
    parse_trees: dict[str, Any] = field(default_factory=dict)
    validated_findings: list[ValidatedFinding] = field(default_factory=list)
    shared: "SharedRepositoryContext | None" = None
    budget: "AIBudgetManager | None" = None
    cache: "AICallCache | None" = None
    # None in free mode: deterministic pipeline only, no AI provider at all.
    provider: "AIProvider | None" = None
    extra: dict[str, Any] = field(default_factory=dict)


class AgentExecutionMetadata(BaseModel):
    """Traceable execution record for one agent run."""

    agent_name: str
    status: AgentStatus = AgentStatus.COMPLETED
    duration_ms: int = 0
    model_used: str | None = None
    model_calls: int = 0
    context_chars: int = 0
    prompt_version: str | None = None
    findings_count: int = 0
    errors: list[str] = Field(default_factory=list)


class AgentExecutionPlan(BaseModel):
    """What the Supervisor decided to run, and why."""

    repository: str = Field(..., description="owner/name or URL being analyzed")
    agents_requested: list[str] = Field(
        ..., description="Agent names in planned execution order"
    )
    ai_budget: int = Field(..., ge=0, description="Nemotron calls allowed for analysis")
    reason: str = Field(..., description="Why this plan fits the mode and repository")
    mode: str = Field(default="free")


class AgentDecision(BaseModel):
    """A recorded judgment by an agent (e.g. supervisor routing, fix triage)."""

    agent_name: str
    decision: str
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class SpecialistAgentResult(BaseModel):
    """Shared shape for the deterministic specialist agents.

    Security, performance, and quality agents all report the same fields;
    per-agent modules subclass this with their own agent_name default.
    Findings here are the agent's view of already-validated deterministic
    findings (security/quality) or its own evidence-gated detections
    (performance/quality extras, validated by the supervisor before fusion).
    """

    agent_name: str
    findings: list[Finding] = Field(default_factory=list)
    # Files ranked by importance for this specialty (most severe first).
    priority_targets: list[str] = Field(default_factory=list)
    # Every file that produced at least one finding for this specialty.
    suspicious_files: list[str] = Field(default_factory=list)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    execution_metadata: AgentExecutionMetadata


class SecurityAgentResult(SpecialistAgentResult):
    agent_name: str = "security"


class PerformanceAgentResult(SpecialistAgentResult):
    agent_name: str = "performance"


class QualityAgentResult(SpecialistAgentResult):
    agent_name: str = "quality"


__all__ = [
    "AgentContext",
    "AgentDecision",
    "AgentExecutionMetadata",
    "AgentExecutionPlan",
    "AgentStatus",
    "PerformanceAgentResult",
    "QualityAgentResult",
    "SecurityAgentResult",
    "SpecialistAgentResult",
]
