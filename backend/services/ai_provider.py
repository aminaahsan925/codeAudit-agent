"""AI provider boundary (provider-agnostic).

Phase 2 extends the Phase 1 interface: the analysis engine depends on this
protocol, never on a concrete model client. Tests inject a fake provider;
production wires the real NemotronService. The contract is:

    Orchestrator
        |
        v
    AIProvider.investigate(findings, context) -> AIInvestigationResult
        |                                            |
        v                                            v
    FakeAIProvider  (tests)              NemotronService (production)

The provider returns assessments of deterministic findings plus candidate
new findings. It never writes the final result: the orchestrator applies
assessments, deduplicates, validates everything through the evidence hard
gate, and scores risk deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from models.schemas import AIAssessment, AIFindingCandidate, Finding

# Canonical home is services.ai_errors; re-exported here so existing
# imports keep working.
from services.ai_errors import AIProviderNotConfigured  # noqa: F401

if TYPE_CHECKING:  # pragma: no cover - typing only
    from services.ai_context_builder import AIContext


@dataclass
class AIInvestigationResult:
    """What one provider investigation produced.

    status: "enabled" (usable result), "disabled" (provider opted out),
            "failed"/"unavailable" (provider attempted and could not deliver).
    Assessments reference deterministic finding ids; candidates are raw model
    output that still needs normalization, schema validation, evidence
    validation, and deduplication by the caller.
    """

    status: str
    assessments: list[AIAssessment] = field(default_factory=list)
    candidates: list[AIFindingCandidate] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    model_calls: int = 0
    context_chars: int = 0
    duration_ms: int = 0
    provider_name: str = ""
    model: str = ""
    prompt_version: str = ""


class AIProvider(Protocol):
    """Contract every AI reasoning provider must satisfy."""

    name: str

    def investigate(
        self, findings: list[Finding], context: "AIContext"
    ) -> AIInvestigationResult:
        """Reason over deterministic findings plus bounded repository context.

        Must return an AIInvestigationResult. Must never invent file paths,
        line numbers, or evidence: every candidate still faces the evidence
        hard gate downstream. Must raise AIError (not raw SDK exceptions) on
        provider failures so the orchestrator can degrade gracefully.
        """
        ...


class StubAIProvider:
    """Test/CI stand-in: performs no AI reasoning.

    Returns an empty, disabled result — the orchestrator then keeps the
    deterministic findings exactly as they are, clearly labeled.
    """

    name = "stub"

    def investigate(
        self, findings: list[Finding], context: "AIContext"
    ) -> AIInvestigationResult:
        return AIInvestigationResult(
            status="disabled",
            provider_name=self.name,
        )
