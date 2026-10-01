"""Test-only fakes for the AI layer.

FakeAIProvider stands in for NemotronService; FakeOpenAIClient stands in for
the real OpenAI-compatible SDK client. Neither is ever used in production:
production wires NemotronService with the real SDK. All hermetic — no
network.
"""

from __future__ import annotations

from types import SimpleNamespace

from models.schemas import AIAssessment, AIFindingCandidate, FixProposal
from services.ai_provider import AIInvestigationResult, FixProposalResult


class _FakeChatCompletions:
    def __init__(self, response_text: str = "", exc: Exception | None = None):
        self.response_text = response_text
        self.exc = exc
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc is not None:
            raise self.exc
        message = SimpleNamespace(content=self.response_text)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class _FakeModels:
    def __init__(self, ids: tuple[str, ...] = (), exc: Exception | None = None):
        self._ids = ids
        self.exc = exc

    def list(self):
        if self.exc is not None:
            raise self.exc
        return SimpleNamespace(data=[SimpleNamespace(id=i) for i in self._ids])


class FakeOpenAIClient:
    """Mimics the subset of the OpenAI client surface NemotronService uses."""

    def __init__(
        self,
        response_text: str = "",
        exc: Exception | None = None,
        model_ids: tuple[str, ...] = (),
        models_exc: Exception | None = None,
    ):
        self.chat = SimpleNamespace(completions=_FakeChatCompletions(response_text, exc))
        self.models = _FakeModels(model_ids, models_exc)

    @property
    def last_create_kwargs(self) -> dict:
        calls = self.chat.completions.calls
        return calls[-1] if calls else {}


class FakeAIProvider:
    """Deterministic stand-in for NemotronService in integration tests.

    Returns canned assessments/candidates, or raises a canned AIError to
    exercise graceful degradation.
    """

    name = "fake"

    def __init__(
        self,
        assessments: list[AIAssessment] | None = None,
        candidates: list[AIFindingCandidate] | None = None,
        status: str = "enabled",
        exc: Exception | None = None,
        error_code: str | None = None,
        fix_proposal: FixProposal | None = None,
        fix_status: str = "enabled",
        fix_exc: Exception | None = None,
    ):
        self._assessments = list(assessments or [])
        self._candidates = list(candidates or [])
        self._status = status
        self._exc = exc
        self._error_code = error_code
        self._fix_proposal = fix_proposal
        self._fix_status = fix_status
        self._fix_exc = fix_exc
        self.received_findings = None
        self.received_context = None
        self.received_fix_finding = None
        self.received_fix_context = None
        # Counters for the multi-agent upgrade: every investigate/propose_fix
        # call increments these, so tests can assert zero-call guarantees.
        self.investigate_calls = 0
        self.propose_fix_calls = 0

    def investigate(self, findings, context) -> AIInvestigationResult:
        self.investigate_calls += 1
        self.received_findings = findings
        self.received_context = context
        if self._exc is not None:
            raise self._exc
        return AIInvestigationResult(
            status=self._status,
            assessments=list(self._assessments),
            candidates=list(self._candidates),
            error_code=self._error_code,
            provider_name=self.name,
            model="fake-model",
            prompt_version="fake-prompt-v1",
            model_calls=1,
            context_chars=42,
            duration_ms=5,
        )

    def propose_fix(self, finding, context) -> FixProposalResult:
        self.propose_fix_calls += 1
        self.received_fix_finding = finding
        self.received_fix_context = context
        if self._fix_exc is not None:
            raise self._fix_exc
        return FixProposalResult(
            status=self._fix_status,
            proposal=self._fix_proposal,
            error_code=self._error_code,
            provider_name=self.name,
            model="fake-model",
            prompt_version="fake-fix-prompt-v1",
            model_calls=1,
            context_chars=42,
            duration_ms=5,
        )
