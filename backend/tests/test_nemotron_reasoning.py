"""Tests for reasoning-model robustness in NemotronService (hermetic).

NVIDIA Nemotron models are reasoning models: the answer often arrives in
``message.reasoning_content`` while ``message.content`` is empty or None.
These tests pin the fallback behavior, plus the configurable
``response_format`` escape hatch for deployments that reject it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.config import Settings
from services.ai_context_builder import AIContext
from services.ai_errors import AIInvalidResponse
from services.nemotron_service import NemotronService

VALID_JSON = '{"assessments": [], "new_findings": []}'


class _ReasoningFakeClient:
    """Fake OpenAI client whose message carries content/reasoning_content."""

    def __init__(self, content=None, reasoning_content=None):
        message = SimpleNamespace(content=content, reasoning_content=reasoning_content)
        self._response = SimpleNamespace(choices=[SimpleNamespace(message=message)])
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._response

    @property
    def last_create_kwargs(self) -> dict:
        return self.calls[-1] if self.calls else {}


def _service(client, **kwargs) -> NemotronService:
    return NemotronService(
        api_key="test-key",
        model="test-model",
        client_factory=lambda: client,
        **kwargs,
    )


def _context() -> AIContext:
    return AIContext(repo_owner="o", repo_name="r")


def test_reasoning_content_fallback():
    """Empty content + JSON in reasoning_content => usable result."""
    client = _ReasoningFakeClient(content="", reasoning_content=VALID_JSON)
    result = _service(client).investigate([], _context())
    assert result.status == "enabled"
    assert result.model_calls == 1


def test_content_preferred_when_both_present():
    client = _ReasoningFakeClient(
        content=VALID_JSON, reasoning_content='{"assessments": ["junk"]}'
    )
    result = _service(client).investigate([], _context())
    assert result.status == "enabled"


def test_both_empty_raises_invalid_response():
    client = _ReasoningFakeClient(content=None, reasoning_content="   ")
    with pytest.raises(AIInvalidResponse):
        _service(client).investigate([], _context())


def test_extract_content_missing_attributes():
    """Messages without either attribute fail closed, not crash."""
    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace())])
    with pytest.raises(AIInvalidResponse):
        NemotronService._extract_content(response)
    with pytest.raises(AIInvalidResponse):
        NemotronService._extract_content(SimpleNamespace(choices=[]))


def test_response_format_sent_by_default(monkeypatch):
    monkeypatch.delenv("CODEAUDIT_AI_RESPONSE_FORMAT", raising=False)
    client = _ReasoningFakeClient(content=VALID_JSON)
    _service(client, cfg=Settings()).investigate([], _context())
    assert client.last_create_kwargs["response_format"] == {"type": "json_object"}


def test_response_format_omitted_when_none(monkeypatch):
    monkeypatch.setenv("CODEAUDIT_AI_RESPONSE_FORMAT", "none")
    client = _ReasoningFakeClient(content=VALID_JSON)
    _service(client, cfg=Settings()).investigate([], _context())
    assert "response_format" not in client.last_create_kwargs


def test_response_format_omitted_for_propose_fix(monkeypatch):
    """The escape hatch applies to the fix path too."""
    monkeypatch.setenv("CODEAUDIT_AI_RESPONSE_FORMAT", "none")
    client = _ReasoningFakeClient(content=VALID_JSON)
    # propose_fix needs a finding + FixContext; only the request-building
    # path matters here, so call the kwargs builder directly.
    service = _service(client, cfg=Settings())
    kwargs = service._completion_kwargs(
        model="m", messages=[], temperature=0.2, max_tokens=10
    )
    assert "response_format" not in kwargs
    service2 = _service(client)
    kwargs2 = service2._completion_kwargs(
        model="m", messages=[], temperature=0.2, max_tokens=10
    )
    assert kwargs2["response_format"] == {"type": "json_object"}


def test_default_client_factory_survives_poisoned_no_proxy(monkeypatch):
    """Regression: bracketed IPv6 entries in NO_PROXY must not crash client
    construction (httpx proxy-map parsing). No network is touched."""
    monkeypatch.setenv("NO_PROXY", "localhost,[::1],[fd8b:4f84:7d32:99::1]")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
    service = NemotronService(api_key="k", model="m")
    client = service._default_client_factory()
    assert client is not None
