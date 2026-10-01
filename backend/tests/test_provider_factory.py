"""Tests for the provider factory and GroqService (hermetic).

Nebius remains the default; Groq is opt-in via CODEAUDIT_AI_PROVIDER=groq.
Every test uses fake clients or unconfigured services — no network, no keys.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from services.ai_provider import StubAIProvider
from services.groq_service import GroqService
from services.nemotron_service import NemotronService
from services.provider_factory import build_ai_provider
from tests.fakes import FakeOpenAIClient
from tests.test_ai_service import VALID_JSON, _context


def _cfg(monkeypatch, **env) -> Settings:
    for key in (
        "CODEAUDIT_AI_PROVIDER",
        "CODEAUDIT_AI_ENABLED",
        "NEBIUS_API_KEY",
        "NEMOTRON_MODEL",
        "GROQ_API_KEY",
        "GROQ_MODEL",
        "GROQ_BASE_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings()


def test_default_is_nebius_when_nothing_configured(monkeypatch):
    provider = build_ai_provider(_cfg(monkeypatch))
    assert provider is None  # no keys -> deterministic-only


def test_nebius_selected_with_key(monkeypatch):
    cfg = _cfg(
        monkeypatch, NEBIUS_API_KEY="k", NEMOTRON_MODEL="nvidia/nemotron-3-ultra"
    )
    provider = build_ai_provider(cfg)
    assert isinstance(provider, NemotronService)
    assert not isinstance(provider, GroqService)
    assert provider.name == "nemotron"
    assert provider.is_configured


def test_groq_selected_with_key(monkeypatch):
    cfg = _cfg(
        monkeypatch,
        CODEAUDIT_AI_PROVIDER="groq",
        GROQ_API_KEY="gsk-test",
        GROQ_MODEL="llama-3.3-70b-versatile",
    )
    provider = build_ai_provider(cfg)
    assert isinstance(provider, GroqService)
    assert provider.name == "groq"
    assert provider.is_configured
    assert provider.base_url == "https://api.groq.com/openai/v1"
    assert provider.model == "llama-3.3-70b-versatile"


def test_groq_without_key_falls_back_to_none(monkeypatch):
    cfg = _cfg(monkeypatch, CODEAUDIT_AI_PROVIDER="groq")
    assert build_ai_provider(cfg) is None


def test_ai_disabled_returns_none(monkeypatch):
    cfg = _cfg(
        monkeypatch,
        CODEAUDIT_AI_ENABLED="false",
        CODEAUDIT_AI_PROVIDER="groq",
        GROQ_API_KEY="gsk-test",
        GROQ_MODEL="llama-3.3-70b-versatile",
    )
    assert build_ai_provider(cfg) is None


def test_unknown_provider_falls_back_to_nebius(monkeypatch):
    cfg = _cfg(
        monkeypatch,
        CODEAUDIT_AI_PROVIDER="watson",
        NEBIUS_API_KEY="k",
        NEMOTRON_MODEL="m",
    )
    provider = build_ai_provider(cfg)
    assert isinstance(provider, NemotronService)
    assert provider.name == "nemotron"


def test_groq_service_investigation_reports_groq(monkeypatch):
    cfg = _cfg(
        monkeypatch, GROQ_API_KEY="gsk-test", GROQ_MODEL="llama-3.3-70b-versatile"
    )
    client = FakeOpenAIClient(response_text=VALID_JSON)
    service = GroqService(
        api_key="gsk-test",
        model="llama-3.3-70b-versatile",
        client_factory=lambda: client,
        cfg=cfg,
    )
    result = service.investigate([], _context())
    assert result.status == "enabled"
    assert result.provider_name == "groq"
    assert result.model == "llama-3.3-70b-versatile"
    assert client.last_create_kwargs["model"] == "llama-3.3-70b-versatile"


def test_groq_defaults_come_from_config(monkeypatch):
    cfg = _cfg(monkeypatch)  # no env at all
    service = GroqService(cfg=cfg)
    assert service.model == "llama-3.3-70b-versatile"
    assert service.base_url == "https://api.groq.com/openai/v1"
    assert not service.is_configured  # no key -> not configured


def test_supervisor_ai_status_attributes_actual_provider(monkeypatch, tmp_path):
    """The AI status must name the provider that really ran (groq here),
    not a hardcoded default. Uses a fake provider — hermetic."""
    from tests.fakes import FakeAIProvider
    from agents.supervisor_agent import SupervisorAgent

    class _NamedFake(FakeAIProvider):
        name = "groq-test"

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    sup = SupervisorAgent(ai_provider=_NamedFake(), default_mode="economy")
    result = sup.run_on_local_path(repo, owner="t", name="r")
    assert result.ai.provider == "groq-test"
