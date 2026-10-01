"""Tests for AI configuration: env parsing, defaults, and provider selection."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.config import Settings
from services.orchestrator import AnalysisOrchestrator


def test_ai_defaults_are_bounded_and_safe():
    cfg = Settings()
    assert cfg.ai_enabled is True
    assert cfg.ai_temperature == 0.2
    assert cfg.ai_max_tokens == 2000
    assert cfg.ai_timeout_seconds == 60.0
    assert cfg.ai_max_retries == 2
    assert cfg.ai_context_chars == 24_000
    assert cfg.ai_max_context_files == 12
    assert cfg.ai_max_file_chars == 6_000
    assert cfg.ai_max_findings == 25
    assert cfg.ai_context_lines == 15


def test_ai_env_overrides_parsed(monkeypatch):
    monkeypatch.setenv("CODEAUDIT_AI_ENABLED", "false")
    monkeypatch.setenv("CODEAUDIT_AI_TEMPERATURE", "0.7")
    monkeypatch.setenv("CODEAUDIT_AI_MAX_TOKENS", "500")
    monkeypatch.setenv("CODEAUDIT_AI_TIMEOUT_SECONDS", "10.5")
    monkeypatch.setenv("CODEAUDIT_AI_MAX_CONTEXT_CHARS", "8000")
    cfg = Settings()
    assert cfg.ai_enabled is False
    assert cfg.ai_temperature == 0.7
    assert cfg.ai_max_tokens == 500
    assert cfg.ai_timeout_seconds == 10.5
    assert cfg.ai_context_chars == 8000


def test_invalid_ai_env_falls_back_to_defaults(monkeypatch):
    monkeypatch.setenv("CODEAUDIT_AI_TEMPERATURE", "not-a-number")
    monkeypatch.setenv("CODEAUDIT_AI_MAX_TOKENS", "nope")
    cfg = Settings()
    assert cfg.ai_temperature == 0.2
    assert cfg.ai_max_tokens == 2000


def test_ai_disabled_flag_selects_no_provider(monkeypatch):
    monkeypatch.setattr(
        "services.provider_factory.settings",
        SimpleNamespace(ai_enabled=False),
    )
    assert AnalysisOrchestrator._default_ai_provider() is None


def test_missing_credentials_selects_no_provider(monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEMOTRON_MODEL", raising=False)
    # Fresh Settings read the cleaned environment (hermetic either way).
    monkeypatch.setattr("services.nemotron_service.settings", Settings())
    monkeypatch.setattr("services.provider_factory.settings", Settings())
    from services.nemotron_service import NemotronService

    assert not NemotronService().is_configured
    assert AnalysisOrchestrator._default_ai_provider() is None


def test_explicit_provider_is_used_not_overridden():
    from services.ai_provider import StubAIProvider

    stub = StubAIProvider()
    assert AnalysisOrchestrator(ai_provider=stub)._ai_provider is stub
