"""Central configuration for the CodeAudit backend.

All secrets and environment-specific values come from environment variables.
Nothing here is committed with real credentials (see backend/.env.example).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # --- AI provider (Phase 2: live Nemotron via Nebius Token Factory) ---
    nebius_api_key: str = field(default_factory=lambda: os.environ.get("NEBIUS_API_KEY", ""))
    nemotron_model: str = field(default_factory=lambda: os.environ.get("NEMOTRON_MODEL", ""))
    nebius_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1"
        )
    )

    # --- AI reasoning tuning (all bounded; see services/nemotron_service.py) ---
    ai_enabled: bool = field(default_factory=lambda: _get_bool("CODEAUDIT_AI_ENABLED", True))
    ai_temperature: float = field(default_factory=lambda: _get_float("CODEAUDIT_AI_TEMPERATURE", 0.2))
    ai_max_tokens: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_MAX_TOKENS", 2000))
    ai_timeout_seconds: float = field(default_factory=lambda: _get_float("CODEAUDIT_AI_TIMEOUT_SECONDS", 60.0))
    ai_max_retries: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_MAX_RETRIES", 2))
    # Context budget: hard caps on what is ever sent to the model.
    ai_context_chars: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_MAX_CONTEXT_CHARS", 24_000))
    ai_max_context_files: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_MAX_CONTEXT_FILES", 12))
    ai_max_file_chars: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_MAX_FILE_CHARS", 6_000))
    ai_max_findings: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_MAX_FINDINGS", 25))
    ai_context_lines: int = field(default_factory=lambda: _get_int("CODEAUDIT_AI_CONTEXT_LINES", 15))

    # --- GitHub ---
    github_token: str = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN", ""))

    # --- Scanner safety limits ---
    max_file_size_bytes: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_FILE_SIZE", 1_000_000))
    max_files: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_FILES", 2_000))
    max_total_bytes: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_TOTAL_BYTES", 50_000_000))
    clone_timeout_seconds: int = field(default_factory=lambda: _get_int("CODEAUDIT_CLONE_TIMEOUT", 120))

    # --- Analyzer thresholds ---
    max_function_lines: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_FUNCTION_LINES", 50))

    # --- Misc ---
    log_level: str = field(default_factory=lambda: os.environ.get("CODEAUDIT_LOG_LEVEL", "INFO"))
    app_name: str = "CodeAudit Agent"
    app_version: str = "0.1.0"


settings = Settings()
