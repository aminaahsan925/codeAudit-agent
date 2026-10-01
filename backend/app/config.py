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


@dataclass(frozen=True)
class Settings:
    # --- AI provider (Phase 1: interface only, no live calls required) ---
    nebius_api_key: str = field(default_factory=lambda: os.environ.get("NEBIUS_API_KEY", ""))
    nemotron_model: str = field(default_factory=lambda: os.environ.get("NEMOTRON_MODEL", ""))
    nebius_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1"
        )
    )

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
