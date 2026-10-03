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


def _get_optional_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


# --- Multi-agent AI operating modes (Phase 3 upgrade) ---
# "free":    never call Nebius; deterministic specialists only (default)
# "economy": deterministic specialists + at most ONE Nemotron analysis call
# "full":    selective multi-agent Nemotron reasoning within hard call caps
AGENT_MODES = ("free", "economy", "full")

_AGENT_ANALYSIS_CALL_DEFAULTS = {"free": 0, "economy": 1, "full": 4}
_AGENT_REMEDIATION_CALL_DEFAULTS = {"free": 0, "economy": 1, "full": 2}


def _get_agent_mode() -> str:
    raw = (os.environ.get("CODEAUDIT_AGENT_MODE") or "").strip().lower()
    return raw if raw in AGENT_MODES else "free"


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

    # --- Alternate AI provider: Groq (OpenAI-compatible, free no-card tier).
    # Nebius remains the default and the hackathon target; Groq is an
    # opt-in second provider for live AI-layer testing without a Nebius key.
    # Select with CODEAUDIT_AI_PROVIDER=groq (default: nebius).
    ai_provider: str = field(
        default_factory=lambda: os.environ.get("CODEAUDIT_AI_PROVIDER", "nebius").strip().lower()
    )
    groq_api_key: str = field(default_factory=lambda: os.environ.get("GROQ_API_KEY", ""))
    groq_model: str = field(
        default_factory=lambda: os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
    )
    groq_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
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
    # Reasoning models (e.g. NVIDIA Nemotron) may reject the strict
    # response_format parameter. "json_object" (default) sends it;
    # "none" omits it — the versioned prompts still demand JSON-only and
    # the parser recovers fenced JSON deterministically.
    ai_response_format: str = field(
        default_factory=lambda: os.environ.get("CODEAUDIT_AI_RESPONSE_FORMAT", "json_object")
    )

    # --- Remediation tuning (Phase 3: bounded fix generation) ---
    fix_max_context_chars: int = field(default_factory=lambda: _get_int("CODEAUDIT_FIX_MAX_CONTEXT_CHARS", 12_000))
    fix_max_file_chars: int = field(default_factory=lambda: _get_int("CODEAUDIT_FIX_MAX_FILE_CHARS", 4_000))
    fix_context_lines: int = field(default_factory=lambda: _get_int("CODEAUDIT_FIX_CONTEXT_LINES", 20))
    fix_temperature: float = field(default_factory=lambda: _get_float("CODEAUDIT_FIX_TEMPERATURE", 0.2))
    fix_max_tokens: int = field(default_factory=lambda: _get_int("CODEAUDIT_FIX_MAX_TOKENS", 1_500))
    fix_max_changes: int = field(default_factory=lambda: _get_int("CODEAUDIT_FIX_MAX_CHANGES", 5))
    max_remediations_per_request: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST", 3))

    # --- GitHub ---
    github_token: str = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN", ""))

    # --- Scanner safety limits ---
    max_file_size_bytes: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_FILE_SIZE", 1_000_000))
    max_files: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_FILES", 2_000))
    max_total_bytes: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_TOTAL_BYTES", 50_000_000))
    clone_timeout_seconds: int = field(default_factory=lambda: _get_int("CODEAUDIT_CLONE_TIMEOUT", 120))

    # --- Analyzer thresholds ---
    max_function_lines: int = field(default_factory=lambda: _get_int("CODEAUDIT_MAX_FUNCTION_LINES", 50))

    # --- Live website scan budgets (Phase B) ---
    # These bound the scanner: pages crawled, requests, timeouts. The scanner
    # needs scan_config_from_settings() values; previously missing entirely.
    scan_max_pages: int = field(default_factory=lambda: _get_int("CODEAUDIT_SCAN_MAX_PAGES", 25))
    scan_max_requests: int = field(default_factory=lambda: _get_int("CODEAUDIT_SCAN_MAX_REQUESTS", 60))
    scan_request_delay_ms: int = field(default_factory=lambda: _get_int("CODEAUDIT_SCAN_REQUEST_DELAY_MS", 250))
    scan_timeout_seconds: float = field(default_factory=lambda: _get_float("CODEAUDIT_SCAN_TIMEOUT_SECONDS", 15.0))
    scan_max_redirects: int = field(default_factory=lambda: _get_int("CODEAUDIT_SCAN_MAX_REDIRECTS", 5))
    scan_max_response_bytes: int = field(default_factory=lambda: _get_int("CODEAUDIT_SCAN_MAX_RESPONSE_BYTES", 2_000_000))
    scan_max_seconds: float = field(default_factory=lambda: _get_float("CODEAUDIT_SCAN_MAX_SECONDS", 180.0))
    scan_allow_localhost: bool = field(default_factory=lambda: _get_bool("CODEAUDIT_SCAN_ALLOW_LOCALHOST", False))
    scan_tokens: str = field(default_factory=lambda: os.environ.get("CODEAUDIT_SCAN_TOKENS", ""))

    # --- Persistence (Phase 7 job queue + Phase 8 finding lifecycle) ---
    database_url: str = field(
        default_factory=lambda: os.environ.get("CODEAUDIT_DATABASE_URL", "sqlite:///codeaudit.db")
    )

    # --- Knowledge base (fix guidance retrieval) ---
    kb_max_chunks_per_finding: int = field(default_factory=lambda: _get_int("CODEAUDIT_KB_MAX_CHUNKS", 3))
    kb_max_chars: int = field(default_factory=lambda: _get_int("CODEAUDIT_KB_MAX_CHARS", 2000))

    # --- Misc ---
    log_level: str = field(default_factory=lambda: os.environ.get("CODEAUDIT_LOG_LEVEL", "INFO"))
    app_name: str = "CodeAudit Agent"
    app_version: str = "0.1.0"

    # --- Multi-agent AI operating mode (Phase 3 upgrade) ---
    # "free" (default): zero Nebius calls. "economy": bounded AI review.
    # "full": selective multi-agent reasoning within hard call caps.
    agent_mode: str = field(default_factory=_get_agent_mode)
    # Explicit overrides; when unset, the mode defaults apply
    # (free: 0/0, economy: 1/1, full: 4/2 for analysis/remediation).
    max_ai_calls_per_analysis: int | None = field(
        default_factory=lambda: _get_optional_int("CODEAUDIT_MAX_AI_CALLS_PER_ANALYSIS")
    )
    max_ai_calls_per_remediation: int | None = field(
        default_factory=lambda: _get_optional_int("CODEAUDIT_MAX_AI_CALLS_PER_REMEDIATION")
    )

    @property
    def ai_calls_analysis_limit(self) -> int:
        """Hard cap on Nemotron calls per analysis. Never unlimited."""
        if self.max_ai_calls_per_analysis is not None:
            return max(0, self.max_ai_calls_per_analysis)
        return _AGENT_ANALYSIS_CALL_DEFAULTS.get(self.agent_mode, 0)

    @property
    def ai_calls_remediation_limit(self) -> int:
        """Hard cap on Nemotron calls per remediation. Never unlimited."""
        if self.max_ai_calls_per_remediation is not None:
            return max(0, self.max_ai_calls_per_remediation)
        return _AGENT_REMEDIATION_CALL_DEFAULTS.get(self.agent_mode, 0)


settings = Settings()
