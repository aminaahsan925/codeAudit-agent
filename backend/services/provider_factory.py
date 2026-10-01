"""Provider factory: select the configured AI provider.

Nebius Token Factory (Nemotron) is the default and the hackathon target.
``CODEAUDIT_AI_PROVIDER=groq`` selects the Groq alternate. Both implement
the AIProvider protocol; callers never branch on the concrete class.

Lives in its own module to avoid import cycles (nemotron_service and
groq_service both build on services.ai_provider).
"""

from __future__ import annotations

import logging

from app.config import Settings, settings
from services.ai_provider import AIProvider
from services.groq_service import GroqService
from services.nemotron_service import NemotronService

logger = logging.getLogger(__name__)


def build_ai_provider(cfg: Settings | None = None) -> AIProvider | None:
    """Return the configured, ready AI provider, or None.

    Returns None when AI is disabled (CODEAUDIT_AI_ENABLED=false) or when
    the selected provider is not configured (missing key/model) — callers
    then run deterministic-only, exactly as before.
    """
    cfg = cfg or settings
    if not cfg.ai_enabled:
        logger.info("AI provider disabled by CODEAUDIT_AI_ENABLED=false")
        return None
    provider_name = (cfg.ai_provider or "nebius").strip().lower()
    if provider_name == "groq":
        service: AIProvider = GroqService(cfg=cfg)
        missing = "GROQ_API_KEY/GROQ_MODEL"
    else:
        if provider_name != "nebius":
            logger.warning(
                "Unknown CODEAUDIT_AI_PROVIDER=%r; falling back to nebius",
                cfg.ai_provider,
            )
        service = NemotronService(cfg=cfg)
        missing = "NEBIUS_API_KEY/NEMOTRON_MODEL"
    if not service.is_configured:
        logger.info("AI provider not configured: %s not set", missing)
        return None
    logger.info("AI provider selected: %s (model=%s)", service.name, service.model)
    return service
