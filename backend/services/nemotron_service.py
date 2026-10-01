"""Nemotron service: Phase 1 interface only.

The final product targets NVIDIA Nemotron 3 Ultra via Nebius Token Factory,
but Phase 1 must not fail just because no API key is configured. This module
defines the concrete provider; the live integration lands in Phase 2.

IMPORTANT: the exact Nebius/Nemotron model identifier must be verified
against current Nebius documentation during the integration phase — do not
trust example strings from older guides.
"""

from __future__ import annotations

import logging

from app.config import settings
from models.schemas import Finding
from services.ai_provider import AIProviderNotConfigured

logger = logging.getLogger(__name__)


class NemotronService:
    """AIProvider implementation for NVIDIA Nemotron via Nebius Token Factory."""

    name = "nemotron"

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
    ) -> None:
        self.api_key = api_key or settings.nebius_api_key
        self.model = model or settings.nemotron_model
        self.base_url = base_url or settings.nebius_base_url

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.model)

    def investigate(self, findings: list[Finding], context: dict) -> list[Finding]:
        """Phase 1: interface only. Live calls arrive in Phase 2."""
        if not self.is_configured:
            raise AIProviderNotConfigured(
                "NemotronService is not configured: set NEBIUS_API_KEY and "
                "NEMOTRON_MODEL to enable AI investigation (Phase 2)."
            )
        # Phase 2 will implement the live call here. Until then, refusing is
        # safer than pretending.
        raise NotImplementedError(
            "Live Nemotron investigation is not implemented in Phase 1."
        )
