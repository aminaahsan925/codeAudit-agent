"""Groq AI provider: OpenAI-compatible alternate to Nebius Token Factory.

Nebius remains the default provider and the hackathon target. Groq is an
opt-in second provider (``CODEAUDIT_AI_PROVIDER=groq``) so the AI layer can
be exercised live without a Nebius key — Groq's free tier needs no card.

Implementation is a thin subclass of NemotronService: the entire
investigation/fix machinery (bounded context, structured JSON parsing,
reasoning_content fallback, typed errors, retries) is provider-agnostic
OpenAI-compatible HTTP. Only identity and defaults differ, so reports
honestly attribute results to "groq".
"""

from __future__ import annotations

from typing import Any, Callable

from app.config import Settings, settings
from services.nemotron_service import NemotronService


class GroqService(NemotronService):
    """AIProvider implementation for Groq's OpenAI-compatible API."""

    name = "groq"

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        *,
        client_factory: Callable[[], Any] | None = None,
        cfg: Settings | None = None,
    ) -> None:
        cfg = cfg or settings
        super().__init__(
            api_key=api_key or cfg.groq_api_key,
            model=model or cfg.groq_model,
            base_url=base_url or cfg.groq_base_url,
            client_factory=client_factory,
            cfg=cfg,
        )
