"""AI provider boundary (provider-agnostic).

Phase 1 establishes the interface only. The analysis engine depends on
this protocol, never on a concrete model client, so tests inject a stub and
Phase 2 can wire the real Nemotron implementation without touching the
pipeline.
"""

from __future__ import annotations

from typing import Protocol

from models.schemas import Finding


class AIProviderNotConfigured(Exception):
    """Raised when AI reasoning is requested but no provider is configured."""


class AIProvider(Protocol):
    """Contract every AI reasoning provider must satisfy."""

    name: str

    def investigate(self, findings: list[Finding], context: dict) -> list[Finding]:
        """Enrich or re-evaluate findings with model reasoning.

        Must return findings that still pass FindingValidator; the provider
        must never invent file paths, line numbers, or evidence.
        """
        ...


class StubAIProvider:
    """Test/CI stand-in: returns findings unchanged, clearly labeled."""

    name = "stub"

    def investigate(self, findings: list[Finding], context: dict) -> list[Finding]:
        return list(findings)
