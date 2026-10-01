"""Typed AI errors: the Phase 2 error contract.

Every failure mode of the Nemotron/Token Factory integration maps to one of
these codes. The orchestrator catches AIError and degrades gracefully
(deterministic findings survive); the API surfaces only the code plus a
sanitized message — never raw SDK exception text, never credentials.
"""

from __future__ import annotations


class AIError(Exception):
    """Base class for all AI-layer failures."""

    code = "AI_ERROR"

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.code)
        self.message = message or self.code


class AIProviderNotConfigured(AIError):
    """No usable AI configuration (missing key/model, or AI explicitly disabled)."""

    code = "AI_PROVIDER_NOT_CONFIGURED"


class AIModelUnavailable(AIError):
    """Token Factory unreachable for auth reasons, or the model id is unknown.

    Covers: invalid API key (401), unknown model (404), and DNS/TLS-level
    connection failures that indicate the endpoint itself is wrong.
    Never retried: retrying a bad key or a wrong model id cannot help.
    """

    code = "AI_MODEL_UNAVAILABLE"


class AIRequestTimeout(AIError):
    """The model request exceeded the configured timeout. Not retried beyond
    the SDK's bounded retry policy: a stuck inference call stays stuck."""

    code = "AI_REQUEST_TIMEOUT"


class AIRateLimited(AIError):
    """Token Factory rate limit hit (HTTP 429). Retried only inside the SDK's
    bounded retry policy with backoff; surfaced if it persists."""

    code = "AI_RATE_LIMITED"


class AIUpstreamError(AIError):
    """Any other upstream failure: 5xx, network errors mid-request, or an
    unexpected exception from the model client."""

    code = "AI_UPSTREAM_ERROR"


class AIInvalidResponse(AIError):
    """The upstream call 'succeeded' but returned something unusable:
    empty content, missing choices, or a non-string payload."""

    code = "AI_INVALID_RESPONSE"


class AIOutputInvalid(AIError):
    """Model output failed JSON extraction or schema validation.

    Fail-closed: the entire AI output is rejected. Nothing is guessed,
    repaired, or partially accepted.
    """

    code = "AI_OUTPUT_INVALID"


# Sanitized, user-safe messages per code. These are what leave the process
# boundary (logs carry more detail; API responses carry only these).
SAFE_MESSAGES = {
    AIProviderNotConfigured.code: "AI investigation is not configured.",
    AIModelUnavailable.code: "The configured AI model is unavailable. Check NEBIUS_API_KEY and NEMOTRON_MODEL.",
    AIRequestTimeout.code: "The AI request timed out.",
    AIRateLimited.code: "The AI provider rate limit was reached.",
    AIUpstreamError.code: "The AI provider returned an error.",
    AIInvalidResponse.code: "The AI provider returned an unusable response.",
    AIOutputInvalid.code: "The AI provider returned output that failed validation.",
}
