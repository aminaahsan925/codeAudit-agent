"""Known secret/token shape detection.

Conservative patterns for well-known credential formats. Used to:
- avoid double-reporting (a value matching a known token shape defers to
  the dedicated SECRET detectors),
- redact token-shaped values from text sent to AI providers.

Patterns are deliberately narrow: unknown shapes are not guessed.
"""

from __future__ import annotations

import re

# Well-known token shapes: (name, compiled pattern).
_KNOWN_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"\b[0-9a-zA-Z/+]{40}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("github_classic", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-[0-9A-Za-z]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def matches_known_token_pattern(value: str) -> bool:
    """True when the value matches a known credential shape."""
    if not value:
        return False
    return any(pattern.search(value) for _, pattern in _KNOWN_TOKEN_PATTERNS)


def redact_known_tokens_in_text(text: str) -> str:
    """Replace known token-shaped values with [REDACTED]."""
    from .redaction import REDACTION_MARKER

    redacted = text
    for _, pattern in _KNOWN_TOKEN_PATTERNS:
        redacted = pattern.sub(REDACTION_MARKER, redacted)
    return redacted
