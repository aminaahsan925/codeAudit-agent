"""Redaction helpers for secret material in findings.

When a finding is marked ``sensitive``, its evidence must never carry the
raw secret value. ``redact_line`` replaces the secret portion of a line
with :data:`REDACTION_MARKER`, keeping the surrounding code context so
the finding stays actionable without leaking the secret.
"""

from __future__ import annotations

import re

REDACTION_MARKER = "[REDACTED]"

# assignment-like: api_key = "value", password: 'value', token="value"
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?token
    |access[_-]?token|client[_-]?secret|private[_-]?key)\b
    \s*[:=]\s*(['"])(?P<value>.+?)\2""",
    re.VERBOSE,
)


def redact_line(line: str, values: list[str] | None = None) -> str:
    """Redact secret values in a single line of code.

    When ``values`` is given, those exact values are replaced with
    :data:`REDACTION_MARKER`. Otherwise, secret-shaped assignments are
    redacted by pattern.
    """
    redacted = line
    for value in values or []:
        if value:
            redacted = redacted.replace(value, REDACTION_MARKER)

    def _replace(match: re.Match) -> str:
        return match.group(0).replace(
            match.group("value"), REDACTION_MARKER
        )

    return _SECRET_ASSIGNMENT_RE.sub(_replace, redacted)
