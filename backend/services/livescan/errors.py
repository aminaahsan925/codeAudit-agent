"""Typed errors for live website scanning.

Each error carries a stable machine-readable ``code``. The API layer maps
them to HTTP statuses; messages are sanitized (never contain tokens,
cookies, or Authorization headers).
"""

from __future__ import annotations


class LiveScanError(Exception):
    """Base class for live-scan failures."""

    code = "SCAN_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ScanAuthorizationError(LiveScanError):
    """The scan was not authorized. Always maps to HTTP 403."""

    code = "SCAN_UNAUTHORIZED"


class ScanScopeError(LiveScanError):
    """Target or discovered URL violates the authorized scope. HTTP 400."""

    code = "SCAN_SCOPE_VIOLATION"


class SSRFBlockedError(LiveScanError):
    """The SSRF guard refused a URL. HTTP 400."""

    code = "SCAN_SSRF_BLOCKED"


class ScanBudgetError(LiveScanError):
    """A scan budget (requests, pages, redirects) was exhausted. HTTP 429."""

    code = "SCAN_BUDGET_EXCEEDED"


class ScanTimeoutError(LiveScanError):
    """The scan exceeded its wall-clock budget. HTTP 504."""

    code = "SCAN_TIMEOUT"
