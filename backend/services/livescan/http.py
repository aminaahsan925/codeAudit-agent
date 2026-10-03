"""Guarded HTTP client for live website scanning.

All outbound traffic goes through :class:`GuardedHTTPClient`:

- Every URL (including each redirect hop) passes the SSRF guard first.
- Redirects are followed manually (never by the transport) so each hop
  is re-validated; chains longer than ``max_redirects`` are refused.
- Hard budgets: max requests per scan, delay between requests
  (rate limiting), per-response byte cap (streamed, never fully
  buffered), per-request timeout, and an overall scan wall-clock
  deadline enforced by the caller via :meth:`check_deadline`.
- ``trust_env=False``: proxy environment variables cannot reroute or
  bypass the guard.
- Authentication material (``Authorization`` header, ``Cookie`` header)
  is attached per request and NEVER logged.

Only GET is exposed: active probes are read-only by design.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .errors import ScanBudgetError, ScanScopeError, ScanTimeoutError
from .ssrf import GuardedURL, validate_url

logger = logging.getLogger(__name__)

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass
class ScanLimits:
    """Hard budgets for one website scan."""

    max_requests: int = 200
    request_delay_seconds: float = 0.25
    timeout_seconds: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 1_000_000
    max_scan_seconds: float = 300.0


@dataclass
class GuardedResponse:
    """A fetched response with its validated final URL."""

    url: str  # final URL after redirects
    status_code: int
    headers: httpx.Headers
    content: bytes
    elapsed_ms: int
    redirect_chain: tuple[str, ...] = ()


class GuardedHTTPClient:
    """httpx wrapper enforcing the SSRF guard and scan budgets."""

    def __init__(
        self,
        limits: ScanLimits,
        *,
        allow_localhost: bool = False,
        extra_headers: dict[str, str] | None = None,
        scope_check: Callable[[str], bool] | None = None,
    ) -> None:
        self._limits = limits
        self._allow_localhost = allow_localhost
        # Copied defensively: header values may carry credentials and must
        # never be mutated or logged by accident.
        self._extra_headers = dict(extra_headers or {})
        # Optional callback: consulted on every redirect hop so a redirect
        # cannot smuggle the crawl outside the authorized scope.
        self._scope_check = scope_check
        self._client = httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(limits.timeout_seconds),
        )
        self.requests_made = 0
        self._deadline = time.monotonic() + limits.max_scan_seconds

    def check_deadline(self) -> None:
        if time.monotonic() > self._deadline:
            raise ScanTimeoutError(
                f"Website scan exceeded its {self._limits.max_scan_seconds:g}s "
                "wall-clock budget."
            )

    def _check_request_budget(self) -> None:
        if self.requests_made >= self._limits.max_requests:
            raise ScanBudgetError(
                f"Website scan exceeded its {self._limits.max_requests} "
                "request budget."
            )

    def get(self, url: str) -> GuardedResponse:
        """GET one URL through the guard, following redirects manually.

        Each redirect hop is re-validated by the SSRF guard. Raises
        SSRFBlockedError, ScanBudgetError, or ScanTimeoutError.
        Transport errors (DNS, connect, TLS) propagate as httpx exceptions
        for the caller to record — they are connectivity facts, not
        findings.
        """
        guarded = validate_url(url, allow_localhost=self._allow_localhost)
        chain: list[str] = []
        current: GuardedURL = guarded

        for _ in range(self._limits.max_redirects + 1):
            self.check_deadline()
            self._check_request_budget()
            if self.requests_made:
                time.sleep(self._limits.request_delay_seconds)
            started = time.monotonic()
            try:
                with self._client.stream(
                    "GET", current.url, headers=self._extra_headers
                ) as response:
                    status = response.status_code
                    headers = response.headers
                    body = self._read_capped(response)
            except httpx.HTTPError:
                # Never log headers here: they may contain Authorization /
                # Cookie values supplied for authenticated scanning.
                logger.debug("HTTP request failed for %s", current.host)
                raise
            elapsed_ms = int((time.monotonic() - started) * 1000)
            self.requests_made += 1

            location = headers.get("location")
            if status in _REDIRECT_STATUSES and location:
                next_url = urljoin(current.url, location)
                if self._scope_check is not None and not self._scope_check(next_url):
                    raise ScanScopeError(
                        "Redirect target is outside the authorized scan scope; "
                        "redirect not followed."
                    )
                chain.append(current.url)
                # Re-validate every hop: a redirect to an internal address
                # is an SSRF vector and is refused here.
                current = validate_url(
                    next_url, allow_localhost=self._allow_localhost
                )
                continue

            return GuardedResponse(
                url=current.url,
                status_code=status,
                headers=headers,
                content=body,
                elapsed_ms=elapsed_ms,
                redirect_chain=tuple(chain),
            )

        raise ScanBudgetError(
            f"Redirect chain exceeded {self._limits.max_redirects} hops."
        )

    def _read_capped(self, response: httpx.Response) -> bytes:
        """Read at most max_response_bytes from a streamed response."""
        cap = self._limits.max_response_bytes
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes(chunk_size=65536):
            if total + len(chunk) > cap:
                chunks.append(chunk[: cap - total])
                total = cap
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def close(self) -> None:
        self._client.close()
