"""Website scan orchestrator.

One scan, in order:

1. Authorization (no network before this passes).
2. SSRF-guard validation of the target.
3. Scope construction.
4. Bounded crawl (BFS, same-scope links only, page cap).
5. Passive checks on every fetched page.
6. Exposed-file probes at the scope root.
7. Active probes (GET-only, rate-limited) when enabled.
8. TLS certificate inspection for https targets.
9. Result assembly with the standard honesty disclaimer.

Budgets: the guarded client enforces request count, redirect depth,
response bytes, per-request timeout, and rate-limit delay; the scanner
additionally enforces the page cap and the overall wall-clock deadline.
Hitting the request/page budget ends the crawl gracefully with
``truncated=True`` — partial results are returned honestly, not dropped.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from models.schemas import WebsiteScanResult

from . import checks
from .auth import parse_scan_tokens, verify_scan_authorization
from .crawl import extract_links
from .errors import ScanBudgetError, ScanTimeoutError
from .http import GuardedHTTPClient, GuardedResponse, ScanLimits
from .scope import ScanScope, in_scope, normalize_scope
from .ssrf import validate_url

logger = logging.getLogger(__name__)

SCAN_DISCLAIMER = (
    "This scan covered {pages} URL(s) with {passive} passive check(s) and "
    "{active} active probe(s) on {host}. It is a point-in-time, scope-limited "
    "assessment: absence of findings is NOT proof of security, and findings "
    "are probe observations, not confirmed exploitations. Active-probe "
    "findings require manual verification by someone authorized to test "
    "this system."
)


@dataclass
class ScanConfig:
    """Everything one website scan needs. Built from the API request plus
    server settings; the scanner takes no other input."""

    target_url: str
    authorization_token: str
    i_authorize_this_scan: bool
    include_subdomains: bool = False
    path_prefix: str | None = None
    max_pages: int | None = None
    active_probes: bool = True
    session_cookie: str | None = None
    authorization_header: str | None = None
    # Server-side (never from the request):
    configured_tokens: dict[str, str] | None = None
    allow_localhost: bool = False
    limits: ScanLimits | None = None


class WebsiteScanner:
    """Runs one authorized, scoped, SSRF-guarded website scan."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        self._limits = config.limits or ScanLimits()
        self._findings: list = []
        self._urls_scanned: list[str] = []
        self._urls_skipped: list[str] = []
        self._passive_checks = 0
        self._active_probes = 0
        self._truncated = False
        self._scope: ScanScope | None = None
        self._client: GuardedHTTPClient | None = None

    # -- public ------------------------------------------------------

    def run(self) -> WebsiteScanResult:
        started = time.monotonic()
        cfg = self._config
        try:
            # 1. Authorization before ANY network I/O. The return value
            # (normalized host) is informational; failure raises.
            verify_scan_authorization(
                cfg.target_url,
                cfg.authorization_token,
                cfg.i_authorize_this_scan,
                cfg.configured_tokens or {},
            )
            # 2. SSRF guard on the target.
            validate_url(cfg.target_url, allow_localhost=cfg.allow_localhost)
            # 3. Scope.
            self._scope = normalize_scope(
                cfg.target_url,
                include_subdomains=cfg.include_subdomains,
                path_prefix=cfg.path_prefix,
            )
            # 4-8. Crawl + checks.
            self._client = self._build_client()
            try:
                self._crawl_and_check()
            finally:
                self._client.close()
        except (ScanBudgetError, ScanTimeoutError):
            # Budgets end the scan gracefully: partial results stay honest.
            self._truncated = True
        duration_ms = int((time.monotonic() - started) * 1000)
        return WebsiteScanResult(
            target_url=cfg.target_url,
            scan_host=self._scope.host if self._scope else "",
            scope=self._scope.describe() if self._scope else "",
            urls_scanned=self._urls_scanned,
            urls_skipped_out_of_scope=self._urls_skipped,
            findings=self._findings,
            checks_run={
                "passive": self._passive_checks,
                "active": self._active_probes,
            },
            requests_made=self._client.requests_made if self._client else 0,
            truncated=self._truncated,
            duration_ms=duration_ms,
            disclaimer=SCAN_DISCLAIMER.format(
                pages=len(self._urls_scanned),
                passive=self._passive_checks,
                active=self._active_probes,
                host=self._scope.host if self._scope else cfg.target_url,
            ),
        )

    # -- internals ---------------------------------------------------

    def _build_client(self) -> GuardedHTTPClient:
        cfg = self._config
        headers: dict[str, str] = {
            "User-Agent": "CodeAudit-Scanner/0.1 (+authorized security scan)"
        }
        if cfg.session_cookie:
            headers["Cookie"] = cfg.session_cookie
        if cfg.authorization_header:
            headers["Authorization"] = cfg.authorization_header
        scope = self._scope
        assert scope is not None
        return GuardedHTTPClient(
            self._limits,
            allow_localhost=cfg.allow_localhost,
            extra_headers=headers,
            scope_check=lambda url: in_scope(scope, url),
        )

    def _crawl_and_check(self) -> None:
        cfg = self._config
        client = self._client
        scope = self._scope
        assert client is not None and scope is not None
        max_pages = cfg.max_pages or self._limits.max_requests
        max_pages = min(max_pages, self._limits.max_requests)

        queue: list[str] = [cfg.target_url]
        seen: set[str] = set()
        pages_done = 0

        while queue and pages_done < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if not in_scope(scope, url):
                self._urls_skipped.append(url)
                continue
            try:
                response = client.get(url)
            except (ScanBudgetError, ScanTimeoutError):
                self._truncated = True
                break
            except httpx.HTTPError:
                # Connectivity failure: recorded as a skipped URL, not a
                # finding. (Debug log only — no credentials involved.)
                logger.debug("unreachable during scan: %s", urlsplit(url).path)
                self._urls_skipped.append(url)
                continue
            self._urls_scanned.append(response.url)
            pages_done += 1
            self._run_passive_checks(response)
            if cfg.active_probes:
                self._run_active_probes(url)

            # Enqueue discovered same-scope links.
            try:
                body = response.content.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            content_type = response.headers.get("content-type", "").lower()
            if "html" in content_type and body:
                for link in extract_links(body, response.url):
                    if link not in seen:
                        if in_scope(scope, link):
                            queue.append(link)
                        else:
                            self._urls_skipped.append(link)

        # Post-crawl checks that need the client.
        scope_root = scope.origin() + scope.path_prefix
        try:
            self._findings.extend(checks.check_exposed_files(client, scope_root))
            self._passive_checks += 2
        except (ScanBudgetError, ScanTimeoutError):
            self._truncated = True

        if scope.scheme == "https":
            try:
                self._findings.extend(
                    checks.probe_tls_certificate(
                        scope.host, timeout=self._limits.timeout_seconds
                    )
                )
                self._passive_checks += 1
            except Exception:
                logger.debug("TLS probe failed for %s", scope.host)

    def _run_passive_checks(self, response: GuardedResponse) -> None:
        url = response.url
        self._findings.extend(checks.check_transport(url))
        self._passive_checks += 1
        self._findings.extend(checks.check_security_headers(url, response))
        self._passive_checks += 5
        self._findings.extend(checks.check_cookie_flags(url, response))
        self._passive_checks += 1
        self._findings.extend(checks.check_server_disclosure(url, response))
        self._passive_checks += 1

    def _run_active_probes(self, url: str) -> None:
        client = self._client
        assert client is not None
        try:
            self._findings.extend(checks.reflected_xss_probe(client, url))
            self._active_probes += 1
            self._findings.extend(checks.sqli_error_probe(client, url))
            self._active_probes += 1
        except (ScanBudgetError, ScanTimeoutError):
            self._truncated = True
            raise


def scan_config_from_settings(
    *,
    target_url: str,
    authorization_token: str,
    i_authorize_this_scan: bool,
    include_subdomains: bool,
    path_prefix: str | None,
    max_pages: int | None,
    active_probes: bool,
    session_cookie: str | None,
    authorization_header: str | None,
    settings,
) -> ScanConfig:
    """Build a ScanConfig from the API request plus server settings."""
    server_max_pages = settings.scan_max_pages
    if max_pages is not None:
        max_pages = max(1, min(max_pages, server_max_pages))
    return ScanConfig(
        target_url=target_url,
        authorization_token=authorization_token,
        i_authorize_this_scan=i_authorize_this_scan,
        include_subdomains=include_subdomains,
        path_prefix=path_prefix,
        max_pages=max_pages,
        active_probes=active_probes,
        session_cookie=session_cookie,
        authorization_header=authorization_header,
        configured_tokens=parse_scan_tokens(settings.scan_tokens),
        allow_localhost=settings.scan_allow_localhost,
        limits=ScanLimits(
            max_requests=settings.scan_max_requests,
            request_delay_seconds=settings.scan_request_delay_ms / 1000.0,
            timeout_seconds=settings.scan_timeout_seconds,
            max_redirects=settings.scan_max_redirects,
            max_response_bytes=settings.scan_max_response_bytes,
            max_scan_seconds=settings.scan_max_seconds,
        ),
    )
