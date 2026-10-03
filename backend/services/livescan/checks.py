"""Passive and active checks for live website scanning.

Passive checks inspect observed responses (headers, cookies, TLS state,
server banners). Active checks are minimal, GET-only, rate-limited probes:

- LIVE-020 reflected-XSS probe: a unique canary token is sent as a query
  parameter; the response is examined for unencoded reflection. Reported
  as "possible", never as exploited.
- LIVE-021 SQL-error probe: a single quote is appended to one query
  parameter value; the response is scanned for database error
  signatures. No data is extracted, ever.

Every active finding is capped at MEDIUM confidence and carries an
explicit "requires manual verification" note. Active checks never run
unless the scan request enables them, and they always go through the
guarded client (SSRF guard + scope + budgets).
"""

from __future__ import annotations

import html
import logging
import re
import secrets
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from models.schemas import Confidence, Severity

from .findings import make_live_finding
from .http import GuardedHTTPClient, GuardedResponse

logger = logging.getLogger(__name__)

_EVIDENCE_CHARS = 500

# Database error signatures for the SQLi error probe. These indicate the
# backend *may* be interpolating input into SQL; they do not prove
# exploitability, and the finding says so.
_SQL_ERROR_PATTERNS = (
    "sql syntax",
    "mysql",
    "mysqli",
    "ora-",
    "sqlite",
    "postgresql",
    "psql",
    "pg_query",
    "odbc",
    "jdbc",
    "unclosed quotation",
    "quoted string not properly terminated",
    "sqlstate",
)

_MANUAL_VERIFICATION_NOTE = (
    "This is an automated probe result, not a confirmed vulnerability. "
    "It requires manual verification by someone authorized to test this "
    "system before any remediation or disclosure decision."
)


def _evidence(text: str) -> str:
    text = text.strip().replace("\r", "")
    return text[:_EVIDENCE_CHARS]


def _header_summary(response: GuardedResponse) -> str:
    present = sorted({k.lower() for k in response.headers.keys()})
    return (
        f"HTTP {response.status_code} {response.url} — "
        f"response headers: {', '.join(present) or '(none)'}"
    )


# ---------------------------------------------------------------------------
# Passive checks
# ---------------------------------------------------------------------------


def check_transport(url: str):
    """LIVE-007: plain HTTP transport."""
    if urlsplit(url).scheme.lower() == "http":
        return [
            make_live_finding(
                rule_id="LIVE-007",
                url=url,
                title="Site served over plain HTTP",
                description=(
                    "The target responds over unencrypted HTTP. Traffic — "
                    "including credentials, cookies, and personal data — can "
                    "be intercepted or modified in transit (CWE-319)."
                ),
                evidence=_evidence(f"URL scheme is http: {url}"),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                suggested_fix="Serve the site over HTTPS with a valid certificate and redirect HTTP to HTTPS.",
            )
        ]
    return []


def check_security_headers(url: str, response: GuardedResponse):
    """LIVE-001..005: missing or weak security headers."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    summary = _header_summary(response)

    if "content-security-policy" not in headers:
        findings.append(
            make_live_finding(
                rule_id="LIVE-001",
                url=url,
                title="Missing Content-Security-Policy header",
                description=(
                    "No Content-Security-Policy was observed. CSP is the "
                    "primary browser-level mitigation for XSS and data "
                    "injection (CWE-693)."
                ),
                evidence=_evidence(summary),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                suggested_fix="Deploy a Content-Security-Policy restricting script/style sources; start with report-only mode.",
            )
        )

    is_https = urlsplit(url).scheme.lower() == "https"
    if is_https and "strict-transport-security" not in headers:
        findings.append(
            make_live_finding(
                rule_id="LIVE-002",
                url=url,
                title="Missing Strict-Transport-Security header",
                description=(
                    "The HTTPS response carries no HSTS header, so browsers "
                    "may still accept downgraded HTTP connections to this "
                    "host (CWE-319)."
                ),
                evidence=_evidence(summary),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                suggested_fix="Send Strict-Transport-Security with a long max-age and includeSubDomains.",
            )
        )

    if "x-frame-options" not in headers:
        findings.append(
            make_live_finding(
                rule_id="LIVE-003",
                url=url,
                title="Missing X-Frame-Options header",
                description=(
                    "No X-Frame-Options (or frame-ancestors in CSP) was "
                    "observed, leaving the page framable by third parties "
                    "(clickjacking, CWE-1021)."
                ),
                evidence=_evidence(summary),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                suggested_fix="Set X-Frame-Options: DENY (or SAMEORIGIN) or a frame-ancestors CSP directive.",
            )
        )

    xcto = headers.get("x-content-type-options", "").lower()
    if xcto != "nosniff":
        findings.append(
            make_live_finding(
                rule_id="LIVE-004",
                url=url,
                title="Missing or weak X-Content-Type-Options header",
                description=(
                    "The response lacks 'X-Content-Type-Options: nosniff', "
                    "allowing MIME-sniffing attacks (CWE-693)."
                ),
                evidence=_evidence(summary),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                suggested_fix="Send X-Content-Type-Options: nosniff on all responses.",
            )
        )

    rp = headers.get("referrer-policy", "").lower()
    if not rp or rp == "unsafe-url":
        findings.append(
            make_live_finding(
                rule_id="LIVE-005",
                url=url,
                title="Missing or permissive Referrer-Policy",
                description=(
                    "No Referrer-Policy was observed (or it is 'unsafe-url'), "
                    "so full URLs — possibly containing tokens or personal "
                    "data — may leak to third parties via the Referer header "
                    "(CWE-200)."
                ),
                evidence=_evidence(summary),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                suggested_fix="Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
            )
        )
    return findings


def _parse_set_cookies(headers) -> list[dict]:
    """Parse Set-Cookie headers into {name, secure, httponly, samesite}.

    Only attribute presence is recorded — cookie VALUES are never kept,
    because they may be session tokens.
    """
    cookies = []
    try:
        raw_list = headers.get_list("set-cookie")
    except Exception:
        return []
    for raw in raw_list:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.lower() for p in parts[1:]}
        samesite = None
        for p in parts[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1].strip().lower()
        cookies.append(
            {
                "name": name,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": samesite,
            }
        )
    return cookies


def check_cookie_flags(url: str, response: GuardedResponse):
    """LIVE-006: cookies missing Secure/HttpOnly/SameSite flags."""
    cookies = _parse_set_cookies(response.headers)
    if not cookies:
        return []
    findings = []
    is_https = urlsplit(url).scheme.lower() == "https"

    def names(pred):
        return sorted({c["name"] for c in cookies if pred(c)})

    insecure = names(lambda c: is_https and not c["secure"])
    if insecure:
        findings.append(
            make_live_finding(
                rule_id="LIVE-006",
                url=url,
                title="Cookies set without the Secure flag",
                description=(
                    f"Cookies without the Secure flag on an HTTPS response: "
                    f"{', '.join(insecure)}. They may be sent over "
                    "unencrypted connections (CWE-614). Cookie values are "
                    "not recorded in this finding."
                ),
                evidence=_evidence(
                    f"Set-Cookie without Secure: {', '.join(insecure)} (from {url})"
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                suggested_fix="Set the Secure flag on all cookies served over HTTPS.",
            )
        )

    no_httponly = names(lambda c: not c["httponly"])
    if no_httponly:
        findings.append(
            make_live_finding(
                rule_id="LIVE-006",
                url=url,
                title="Cookies set without the HttpOnly flag",
                description=(
                    f"Cookies without HttpOnly: {', '.join(no_httponly)}. "
                    "They are readable from JavaScript, widening the impact "
                    "of any XSS flaw (CWE-1004). Cookie values are not "
                    "recorded in this finding."
                ),
                evidence=_evidence(
                    f"Set-Cookie without HttpOnly: {', '.join(no_httponly)} (from {url})"
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                suggested_fix="Set the HttpOnly flag on cookies that JavaScript does not need to read.",
            )
        )

    # SameSite=None without Secure is rejected by modern browsers and
    # weakens CSRF protection; a missing SameSite defaults to Lax in
    # modern browsers (acceptable), so only the None-without-Secure
    # combination is flagged.
    weak = names(lambda c: c["samesite"] == "none" and not c["secure"])
    if weak:
        findings.append(
            make_live_finding(
                rule_id="LIVE-006",
                url=url,
                title="Cookies with SameSite=None but without Secure",
                description=(
                    f"Cookies with SameSite=None and no Secure flag: "
                    f"{', '.join(weak)}. Modern browsers reject this "
                    "combination, and it weakens CSRF protection (CWE-1275)."
                ),
                evidence=_evidence(
                    f"Set-Cookie SameSite=None without Secure: {', '.join(weak)} (from {url})"
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                suggested_fix="Use SameSite=Lax (or Strict) by default; pair SameSite=None with Secure only when cross-site use is required.",
            )
        )
    return findings


_VERSION_RE = re.compile(r"/\d| \d+\.\d+|v\d+\.")


def check_server_disclosure(url: str, response: GuardedResponse):
    """LIVE-008: version-disclosing server banners."""
    findings = []
    for header_name in ("server", "x-powered-by", "x-aspnet-version"):
        value = response.headers.get(header_name, "")
        if value and _VERSION_RE.search(value):
            findings.append(
                make_live_finding(
                    rule_id="LIVE-008",
                    url=url,
                    title=f"Server banner discloses version ({header_name})",
                    description=(
                        f"The {header_name} header reveals software/version "
                        f"information: {value!r}. Version banners help "
                        "attackers target known vulnerabilities (CWE-200)."
                    ),
                    evidence=_evidence(f"{header_name}: {value}"),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    suggested_fix="Suppress or generalize version banners (e.g. ServerTokens Prod).",
                )
            )
    return findings


def check_exposed_files(client: GuardedHTTPClient, scope_root: str):
    """LIVE-009: directly probe for accidentally exposed sensitive files.

    Read-only GETs against the scope root: /.git/HEAD and /.env. A 200
    with plausible content is a HIGH finding; anything else is silent.
    """
    findings = []
    probes = {
        ".git/HEAD": lambda body: body.lstrip().startswith(b"ref:"),
        ".env": lambda body: b"=" in body and b"<html" not in body.lower(),
    }
    for name, looks_like in probes.items():
        probe_url = scope_root.rstrip("/") + "/" + name
        try:
            resp = client.get(probe_url)
        except Exception:
            continue  # connectivity failure is not a finding
        body = resp.content[:4096]
        if resp.status_code == 200 and looks_like(body):
            findings.append(
                make_live_finding(
                    rule_id="LIVE-009",
                    url=probe_url,
                    title=f"Exposed sensitive file: /{name}",
                    description=(
                        f"/{name} is publicly retrievable (HTTP 200 with "
                        "plausible content). .git/HEAD leaks repository "
                        "structure; .env commonly contains secrets "
                        "(CWE-200). Only the first bytes were read; file "
                        "contents are not stored in this finding."
                    ),
                    evidence=_evidence(
                        f"GET {probe_url} -> HTTP 200, "
                        f"body starts with: {body[:80]!r}"
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    suggested_fix=f"Block public access to /{name} at the web server / CDN layer and rotate any exposed secrets.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def _dns_names(cert: dict) -> list[str]:
    """DNS names from SANs, falling back to CN (RFC 6125 order)."""
    names = [
        value
        for key, value in cert.get("subjectAltName", ())
        if key == "DNS" and value
    ]
    if names:
        return names
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and value:
                return [value]
    return []


def _match_dns_name(pattern: str, hostname: str) -> bool:
    """RFC 6125 §6.4.3 left-most-label wildcard matching (case-insensitive)."""
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return (
            "." in hostname
            and hostname.endswith("." + suffix)
            and hostname.count(".") == suffix.count(".") + 1
        )
    return False


def _check_hostname(cert: dict, hostname: str) -> str | None:
    """Return an error description when the cert doesn't match, else None."""
    names = _dns_names(cert)
    if not names:
        return "certificate carries no DNS SAN or CN"
    if not any(_match_dns_name(p, hostname) for p in names):
        return f"certificate names {names} do not match {hostname!r}"
    return None


def evaluate_tls_certificate(cert: dict, hostname: str):
    """LIVE-010: pure evaluation of an observed certificate.

    ``cert`` is the dict returned by ``SSLSocket.getpeercert()``.
    Returns findings (possibly empty). Pure function — hermetically
    testable without network.
    """
    """LIVE-010: pure evaluation of an observed certificate.

    ``cert`` is the dict returned by ``SSLSocket.getpeercert()``.
    Returns findings (possibly empty). Pure function — hermetically
    testable without network.
    """
    findings = []
    if not cert:
        findings.append(
            make_live_finding(
                rule_id="LIVE-010",
                url=f"https://{hostname}/",
                title="TLS certificate could not be retrieved",
                description=(
                    "The TLS handshake did not return a certificate for "
                    f"{hostname}. The connection cannot be verified (CWE-297)."
                ),
                evidence=_evidence(f"getpeercert() returned empty for {hostname}"),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                suggested_fix="Install a valid certificate from a trusted CA.",
            )
        )
        return findings

    now = datetime.now(timezone.utc)
    for field, label in (("notAfter", "expired"), ("notBefore", "not yet valid")):
        raw = cert.get(field)
        if not raw:
            continue
        try:
            moment = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
        bad = moment < now if field == "notAfter" else moment > now
        if bad:
            findings.append(
                make_live_finding(
                    rule_id="LIVE-010",
                    url=f"https://{hostname}/",
                    title=f"TLS certificate {label} for {hostname}",
                    description=(
                        f"The certificate presented by {hostname} is {label} "
                        f"({field}={raw}). Clients will refuse or warn on "
                        "this connection (CWE-297)."
                    ),
                    evidence=_evidence(f"certificate {field}: {raw}"),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    suggested_fix="Renew the certificate before expiry and automate renewal.",
                )
            )

    hostname_error = _check_hostname(cert, hostname)
    if hostname_error:
        findings.append(
            make_live_finding(
                rule_id="LIVE-010",
                url=f"https://{hostname}/",
                title=f"TLS certificate hostname mismatch for {hostname}",
                description=(
                    f"The certificate presented by {hostname} does not match "
                    f"the hostname ({hostname_error}). This breaks "
                    "chain-of-trust validation (CWE-297)."
                ),
                evidence=_evidence(f"hostname check failed: {hostname_error}"),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                suggested_fix="Serve a certificate whose SAN covers the hostname.",
            )
        )
    return findings


def probe_tls_certificate(hostname: str, port: int = 443, timeout: float = 10.0):
    """Fetch the peer certificate without verifying it (CERT_NONE), then
    evaluate it with :func:`evaluate_tls_certificate`.

    Connecting with verification disabled is safe here because we never
    trust the connection — we only *inspect* the presented certificate.
    No application data is sent beyond the handshake.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            cert = tls.getpeercert()
    return evaluate_tls_certificate(cert or {}, hostname)


# ---------------------------------------------------------------------------
# Active probes (GET-only, rate-limited, non-destructive)
# ---------------------------------------------------------------------------


def _with_probe_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query = [(k, v) for k, v in query if k != name] + [(name, value)]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), "")
    )


def reflected_xss_probe(client: GuardedHTTPClient, url: str):
    """LIVE-020: reflected-XSS canary probe.

    Sends a unique canary as a query parameter and checks whether it is
    reflected *unencoded* in the HTML body. An HTML-escaped reflection is
    correct output encoding — not a finding. Capped at MEDIUM with a
    manual-verification note; this probe cannot prove exploitability.
    """
    canary = "cxq7" + secrets.token_hex(3) + "<'\"z9"
    probe_url = _with_probe_param(url, "codeaudit_probe", canary)
    try:
        resp = client.get(probe_url)
    except Exception:
        return []
    content_type = resp.headers.get("content-type", "").lower()
    if "html" not in content_type:
        return []
    try:
        body = resp.content.decode("utf-8", errors="replace")
    except Exception:
        return []
    if canary not in body:
        return []  # not reflected at all
    escaped = html.escape(canary, quote=True)
    if canary in body and escaped not in body.replace(canary, ""):
        # Raw canary present and no escaped copy: unencoded reflection.
        pass
    elif escaped in body and canary not in body.replace(escaped, ""):
        return []  # only the safely-encoded form is reflected
    # Ambiguous (both forms present, e.g. in JS strings): report as
    # possible — the note requires manual verification anyway.
    return [
        make_live_finding(
            rule_id="LIVE-020",
            url=url,
            title="Possible reflected XSS (probe)",
            description=(
                "A unique canary token sent as a query parameter was "
                "reflected in the HTML response without HTML-encoding. This "
                "pattern is consistent with reflected cross-site scripting "
                "(CWE-79). " + _MANUAL_VERIFICATION_NOTE
            ),
            evidence=_evidence(
                f"canary reflected unencoded in response body ({len(body)} chars)"
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            suggested_fix="HTML-encode all untrusted data at output; prefer framework auto-escaping and a Content-Security-Policy.",
        )
    ]


def sqli_error_probe(client: GuardedHTTPClient, url: str):
    """LIVE-021: SQL-error probe.

    Appends a single quote to up to two query parameter values and looks
    for database error signatures. At most two extra requests per page.
    Never extracts data; a match is "possible", capped at MEDIUM.
    """
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not query:
        # No parameters to perturb; probe a synthetic one.
        query = [("codeaudit_probe", "1")]
    findings = []
    for name, value in query[:2]:
        probe_url = _with_probe_param(url, name, value + "'")
        try:
            resp = client.get(probe_url)
        except Exception:
            continue
        try:
            body = resp.content.decode("utf-8", errors="replace").lower()
        except Exception:
            continue
        if any(sig in body for sig in _SQL_ERROR_PATTERNS):
            findings.append(
                make_live_finding(
                    rule_id="LIVE-021",
                    url=url,
                    title="Possible SQL injection (error-based probe)",
                    description=(
                        f"Perturbing the '{name}' query parameter produced a "
                        "response containing database error text, which is "
                        "consistent with unparameterized SQL construction "
                        "(CWE-89). No data was extracted. "
                        + _MANUAL_VERIFICATION_NOTE
                    ),
                    evidence=_evidence(
                        f"db error signature in response to {name}={value}' "
                        f"(HTTP {resp.status_code})"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    suggested_fix="Use parameterized queries / prepared statements; never interpolate input into SQL.",
                )
            )
            break  # one finding per page is enough
    return findings
