"""SSRF guard for live website scanning.

``validate_url`` runs BEFORE any network I/O (the scanner calls it first).
It rejects:
- non-http(s) schemes (file://, gopher://, dict://, ...),
- URLs with embedded credentials (user:pass@host),
- unresolvable hosts,
- hosts resolving to non-public IPs (private, loopback, link-local,
  multicast, reserved, unspecified) — unless ``allow_localhost`` permits
  loopback for local development.

DNS is resolved at validation time; the guarded HTTP client re-checks per
connection as defense in depth. Raises :class:`SSRFBlockedError`.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import SSRFBlockedError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GuardedURL:
    """A URL that passed the SSRF guard, with its parsed host attached."""

    url: str
    host: str


def validate_url(url: str, allow_localhost: bool = False) -> GuardedURL:
    """Validate a scan target URL against SSRF. Returns the guarded URL.

    Raises:
        SSRFBlockedError: if the URL is not an acceptable public scan target.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise SSRFBlockedError("Empty scan target URL.")
    try:
        parts = urlsplit(cleaned)
    except ValueError as exc:
        raise SSRFBlockedError(f"Malformed URL: {exc}") from exc

    if parts.scheme.lower() not in ("http", "https"):
        raise SSRFBlockedError(
            f"Only http(s) URLs may be scanned, got scheme {parts.scheme!r}."
        )
    if parts.username or parts.password:
        raise SSRFBlockedError("URLs with embedded credentials are not allowed.")
    host = parts.hostname
    if not host:
        raise SSRFBlockedError("URL has no host.")

    try:
        addr_infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Could not resolve host {host!r}.") from exc

    ips = set()
    for _family, _type, _proto, _canon, sockaddr in addr_infos:
        try:
            ips.add(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not ips:
        raise SSRFBlockedError(f"Could not resolve host {host!r} to an IP address.")

    for ip in ips:
        if ip.is_global:
            continue
        if allow_localhost and ip.is_loopback:
            continue
        raise SSRFBlockedError(
            f"Host {host!r} resolves to non-public IP {ip}; refusing to scan."
        )

    logger.info("SSRF check passed for %s (%d resolved IP(s))", host, len(ips))
    return GuardedURL(url=cleaned, host=host)
