"""Target authorization model for live website scanning.

A scan is authorized ONLY when BOTH hold:

1. The request supplies ``authorization_token`` matching the token the
   operator configured server-side for the target host
   (``CODEAUDIT_SCAN_TOKENS="host:token,host2:token2"``), compared with
   ``hmac.compare_digest``.
2. The request sets ``i_authorize_this_scan: true`` — an explicit,
   per-request confirmation that the caller has permission to test the
   target (e.g. they own it or have written authorization).

Anything else → ScanAuthorizationError (HTTP 403). There is no default
allow: with no tokens configured, every scan is refused.

Tokens are secrets: they are never logged, never echoed in errors, and
never included in results.
"""

from __future__ import annotations

import hmac
from urllib.parse import urlsplit

from .errors import ScanAuthorizationError


def parse_scan_tokens(raw: str) -> dict[str, str]:
    """Parse ``CODEAUDIT_SCAN_TOKENS`` into {host: token}.

    Format: ``"example.com:tok123,shop.example.com:tok456"``. Hosts are
    lowercased; surrounding whitespace is ignored; empty entries are
    skipped. Malformed entries (no colon) are ignored rather than
    half-parsed — a token that cannot be parsed cannot authorize.
    """
    tokens: dict[str, str] = {}
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        host, _, token = entry.partition(":")
        host = host.strip().lower()
        token = token.strip()
        if host and token:
            tokens[host] = token
    return tokens


def _target_host(target_url: str) -> str:
    try:
        host = urlsplit(target_url).hostname or ""
    except ValueError:
        host = ""
    return host.lower()


def verify_scan_authorization(
    target_url: str,
    authorization_token: str,
    i_authorize_this_scan: bool,
    configured_tokens: dict[str, str],
) -> str:
    """Verify a live-scan request is authorized.

    Returns the normalized target host on success. Raises
    ScanAuthorizationError on any failure. Error messages never reveal
    whether a host has a token configured (no oracle for attackers).
    """
    if not i_authorize_this_scan:
        raise ScanAuthorizationError(
            "Live website scanning requires explicit authorization: set "
            "'i_authorize_this_scan' to true to confirm you are permitted "
            "to test this target."
        )
    host = _target_host(target_url)
    expected = configured_tokens.get(host) if host else None
    # Constant-time compare against "" when unconfigured so the failure
    # message and timing don't reveal whether the host is enrolled.
    if not hmac.compare_digest(authorization_token or "", expected or ""):
        raise ScanAuthorizationError(
            "Scan not authorized for this target: the authorization token "
            "is missing, invalid, or no token is configured for the "
            "target host."
        )
    return host
