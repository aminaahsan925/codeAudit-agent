"""Scope enforcement for live website scanning.

A scan is confined to one authorized target: a scheme + host (+ optional
subdomains) + path prefix. The crawler follows only in-scope links; every
out-of-scope URL is skipped and recorded in the result (never fetched).

Scope is syntactic (host/path matching). The SSRF guard still runs on
every fetch — scope and SSRF are independent layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ScanScope:
    """The authorized boundary of one website scan."""

    scheme: str  # "http" or "https"
    host: str  # normalized lowercase host, no port
    port: int  # explicit port (default 443/80 by scheme)
    path_prefix: str  # always starts with "/"
    include_subdomains: bool = False

    def describe(self) -> str:
        sub = " (including subdomains)" if self.include_subdomains else ""
        default_port = 443 if self.scheme == "https" else 80
        port = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}{self.path_prefix}{sub}"

    def origin(self) -> str:
        """Scheme + host + port, for building in-scope probe URLs."""
        return f"{self.scheme}://{self.host}:{self.port}"


def normalize_scope(
    target_url: str,
    *,
    include_subdomains: bool = False,
    path_prefix: str | None = None,
) -> ScanScope:
    """Build the authorized scope from the scan target.

    ``path_prefix`` defaults to the target URL's own path (so scanning
    ``https://example.com/blog/`` stays under ``/blog/``). A custom
    prefix must start with ``/``.
    """
    parts = urlsplit(target_url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        raise ValueError(f"cannot build a scan scope from {target_url!r}")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"invalid port in {target_url!r}") from None
    if port is None:
        port = 443 if scheme == "https" else 80
    prefix = path_prefix if path_prefix is not None else (parts.path or "/")
    if not prefix.startswith("/"):
        raise ValueError(f"path_prefix must start with '/': {prefix!r}")
    return ScanScope(
        scheme=scheme,
        host=host,
        port=port,
        path_prefix=prefix,
        include_subdomains=include_subdomains,
    )


def in_scope(scope: ScanScope, url: str) -> bool:
    """True when ``url`` is inside the authorized scope (syntactic check)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if (parts.scheme or "").lower() != scope.scheme:
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    try:
        port = parts.port
    except ValueError:
        return False
    if port is None:
        port = 443 if scope.scheme == "https" else 80
    if port != scope.port:
        return False
    if host == scope.host:
        host_ok = True
    elif scope.include_subdomains and host.endswith("." + scope.host):
        host_ok = True
    else:
        host_ok = False
    if not host_ok:
        return False
    path = parts.path or "/"
    return path.startswith(scope.path_prefix)
