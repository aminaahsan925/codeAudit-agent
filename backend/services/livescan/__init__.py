"""Authorized live website security scanning (Phase 6).

This package is deliberately separate from repository analysis: scanning a
live website makes outbound network requests to someone's infrastructure,
so it has its own authorization model, scope enforcement, and SSRF guard.
The guards are built FIRST (auth.py, scope.py, ssrf.py); the scanner
(scanner.py) cannot make a request without passing through all of them.

Design rules:
- No scan runs without BOTH a per-host authorization token (configured
  server-side, compared with hmac.compare_digest) AND an explicit
  ``i_authorize_this_scan: true`` in the request.
- Every outbound URL passes the SSRF guard (resolve-then-check against
  ipaddress; private/loopback/link-local/multicast/reserved rejected;
  localhost only with explicit opt-in).
- The crawler stays within the authorized host + path prefix.
- Active probes are GET-only, rate-limited, non-destructive, and every
  active finding is capped at MEDIUM confidence with a "requires manual
  verification" note.
- Credentials (scan tokens, session cookies, Authorization headers) are
  never logged.
- A scan NEVER claims the site is secure: the result carries a standard
  disclaimer stating exactly what was covered.
"""
