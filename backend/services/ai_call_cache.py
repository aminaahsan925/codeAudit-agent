"""Request-scoped AI call cache (Phase 3 upgrade).

Within one analysis or remediation run, identical model contexts must never
be sent to Nebius twice: every paid call is checked against this cache
first. The cache key is a SHA-256 over:

    repository identifier + sorted finding ids + context hash + prompt version

Only hashes are stored as keys — never source code — and values are the
provider's structured results. The cache lives for exactly one run
(request-scoped, in-memory); nothing is persisted.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_cache_key(
    repo_id: str,
    finding_ids: list[str],
    context_text: str,
    prompt_version: str,
) -> str:
    """Deterministic cache key for one would-be model call."""
    canonical = "\n".join(
        [
            repo_id,
            ",".join(sorted(finding_ids)),
            _sha256_hex(context_text),
            prompt_version,
        ]
    )
    return _sha256_hex(canonical)


class AICallCache:
    """In-memory, request-scoped cache for provider results. Thread-safe."""

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        with self._lock:
            value = self._store.get(key)
        if value is None:
            self.misses += 1
        else:
            self.hits += 1
        return value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = value

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


__all__ = ["AICallCache", "make_cache_key"]
