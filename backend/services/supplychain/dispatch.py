"""Supply-chain dispatch: file routing and advisory source.

The full advisory database (OSV/NVD-backed) is a deployment concern and
is not bundled here. This module provides the interface the orchestrator
expects:
- ``get_advisory_source()``: returns the advisory source handle. Without
  a configured database the status is "not_configured" and no
  advisory-backed findings are produced (never fabricated).
- ``analyze_supplychain_file()``: per-file supply-chain findings.
- ``supplychain_covered_files()``: which paths the supply-chain stage
  claims as analyzed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AdvisorySource:
    """Handle to the vulnerability advisory database."""

    status: str = "not_configured"
    generated_at: str | None = None
    entries: dict = field(default_factory=dict)


def get_advisory_source() -> AdvisorySource:
    """Build (or reuse) the advisory source.

    No advisory database is bundled or downloaded by default, so this
    returns a "not_configured" source. Callers must treat that status as
    "advisory checks unavailable", not "no vulnerabilities".
    """
    return AdvisorySource()


def analyze_supplychain_file(
    relative_path: str, content: str, advisory_source: AdvisorySource
) -> list:
    """Supply-chain findings for one file. Empty without an advisory DB."""
    if advisory_source.status != "ready":
        return []
    return []


def supplychain_covered_files(paths: list[str]) -> set[str]:
    """Paths the supply-chain stage claims as analyzed.

    Without manifest/Dockerfile/workflow parsers bundled, nothing is
    claimed — files fall through to the language analyzers honestly.
    """
    return set()
