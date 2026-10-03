"""SBOM generation from scanned manifests.

Minimal implementation: reports the repository identity, the advisory
source status, and the manifest files seen. Dependency extraction
requires the manifest parsers; until they land, the SBOM honestly
reports what was (and was not) analyzed.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_MANIFEST_NAMES = (
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "composer.json",
    "Gemfile",
    "Gemfile.lock",
)


def build_sbom_for_scan(
    contents: dict[str, str],
    repository,
    advisory_status: str | None = None,
    advisory_generated_at: str | None = None,
) -> dict:
    """Build a minimal SBOM dict for a scan."""
    manifests = [
        path
        for path in contents
        if path.split("/")[-1] in _MANIFEST_NAMES
    ]
    repo_name = getattr(repository, "full_name", None) or getattr(
        repository, "name", ""
    )
    return {
        "sbom_version": "codeaudit-minimal-1",
        "repository": repo_name,
        "manifests_seen": sorted(manifests),
        "packages": [],
        "advisory_status": advisory_status or "not_configured",
        "advisory_generated_at": advisory_generated_at,
        "note": (
            "Dependency extraction not yet implemented; "
            "packages list is empty by design, not by analysis."
        ),
    }
