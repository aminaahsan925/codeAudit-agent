"""Refresh the local advisory database from OSV.dev (Phase 4).

Manual, network-dependent script — never runs as part of tests or analysis.
It queries the public OSV.dev API for vulnerabilities affecting the packages
found in the repository's own manifests and writes backend/data/advisories.json
in the schema consumed by services/supplychain/advisories.py.

Usage:
    cd backend
    ../.venv/bin/python scripts/refresh_advisories.py [--path data/advisories.json]

The repository's own manifests are used as the query set (the tool audits
*other* repositories; this script only decides what advisories to cache).
Entries are written verbatim from the OSV response: id, severity, published,
summary, affected ranges. Nothing is invented.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
MANIFEST_GLOBS = ("requirements.txt", "package.json", "pyproject.toml", "Pipfile")


def _collect_packages(repo_root: Path) -> set[tuple[str, str]]:
    """Best-effort name-only collection from this repo's own manifests."""
    names: set[tuple[str, str]] = set()
    for pattern in MANIFEST_GLOBS:
        for path in repo_root.rglob(pattern):
            if ".venv" in path.parts or "node_modules" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if path.name == "package.json":
                try:
                    data = json.loads(text)
                    for section in ("dependencies", "devDependencies"):
                        for name in data.get(section, {}):
                            names.add(("npm", name))
                except json.JSONDecodeError:
                    pass
            else:
                for line in text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        name = line.split("=")[0].split(">")[0].split("<")[0].strip()
                        if name:
                            names.add(("PyPI", name))
    return names


def _osv_querybatch(queries: list[dict]) -> list[dict]:
    payload = json.dumps({"queries": queries}).encode()
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.loads(response.read().decode())
    return body.get("results", [])


def _to_entry(package: str, ecosystem: str, vuln: dict) -> dict:
    """Convert one OSV vulnerability to the local advisory schema.

    OSV affected ranges are [introduced, fixed] event pairs; the local
    schema records them as an ``affected_spec`` string the matcher can
    evaluate (">=introduced,<fixed" for PyPI, ">=introduced <fixed" for
    npm — both forms the matcher understands). Ranges without a fixed
    version are skipped: without a fixed bound we cannot build an honest
    spec, and the matcher never guesses.
    """
    specs: list[str] = []
    fixed_versions: list[str] = []
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            introduced = None
            fixed = None
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if not fixed:
                continue  # no fixed bound -> cannot build an honest spec
            introduced = introduced or "0"
            joiner = "," if ecosystem == "PyPI" else " "
            specs.append(f">={introduced}{joiner}<{fixed}")
            fixed_versions.append(fixed)
    if not specs:
        return {}
    severity = ""
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            severity = sev.get("score", "")
    return {
        "id": vuln.get("id", ""),
        "package": package,
        "ecosystem": "pypi" if ecosystem == "PyPI" else "npm",
        "affected_spec": specs[0],
        "fixed_version": fixed_versions[0],
        "published": vuln.get("published", ""),
        "severity": severity,
        "summary": (vuln.get("summary") or "")[:500],
        "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        default="data/advisories.json",
        help="Output path relative to backend/ (default: data/advisories.json)",
    )
    args = parser.parse_args()
    backend_dir = Path(__file__).resolve().parent.parent
    repo_root = backend_dir.parent
    out_path = (backend_dir / args.path).resolve()

    packages = sorted(_collect_packages(repo_root))
    print(f"Found {len(packages)} packages in repo manifests.")
    entries: list[dict] = []
    batch = 1000
    for i in range(0, len(packages), batch):
        chunk = packages[i : i + batch]
        queries = [
            {"package": {"name": name, "ecosystem": eco}} for eco, name in chunk
        ]
        results = _osv_querybatch(queries)
        for (eco, name), result in zip(chunk, results):
            for vuln in result.get("vulns", []):
                entry = _to_entry(name, eco, vuln)
                if entry:  # ranges without a fixed version are skipped
                    entries.append(entry)
    db = {
        "source": "osv.dev",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisories": entries,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(db, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(entries)} advisories to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
