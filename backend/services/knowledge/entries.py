"""Curated knowledge entries for CodeAudit findings.

The knowledge base (KB) is hand-written remediation guidance stored as JSON
under ``backend/data/knowledge/``. It is KNOWLEDGE-ONLY: entries enrich AI
explanations and fix proposals, but they never determine whether a finding
exists. Detectors and the evidence-validator hard gate remain the sole
source of truth.

Loading is lazy and cached; entry order is deterministic (sorted by id).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_KB_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "knowledge"


@dataclass(frozen=True)
class KnowledgeEntry:
    """One curated guidance entry."""

    id: str
    title: str
    body: str
    rule_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    source: str = "curated"
    version: str = ""


@dataclass(frozen=True)
class KnowledgeBase:
    """Loaded KB: versioned, deterministically ordered entries."""

    version: str
    entries: tuple[KnowledgeEntry, ...] = field(default_factory=tuple)

    def by_id(self, entry_id: str) -> KnowledgeEntry | None:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None


_cache: KnowledgeBase | None = None


def _load_file(path: Path) -> KnowledgeBase | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Knowledge base: cannot read %s (%s)", path, exc)
        return None
    entries: list[KnowledgeEntry] = []
    for item in raw.get("entries", []):
        try:
            entries.append(
                KnowledgeEntry(
                    id=str(item["id"]),
                    title=str(item.get("title", "")),
                    body=str(item.get("body", "")),
                    rule_ids=tuple(item.get("rule_ids", ())),
                    cwe_ids=tuple(item.get("cwe_ids", ())),
                    languages=tuple(item.get("languages", ())),
                    source=str(item.get("source", "curated")),
                    version=str(item.get("version", "")),
                )
            )
        except (KeyError, TypeError) as exc:
            logger.warning("Knowledge base: skipping malformed entry (%s)", exc)
    entries.sort(key=lambda e: e.id)
    return KnowledgeBase(
        version=str(raw.get("version", path.stem)),
        entries=tuple(entries),
    )


def load_knowledge_base(directory: Path | None = None) -> KnowledgeBase:
    """Load (and cache) the curated KB. Empty base on any load failure."""
    global _cache
    if _cache is not None and directory is None:
        return _cache
    kb_dir = directory or _KB_DIR
    merged: list[KnowledgeEntry] = []
    version = "empty"
    if kb_dir.is_dir():
        for path in sorted(kb_dir.glob("*.json")):
            base = _load_file(path)
            if base is None:
                continue
            version = base.version
            merged.extend(base.entries)
    # Deterministic: sort by id, first occurrence wins on duplicates.
    seen: set[str] = set()
    ordered: list[KnowledgeEntry] = []
    for entry in sorted(merged, key=lambda e: e.id):
        if entry.id not in seen:
            seen.add(entry.id)
            ordered.append(entry)
    base = KnowledgeBase(version=version, entries=tuple(ordered))
    if directory is None:
        _cache = base
    return base


def reset_cache() -> None:
    """Test hook: drop the cached KB so a fresh load happens next call."""
    global _cache
    _cache = None


__all__ = [
    "KnowledgeBase",
    "KnowledgeEntry",
    "load_knowledge_base",
    "reset_cache",
]
