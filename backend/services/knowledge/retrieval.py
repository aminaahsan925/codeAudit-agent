"""Deterministic TF-IDF retrieval over the curated knowledge base.

Ranking is tag-first, then text similarity:

    1. entries tagged with the finding's ``rule_id`` (exact rule guidance)
    2. entries sharing a CWE id with the finding
    3. entries matching the finding's language, ranked by TF-IDF text score

Pure text similarity with no tag or language overlap never qualifies: it is
too weak a signal, and irrelevant "guidance" would mislead the model. When
nothing qualifies, no knowledge section is emitted — never padded.

Within each tier, TF-IDF cosine similarity breaks ties, then entry id —
fully deterministic. Hard caps bound how much knowledge ever reaches the
model: max chunks per finding and max total characters (from Settings).

Hard boundaries:
  * Retrieval is KNOWLEDGE-ONLY. It never creates, suppresses, or modifies
    findings; callers only attach guidance text + citations.
  * Sensitive findings (secret material) get NO retrieval at all: nothing
    about them may flow into AI context, per the Phase 4 guarantee.
  * No network, no embeddings service: pure stdlib TF-IDF over the local KB.

Runs in every agent mode (including free) — it is deterministic and makes
no AI call.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from app.config import Settings, settings
from models.schemas import Finding
from services.knowledge.entries import KnowledgeBase, KnowledgeEntry, load_knowledge_base

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Common English stopwords kept minimal so security vocabulary survives.
_STOPWORDS = frozenset(
    "a an the and or of to in for on with is are was were be been by as at "
    "from that this it its into not no do does did will would can could "
    "should have has had you your we our they their he she him her them "
    "but if then than so such only also when which who what where how why "
    "all any each more most other some any than too very".split()
)


def _tokenize(text: str) -> list[str]:
    return [
        tok
        for tok in _TOKEN_RE.findall(text.lower())
        if tok not in _STOPWORDS and len(tok) > 1
    ]


@dataclass
class KnowledgeHit:
    """One retrieved entry, with how it matched and a bounded excerpt."""

    entry: KnowledgeEntry
    score: float
    matched_on: str  # "rule" | "cwe" | "language" | "text"
    excerpt: str  # bounded slice of the entry body


@dataclass
class _Index:
    """Precomputed TF-IDF vectors for the KB (built once per KB version)."""

    base: KnowledgeBase
    idf: dict[str, float] = field(default_factory=dict)
    vectors: dict[str, dict[str, float]] = field(default_factory=dict)
    norms: dict[str, float] = field(default_factory=dict)

    @classmethod
    def build(cls, base: KnowledgeBase) -> "_Index":
        doc_tokens: dict[str, list[str]] = {}
        df: Counter[str] = Counter()
        for entry in base.entries:
            toks = _tokenize(f"{entry.title} {entry.body}")
            doc_tokens[entry.id] = toks
            df.update(set(toks))
        n = max(1, len(base.entries))
        idf = {tok: math.log(1 + n / (1 + count)) for tok, count in df.items()}
        vectors: dict[str, dict[str, float]] = {}
        norms: dict[str, float] = {}
        for entry_id, toks in doc_tokens.items():
            tf = Counter(toks)
            vec = {tok: (1 + math.log(c)) * idf[tok] for tok, c in tf.items()}
            vectors[entry_id] = vec
            norms[entry_id] = math.sqrt(sum(v * v for v in vec.values()))
        return cls(base=base, idf=idf, vectors=vectors, norms=norms)

    def score(self, entry_id: str, query_vec: dict[str, float], query_norm: float) -> float:
        vec = self.vectors.get(entry_id, {})
        denom = self.norms.get(entry_id, 0.0) * query_norm
        if not vec or denom == 0.0:
            return 0.0
        dot = sum(vec.get(tok, 0.0) * w for tok, w in query_vec.items())
        return dot / denom


_index_cache: _Index | None = None
_index_version: str | None = None


def _get_index(base: KnowledgeBase | None = None) -> _Index:
    global _index_cache, _index_version
    kb = base or load_knowledge_base()
    if _index_cache is None or _index_version != kb.version:
        _index_cache = _Index.build(kb)
        _index_version = kb.version
    return _index_cache


def _query_text(finding: Finding) -> str:
    return f"{finding.title} {finding.description} {finding.detector}".replace("_", " ")


def _excerpt(entry: KnowledgeEntry, max_chars: int) -> str:
    body = entry.body.strip()
    if len(body) <= max_chars:
        return body
    cut = body.rfind(" ", 0, max_chars)
    cut = cut if cut > 0 else max_chars
    return body[:cut].rstrip() + " …"


def retrieve_for_finding(
    finding: Finding,
    cfg: Settings | None = None,
    base: KnowledgeBase | None = None,
) -> list[KnowledgeHit]:
    """Retrieve bounded guidance for one finding. Empty for sensitive findings.

    Tag tier (rule -> cwe -> language) outranks text similarity; inside a
    tier, TF-IDF cosine then entry id decide. Returns at most
    ``kb_max_chunks_per_finding`` hits totalling at most ``kb_max_chars``.
    """
    cfg = cfg or settings
    # Phase 4 guarantee: secret material never flows toward AI context.
    if finding.sensitive:
        return []
    kb = base or load_knowledge_base()
    if not kb.entries:
        return []
    index = _get_index(kb)

    max_chunks = max(1, cfg.kb_max_chunks_per_finding)
    max_chars = max(256, cfg.kb_max_chars)

    query_toks = _tokenize(_query_text(finding))
    query_tf = Counter(query_toks)
    query_vec = {
        tok: (1 + math.log(c)) * index.idf.get(tok, 0.0)
        for tok, c in query_tf.items()
        if tok in index.idf
    }
    query_norm = math.sqrt(sum(w * w for w in query_vec.values()))

    finding_cwes = {c.upper() for c in (finding.cwe_ids or [])}
    finding_lang = (finding.language or "").lower()

    def tier(entry: KnowledgeEntry) -> int:
        if finding.rule_id and finding.rule_id in entry.rule_ids:
            return 0
        if finding_cwes and {c.upper() for c in entry.cwe_ids} & finding_cwes:
            return 1
        if finding_lang and finding_lang in {l.lower() for l in entry.languages}:
            return 2
        return 3

    ranked = sorted(
        kb.entries,
        key=lambda e: (
            tier(e),
            -index.score(e.id, query_vec, query_norm),
            e.id,
        ),
    )

    # Tier 0 (exact rule match) always qualifies; tier 1 (CWE) is a curated
    # mapping and qualifies too. Tiers 2/3 need a real text signal so
    # unrelated entries are not padded in — and tier 3 (no rule, no CWE,
    # no language overlap) is dropped outright: pure text similarity is too
    # weak a signal to attach guidance to an untagged finding, and showing
    # irrelevant "knowledge" would mislead the model. When nothing
    # qualifies, the knowledge section is omitted, never padded.
    hits: list[KnowledgeHit] = []
    chars_used = 0
    for entry in ranked:
        t = tier(entry)
        if t >= 3:
            continue
        score = index.score(entry.id, query_vec, query_norm)
        if t > 1 and score <= 0.0:
            continue
        matched_on = ("rule", "cwe", "language")[t]
        excerpt = _excerpt(entry, max_chars - chars_used)
        # Keep at least a stub of the entry so citations stay meaningful.
        if len(excerpt) < 64 and hits:
            break
        hits.append(
            KnowledgeHit(
                entry=entry, score=score, matched_on=matched_on, excerpt=excerpt
            )
        )
        chars_used += len(excerpt)
        if len(hits) >= max_chunks or chars_used >= max_chars:
            break
    return hits


def format_knowledge_block(hits: list[KnowledgeHit]) -> str:
    """Render hits as a labeled guidance block for a model prompt."""
    lines = [
        "CURATED REMEDIATION KNOWLEDGE (guidance only — NOT evidence).",
        "These entries describe how to fix the issue class. They do NOT",
        "establish that the finding is real; the evidence above does that.",
        "When your reasoning or fix relies on an entry, cite its id",
        "(e.g. [KB-PY-SEC-002]). Never invent entry ids.",
    ]
    for hit in hits:
        lines.append(f"\n[{hit.entry.id}] {hit.entry.title}")
        lines.append(hit.excerpt)
    return "\n".join(lines)


def reset_index_cache() -> None:
    """Test hook: drop the cached TF-IDF index."""
    global _index_cache, _index_version
    _index_cache = None
    _index_version = None


__all__ = [
    "KnowledgeHit",
    "format_knowledge_block",
    "reset_index_cache",
    "retrieve_for_finding",
]
