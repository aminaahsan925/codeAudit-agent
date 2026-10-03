"""Knowledge-only retrieval for CodeAudit agents.

``services/knowledge/entries.py`` loads the curated KB;
``services/knowledge/retrieval.py`` retrieves bounded guidance per finding.
"""

from services.knowledge.entries import (
    KnowledgeBase,
    KnowledgeEntry,
    load_knowledge_base,
    reset_cache,
)
from services.knowledge.retrieval import (
    KnowledgeHit,
    format_knowledge_block,
    reset_index_cache,
    retrieve_for_finding,
)

__all__ = [
    "KnowledgeBase",
    "KnowledgeEntry",
    "KnowledgeHit",
    "format_knowledge_block",
    "load_knowledge_base",
    "reset_cache",
    "reset_index_cache",
    "retrieve_for_finding",
]
