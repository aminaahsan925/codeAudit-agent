"""Language analyzer registry: single source of truth for deep analysis.

The registry is built from utils.constants.DEEP_ANALYSIS_LANGUAGES, so the
declarative language set and the available analyzers cannot drift apart: a
language listed there gets an analyzer here, and supports_deep_analysis()
simply asks whether the registry has one. Languages without an analyzer
stay recognized (for future parsers) but unsupported.
"""

from __future__ import annotations

from services.languages.base import LanguageAnalyzer
from services.languages.javascript_analyzer import JavaScriptAnalyzer
from services.languages.python_analyzer import PythonAnalyzer
from utils.constants import DEEP_ANALYSIS_LANGUAGES


def _build_registry() -> dict[str, LanguageAnalyzer]:
    registry: dict[str, LanguageAnalyzer] = {}
    for language in DEEP_ANALYSIS_LANGUAGES:
        if language == "python":
            registry[language] = PythonAnalyzer()
        elif language in ("javascript", "typescript"):
            # One analyzer class, instantiated per language so each instance
            # selects the right tree-sitter grammar.
            registry[language] = JavaScriptAnalyzer(language)
        # else: recognized but no analyzer yet -> remains unsupported
    return registry


_REGISTRY: dict[str, LanguageAnalyzer] = _build_registry()


def get_analyzer(language: str | None) -> LanguageAnalyzer | None:
    """The deep-analysis plugin for a language, or None if unsupported."""
    if not language:
        return None
    return _REGISTRY.get(language)


def supported_languages() -> frozenset[str]:
    """Languages with a registered deep-analysis plugin."""
    return frozenset(_REGISTRY)
