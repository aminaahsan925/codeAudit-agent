"""Language analyzer plugins: one deep-analysis implementation per language.

Each supported language provides a LanguageAnalyzer (AST-level parsing plus
deterministic security detectors) that shares the common Finding model.
The registry (registry.py) is the single source of truth for which languages
get deep analysis; it is built from DEEP_ANALYSIS_LANGUAGES so the
declarative set and the available analyzers cannot drift apart.
"""
