"""Python language analyzer: thin adapter over the existing Python pipeline.

Behavior for Python is unchanged: parsing goes through code_parser and
detection through static_analyzer's detector registry, so findings and
finding IDs are byte-identical to the pre-plugin pipeline. The adapter only
stamps the language attribution the common Finding model now carries.

Parse-tree reuse: parse_source retains the ast.Module in ParsedSource.tree,
and analyze_parsed runs the detectors directly on that tree instead of
parsing the content a second time.
"""

from __future__ import annotations

import ast
import logging

from models.schemas import Finding
from services.code_parser import parse_python_tree
from services.languages.base import LanguageAnalyzer, ParsedSource
from services.static_analyzer import DETECTORS

logger = logging.getLogger(__name__)


class PythonAnalyzer(LanguageAnalyzer):
    """Deep analysis for Python, delegating to the battle-tested modules."""

    language = "python"

    def parse_source(self, content: str, relative_path: str) -> ParsedSource:
        parsed, tree = parse_python_tree(relative_path, content)
        return ParsedSource(
            relative_path=parsed.relative_path,
            language=self.language,
            symbols=parsed.symbols,
            parse_error=parsed.parse_error,
            tree=tree,
        )

    def analyze_parsed(
        self, relative_path: str, content: str, parsed: ParsedSource
    ) -> list[Finding]:
        """Run the detector registry on the already-parsed tree.

        Identical to static_analyzer.analyze_content except the tree comes
        from parse_source instead of a second ast.parse call: same
        detectors, same per-detector isolation, same deterministic ordering,
        same finding IDs.
        """
        tree = parsed.tree
        if tree is None or not isinstance(tree, ast.AST):
            # Parse failed (or no tree retained): analyze_content would have
            # re-parsed and returned [] here as well.
            return []
        lines = content.splitlines()
        findings: list[Finding] = []
        for detector in DETECTORS:
            try:
                findings.extend(detector(tree, lines, relative_path))
            except Exception as exc:  # noqa: BLE001 - one bad detector must not kill analysis
                logger.warning(
                    "Detector %s failed on %s: %s",
                    detector.__name__,
                    relative_path,
                    exc,
                )
        for finding in findings:
            finding.language = self.language
        # Deterministic ordering for stable output (mirrors analyze_content).
        findings.sort(key=lambda f: (f.file, f.line, f.detector))
        return findings

    def analyze_file(self, relative_path: str, content: str) -> list[Finding]:
        return self.analyze_parsed(
            relative_path, content, self.parse_source(content, relative_path)
        )
