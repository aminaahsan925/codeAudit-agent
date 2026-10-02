"""Python language analyzer: thin adapter over the existing Python pipeline.

Behavior for Python is unchanged: parsing goes through code_parser and
detection through static_analyzer.analyze_content, so findings and finding
IDs are byte-identical to the pre-plugin pipeline. The adapter only stamps
the language attribution the common Finding model now carries.
"""

from __future__ import annotations

from models.schemas import Finding
from services.code_parser import parse_python
from services.languages.base import LanguageAnalyzer, ParsedSource
from services.static_analyzer import analyze_content


class PythonAnalyzer(LanguageAnalyzer):
    """Deep analysis for Python, delegating to the battle-tested modules."""

    language = "python"

    def parse_source(self, content: str, relative_path: str) -> ParsedSource:
        parsed = parse_python(relative_path, content)
        return ParsedSource(
            relative_path=parsed.relative_path,
            language=self.language,
            symbols=parsed.symbols,
            parse_error=parsed.parse_error,
        )

    def analyze_file(self, relative_path: str, content: str) -> list[Finding]:
        findings = analyze_content(relative_path, content)
        for finding in findings:
            finding.language = self.language
        return findings
