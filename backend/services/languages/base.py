"""Language analyzer plugin interface.

A LanguageAnalyzer owns one language's deep analysis: parsing source into
structural symbols and running that language's deterministic security
detectors. Every detector obeys the same contract as the Python analyzer:
each finding carries the exact source line as evidence, and when in doubt
the detector stays silent — false positives are worse than misses.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from models.schemas import CodeSymbol, Finding


@dataclass
class ParsedSource:
    """Language-neutral parse result.

    Mirrors models.schemas.ParsedFile so the orchestrator can convert without
    knowing which language produced it. Parsing never raises on bad input: a
    total failure is captured structurally in parse_error, exactly like the
    Python path.
    """

    relative_path: str
    language: str
    symbols: list[CodeSymbol] = field(default_factory=list)
    parse_error: str | None = None


class LanguageAnalyzer(ABC):
    """One language's deep-analysis plugin: parse + deterministic detectors."""

    #: Language key this analyzer handles, e.g. "python".
    language: str

    @abstractmethod
    def parse_source(self, content: str, relative_path: str) -> ParsedSource:
        """Parse source into symbols. Never raises on bad input: total
        failures become ParsedSource.parse_error."""
        ...

    @abstractmethod
    def analyze_file(self, relative_path: str, content: str) -> list[Finding]:
        """Run this language's deterministic detectors over one file.

        Every finding carries the exact source line as evidence. Detectors
        are conservative by design.
        """
        ...
