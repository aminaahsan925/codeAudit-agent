"""Shared bounded repository context layer (Phase 3 upgrade).

One context object is built per analysis run from the scan results; each
agent receives only the subset relevant to its specialty instead of every
agent copying the whole repository. Everything here is bounded: excerpts
are cut at fixed line windows, and per-agent subsets cap the number of
files and findings.

No source code leaves this object except through the budgeted AI context
builders (evidence agent / specialist review), which apply their own
character budgets on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.schemas import Category, ParsedFile, ValidatedFinding

# Lines of source shown around each cited evidence line.
EXCERPT_RADIUS_LINES = 8
# Hard cap on excerpts handed to any single agent.
MAX_EXCERPTS_PER_AGENT = 12


def _excerpt(lines: list[str], lineno: int, radius: int = EXCERPT_RADIUS_LINES) -> str:
    start = max(1, lineno - radius)
    end = min(len(lines), lineno + radius)
    numbered = [f"{start + i} | {line}" for i, line in enumerate(lines[start - 1 : end])]
    return "\n".join(numbered)


@dataclass
class SharedRepositoryContext:
    """One bounded view of the repository, shared by all agents in a run."""

    contents: dict[str, str] = field(default_factory=dict)
    parsed: list[ParsedFile] = field(default_factory=list)
    validated: list[ValidatedFinding] = field(default_factory=list)
    # finding_id -> bounded, line-numbered source excerpt around the evidence.
    finding_excerpts: dict[str, str] = field(default_factory=dict)
    # relative_path -> total line count (cheap structural signal).
    file_line_counts: dict[str, int] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        contents: dict[str, str],
        parsed: list[ParsedFile],
        validated: list[ValidatedFinding],
    ) -> "SharedRepositoryContext":
        finding_excerpts: dict[str, str] = {}
        for finding in validated:
            text = contents.get(finding.file)
            if not text:
                continue
            lines = text.split("\n")
            finding_excerpts[finding.id] = _excerpt(lines, finding.line)
        return cls(
            contents=dict(contents),
            parsed=list(parsed),
            validated=list(validated),
            finding_excerpts=finding_excerpts,
            file_line_counts={
                path: len(text.split("\n")) for path, text in contents.items()
            },
        )

    def findings_for(self, category: Category) -> list[ValidatedFinding]:
        """Validated findings of one category (a specialist's slice)."""
        return [f for f in self.validated if f.category == category]

    def excerpts_for_findings(
        self, findings: list[ValidatedFinding], limit: int = MAX_EXCERPTS_PER_AGENT
    ) -> dict[str, str]:
        """Bounded excerpts for a set of findings (one agent's subset)."""
        excerpts: dict[str, str] = {}
        for finding in findings[:limit]:
            excerpt = self.finding_excerpts.get(finding.id)
            if excerpt:
                excerpts[finding.id] = excerpt
        return excerpts

    def file_excerpt(
        self, path: str, start_line: int = 1, max_lines: int = 60
    ) -> str:
        """Bounded head excerpt of one file (for priority-target review)."""
        text = self.contents.get(path)
        if not text:
            return ""
        lines = text.split("\n")
        kept = lines[start_line - 1 : start_line - 1 + max_lines]
        return "\n".join(
            f"{start_line + i} | {line}" for i, line in enumerate(kept)
        )


__all__ = [
    "EXCERPT_RADIUS_LINES",
    "MAX_EXCERPTS_PER_AGENT",
    "SharedRepositoryContext",
]
