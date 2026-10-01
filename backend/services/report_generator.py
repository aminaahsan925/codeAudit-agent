"""Report generator: Phase 1 establishes the interface.

Consumes structured AnalysisResult objects (never raw AI text). Polished
reports and PDF export arrive in a later phase.
"""

from __future__ import annotations

from models.schemas import AnalysisResult


class ReportGenerator:
    """Renders an AnalysisResult into human-readable summaries."""

    def to_markdown(self, result: AnalysisResult) -> str:
        repo = result.repository
        summary = result.summary
        risk = result.risk
        lines = [
            f"# CodeAudit Report — {repo.owner}/{repo.name}",
            "",
            f"Files: {summary.files_discovered} discovered, {summary.files_scanned} scanned "
            f"({summary.files_deep_analyzed} deep-analyzed, {summary.files_unsupported} unsupported, "
            f"{summary.files_skipped} skipped, {summary.files_failed_parse} failed to parse)",
            f"Findings: {summary.findings_total} | Risk: {risk.score}/10 ({risk.level})",
            "",
            "## Findings",
        ]
        for finding in result.findings:
            lines.extend(
                [
                    "",
                    f"### [{finding.severity.value.upper()}] {finding.title}",
                    f"File: `{finding.file}` line {finding.line} "
                    f"(confidence: {finding.confidence.value}, source: {finding.source.value})",
                    "",
                    "```",
                    finding.evidence,
                    "```",
                    "",
                    finding.description,
                ]
            )
            if finding.suggested_fix:
                lines.extend(["", f"Suggested fix: {finding.suggested_fix}"])
        return "\n".join(lines) + "\n"

    def to_dict(self, result: AnalysisResult) -> dict:
        """Structured dict form; the JSON API already serializes the model."""
        return result.model_dump(mode="json")
