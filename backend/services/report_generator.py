"""Report generator: Phase 1 establishes the interface.

Consumes structured AnalysisResult objects (never raw AI text). Polished
reports and PDF export arrive in a later phase.
"""

from __future__ import annotations

from models.schemas import AnalysisResult


def _ai_line(result: AnalysisResult) -> str:
    """One honest line about what the AI layer did in this run."""
    ai = result.ai
    if ai.status.value == "disabled":
        return "AI: disabled (deterministic analysis only)"
    if ai.status.value == "enabled":
        return (
            f"AI: {ai.provider} enriched {ai.findings_enriched}, accepted "
            f"{ai.ai_findings_accepted} new, dropped {ai.ai_findings_dropped}, "
            f"merged {ai.duplicates_merged} duplicates"
        )
    detail = f" ({ai.error_code})" if ai.error_code else ""
    return f"AI: {ai.status.value}{detail} — deterministic findings retained"


def _agents_section(result: AnalysisResult) -> list[str]:
    """Render the multi-agent execution summary, when present."""
    run = result.agents
    if run is None:
        return []
    lines = [
        "",
        "## Multi-agent execution",
        f"Mode: `{run.mode}` | Agents completed: {run.completed} | "
        f"Nemotron calls: {run.ai_calls}",
    ]
    if result.ai_budget is not None:
        b = result.ai_budget
        lines.append(
            f"AI budget ({b.purpose}): {b.used}/{b.limit} used, "
            f"{b.remaining} remaining"
        )
    for agent in run.agents:
        detail = f"{agent.agent_name}: {agent.status} ({agent.duration_ms} ms"
        if agent.model_calls:
            detail += f", {agent.model_calls} model call(s)"
            if agent.model_used:
                detail += f" via {agent.model_used}"
        if agent.findings_count:
            detail += f", {agent.findings_count} finding(s)"
        if agent.errors:
            detail += f", errors: {'; '.join(agent.errors)}"
        detail += ")"
        lines.append(f"- {detail}")
    return lines


def _provenance_line(finding) -> str | None:
    prov = finding.provenance
    if prov is None:
        return None
    parts = []
    if prov.detected_by:
        parts.append(f"detected by {', '.join(prov.detected_by)}")
    if prov.reviewed_by:
        parts.append(f"reviewed by {', '.join(prov.reviewed_by)}")
    if prov.fixed_by:
        parts.append(f"fixed by {', '.join(prov.fixed_by)}")
    if prov.verified_by:
        parts.append(f"verified by {', '.join(prov.verified_by)}")
    return "Provenance: " + "; ".join(parts) if parts else None


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
            _ai_line(result),
        ]
        lines.extend(_agents_section(result))
        lines.extend(["", "## Findings"])
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
            provenance = _provenance_line(finding)
            if provenance:
                lines.extend(["", provenance])
            if finding.suggested_fix:
                lines.extend(["", f"Suggested fix: {finding.suggested_fix}"])
            if finding.ai_reasoning:
                lines.extend(["", f"AI reasoning ({finding.enriched_by}): {finding.ai_reasoning}"])
        return "\n".join(lines) + "\n"

    def to_dict(self, result: AnalysisResult) -> dict:
        """Structured dict form; the JSON API already serializes the model."""
        return result.model_dump(mode="json")
