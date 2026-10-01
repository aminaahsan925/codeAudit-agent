"""Security agent: deterministic security triage.

An orchestration layer around the existing static analyzer — NOT a second
copy of every detector. It consumes the evidence-validated security
findings, groups related ones, ranks priority targets (files where a fix
matters most), and flags ambiguous findings for the Evidence agent's AI
review.

Responsibility boundary:
    IN:  validated deterministic findings + shared repository context
    OUT: triaged security view (same findings, grouped and ranked)
    NEVER: creates new detectors, modifies files, calls the model directly
           (optional full-mode review goes through the shared review path
           and is recorded in execution metadata)
"""

from __future__ import annotations

import logging
import time
from collections import Counter

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
    SecurityAgentResult,
)
from agents.registry import SECURITY_AGENT
from models.schemas import Category, Severity

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class SecurityAgent:
    """Deterministic security triage over validated findings."""

    name = SECURITY_AGENT

    def run(self, ctx: AgentContext) -> SecurityAgentResult:
        started = time.monotonic()
        findings = [
            f for f in ctx.validated_findings if f.category == Category.SECURITY
        ]

        by_file: dict[str, list] = {}
        for finding in findings:
            by_file.setdefault(finding.file, []).append(finding)

        # Priority targets: files with the most severe findings first.
        def _file_rank(item: tuple[str, list]) -> tuple[int, int, str]:
            worst = min(_SEVERITY_RANK[f.severity] for f in item[1])
            return (worst, -len(item[1]), item[0])

        priority_targets = [
            path for path, _ in sorted(by_file.items(), key=_file_rank)
        ]
        suspicious_files = sorted(by_file)

        detector_counts = Counter(f.detector for f in findings)
        severity_counts = Counter(f.severity.value for f in findings)
        # Ambiguous findings (low confidence) are the review queue for AI.
        needs_review = sorted(
            {f.id for f in findings if f.confidence.value == "low"}
        )

        metadata = AgentExecutionMetadata(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            duration_ms=int((time.monotonic() - started) * 1000),
            findings_count=len(findings),
        )
        return SecurityAgentResult(
            agent_name=self.name,
            findings=list(findings),
            priority_targets=priority_targets,
            suspicious_files=suspicious_files,
            evidence_summary={
                "total": len(findings),
                "by_detector": dict(detector_counts),
                "by_severity": dict(severity_counts),
                "needs_ai_review": needs_review,
            },
            execution_metadata=metadata,
        )


__all__ = ["SecurityAgent"]
