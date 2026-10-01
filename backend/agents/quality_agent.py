"""Quality agent: deterministic maintainability triage.

Wraps the static analyzer's quality detectors (long_function, bare_except)
and adds a small set of conservative AST rules for structural quality
signals the line-based detectors do not cover: high branch complexity and
excessive parameter counts. Thresholds are deliberately high so only
clear-cut cases are reported; borderline code is left alone.

Responsibility boundary:
    IN:  validated deterministic findings + shared repository context
    OUT: triaged quality view (wrapped analyzer findings + conservative
         AST extras, all still gated by the supervisor's evidence hard gate)
    NEVER: invents style rules, rewrites code, modifies files
"""

from __future__ import annotations

import ast
import logging
import time

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
    QualityAgentResult,
)
from agents.registry import QUALITY_AGENT
from models.schemas import (
    Category,
    Confidence,
    Finding,
    FindingSource,
    Severity,
)

logger = logging.getLogger(__name__)

# Conservative thresholds: only flag the obvious cases.
BRANCH_COMPLEXITY_THRESHOLD = 15
MAX_PARAMETERS_THRESHOLD = 10


def _line(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip("\n")
    return ""


def _branch_points(node: ast.AST) -> int:
    """Count decision points in a function body (conservative complexity)."""
    count = 0
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While,
                              ast.ExceptHandler, ast.With, ast.Assert)):
            count += 1
        elif isinstance(child, ast.BoolOp):
            count += max(0, len(child.values) - 1)
        elif isinstance(child, ast.IfExp):
            count += 1
    return count


def _make_finding(
    *,
    detector: str,
    title: str,
    description: str,
    relative_path: str,
    line: int,
    evidence: str,
    severity: Severity,
    confidence: Confidence = Confidence.MEDIUM,
    suggested_fix: str | None = None,
) -> Finding:
    return Finding(
        id=f"{detector}:{relative_path}:{line}",
        category=Category.QUALITY,
        severity=severity,
        title=title,
        description=description,
        file=relative_path,
        line=line,
        evidence=evidence,
        suggested_fix=suggested_fix,
        confidence=confidence,
        source=FindingSource.DETERMINISTIC,
        detector=detector,
    )


def detect_quality_patterns(relative_path: str, content: str) -> list[Finding]:
    """Conservative AST quality rules for one Python file."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    lines = content.split("\n")
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        branches = _branch_points(node)
        if branches > BRANCH_COMPLEXITY_THRESHOLD:
            findings.append(
                _make_finding(
                    detector="high_branch_complexity",
                    title=f"High branch complexity in '{node.name}'",
                    description=(
                        f"Function '{node.name}' contains ~{branches} decision "
                        f"points (threshold {BRANCH_COMPLEXITY_THRESHOLD}). "
                        "Deeply branched functions are hard to test and "
                        "easy to break when changed."
                    ),
                    relative_path=relative_path,
                    line=node.lineno,
                    evidence=_line(lines, node.lineno),
                    severity=Severity.LOW,
                    suggested_fix="Extract branches into smaller, named helper functions.",
                )
            )
        param_count = len(node.args.args) + len(node.args.kwonlyargs)
        if param_count > MAX_PARAMETERS_THRESHOLD:
            findings.append(
                _make_finding(
                    detector="too_many_parameters",
                    title=f"Too many parameters in '{node.name}'",
                    description=(
                        f"Function '{node.name}' takes {param_count} parameters "
                        f"(threshold {MAX_PARAMETERS_THRESHOLD}), which makes "
                        "call sites error-prone."
                    ),
                    relative_path=relative_path,
                    line=node.lineno,
                    evidence=_line(lines, node.lineno),
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    suggested_fix="Group related parameters into a dataclass or options object.",
                )
            )
    return findings


class QualityAgent:
    """Deterministic quality triage: wrapped analyzer findings + AST extras."""

    name = QUALITY_AGENT

    def detect(self, ctx: AgentContext) -> list[Finding]:
        """Run the conservative AST quality rules over parsed files."""
        findings: list[Finding] = []
        for parsed in ctx.parsed:
            if parsed.parse_error:
                continue
            content = ctx.scan.contents.get(parsed.relative_path, "")
            if not content:
                continue
            findings.extend(detect_quality_patterns(parsed.relative_path, content))
        findings.sort(key=lambda f: (f.file, f.line, f.detector))
        return findings

    def run(self, ctx: AgentContext) -> QualityAgentResult:
        started = time.monotonic()
        # Triage view: validated quality findings — the analyzer's wrapped
        # detectors (long_function, bare_except) plus this agent's gated
        # AST extras. Raw detection happens in detect(); the supervisor
        # runs everything through the evidence hard gate first.
        findings = [f for f in ctx.validated_findings if f.category == Category.QUALITY]

        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file, []).append(finding)
        priority_targets = sorted(
            by_file, key=lambda p: (-len(by_file[p]), p)
        )

        metadata = AgentExecutionMetadata(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            duration_ms=int((time.monotonic() - started) * 1000),
            findings_count=len(findings),
        )
        return QualityAgentResult(
            agent_name=self.name,
            findings=findings,
            priority_targets=priority_targets,
            suspicious_files=sorted(by_file),
            evidence_summary={
                "total": len(findings),
                "by_detector": {
                    detector: sum(1 for f in findings if f.detector == detector)
                    for detector in {f.detector for f in findings}
                },
            },
            execution_metadata=metadata,
        )


__all__ = ["QualityAgent", "detect_quality_patterns"]
