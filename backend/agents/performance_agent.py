"""Performance agent: deterministic performance-pattern detection.

AST-based rules over parsed Python files. This agent NEVER measures
runtime performance and never claims to: every finding describes a code
pattern that is *structurally* wasteful (work repeated inside a loop that
could be hoisted or avoided), reported at low severity with the exact
evidence line. No benchmarks, no timings, no fake measurements.

Responsibility boundary:
    IN:  shared repository context (contents + parsed files)
    OUT: new deterministic PERFORMANCE findings (still gated by the
         supervisor through the FindingValidator evidence hard gate)
    NEVER: executes repository code, measures wall-clock time, modifies files
"""

from __future__ import annotations

import ast
import logging
import time

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
    PerformanceAgentResult,
)
from agents.registry import PERFORMANCE_AGENT
from models.schemas import (
    Category,
    Confidence,
    Finding,
    FindingSource,
    Severity,
)

logger = logging.getLogger(__name__)

# Calls that are structurally expensive and almost always hoistable out of
# a loop body (recompilation, I/O setup, serialization, process spawn).
_EXPENSIVE_CALLS = frozenset(
    {
        "re.compile",
        "open",
        "time.sleep",
        "json.loads",
        "json.dumps",
        "pickle.loads",
        "pickle.dumps",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "socket.socket",
    }
)

_LOOP_NODES = (ast.For, ast.AsyncFor, ast.While)


def _line(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip("\n")
    return ""


def _dotted_name(node: ast.AST) -> str | None:
    """Best-effort dotted name for a call func (e.g. re.compile)."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _make_finding(
    *,
    detector: str,
    title: str,
    description: str,
    relative_path: str,
    line: int,
    evidence: str,
    severity: Severity,
    suggested_fix: str | None = None,
) -> Finding:
    return Finding(
        id=f"{detector}:{relative_path}:{line}",
        category=Category.PERFORMANCE,
        severity=severity,
        title=title,
        description=description,
        file=relative_path,
        line=line,
        evidence=evidence,
        suggested_fix=suggested_fix,
        confidence=Confidence.MEDIUM,
        source=FindingSource.DETERMINISTIC,
        detector=detector,
    )


class _LoopVisitor(ast.NodeVisitor):
    """Collects loop-related performance patterns in one AST pass."""

    def __init__(self, lines: list[str], path: str) -> None:
        self._lines = lines
        self._path = path
        self.findings: list[Finding] = []
        self._loop_depth = 0

    def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
        if self._loop_depth >= 1:
            # Nested loop: report the inner loop's location once.
            self.findings.append(
                _make_finding(
                    detector="nested_loop",
                    title="Nested loop",
                    description=(
                        "A loop directly contains another loop, giving "
                        "quadratic (or worse) iteration behavior over the "
                        "combined inputs. Consider restructuring the data "
                        "access (e.g. index lookups) if the inputs can grow."
                    ),
                    relative_path=self._path,
                    line=node.lineno,
                    evidence=_line(self._lines, node.lineno),
                    severity=Severity.LOW,
                    suggested_fix="Hoist invariant work out of the inner loop or replace the inner scan with a dict/set lookup.",
                )
            )
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self._visit_loop(node)

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        self._visit_loop(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        # `s += "literal"` inside a loop: quadratic string building.
        if (
            self._loop_depth >= 1
            and isinstance(node.op, ast.Add)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            self.findings.append(
                _make_finding(
                    detector="inefficient_string_concat_in_loop",
                    title="String concatenation inside a loop",
                    description=(
                        f"Variable '{node.target.id}' is extended with '+=' "
                        "inside a loop, which copies the whole string on "
                        "every iteration (quadratic behavior)."
                    ),
                    relative_path=self._path,
                    line=node.lineno,
                    evidence=_line(self._lines, node.lineno),
                    severity=Severity.LOW,
                    suggested_fix="Collect parts in a list and ''.join() once after the loop.",
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if self._loop_depth >= 1:
            dotted = _dotted_name(node.func)
            if dotted in _EXPENSIVE_CALLS:
                self.findings.append(
                    _make_finding(
                        detector="expensive_call_in_loop",
                        title=f"Expensive call inside a loop: {dotted}()",
                        description=(
                            f"{dotted}() is invoked on every loop iteration. "
                            "Such calls (compilation, I/O, serialization, "
                            "process spawn) can usually be hoisted out of "
                            "the loop."
                        ),
                        relative_path=self._path,
                        line=node.lineno,
                        evidence=_line(self._lines, node.lineno),
                        severity=Severity.LOW,
                        suggested_fix=f"Move {dotted}() out of the loop when its arguments do not change per iteration.",
                    )
                )
        self.generic_visit(node)


def detect_performance_patterns(
    relative_path: str, content: str
) -> list[Finding]:
    """Run the deterministic performance rules over one Python file."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    lines = content.split("\n")
    visitor = _LoopVisitor(lines, relative_path)
    visitor.visit(tree)
    return visitor.findings


class PerformanceAgent:
    """Deterministic performance-pattern detection and triage."""

    name = PERFORMANCE_AGENT

    def detect(self, ctx: AgentContext) -> list[Finding]:
        """Detect performance patterns across parsed Python files."""
        findings: list[Finding] = []
        for parsed in ctx.parsed:
            if parsed.parse_error:
                continue
            content = ctx.scan.contents.get(parsed.relative_path, "")
            if not content:
                continue
            findings.extend(detect_performance_patterns(parsed.relative_path, content))
        findings.sort(key=lambda f: (f.file, f.line, f.detector))
        return findings

    def run(self, ctx: AgentContext) -> PerformanceAgentResult:
        started = time.monotonic()
        # Triage view: validated performance findings (this agent's gated
        # detections). Raw detection happens in detect(); the supervisor
        # runs everything through the evidence hard gate first.
        findings = [
            f for f in ctx.validated_findings if f.category == Category.PERFORMANCE
        ]

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
        return PerformanceAgentResult(
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
                "note": "Structural patterns only; no runtime measurements taken.",
            },
            execution_metadata=metadata,
        )


__all__ = ["PerformanceAgent", "detect_performance_patterns"]
