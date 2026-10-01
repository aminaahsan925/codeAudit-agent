"""CodeAudit end-to-end demo runner (no network, no API key required).

Runs the full multi-agent pipeline in FREE mode (zero Nebius calls) against
the bundled vulnerable demo fixture, prints a console summary, and writes a
Markdown report. This is the script to record for the hackathon demo video.

Usage (from backend/):
    ../.venv/bin/python scripts/demo.py [--out /tmp/codeaudit_demo_report.md]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.supervisor_agent import SupervisorAgent
from services.report_generator import ReportGenerator

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "multiagent_demo"


def _bar(score: int, width: int = 20) -> str:
    filled = int(round(score / 10 * width))
    return "#" * filled + "-" * (width - filled)


def main() -> int:
    parser = argparse.ArgumentParser(description="CodeAudit multi-agent demo (free mode)")
    parser.add_argument(
        "--out",
        default="/tmp/codeaudit_demo_report.md",
        help="Where to write the Markdown report",
    )
    parser.add_argument(
        "--repo",
        default=str(FIXTURE_DIR),
        help="Repository directory to analyze (default: bundled demo fixture)",
    )
    args = parser.parse_args()

    repo_dir = Path(args.repo)
    if not repo_dir.is_dir():
        print(f"error: not a directory: {repo_dir}", file=sys.stderr)
        return 2

    print("=" * 64)
    print("CodeAudit Agent — hybrid multi-agent security analysis (FREE mode)")
    print("=" * 64)
    print(f"Repository : {repo_dir}")
    print("Mode       : free (deterministic agents, 0 Nebius calls)")
    print("-" * 64)

    supervisor = SupervisorAgent(default_mode="free")
    started = time.monotonic()
    result = supervisor.run_on_local_path(repo_dir, owner="demo", name="vulnerable-app")
    elapsed_ms = int((time.monotonic() - started) * 1000)

    by_severity: dict[str, int] = {}
    for f in result.findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    print(f"Files scanned : {result.summary.files_scanned}")
    print(f"Findings      : {result.summary.findings_total} " + " ".join(
        f"{sev}={n}" for sev, n in sorted(by_severity.items())
    ))
    print(f"Risk          : {result.risk.score}/10 [{_bar(result.risk.score)}] {result.risk.level}")
    print(f"Analysis time : {elapsed_ms} ms")
    print("-" * 64)

    if result.agents is not None:
        print("Agents:")
        for agent in result.agents.agents:
            extra = ""
            if agent.model_calls:
                extra = f", {agent.model_calls} Nemotron call(s)"
            print(f"  - {agent.agent_name:12s} {agent.status:10s} {agent.duration_ms:5d} ms{extra}")
        if result.ai_budget is not None:
            b = result.ai_budget
            print(f"AI budget     : {b.used}/{b.limit} calls used ({b.remaining} remaining)")
        print("-" * 64)

    print("Top findings:")
    for f in result.findings[:8]:
        prov = ""
        if f.provenance and f.provenance.detected_by:
            prov = f"  <- {', '.join(f.provenance.detected_by)}"
        print(f"  [{f.severity.value.upper():8s}] {f.file}:{f.line} {f.title}{prov}")
    if result.summary.findings_total > 8:
        print(f"  ... and {result.summary.findings_total - 8} more (see report)")
    print("-" * 64)

    report = ReportGenerator().to_markdown(result)
    out_path = Path(args.out)
    out_path.write_text(report, encoding="utf-8")
    print(f"Full Markdown report written to: {out_path}")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
