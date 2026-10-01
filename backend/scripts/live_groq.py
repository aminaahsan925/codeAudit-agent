"""CodeAudit live-AI smoke test (Groq provider).

Runs the full multi-agent pipeline against a real model in ECONOMY mode
(exactly 1 budgeted AI call): deterministic specialists in parallel, one
Groq evidence review, deterministic fusion. Prints a console summary that
proves the AI layer works end to end.

Setup (in your terminal — the key is never written anywhere by this script):
    export GROQ_API_KEY=<your key>
    export CODEAUDIT_AI_PROVIDER=groq
    # optional: export GROQ_MODEL=openai/gpt-oss-120b   (this is the default)
    # optional: export CODEAUDIT_AGENT_MODE=full       (default: economy)

Usage (from backend/):
    ../.venv/bin/python scripts/live_groq.py [path/to/repo]
    (defaults to the bundled vulnerable demo fixture)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Non-secret wiring the script owns so the user doesn't have to export it.
os.environ.setdefault("CODEAUDIT_AI_PROVIDER", "groq")
os.environ.setdefault("CODEAUDIT_AGENT_MODE", "economy")

from agents.supervisor_agent import SupervisorAgent  # noqa: E402
from services.groq_service import GroqService  # noqa: E402

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "multiagent_demo"


def main() -> int:
    parser = argparse.ArgumentParser(description="CodeAudit live Groq smoke test")
    parser.add_argument(
        "target",
        nargs="?",
        default=str(FIXTURE_DIR),
        help="Local repository path to analyze (default: bundled demo fixture)",
    )
    args = parser.parse_args()

    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set. Run: export GROQ_API_KEY=<your key>")
        return 2

    provider = GroqService()
    if not provider.is_configured:
        print("Groq provider is not configured (missing GROQ_API_KEY or GROQ_MODEL).")
        return 2

    print(f"provider: {provider.name} | model: {provider.model} | target: {args.target}")
    started = time.monotonic()
    sup = SupervisorAgent(ai_provider=provider, default_mode=os.environ["CODEAUDIT_AGENT_MODE"])
    result = sup.run_on_local_path(args.target, owner="local", name=Path(args.target).name)
    elapsed = time.monotonic() - started

    ai = result.ai
    print("=" * 64)
    print(f"findings: {result.summary.findings_total} | risk: {result.risk.score}/10 {result.risk.level}")
    print(
        f"AI: {ai.status.value} | provider: {ai.provider} | model: {ai.model} | "
        f"enriched: {ai.findings_enriched} | accepted: {ai.ai_findings_accepted} | "
        f"dropped: {ai.ai_findings_dropped} | err: {ai.error_code}"
    )
    if result.ai_budget:
        print(f"budget: {result.ai_budget.used}/{result.ai_budget.limit} calls used")
    if result.agents:
        for a in result.agents.agents:
            print(
                f"  agent {a.agent_name}: {a.status} "
                f"calls={a.model_calls} findings={a.findings_count}"
            )
    print("=" * 64)
    for f in result.findings:
        print(f"[{f.severity.value.upper()}] {f.file}:{f.line} {f.title} (src={f.source.value})")
        if f.ai_reasoning:
            print(f"   AI: {f.ai_reasoning[:180]}")
    print(f"\ndone in {elapsed:.1f}s")

    if ai.status.value != "enabled":
        print("\nNOTE: AI layer did not engage — check GROQ_API_KEY and network access.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
