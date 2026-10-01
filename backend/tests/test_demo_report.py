"""Tests for the demo-facing report: agent metadata, budget, provenance.

Covers the report_generator upgrade (multi-agent execution section, AI
budget visibility, per-finding provenance) and smoke-tests scripts/demo.py.
All hermetic — the demo runs in free mode against the bundled fixture.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agents.supervisor_agent import SupervisorAgent
from services.report_generator import ReportGenerator

BACKEND_DIR = Path(__file__).resolve().parent.parent
FIXTURE_DIR = BACKEND_DIR / "tests" / "fixtures" / "multiagent_demo"


def _demo_result():
    supervisor = SupervisorAgent(default_mode="free")
    return supervisor.run_on_local_path(FIXTURE_DIR, owner="demo", name="vulnerable-app")


def test_report_contains_agent_execution_section():
    report = ReportGenerator().to_markdown(_demo_result())
    assert "## Multi-agent execution" in report
    assert "Mode: `free`" in report
    assert "Nemotron calls: 0" in report
    for name in ("security", "performance", "quality", "fusion"):
        assert name in report


def test_report_contains_budget_visibility():
    report = ReportGenerator().to_markdown(_demo_result())
    assert "AI budget" in report
    assert "0/0" in report


def test_report_contains_finding_provenance():
    report = ReportGenerator().to_markdown(_demo_result())
    assert "Provenance: detected by" in report


def test_demo_script_runs_clean(tmp_path):
    out = tmp_path / "report.md"
    proc = subprocess.run(
        [sys.executable, str(BACKEND_DIR / "scripts" / "demo.py"), "--out", str(out)],
        cwd=str(BACKEND_DIR),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "CodeAudit Agent" in proc.stdout
    assert "Findings" in proc.stdout
    assert out.exists()
    written = out.read_text(encoding="utf-8")
    assert "## Multi-agent execution" in written
    assert "Provenance: detected by" in written
