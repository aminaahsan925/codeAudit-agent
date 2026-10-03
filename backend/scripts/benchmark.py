"""CodeAudit benchmark: per-stage wall-clock timings on fixed fixtures.

Additive-only measurement tooling for Phase Zero of the engineering plan.
It drives the orchestrator's tool-style stages directly (no API, no
network, no AI — StubAIProvider / free mode), so results are hermetic and
repeatable.

Usage (from backend/):
    ../.venv/bin/python scripts/benchmark.py [--runs 3]

Stages timed per fixture:
    scan           orchestrator.scan_files          (file discovery + reads)
    parse          orchestrator.parse               (per-language AST parsing)
    analyze        orchestrator.analyze_static      (detectors, reusing parsed trees)
    analyze_legacy orchestrator.analyze_static      (detectors, legacy re-parse path;
                                                   comparison baseline only)
    validate       orchestrator.validate_findings   (evidence hard gate)
    risk           orchestrator.score_risk          (deterministic scoring)
    full           supervisor.run_on_local_path     (end-to-end, free mode)

Output: per-fixture, per-stage min/mean/max over N runs (ms), plus file
counts. Numbers are observations on this machine, not performance claims.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.supervisor_agent import SupervisorAgent
from services.ai_provider import StubAIProvider
from services.orchestrator import AnalysisOrchestrator

FIXTURES = {
    "js_vulnerable": "tests/fixtures/js_vulnerable",
    "ts_vulnerable": "tests/fixtures/ts_vulnerable",
    "sql_injection_example": "tests/fixtures/sql_injection_example",
    "mixed_repository": "tests/fixtures/mixed_repository",
    # Scaling probe: this backend's own source tree (~100 files). Exercises
    # the parse-reuse path at a realistic size; hermetic (local directory).
    "self_tree": ".",
}

# Stages printed per fixture. analyze_legacy is the old double-parse path,
# kept in the benchmark as the comparison baseline for parse reuse.
STAGES = ("scan", "parse", "analyze", "analyze_legacy", "validate", "risk", "full")


def _time(fn):
    start = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - start) * 1000.0


def benchmark_fixture(repo_dir: Path, runs: int) -> dict:
    orch = AnalysisOrchestrator(ai_provider=StubAIProvider())
    supervisor = SupervisorAgent(orchestrator=orch, default_mode="free")
    stages: dict[str, list[float]] = {
        "scan": [],
        "parse": [],
        "analyze": [],
        "analyze_legacy": [],
        "validate": [],
        "risk": [],
        "full": [],
    }
    meta: dict = {}
    for _ in range(runs):
        scan, dt = _time(lambda: orch.scan_files(repo_dir))
        stages["scan"].append(dt)
        (parsed, sources, _failed), dt = _time(lambda: orch.parse(scan))
        stages["parse"].append(dt)
        findings, dt = _time(lambda: orch.analyze_static(scan, sources))
        stages["analyze"].append(dt)
        # Legacy path (no shared trees): each file parsed again inside
        # analyze_file. Timed for comparison, not used by the pipeline.
        legacy_findings, dt = _time(lambda: orch.analyze_static(scan))
        stages["analyze_legacy"].append(dt)
        assert [f.id for f in findings] == [f.id for f in legacy_findings]
        validated, dt = _time(lambda: orch.validate_findings(findings, scan))
        stages["validate"].append(dt)
        _, dt = _time(lambda: orch.score_risk(validated[0]))
        stages["risk"].append(dt)
        _, dt = _time(lambda: supervisor.run_on_local_path(repo_dir))
        stages["full"].append(dt)
        meta = {
            "files": len(scan.files),
            "skipped": scan.skipped,
            "findings": len(validated[0]),
        }
    summary = {}
    for stage, samples in stages.items():
        summary[stage] = {
            "min_ms": round(min(samples), 2),
            "mean_ms": round(statistics.mean(samples), 2),
            "max_ms": round(max(samples), 2),
        }
    summary["meta"] = meta
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="CodeAudit stage timings")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    backend = Path(__file__).resolve().parent.parent
    print(f"# CodeAudit benchmark — {args.runs} runs per fixture (ms)")
    print(f"# host: {sys.platform}, python {sys.version.split()[0]}")
    for name, rel in FIXTURES.items():
        repo_dir = backend / rel
        if not repo_dir.is_dir():
            print(f"\n## {name}: MISSING ({rel})")
            continue
        result = benchmark_fixture(repo_dir, args.runs)
        print(f"\n## {name}  (files={result['meta']['files']}, "
              f"skipped={result['meta']['skipped']}, "
              f"findings={result['meta']['findings']})")
        print(f"{'stage':<14} {'min':>10} {'mean':>10} {'max':>10}")
        for stage in STAGES:
            s = result[stage]
            print(f"{stage:<14} {s['min_ms']:>10.2f} {s['mean_ms']:>10.2f} "
                  f"{s['max_ms']:>10.2f}")
        if result["analyze_legacy"]["mean_ms"] > 0:
            ratio = (
                result["analyze"]["mean_ms"] / result["analyze_legacy"]["mean_ms"]
            )
            print(f"# parse-reuse speedup: analyze is {ratio:.2f}x analyze_legacy "
                  f"(lower is better; <1.0 means reuse wins)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
