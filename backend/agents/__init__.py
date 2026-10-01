"""CodeAudit multi-agent backend (Phase 3 upgrade).

Hybrid multi-agent architecture: deterministic specialist agents do the
cheap, reliable analysis locally; Nemotron reasons only where AI adds
meaningful value, inside hard per-run call budgets enforced by the
Supervisor.

Agent inventory (canonical names live in agents/registry.py):
    supervisor        coordinates the whole run
    security          deterministic security triage (wraps static_analyzer)
    performance       deterministic performance rules (AST-based, no fake metrics)
    quality           deterministic quality triage (wraps static_analyzer + AST)
    evidence          Nemotron evidence review (budgeted, never overrides evidence)
    fusion            deterministic finding fusion with provenance
    fix               Nemotron fix proposal behind an agent boundary (never writes)
    verification      coordinates deterministic verification (AI may not override)
    patch_guard       NOT an LLM: services/patch_engine.py, authoritative
"""

from __future__ import annotations
