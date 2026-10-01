"""End-to-end AI integration tests (hermetic, §41).

Simulates the full Phase 2 flow with a FakeAIProvider standing in for
Nemotron — no network, no API key:

    fixture repository
        -> deterministic static findings
        -> AI assessments (enrichment) + AI candidates (discovery)
        -> assessment application + deduplication
        -> evidence hard gate over everything
        -> deterministic risk engine
        -> final result with AI response metadata

The fake provider's outputs are canned, but every downstream stage is the
real production code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from models.schemas import (
    AIAssessment,
    AIFindingCandidate,
    AIStatusValue,
    AIVerdict,
    Category,
    Confidence,
    FindingSource,
    Severity,
)
from services import risk_engine
from services.ai_errors import AIUpstreamError
from services.ai_provider import StubAIProvider
from services.orchestrator import AnalysisOrchestrator
from tests.fakes import FakeAIProvider

FIXTURE = Path(__file__).parent / "fixtures" / "ai_integration_example"


def _deterministic_result():
    return AnalysisOrchestrator(ai_provider=StubAIProvider()).run_on_local_path(FIXTURE)


def _sql_finding_id(result) -> str:
    ids = [f.id for f in result.findings if f.detector == "sql_string_construction"]
    assert ids, "fixture must produce a SQL finding"
    return ids[0]


def _line_of(path: Path, needle: str) -> tuple[int, str]:
    for i, line in enumerate(path.read_text().splitlines(), start=1):
        if needle in line:
            return i, line.strip()
    raise AssertionError(f"{needle!r} not found in {path}")


def _fake_provider(sql_id: str) -> FakeAIProvider:
    app_py = FIXTURE / "app.py"
    import_line, import_evidence = _line_of(app_py, "import os")
    sql_line, _ = _line_of(app_py, '"SELECT * FROM items')
    return FakeAIProvider(
        assessments=[
            AIAssessment(
                finding_id=sql_id,
                verdict=AIVerdict.CONFIRMED,
                confidence=Confidence.HIGH,
                reasoning="EVIDENCE: SQL built by string concatenation with `name`. "
                "INFERENCE: user input reaches the query unsanitized.",
                suggested_fix="Use a parameterized query.",
            )
        ],
        candidates=[
            # Genuine new issue: evidence matches the real line exactly.
            AIFindingCandidate(
                title="Possibly unused import",
                category=Category.QUALITY,
                severity=Severity.LOW,
                file="app.py",
                line=import_line,
                evidence=import_evidence,
                description="`os` is imported but never used in this file.",
                confidence=Confidence.MEDIUM,
                reasoning="EVIDENCE: `import os` at the top; no `os.` usage below.",
            ),
            # Hallucinated: line does not exist -> hard gate must drop it.
            AIFindingCandidate(
                title="Imaginary flaw",
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                file="app.py",
                line=9999,
                evidence="totally_made_up()",
                description="This line does not exist.",
                confidence=Confidence.HIGH,
                reasoning="Fabricated.",
            ),
            # Duplicate of the deterministic SQL finding -> must merge, not double-count.
            AIFindingCandidate(
                title="SQL injection (AI spotted too)",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                file="app.py",
                line=sql_line,
                evidence='"SELECT * FROM items WHERE name = \'" + name + "\'"',
                description="Same underlying issue as the deterministic finding.",
                confidence=Confidence.HIGH,
                reasoning="EVIDENCE matches the deterministic finding's line.",
            ),
        ],
    )


def test_full_flow_with_fake_provider():
    deterministic = _deterministic_result()
    sql_id = _sql_finding_id(deterministic)

    provider = _fake_provider(sql_id)
    result = AnalysisOrchestrator(ai_provider=provider).run_on_local_path(FIXTURE)

    ai = result.ai
    assert ai.status == AIStatusValue.ENABLED
    assert ai.provider == "fake"
    assert ai.deterministic_findings == len(deterministic.findings)
    assert ai.findings_enriched == 1
    assert ai.ai_findings_accepted == 1
    assert ai.ai_findings_dropped == 1  # the hallucinated line-9999 candidate
    assert ai.duplicates_merged == 1

    # Enrichment landed on the deterministic anchor, which kept its identity.
    enriched = next(f for f in result.findings if f.id == sql_id)
    before = next(f for f in deterministic.findings if f.id == sql_id)
    assert enriched.source == FindingSource.DETERMINISTIC
    assert enriched.detector == "sql_string_construction"
    assert enriched.ai_reasoning.startswith("EVIDENCE")
    assert enriched.suggested_fix == "Use a parameterized query."
    assert enriched.confidence == before.confidence  # confirmed: no demotion

    # The genuine AI discovery was accepted, with AI attribution.
    ai_findings = [f for f in result.findings if f.source == FindingSource.AI]
    assert len(ai_findings) == 1
    assert ai_findings[0].detector == "nemotron_security_v1"
    assert ai_findings[0].validation == "passed"
    assert ai_findings[0].title == "Possibly unused import"

    # The hallucinated finding never appears.
    assert all(f.title != "Imaginary flaw" for f in result.findings)

    # No duplicate card for the SQL issue.
    sql_cards = [f for f in result.findings if f.detector == "sql_string_construction"]
    assert len(sql_cards) == 1

    # Provider actually saw the deterministic findings and a budgeted context.
    assert provider.received_findings is not None
    assert len(provider.received_findings) == len(deterministic.findings)
    assert provider.received_context.budget["chars_used"] <= 24_000


def test_risk_stays_deterministic_with_confirmed_assessments():
    deterministic = _deterministic_result()
    sql_id = _sql_finding_id(deterministic)
    result = AnalysisOrchestrator(ai_provider=_fake_provider(sql_id)).run_on_local_path(FIXTURE)
    # Independent recomputation from the final findings must match exactly.
    expected = risk_engine.calculate_risk(result.findings)
    assert result.risk.score == expected.score
    assert result.risk.level == expected.level


def test_ai_failure_degrades_gracefully_deterministic_survives():
    deterministic = _deterministic_result()
    provider = FakeAIProvider(exc=AIUpstreamError("upstream exploded"))
    result = AnalysisOrchestrator(ai_provider=provider).run_on_local_path(FIXTURE)

    assert result.ai.status == AIStatusValue.FAILED
    assert result.ai.error_code == AIUpstreamError.code
    assert [f.id for f in result.findings] == [f.id for f in deterministic.findings]
    assert result.risk.score == deterministic.risk.score
    assert result.summary.findings_total == deterministic.summary.findings_total


def test_unexpected_provider_exception_degrades_not_500():
    provider = FakeAIProvider(exc=RuntimeError("provider bug"))
    result = AnalysisOrchestrator(ai_provider=provider).run_on_local_path(FIXTURE)
    assert result.ai.status == AIStatusValue.FAILED
    assert result.ai.error_code == AIUpstreamError.code
    assert result.summary.findings_total > 0


def test_stub_provider_means_ai_disabled_findings_unchanged():
    deterministic = _deterministic_result()
    assert deterministic.ai.status == AIStatusValue.DISABLED
    plain = AnalysisOrchestrator(ai_provider=None)
    # No credentials in this environment -> auto-resolves to disabled too.
    if plain._ai_provider is None:
        again = plain.run_on_local_path(FIXTURE)
        assert [f.id for f in again.findings] == [f.id for f in deterministic.findings]


def test_unlikely_verdict_demotes_confidence_and_lowers_risk_input():
    deterministic = _deterministic_result()
    sql_id = _sql_finding_id(deterministic)

    provider = FakeAIProvider(
        assessments=[
            AIAssessment(
                finding_id=sql_id,
                verdict=AIVerdict.UNLIKELY,
                confidence=Confidence.HIGH,
                reasoning="EVIDENCE suggests the value is sanitized elsewhere.",
            )
        ]
    )
    result = AnalysisOrchestrator(ai_provider=provider).run_on_local_path(FIXTURE)
    after = next(f for f in result.findings if f.id == sql_id)
    assert after.confidence == Confidence.LOW
    # The finding still exists (fail-closed); risk is recomputed deterministically.
    assert result.risk.score == risk_engine.calculate_risk(result.findings).score
