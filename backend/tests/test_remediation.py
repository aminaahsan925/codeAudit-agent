"""End-to-end remediation tests: FIND -> FIX -> VERIFY (§20 and §14).

All runs are hermetic: fixture repositories are copied into tmp_path, the AI
provider is a FakeAIProvider or a NemotronService with a FakeOpenAIClient —
no network, no API key. Every failure mode asserts the original repository is
byte-identical afterwards (§14): the model proposes, the system controls the
patch, the system verifies.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from models.schemas import (
    AnalysisResult,
    FixChange,
    FixDecision,
    FixProposal,
    RemediationStatus,
    VerificationStatus,
)
from services.ai_errors import (
    AIOutputInvalid,
    AIProviderNotConfigured,
    AIUpstreamError,
)
from services.ai_provider import StubAIProvider
from services.nemotron_service import NemotronService
from services.orchestrator import AnalysisOrchestrator
from services.remediation_engine import RemediationEngine, temporary_workspace
from services.remediation_errors import RemediationFindingNotFound
from tests.fakes import FakeAIProvider, FakeOpenAIClient

SQLI = "sql_string_construction:app.py:9"
EVAL = "dangerous_eval:app.py:5"
EXEC_LINE = '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
GOOD_FIX = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
BAD_FIX = '    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
EVAL_FIX = '    eval("fetch_user_" + user_id)'
EVAL_EVIDENCE = "    return eval(payload)"
EVAL_SAFE = "    return ast.literal_eval(payload)"


@pytest.fixture()
def repo(tmp_path: Path, fixtures_dir: Path) -> Path:
    dest = tmp_path / "repo"
    shutil.copytree(fixtures_dir / "remediation_sqli", dest)
    return dest


@pytest.fixture()
def eval_repo(tmp_path: Path, fixtures_dir: Path) -> Path:
    dest = tmp_path / "repo"
    shutil.copytree(fixtures_dir / "remediation_eval", dest)
    return dest


def _before(repo_dir: Path) -> AnalysisResult:
    orch = AnalysisOrchestrator(ai_provider=StubAIProvider())
    return orch.run_on_local_path(repo_dir)


def _proposal(
    finding_id: str,
    changes: list[FixChange],
    decision: FixDecision = FixDecision.FIX,
    reasoning: str = "parameterize the query",
) -> FixProposal:
    return FixProposal(
        finding_id=finding_id,
        decision=decision,
        reasoning=reasoning,
        changes=changes,
        expected_effect="finding eliminated",
        verification_notes="rerun the analyzer",
    )


def _change(file: str, old: str, new: str, start: int = 9, end: int = 9) -> FixChange:
    return FixChange(
        file=file,
        start_line=start,
        end_line=end,
        old_text=old,
        new_text=new,
        rationale="fix",
    )


def _engine_for(proposal=None, **fake_kwargs) -> RemediationEngine:
    return RemediationEngine(ai_provider=FakeAIProvider(fix_proposal=proposal, **fake_kwargs))


def _snapshot(repo_dir: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(repo_dir)): p.read_bytes()
        for p in sorted(repo_dir.rglob("*"))
        if p.is_file()
    }


# --- §20: the three canonical outcomes -------------------------------------


def test_good_fix_verifies(repo: Path):
    """(J) Parameterized query: the finding is gone, nothing new appears."""
    before = _before(repo)
    original = _snapshot(repo)
    proposal = _proposal(SQLI, [_change("app.py", EXEC_LINE, GOOD_FIX)])

    result = _engine_for(proposal).remediate_finding(SQLI, repo, before)

    assert result.status == RemediationStatus.VERIFIED
    assert result.verification.status == VerificationStatus.VERIFIED
    assert result.verification.verified is True
    assert len(result.changes_applied) == 1
    assert result.changes_rejected == []
    # Traceability is stamped by the system.
    assert result.proposal.finding_id == SQLI
    assert result.proposal.provider == "fake"
    assert result.proposal.prompt_version == "fake-fix-prompt-v1"
    # The original repository was never modified.
    assert _snapshot(repo) == original


def test_bad_fix_does_not_verify(repo: Path):
    """(K) %-formatting is still dynamic SQL: the detector still fires."""
    before = _before(repo)
    original = _snapshot(repo)
    proposal = _proposal(SQLI, [_change("app.py", EXEC_LINE, BAD_FIX)])

    result = _engine_for(proposal).remediate_finding(SQLI, repo, before)

    assert result.status == RemediationStatus.NOT_VERIFIED
    assert result.verification.verified is False
    # The model's claim does not override the deterministic verdict.
    assert _snapshot(repo) == original


def test_fix_introducing_new_issue_is_flagged(repo: Path):
    """(L) SQLi gone, but eval() appears: NEW_ISSUE_INTRODUCED."""
    before = _before(repo)
    original = _snapshot(repo)
    proposal = _proposal(SQLI, [_change("app.py", EXEC_LINE, EVAL_FIX)])

    result = _engine_for(proposal).remediate_finding(SQLI, repo, before)

    assert result.status == RemediationStatus.NEW_ISSUE_INTRODUCED
    assert result.verification.verified is False
    assert "dangerous_eval:app.py:9" in result.verification.new_findings_introduced
    assert _snapshot(repo) == original


# --- line shifts, risk, traceability ---------------------------------------


def test_fix_that_shifts_lines_still_verifies(repo: Path):
    """(Q) A fix inserting lines above the finding still verifies."""
    before = _before(repo)
    shift = _change("app.py", "import sqlite3", "import sqlite3\nimport os",
                    start=3, end=3)
    fix = _change("app.py", EXEC_LINE, GOOD_FIX, start=9, end=9)
    proposal = _proposal(SQLI, [shift, fix])

    result = _engine_for(proposal).remediate_finding(SQLI, repo, before)

    assert result.status == RemediationStatus.VERIFIED
    assert len(result.changes_applied) == 2


def test_risk_recalculated_after_remediation(eval_repo: Path):
    """(R) risk_before/risk_after bracket the verified fix."""
    before = _before(eval_repo)
    assert before.risk.score == 1
    proposal = _proposal(EVAL, [_change("app.py", EVAL_EVIDENCE, EVAL_SAFE,
                                        start=5, end=5)])

    result = _engine_for(proposal).remediate_finding(EVAL, eval_repo, before)

    assert result.status == RemediationStatus.VERIFIED
    assert result.risk_before is not None and result.risk_before.score == 1
    assert result.risk_after is not None and result.risk_after.score == 0


def test_cannot_fix_decision_is_recorded(repo: Path):
    before = _before(repo)
    original = _snapshot(repo)
    proposal = _proposal(
        SQLI, [], decision=FixDecision.CANNOT_FIX,
        reasoning="The query builder is generated; a safe rewrite needs the ORM layer.",
    )

    result = _engine_for(proposal).remediate_finding(SQLI, repo, before)

    assert result.status == RemediationStatus.NOT_VERIFIED
    assert result.proposal.decision == FixDecision.CANNOT_FIX
    assert result.verification is None
    assert result.changes_applied == []
    assert _snapshot(repo) == original


def test_finding_not_in_result_raises(repo: Path):
    before = _before(repo)
    engine = RemediationEngine(ai_provider=FakeAIProvider())
    with pytest.raises(RemediationFindingNotFound):
        engine.remediate_finding("nope:here:1", repo, before)


# --- graceful degradation (§14: original untouched in every mode) ----------


def _service_with_response(response_text: str) -> NemotronService:
    return NemotronService(
        api_key="test-key",
        model="test-model",
        client_factory=lambda: FakeOpenAIClient(response_text=response_text),
    )


@pytest.mark.parametrize(
    "mode,make_engine,expected_status",
    [
        ("ai_upstream_error",
         lambda: RemediationEngine(ai_provider=FakeAIProvider(fix_exc=AIUpstreamError("boom"))),
         RemediationStatus.FAILED),
        ("ai_unexpected_exception",
         lambda: RemediationEngine(ai_provider=FakeAIProvider(fix_exc=RuntimeError("boom"))),
         RemediationStatus.FAILED),
        ("ai_disabled",
         lambda: RemediationEngine(ai_provider=FakeAIProvider(fix_status="disabled")),
         RemediationStatus.UNAVAILABLE),
        ("ai_not_configured",
         lambda: RemediationEngine(ai_provider=NemotronService()),
         RemediationStatus.UNAVAILABLE),
        ("malformed_model_json",
         lambda: RemediationEngine(ai_provider=_service_with_response("this is not json")),
         RemediationStatus.FAILED),
        ("patch_validation_failure",
         lambda: _engine_for(_proposal(SQLI, [_change("app.py", "WRONG OLD TEXT", GOOD_FIX)])),
         RemediationStatus.PATCH_REJECTED),
        ("verification_failure",
         lambda: _engine_for(_proposal(SQLI, [_change("app.py", EXEC_LINE, BAD_FIX)])),
         RemediationStatus.NOT_VERIFIED),
        ("cannot_fix",
         lambda: _engine_for(_proposal(SQLI, [], decision=FixDecision.CANNOT_FIX)),
         RemediationStatus.NOT_VERIFIED),
    ],
)
def test_original_untouched_across_failure_modes(repo: Path, mode, make_engine, expected_status):
    before = _before(repo)
    original = _snapshot(repo)

    result = make_engine().remediate_finding(SQLI, repo, before)

    assert result.status == expected_status, mode
    assert result.error_code is None or isinstance(result.error_code, str)
    assert _snapshot(repo) == original, mode


def test_malformed_json_maps_to_sanitized_error_code(repo: Path):
    before = _before(repo)
    engine = RemediationEngine(ai_provider=_service_with_response("{oops"))
    result = engine.remediate_finding(SQLI, repo, before)
    assert result.status == RemediationStatus.FAILED
    assert result.error_code == AIOutputInvalid.code


def test_ai_error_carries_code_not_traceback(repo: Path):
    before = _before(repo)
    engine = RemediationEngine(
        ai_provider=FakeAIProvider(fix_exc=AIUpstreamError("connection reset by peer"))
    )
    result = engine.remediate_finding(SQLI, repo, before)
    assert result.status == RemediationStatus.FAILED
    assert result.error_code == AIUpstreamError.code
    assert "Traceback" not in (result.error_message or "")
    assert "connection reset" not in (result.error_message or "")


def test_unconfigured_provider_degrades_to_unavailable(repo: Path):
    engine = RemediationEngine(ai_provider=NemotronService())
    result = engine.remediate_finding(SQLI, repo, _before(repo))
    assert result.status == RemediationStatus.UNAVAILABLE
    assert result.error_code == AIProviderNotConfigured.code


def test_none_provider_auto_selects_and_degrades(repo: Path):
    # No NEBIUS_API_KEY in this environment: auto-selection yields no provider.
    engine = RemediationEngine(ai_provider=None)
    assert engine._ai_provider is None
    result = engine.remediate_finding(SQLI, repo, _before(repo))
    assert result.status == RemediationStatus.UNAVAILABLE
    assert result.error_code == AIProviderNotConfigured.code


# --- workspace isolation (I) ------------------------------------------------


def test_temporary_workspace_is_isolated_and_cleaned_up(repo: Path):
    probe = repo / "probe.txt"
    probe.write_text("x", encoding="utf-8")
    with temporary_workspace(repo) as ws:
        assert ws != repo
        assert (ws / "app.py").exists()
        (ws / "app.py").write_text("mutated", encoding="utf-8")
        (ws / "new_file.py").write_text("new", encoding="utf-8")
        assert probe.read_text(encoding="utf-8") == "x"
    assert (repo / "app.py").read_text(encoding="utf-8") != "mutated"
    assert not (repo / "new_file.py").exists()
    # The temp directory itself is gone.
    assert not ws.exists()


def test_workspace_cleans_up_on_error(repo: Path):
    captured = {}
    try:
        with temporary_workspace(repo) as ws:
            captured["ws"] = ws
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert not captured["ws"].exists()


# --- batch ------------------------------------------------------------------


def test_batch_cap_is_enforced(repo: Path):
    before = _before(repo)
    engine = _engine_for(_proposal(SQLI, [_change("app.py", EXEC_LINE, GOOD_FIX)]))
    results = engine.remediate_findings([SQLI] * 5, repo, before)
    assert len(results) == 3  # CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST
    assert all(r.status == RemediationStatus.VERIFIED for r in results)


def test_batch_each_finding_independent(repo: Path):
    before = _before(repo)
    engine = _engine_for(_proposal(SQLI, [_change("app.py", EXEC_LINE, GOOD_FIX)]))
    results = engine.remediate_findings([SQLI, SQLI], repo, before)
    assert len(results) == 2
    assert all(r.status == RemediationStatus.VERIFIED for r in results)


# --- service-level propose_fix ----------------------------------------------


def _fix_context_for(finding) -> "FixContext":
    from services.fix_context_builder import FixContext

    return FixContext(
        finding=finding,
        file_path=finding.file,
        evidence_window=f"9 | {EXEC_LINE}",
        window_start=9,
        window_end=9,
    )


def test_propose_fix_not_configured_raises():
    from tests.test_verification_engine import _finding as mk

    service = NemotronService()
    assert not service.is_configured
    with pytest.raises(AIProviderNotConfigured):
        service.propose_fix(mk(), _fix_context_for(mk()))


def test_propose_fix_parses_valid_proposal():
    import json

    payload = json.dumps({
        "decision": "fix",
        "reasoning": "Use parameterized queries.",
        "changes": [{
            "file": "app.py",
            "start_line": 9,
            "end_line": 9,
            "old_text": EXEC_LINE,
            "new_text": GOOD_FIX,
            "rationale": "parameterize",
        }],
        "expected_effect": "sql_string_construction eliminated",
        "verification_notes": "rerun analyzer",
    })
    service = _service_with_response(payload)
    from tests.test_verification_engine import _finding as mk

    finding = mk()
    result = service.propose_fix(finding, _fix_context_for(finding))
    assert result.status == "enabled"
    assert result.proposal.decision == FixDecision.FIX
    assert len(result.proposal.changes) == 1
    assert result.prompt_version == "codeaudit-remediation-v1"


def test_propose_fix_rejects_traversal_path():
    import json

    payload = json.dumps({
        "decision": "fix",
        "reasoning": "r",
        "changes": [{
            "file": "../../evil.py",
            "start_line": 1,
            "end_line": 1,
            "old_text": "x",
            "new_text": "y",
            "rationale": "evil",
        }],
        "expected_effect": "e",
        "verification_notes": "v",
    })
    service = _service_with_response(payload)
    from tests.test_verification_engine import _finding as mk

    finding = mk()
    with pytest.raises(AIOutputInvalid):
        service.propose_fix(finding, _fix_context_for(finding))
