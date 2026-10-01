"""Tests for the AI result processor: assessment application + deduplication.

Pure deterministic rules — no network, no model. The invariants under test:
AI enriches but never rewrites the evidence anchor (id/file/line/evidence/
severity/detector/source stay fixed) and never deletes a deterministic
finding; duplicates merge into the deterministic anchor.
"""

from __future__ import annotations

from models.schemas import (
    AIAssessment,
    AIFindingCandidate,
    AIVerdict,
    Category,
    Confidence,
    Finding,
    FindingSource,
    Severity,
)
from services.ai_provider import AIInvestigationResult
from services.ai_result_processor import (
    AI_DETECTOR_NAME,
    apply_assessments,
    candidate_to_finding,
    merge_ai_results,
)
from services.finding_validator import validate_findings


def _finding(fid="det:app.py:10", confidence=Confidence.HIGH, **over) -> Finding:
    base = dict(
        id=fid,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="SQL concat",
        description="String-built SQL.",
        file="app.py",
        line=10,
        evidence="q = 'SELECT ' + x",
        confidence=confidence,
        source=FindingSource.DETERMINISTIC,
        detector="sql_string_construction",
    )
    base.update(over)
    return Finding(**base)


def _assessment(fid, verdict=AIVerdict.CONFIRMED) -> AIAssessment:
    return AIAssessment(
        finding_id=fid,
        verdict=verdict,
        confidence=Confidence.HIGH,
        reasoning="EVIDENCE: concat. INFERENCE: injectable.",
        suggested_fix="Parameterize.",
    )


def _candidate(line=50, category=Category.SECURITY, file="app.py") -> AIFindingCandidate:
    return AIFindingCandidate(
        title="New issue",
        category=category,
        severity=Severity.MEDIUM,
        file=file,
        line=line,
        evidence="do_evil(x)",
        description="Suspicious call.",
        confidence=Confidence.MEDIUM,
        reasoning="EVIDENCE shows the call.",
    )


def _result(assessments=(), candidates=()) -> AIInvestigationResult:
    return AIInvestigationResult(
        status="enabled",
        assessments=list(assessments),
        candidates=list(candidates),
        provider_name="nemotron",
        prompt_version="codeaudit-security-v1",
    )


def test_confirmed_attaches_reasoning_and_fix():
    enriched, count, ignored = apply_assessments(
        [_finding()], [_assessment("det:app.py:10")],
        provider_name="nemotron", prompt_version="v1",
    )
    assert count == 1 and ignored == 0
    f = enriched[0]
    assert f.ai_reasoning.startswith("EVIDENCE")
    assert f.suggested_fix == "Parameterize."
    assert f.enriched_by == "nemotron"
    assert f.prompt_version == "v1"
    # Evidence anchor untouched.
    assert (f.id, f.file, f.line, f.evidence, f.detector) == (
        "det:app.py:10", "app.py", 10, "q = 'SELECT ' + x", "sql_string_construction",
    )
    assert f.severity == Severity.HIGH
    assert f.source == FindingSource.DETERMINISTIC
    assert f.confidence == Confidence.HIGH  # confirmed: no demotion


def test_uncertain_demotes_confidence_one_step():
    enriched, _, _ = apply_assessments(
        [_finding(confidence=Confidence.HIGH)],
        [_assessment("det:app.py:10", AIVerdict.UNCERTAIN)],
        provider_name="nemotron", prompt_version="v1",
    )
    assert enriched[0].confidence == Confidence.MEDIUM


def test_unlikely_demotes_to_low_but_keeps_finding():
    enriched, count, _ = apply_assessments(
        [_finding()],
        [_assessment("det:app.py:10", AIVerdict.UNLIKELY)],
        provider_name="nemotron", prompt_version="v1",
    )
    assert count == 1  # finding survives; AI never deletes deterministic findings
    assert enriched[0].confidence == Confidence.LOW
    assert enriched[0].ai_reasoning  # reasoning still recorded


def test_unknown_assessment_id_ignored():
    _, count, ignored = apply_assessments(
        [_finding()], [_assessment("nope:app.py:1")],
        provider_name="nemotron", prompt_version="v1",
    )
    assert count == 0 and ignored == 1


def test_duplicate_assessment_first_wins():
    _, count, ignored = apply_assessments(
        [_finding()],
        [_assessment("det:app.py:10"), _assessment("det:app.py:10", AIVerdict.UNLIKELY)],
        provider_name="nemotron", prompt_version="v1",
    )
    assert count == 1 and ignored == 1


def test_exact_duplicate_candidate_merges_into_anchor():
    merged = merge_ai_results(
        [_finding()], _result(candidates=[_candidate(line=10)])
    )
    assert merged.new_candidates == []
    assert merged.duplicates_merged == 1
    # Candidate reasoning enriches the anchor; anchor identity preserved.
    assert merged.enriched[0].ai_reasoning == "EVIDENCE shows the call."
    assert merged.enriched[0].source == FindingSource.DETERMINISTIC


def test_near_line_duplicate_merges():
    merged = merge_ai_results(
        [_finding()], _result(candidates=[_candidate(line=11)])
    )
    assert merged.duplicates_merged == 1
    assert merged.new_candidates == []


def test_different_category_same_file_not_merged():
    merged = merge_ai_results(
        [_finding()], _result(candidates=[_candidate(line=10, category=Category.QUALITY)])
    )
    assert merged.duplicates_merged == 0
    assert len(merged.new_candidates) == 1


def test_far_line_not_merged():
    merged = merge_ai_results(
        [_finding()], _result(candidates=[_candidate(line=50)])
    )
    assert len(merged.new_candidates) == 1


def test_candidate_candidate_duplicate_first_wins():
    merged = merge_ai_results(
        [], _result(candidates=[_candidate(line=50), _candidate(line=51)])
    )
    assert len(merged.new_candidates) == 1
    assert merged.duplicates_merged == 1


def test_candidate_converted_with_ai_attribution():
    finding = candidate_to_finding(
        _candidate(), provider_name="nemotron", prompt_version="v1"
    )
    assert finding.source == FindingSource.AI
    assert finding.detector == AI_DETECTOR_NAME
    assert finding.enriched_by == "nemotron"
    assert finding.prompt_version == "v1"
    assert finding.id.startswith("ai:app.py:50:")
    # Deterministic ids for identical candidates.
    again = candidate_to_finding(
        _candidate(), provider_name="nemotron", prompt_version="v1"
    )
    assert again.id == finding.id


def test_input_lists_not_mutated():
    findings = [_finding()]
    assessments = [_assessment("det:app.py:10", AIVerdict.UNLIKELY)]
    apply_assessments(findings, assessments, provider_name="n", prompt_version="v")
    assert findings[0].confidence == Confidence.HIGH
    assert findings[0].ai_reasoning is None


# --- Regression tests: case-sensitive repository path handling ---
#
# _normalize_path() used to lowercase the whole path, which corrupted
# case-sensitive repository paths ("Auth/Login.py" -> "auth/login.py") and
# made findings miss the evidence hard gate's exact lookup in scan.contents.
# Canonical paths must preserve case; only separators/whitespace normalize.


def test_candidate_path_case_preserved():
    # A: AI candidate file "Auth/Login.py" -> final finding keeps its case.
    finding = candidate_to_finding(
        _candidate(file="Auth/Login.py"), provider_name="nemotron", prompt_version="v1"
    )
    assert finding.file == "Auth/Login.py"
    assert finding.id.startswith("ai:Auth/Login.py:50:")


def test_backslash_normalized_without_lowercasing():
    # B: "Auth\Login.py" -> "Auth/Login.py" (separators fixed, case kept).
    finding = candidate_to_finding(
        _candidate(file="Auth\\Login.py"),
        provider_name="nemotron",
        prompt_version="v1",
    )
    assert finding.file == "Auth/Login.py"


def test_evidence_gate_passes_for_case_matching_path():
    # C: scanned path "Auth/Login.py" + AI citing "Auth/Login.py" -> validated.
    contents = {"Auth/Login.py": "header = True\nq = 'SELECT ' + x\nfooter = True\n"}
    candidate = _candidate(file="Auth/Login.py", line=2).model_copy(
        update={"evidence": "q = 'SELECT ' + x"}
    )
    merged = merge_ai_results([], _result(candidates=[candidate]))
    assert len(merged.new_candidates) == 1
    result = validate_findings(merged.new_candidates, contents)
    assert len(result.validated) == 1
    assert result.validated[0].file == "Auth/Login.py"
    assert result.drop_reasons == {}


def test_mismatched_case_path_does_not_silently_resolve():
    # D: only "Auth/Login.py" exists but AI cites "auth/login.py" ->
    # the candidate is dropped (file_not_found), NOT rewritten to the
    # real file's case.
    contents = {"Auth/Login.py": "header = True\nq = 'SELECT ' + x\nfooter = True\n"}
    candidate = _candidate(file="auth/login.py", line=2).model_copy(
        update={"evidence": "q = 'SELECT ' + x"}
    )
    merged = merge_ai_results([], _result(candidates=[candidate]))
    assert len(merged.new_candidates) == 1
    assert merged.new_candidates[0].file == "auth/login.py"
    result = validate_findings(merged.new_candidates, contents)
    assert len(result.validated) == 0
    assert result.drop_reasons.get("file_not_found") == 1


def test_dedup_matching_is_case_sensitive():
    # A wrong-case AI candidate must not merge into a deterministic anchor:
    # on a case-sensitive filesystem these are different files, and merging
    # would attach reasoning to evidence it does not match.
    det = _finding(file="Auth/Login.py", line=10)
    merged = merge_ai_results(
        [det], _result(candidates=[_candidate(file="auth/login.py", line=10)])
    )
    assert merged.duplicates_merged == 0
    assert len(merged.new_candidates) == 1
    assert merged.new_candidates[0].file == "auth/login.py"


def test_repeated_separators_collapsed_case_preserved():
    finding = candidate_to_finding(
        _candidate(file="  Auth//Login.py  "),
        provider_name="nemotron",
        prompt_version="v1",
    )
    assert finding.file == "Auth/Login.py"


def test_traversal_segments_not_silently_repaired():
    # E (processor layer): ".." is never normalized away here. Rejection
    # stays enforced fail-closed at the service boundary — see
    # test_path_traversal_rejected / test_absolute_path_rejected in
    # test_ai_service.py, which must keep passing.
    finding = candidate_to_finding(
        _candidate(file="a/../../etc/passwd"),
        provider_name="nemotron",
        prompt_version="v1",
    )
    assert ".." in finding.file.split("/")
