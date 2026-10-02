"""Typed API and domain models for CodeAudit.

Enums keep category/severity/confidence/source values consistent across
the codebase. Pydantic models define the API contract.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    QUALITY = "quality"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingSource(str, Enum):
    DETERMINISTIC = "deterministic"
    AI = "ai"


class AIVerdict(str, Enum):
    """Nemotron's judgment on one deterministic finding, from supplied evidence."""

    CONFIRMED = "confirmed"  # evidence supports the finding as stated
    UNCERTAIN = "uncertain"  # suspicious but evidence is insufficient
    UNLIKELY = "unlikely"  # evidence suggests a false positive


class AIStatusValue(str, Enum):
    DISABLED = "disabled"  # no provider configured (or explicitly turned off)
    ENABLED = "enabled"  # provider ran and returned a usable result
    UNAVAILABLE = "unavailable"  # provider misconfigured / model not reachable
    FAILED = "failed"  # provider call failed; deterministic results still returned


class AnalysisRequest(BaseModel):
    repository_url: str = Field(
        ..., description="Public GitHub repository URL, e.g. https://github.com/owner/repo"
    )


class RepositoryMetadata(BaseModel):
    owner: str
    name: str
    url: str
    default_branch: Optional[str] = None
    description: Optional[str] = None


class AnalyzedFile(BaseModel):
    relative_path: str
    language: Optional[str] = None
    size_bytes: int
    # Full content is kept in memory only during analysis; never serialized
    # into API responses.


class CodeSymbol(BaseModel):
    kind: str  # "function" | "class" | "import"
    name: str
    line: int
    end_line: Optional[int] = None


class ParsedFile(BaseModel):
    relative_path: str
    language: Optional[str] = None
    symbols: list[CodeSymbol] = Field(default_factory=list)
    parse_error: Optional[str] = None


class Finding(BaseModel):
    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    column: Optional[int] = None
    evidence: str = Field(..., description="Exact source snippet backing this finding")
    suggested_fix: Optional[str] = None
    confidence: Confidence
    source: FindingSource
    detector: str = Field(..., description="Name of the detector that produced this finding")
    language: Optional[str] = Field(
        default=None,
        description="Language the finding was detected in, e.g. 'python' or 'javascript'",
    )
    # AI traceability (Phase 2). Set only when Nemotron reasoned over this
    # finding. The deterministic fields above (id/file/line/evidence/detector)
    # are never rewritten by AI enrichment — they remain the evidence anchor.
    ai_reasoning: Optional[str] = Field(
        default=None, description="Nemotron's evidence-grounded reasoning, if any"
    )
    enriched_by: Optional[str] = Field(
        default=None, description="AI provider that enriched this finding, e.g. 'nemotron'"
    )
    prompt_version: Optional[str] = Field(
        default=None, description="Prompt version used for the AI reasoning, if any"
    )
    # Multi-agent traceability (Phase 3 upgrade). Which agents genuinely
    # participated in this finding's lifecycle. Never claims participation
    # that did not happen.
    provenance: Optional["FindingProvenance"] = Field(
        default=None, description="Agent participation trail for this finding"
    )


class FindingProvenance(BaseModel):
    """Which agents genuinely participated in a finding's lifecycle.

    detected_by: specialist agent(s) that surfaced it (or "evidence_agent"
        for AI-discovered findings that passed the evidence hard gate).
    reviewed_by: agents that reasoned over it (e.g. "evidence_agent").
    fixed_by / verified_by: populated along the remediation trail.
    """

    detected_by: list[str] = Field(default_factory=list)
    reviewed_by: list[str] = Field(default_factory=list)
    fixed_by: list[str] = Field(default_factory=list)
    verified_by: list[str] = Field(default_factory=list)


class ValidatedFinding(Finding):
    validation: str = Field(default="passed", description="'passed' or 'unverified'")


class RiskBreakdown(BaseModel):
    """Transparent, auditable account of how the risk score was computed."""

    formula: str = Field(
        default=(
            "per_finding_score = severity_weight * confidence_factor * reachability_factor; "
            "repository_score = min(10, round(sum(per_finding_score) / 100)), "
            "an integer on a 0-10 scale. "
            "reachability_factor is 1.25 when the finding's file path suggests "
            "web-exposed code (views/routes/handlers/controllers/api), else 1.0. "
            "Weights are heuristic and not scientifically validated."
        )
    )
    severity_weights: dict[str, int]
    confidence_factors: dict[str, float]
    reachability_factors: dict[str, float]
    findings_counted: int
    total_weighted_points: float


class RiskResult(BaseModel):
    score: int = Field(..., ge=0, le=10, description="Repository risk on a 0-10 scale")
    level: str  # critical | high | medium | low
    breakdown: RiskBreakdown


class AnalysisSummary(BaseModel):
    """File accounting for one analysis run.

    Every discovered file lands in exactly one terminal bucket:
    deep-analyzed, unsupported, skipped, or parse-failed.

    Reconciliation invariant (enforced below):
        files_discovered == files_deep_analyzed + files_unsupported
                            + files_skipped + files_failed_parse
        files_scanned    == files_deep_analyzed + files_unsupported
                            + files_failed_parse
    """

    files_discovered: int = Field(
        ..., description="Every file entry the walk encountered (dirs excluded)"
    )
    files_scanned: int = Field(
        ..., description="Passed exclusion filters; read and content-sniffed"
    )
    files_deep_analyzed: int = Field(
        ..., description="Python files successfully parsed and run through detectors"
    )
    files_unsupported: int = Field(
        ..., description="Scanned but not deep-analyzable (non-Python / unknown language)"
    )
    files_skipped: int = Field(
        ..., description="Excluded by ignore rules, limits, or unreadable (see skip_reasons)"
    )
    files_failed_parse: int = Field(
        ..., description="Python files whose AST parse failed"
    )
    findings_total: int
    findings_dropped: int = 0  # findings rejected by the evidence hard gate
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    skip_reasons: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_accounting(self) -> "AnalysisSummary":
        terminal = (
            self.files_deep_analyzed
            + self.files_unsupported
            + self.files_skipped
            + self.files_failed_parse
        )
        if self.files_discovered != terminal:
            raise ValueError(
                f"files_discovered ({self.files_discovered}) != deep_analyzed "
                f"({self.files_deep_analyzed}) + unsupported ({self.files_unsupported}) "
                f"+ skipped ({self.files_skipped}) + failed_parse ({self.files_failed_parse})"
            )
        if self.files_scanned != terminal - self.files_skipped:
            raise ValueError(
                f"files_scanned ({self.files_scanned}) != deep_analyzed "
                f"({self.files_deep_analyzed}) + unsupported ({self.files_unsupported}) "
                f"+ failed_parse ({self.files_failed_parse})"
            )
        return self


class AIFindingCandidate(BaseModel):
    """One raw candidate finding parsed from Nemotron's structured output.

    Never trusted directly: candidates go through path normalization,
    Pydantic validation, the evidence hard gate (FindingValidator), and
    deduplication before they can appear in a final result.
    """

    title: str = Field(..., min_length=1)
    category: Category
    severity: Severity
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    evidence: str = Field(..., min_length=1, description="Verbatim source snippet")
    description: str = Field(..., min_length=1)
    suggested_fix: Optional[str] = None
    confidence: Confidence
    reasoning: str = Field(
        ..., min_length=1, description="Why the evidence supports this conclusion"
    )


class AIAssessment(BaseModel):
    """Nemotron's verdict on one deterministic finding."""

    finding_id: str = Field(..., min_length=1)
    verdict: AIVerdict
    confidence: Confidence = Field(
        ..., description="The model's confidence in its own verdict"
    )
    reasoning: str = Field(..., min_length=1)
    suggested_fix: Optional[str] = None


class AIInvestigationResponse(BaseModel):
    """The complete structured contract Nemotron must return.

    The model must return exactly this JSON shape (see services/prompts).
    Anything else is rejected fail-closed: no AI findings are fabricated.
    """

    assessments: list[AIAssessment] = Field(default_factory=list)
    new_findings: list[AIFindingCandidate] = Field(default_factory=list)


class AIStatus(BaseModel):
    """Response metadata describing what the AI layer did (or why it didn't)."""

    status: AIStatusValue
    provider: str = Field(default="", description="AI provider name, e.g. 'nemotron'")
    model: Optional[str] = Field(default=None, description="Model id used, if any")
    prompt_version: Optional[str] = None
    model_calls: int = 0
    context_chars: int = 0
    deterministic_findings: int = 0
    findings_enriched: int = 0
    ai_findings_accepted: int = 0
    ai_findings_dropped: int = 0
    duplicates_merged: int = 0
    duration_ms: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = Field(
        default=None, description="Sanitized; never contains credentials or SDK internals"
    )


def _disabled_ai_status() -> AIStatus:
    return AIStatus(status=AIStatusValue.DISABLED)


class AIBudgetReport(BaseModel):
    """Cost visibility for one bounded AI budget (analysis or remediation).

    Monetary cost is deliberately NOT estimated: only call counts against
    the configured hard limit are reported.
    """

    mode: str = Field(..., description="'free' | 'economy' | 'full'")
    purpose: str = Field(..., description="'analysis' or 'remediation'")
    limit: int = Field(..., ge=0, description="Hard cap on Nemotron calls")
    used: int = Field(..., ge=0, description="Nemotron calls actually made")
    remaining: int = Field(..., ge=0)


class AgentInfo(BaseModel):
    """Per-agent execution record for the final supervisor report."""

    agent_name: str
    status: str = Field(..., description="'completed' | 'failed' | 'skipped' | 'degraded'")
    duration_ms: int = 0
    model_used: Optional[str] = Field(default=None)
    model_calls: int = 0
    context_chars: int = 0
    prompt_version: Optional[str] = None
    findings_count: int = 0
    errors: list[str] = Field(default_factory=list)


class AgentRunSummary(BaseModel):
    """Multi-agent execution metadata attached to an analysis result."""

    execution_id: str
    mode: str = Field(..., description="AI operating mode: 'free' | 'economy' | 'full'")
    completed: int = Field(default=0, description="Agents that completed")
    ai_calls: int = Field(default=0, description="Total Nemotron calls made")
    agents: list[AgentInfo] = Field(default_factory=list)
    budget: Optional[AIBudgetReport] = Field(
        default=None, description="Analysis-budget visibility"
    )


class AnalysisResult(BaseModel):
    repository: RepositoryMetadata
    summary: AnalysisSummary
    findings: list[ValidatedFinding]
    risk: RiskResult
    ai: AIStatus = Field(default_factory=_disabled_ai_status)
    # Multi-agent upgrade (Phase 3): optional so older clients keep working.
    agents: Optional[AgentRunSummary] = Field(
        default=None, description="Per-agent execution metadata, when run via the supervisor"
    )
    ai_budget: Optional[AIBudgetReport] = Field(
        default=None, description="AI call budget visibility for this analysis"
    )


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


# ---------------------------------------------------------------------------
# Phase 3 — safe remediation (FIND -> FIX -> VERIFY)
# ---------------------------------------------------------------------------


class FixDecision(str, Enum):
    """The model's verdict on whether it can propose a remediation."""

    FIX = "fix"
    CANNOT_FIX = "cannot_fix"


class VerificationStatus(str, Enum):
    """Deterministic outcome of verifying a proposed patch.

    Only the verification engine assigns these — never the model. The engine
    reruns the existing deterministic analyzers on the patched workspace and
    compares BEFORE vs AFTER.
    """

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    NOT_VERIFIED = "not_verified"
    PATCH_REJECTED = "patch_rejected"
    NEW_ISSUE_INTRODUCED = "new_issue_introduced"
    CANNOT_VERIFY = "cannot_verify"


class RemediationStatus(str, Enum):
    """Overall remediation outcome, returned by the remediation engine/API.

    Extends the verification outcomes with AI-layer outcomes: the model may
    be unavailable or fail, in which case the original analysis is preserved
    and nothing is patched.
    """

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    NOT_VERIFIED = "not_verified"
    PATCH_REJECTED = "patch_rejected"
    NEW_ISSUE_INTRODUCED = "new_issue_introduced"
    CANNOT_VERIFY = "cannot_verify"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class FixChange(BaseModel):
    """One proposed source change, anchored to exact existing content.

    Phase 3 v1 only modifies existing lines: every change must reference an
    existing repository-relative file and a valid line range, and ``old_text``
    must match the actual content at that range before anything is applied.
    Arbitrary file creation/deletion is not representable.
    """

    file: str = Field(..., min_length=1, description="Repository-relative path, case-sensitive")
    start_line: int = Field(..., ge=1)
    end_line: int = Field(..., ge=1)
    old_text: str = Field(..., min_length=1, description="Exact current text at the range")
    new_text: str = Field(..., min_length=1, description="Replacement text (never empty: no deletions in v1)")

    @field_validator("new_text")
    @classmethod
    def _new_text_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("new_text must not be blank (no deletions in v1)")
        return v

    @model_validator(mode="after")
    def _range_must_be_ordered(self) -> "FixChange":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class FixProposal(BaseModel):
    """Structured remediation proposal. The model proposes; the system stamps
    traceability fields (finding_id/provider/model/prompt_version) — the
    model's own values for these are never trusted."""

    finding_id: str = Field(..., min_length=1)
    decision: FixDecision
    reasoning: str = Field(..., min_length=1)
    changes: list[FixChange] = Field(default_factory=list)
    expected_effect: str = ""
    verification_notes: str = ""
    provider: str = ""
    model: str = ""
    prompt_version: str = ""

    @model_validator(mode="after")
    def _decision_matches_changes(self) -> "FixProposal":
        if self.decision == FixDecision.CANNOT_FIX and self.changes:
            raise ValueError("decision 'cannot_fix' must not carry changes")
        if self.decision == FixDecision.FIX and not self.changes:
            raise ValueError("decision 'fix' requires at least one change")
        return self


class AppliedChange(BaseModel):
    """Record of one change the patch engine applied in the temp workspace."""

    file: str
    start_line: int
    end_line: int
    lines_changed: int
    before: str = Field(..., description="Original text (bounded excerpt)")
    after: str = Field(..., description="Patched text (bounded excerpt)")


class RejectedChange(BaseModel):
    """Record of one proposed change the patch engine refused to apply."""

    file: str
    start_line: int
    end_line: int
    reason: str = Field(..., description="Machine-readable rejection reason")


class VerificationResult(BaseModel):
    """Deterministic BEFORE/AFTER comparison for one remediated finding."""

    status: VerificationStatus
    original_finding_id: str
    finding_present_before: bool
    finding_present_after: bool
    original_evidence_present_before: bool
    original_evidence_present_after: bool
    new_findings_introduced: list[str] = Field(
        default_factory=list, description="Ids of verified findings introduced by the patch"
    )
    verified: bool = Field(..., description="True only when status == verified")
    reason: str = ""


class RemediationResult(BaseModel):
    """Complete outcome of one FIND -> FIX -> VERIFY cycle."""

    status: RemediationStatus
    finding_id: str
    proposal: Optional[FixProposal] = None
    verification: Optional[VerificationResult] = None
    changes_applied: list[AppliedChange] = Field(default_factory=list)
    changes_rejected: list[RejectedChange] = Field(default_factory=list)
    risk_before: Optional[RiskResult] = None
    risk_after: Optional[RiskResult] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    # Multi-agent upgrade: which agents genuinely participated in this
    # remediation (subset of fix_agent / patch_guard / verification_agent).
    agent_trail: list[str] = Field(default_factory=list)


class RemediationRequest(BaseModel):
    repository_url: str = Field(..., min_length=1)
    finding_id: str = Field(..., min_length=1)


class BatchRemediationRequest(BaseModel):
    repository_url: str = Field(..., min_length=1)
    finding_ids: List[str] = Field(..., min_length=1)
