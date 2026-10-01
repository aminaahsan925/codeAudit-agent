"""Typed API and domain models for CodeAudit.

Enums keep category/severity/confidence/source values consistent across
the codebase. Pydantic models define the API contract.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


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


class AnalysisResult(BaseModel):
    repository: RepositoryMetadata
    summary: AnalysisSummary
    findings: list[ValidatedFinding]
    risk: RiskResult
    ai: AIStatus = Field(default_factory=_disabled_ai_status)


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
