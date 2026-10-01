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


class AnalysisResult(BaseModel):
    repository: RepositoryMetadata
    summary: AnalysisSummary
    findings: list[ValidatedFinding]
    risk: RiskResult


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
