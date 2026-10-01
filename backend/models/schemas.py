"""Typed API and domain models for CodeAudit.

Enums keep category/severity/confidence/source values consistent across
the codebase. Pydantic models define the API contract.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


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
            "per_finding_score = severity_weight * confidence_factor; "
            "repository_score = min(100, round(sum(per_finding_score) / 10)). "
            "Weights are heuristic and not scientifically validated."
        )
    )
    severity_weights: dict[str, int]
    confidence_factors: dict[str, float]
    findings_counted: int
    total_weighted_points: float


class RiskResult(BaseModel):
    score: int = Field(..., ge=0, le=100)
    level: str  # critical | high | medium | low
    breakdown: RiskBreakdown


class AnalysisSummary(BaseModel):
    files_discovered: int
    files_analyzed: int
    files_skipped: int
    files_failed_parse: int
    findings_total: int
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]


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
