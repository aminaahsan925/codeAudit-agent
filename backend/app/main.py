"""CodeAudit Agent backend — FastAPI application entry point.

Small by design: route registration and error mapping only. All analysis
logic lives in the service layer (see services/orchestrator.py).
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import settings
from models.schemas import (
    AnalysisRequest,
    AnalysisResult,
    BatchRemediationRequest,
    ErrorResponse,
    RemediationRequest,
    RemediationResult,
)
from services import github_service, repository_scanner
from services.orchestrator import AnalysisOrchestrator
from services.remediation_engine import RemediationEngine
from services.remediation_errors import (
    RemediationError,
    RemediationFindingNotFound,
    SAFE_MESSAGES as REMEDIATION_SAFE_MESSAGES,
)

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Evidence-driven security and code-quality analysis for GitHub repositories. "
        "Phase 2: deterministic static analysis plus Nemotron AI reasoning over "
        "verified repository evidence."
    ),
)

orchestrator = AnalysisOrchestrator()
remediation_engine = RemediationEngine()


@app.exception_handler(RemediationFindingNotFound)
async def remediation_not_found_handler(
    request: Request, exc: RemediationFindingNotFound
) -> JSONResponse:
    logger.warning("Remediation finding not found for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content=ErrorResponse(
            error={
                "code": exc.code,
                "message": REMEDIATION_SAFE_MESSAGES.get(exc.code, exc.code),
            }
        ).model_dump(mode="json"),
    )


@app.exception_handler(RemediationError)
async def remediation_error_handler(
    request: Request, exc: RemediationError
) -> JSONResponse:
    logger.warning("Remediation error for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error={
                "code": exc.code,
                "message": REMEDIATION_SAFE_MESSAGES.get(exc.code, exc.code),
            }
        ).model_dump(mode="json"),
    )


@app.exception_handler(github_service.GitHubError)
async def github_error_handler(request: Request, exc: github_service.GitHubError) -> JSONResponse:
    status_code = {
        github_service.InvalidRepositoryURLError: status.HTTP_422_UNPROCESSABLE_CONTENT,
        github_service.RepositoryNotFoundError: status.HTTP_404_NOT_FOUND,
        github_service.CloneTimeoutError: status.HTTP_504_GATEWAY_TIMEOUT,
    }.get(type(exc), status.HTTP_502_BAD_GATEWAY)
    logger.warning("GitHub error for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            error={"code": exc.code, "message": str(exc)}
        ).model_dump(mode="json"),
    )


@app.exception_handler(repository_scanner.RepositoryTooLargeError)
async def repo_too_large_handler(
    request: Request, exc: repository_scanner.RepositoryTooLargeError
) -> JSONResponse:
    logger.warning("Repository too large for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        content=ErrorResponse(
            error={"code": exc.code, "message": str(exc)}
        ).model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Preserve FastAPI's own HTTP error contract (validation 422s, etc.);
    # only unexpected failures become structured 500s.
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None),
        )
    logger.exception("Unhandled error during %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error={
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred while analyzing the repository.",
            }
        ).model_dump(mode="json"),
    )


@app.get("/health")
def health() -> dict:
    """Liveness probe: stable, minimal contract."""
    return {"status": "ok", "version": settings.app_version}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(request: AnalysisRequest) -> AnalysisResult:
    """Analyze a public GitHub repository and return structured findings."""
    ref = github_service.validate_github_url(request.repository_url)
    with github_service.temporary_repo_dir() as tmp:
        repo_dir = tmp / "repo"
        orchestrator.fetch_repo(request.repository_url, repo_dir)
        return orchestrator.run(request.repository_url, repo_dir)


@app.post("/remediate", response_model=RemediationResult)
def remediate(request: RemediationRequest) -> RemediationResult:
    """Propose and deterministically verify a fix for one finding.

    FIND -> FIX -> VERIFY: Nemotron proposes a minimal patch, the patch
    engine validates and applies it inside an isolated temporary workspace,
    and the deterministic analyzer verifies the outcome. The original
    repository is never modified.
    """
    github_service.validate_github_url(request.repository_url)
    with github_service.temporary_repo_dir() as tmp:
        repo_dir = tmp / "repo"
        orchestrator.fetch_repo(request.repository_url, repo_dir)
        before = orchestrator.run(request.repository_url, repo_dir)
        return remediation_engine.remediate_finding(
            request.finding_id, repo_dir, before
        )


@app.post("/remediate/batch", response_model=list[RemediationResult])
def remediate_batch(request: BatchRemediationRequest) -> list[RemediationResult]:
    """Remediate several findings, each independently against the original
    repository. Hard-capped by CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST."""
    cap = settings.max_remediations_per_request
    if len(request.finding_ids) > cap:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"finding_ids exceeds the per-request limit of {cap} "
                "(CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST)"
            ),
        )
    github_service.validate_github_url(request.repository_url)
    with github_service.temporary_repo_dir() as tmp:
        repo_dir = tmp / "repo"
        orchestrator.fetch_repo(request.repository_url, repo_dir)
        before = orchestrator.run(request.repository_url, repo_dir)
        return remediation_engine.remediate_findings(
            request.finding_ids, repo_dir, before
        )
