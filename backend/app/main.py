"""CodeAudit Agent backend — FastAPI application entry point.

Small by design: route registration and error mapping only. All analysis
logic lives in the service layer (see services/orchestrator.py).
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.config import settings
from models.schemas import AnalysisRequest, AnalysisResult, ErrorResponse
from services import github_service
from services.orchestrator import AnalysisOrchestrator

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
        "Phase 1: deterministic static analysis over a FastAPI backend."
    ),
)

orchestrator = AnalysisOrchestrator()


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
