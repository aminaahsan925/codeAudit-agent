"""CodeAudit Agent backend — FastAPI application entry point.

Route registration and error mapping only. All analysis logic lives in
the service layer (see services/orchestrator.py). Persistence-backed
routes (jobs, projects, website scans) are wired here; the engines live
in services/persistence and services/livescan.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from models.schemas import (
    AnalysisRequest,
    AnalysisResult,
    BatchRemediationRequest,
    ErrorResponse,
    FindingStatusUpdate,
    JobEnqueueResponse,
    JobStatusResponse,
    ProjectCreate,
    ProjectResponse,
    ProjectScansResponse,
    RemediationRequest,
    RemediationResult,
    RetestRequest,
    RetestResponse,
    WebsiteScanRequest,
    WebsiteScanResult,
)
from services import github_service, repository_scanner
from agents.supervisor_agent import SupervisorAgent
from services.livescan.errors import (
    LiveScanError,
    ScanAuthorizationError,
    ScanBudgetError,
    ScanScopeError,
    ScanTimeoutError,
    SSRFBlockedError,
)
from services.livescan.scanner import (
    WebsiteScanner,
    scan_config_from_settings,
)
from services.orchestrator import AnalysisOrchestrator
from services.persistence.database import (
    get_session_factory as db_get_session_factory,
)
from services.persistence.database import (
    init_db,
)
from services.persistence.jobs import (
    HANDLERS,
    JOB_KIND_REPO_ANALYSIS,
    JOB_KIND_WEBSITE_SCAN,
    enqueue_job,
    run_worker_forever,
)
from services.persistence.models import (
    FindingStatus,
    Project,
    RepoAnalysis,
    ScanJob,
    WebsiteScan,
)
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


# ---------------------------------------------------------------------------
# Persistence + background worker (Phase 7). Lazily initialized so importing
# this module (tests, etc.) never touches the database.
# ---------------------------------------------------------------------------

_session_factory_cache = None
_worker_stop = threading.Event()


def _session_factory():
    global _session_factory_cache
    if _session_factory_cache is None:
        init_db(settings.database_url)
        _session_factory_cache = db_get_session_factory(settings.database_url)
    return _session_factory_cache


def _utcnow_iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def finding_fingerprint(finding: dict) -> str:
    """Deterministic finding identity for lifecycle tracking + retest diffs."""
    key = "|".join(
        [
            str(finding.get("rule_id") or finding.get("detector") or ""),
            str(finding.get("file") or finding.get("url") or ""),
            str(finding.get("line") or 0),
            str(finding.get("title") or ""),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _store_repo_analysis(
    session, repository_url: str, project_id: str | None, result: dict
) -> str:
    record = RepoAnalysis(
        project_id=project_id,
        repository_url=repository_url,
        result_json=json.dumps(result),
    )
    session.add(record)
    session.flush()
    return record.id


def _store_website_scan(
    session, target_url: str, project_id: str | None, result: dict
) -> str:
    record = WebsiteScan(
        project_id=project_id,
        target_url=target_url,
        result_json=json.dumps(result),
    )
    session.add(record)
    session.flush()
    return record.id


def _run_repo_analysis_job(request: dict) -> dict:
    """Job handler: full repo analysis, result stored when project_id set."""
    repository_url = request.get("repository_url", "")
    project_id = request.get("project_id")
    ref = github_service.validate_github_url(repository_url)
    with github_service.temporary_repo_dir() as tmp:
        repo_dir = tmp / "repo"
        orchestrator.fetch_repo(repository_url, repo_dir)
        result = supervisor.run(repository_url, repo_dir)
    result_dict = result.model_dump(mode="json")
    if project_id:
        with _session_factory()() as session:
            _store_repo_analysis(session, repository_url, project_id, result_dict)
            session.commit()
    return result_dict


def _run_website_scan_job(request: dict) -> dict:
    """Job handler: full website scan, result stored when project_id set."""
    target_url = request.get("target_url", "")
    project_id = request.get("project_id")
    config = scan_config_from_settings(
        target_url=target_url,
        authorization_token=request.get("authorization_token", ""),
        i_authorize_this_scan=bool(request.get("i_authorize_this_scan")),
        include_subdomains=bool(request.get("include_subdomains", False)),
        path_prefix=request.get("path_prefix"),
        max_pages=request.get("max_pages"),
        active_probes=bool(request.get("active_probes", True)),
        session_cookie=request.get("session_cookie"),
        authorization_header=request.get("authorization_header"),
        settings=settings,
    )
    result = WebsiteScanner(config).run()
    result_dict = result.model_dump(mode="json")
    if project_id:
        with _session_factory()() as session:
            _store_website_scan(session, target_url, project_id, result_dict)
            session.commit()
    return result_dict


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Register job handlers and start the DEV-ONLY in-process worker.
    HANDLERS[JOB_KIND_REPO_ANALYSIS] = _run_repo_analysis_job
    HANDLERS[JOB_KIND_WEBSITE_SCAN] = _run_website_scan_job
    factory = _session_factory()
    worker = threading.Thread(
        target=run_worker_forever,
        args=(factory, _worker_stop),
        daemon=True,
        name="codeaudit-job-worker",
    )
    worker.start()
    logger.info("Background job worker started (dev in-process mode)")
    yield
    _worker_stop.set()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Evidence-driven security and code-quality analysis for GitHub repositories. "
        "Multi-agent backend: deterministic specialist agents (security, "
        "performance, quality) coordinated by a supervisor, with cost-capped "
        "Nemotron AI reasoning over verified repository evidence."
    ),
    lifespan=lifespan,
)

# The demo frontend is served from a different origin (e.g. 127.0.0.1:8080)
# than the API (:8000). Without CORS the browser blocks every response.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8080", "http://localhost:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = AnalysisOrchestrator()
remediation_engine = RemediationEngine()
# Multi-agent backend: the supervisor coordinates specialist agents with a
# hard AI-call budget (FREE/ECONOMY/FULL modes). Module-level `orchestrator`
# and `remediation_engine` names are kept for backward compatibility.
supervisor = SupervisorAgent(orchestrator=orchestrator)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------


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


@app.exception_handler(repository_scanner.AnalysisTimeoutError)
async def analysis_timeout_handler(
    request: Request, exc: repository_scanner.AnalysisTimeoutError
) -> JSONResponse:
    logger.warning("Analysis timed out for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        content=ErrorResponse(
            error={"code": exc.code, "message": str(exc)}
        ).model_dump(mode="json"),
    )


@app.exception_handler(LiveScanError)
async def livescan_error_handler(request: Request, exc: LiveScanError) -> JSONResponse:
    status_code = {
        ScanAuthorizationError: status.HTTP_403_FORBIDDEN,
        ScanScopeError: status.HTTP_400_BAD_REQUEST,
        SSRFBlockedError: status.HTTP_400_BAD_REQUEST,
        ScanBudgetError: status.HTTP_429_TOO_MANY_REQUESTS,
        ScanTimeoutError: status.HTTP_504_GATEWAY_TIMEOUT,
    }.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)
    logger.warning("Live scan error for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            error={"code": exc.code, "message": exc.message}
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
                "message": "An unexpected error occurred.",
            }
        ).model_dump(mode="json"),
    )


# ---------------------------------------------------------------------------
# Health + repository analysis
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    """Liveness probe: stable, minimal contract."""
    return {"status": "ok", "version": settings.app_version}


@app.post("/analyze", response_model=AnalysisResult, status_code=200)
def analyze(
    request: AnalysisRequest, async_mode: bool = Query(False, alias="async")
):
    """Analyze a public GitHub repository and return structured findings.

    Runs through the multi-agent supervisor: deterministic specialists
    (security, performance, quality) in parallel, budgeted Nemotron
    evidence review per the configured agent mode, deterministic fusion.

    With ``?async=true`` the analysis is queued as a background job and
    this returns HTTP 202 with a job id; poll ``GET /jobs/{job_id}``.
    """
    ref = github_service.validate_github_url(request.repository_url)
    if async_mode:
        with _session_factory()() as session:
            job = enqueue_job(
                session,
                kind=JOB_KIND_REPO_ANALYSIS,
                request=request.model_dump(mode="json"),
                project_id=request.project_id,
            )
            session.commit()
            job_id = job.id
        logger.info("Queued repo analysis job %s for %s", job_id, ref.url)
        return JSONResponse(status_code=202, content={"job_id": job_id})

    with github_service.temporary_repo_dir() as tmp:
        repo_dir = tmp / "repo"
        orchestrator.fetch_repo(request.repository_url, repo_dir)
        result = supervisor.run(request.repository_url, repo_dir)

    if request.project_id:
        with _session_factory()() as session:
            _store_repo_analysis(
                session,
                request.repository_url,
                request.project_id,
                result.model_dump(mode="json"),
            )
            session.commit()
    return result


@app.get("/jobs/{job_id}", response_model=JobStatusResponse)
def get_job(job_id: str) -> JobStatusResponse:
    """Poll a background job (queued by ``POST /analyze?async=true``)."""
    with _session_factory()() as session:
        job = session.get(ScanJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        result = json.loads(job.result_json) if job.result_json else None
        return JobStatusResponse(
            job_id=job.id,
            kind=job.kind,
            state=job.state,
            result=result,
            error_code=job.error_code,
            error_message=job.error_message,
            created_at=_utcnow_iso(job.created_at),
            updated_at=_utcnow_iso(job.updated_at),
        )


# ---------------------------------------------------------------------------
# Live website scanning (Phase B)
# ---------------------------------------------------------------------------


@app.post("/scan/website", response_model=WebsiteScanResult)
def scan_website(request: WebsiteScanRequest) -> WebsiteScanResult:
    """Run an authorized, SSRF-guarded live website scan.

    Authorization is verified before any network I/O. LiveScanError
    subclasses map to 400/403/429/504 via the registered handler.
    """
    config = scan_config_from_settings(
        target_url=request.target_url,
        authorization_token=request.authorization_token,
        i_authorize_this_scan=request.i_authorize_this_scan,
        include_subdomains=request.include_subdomains,
        path_prefix=request.path_prefix,
        max_pages=request.max_pages,
        active_probes=request.active_probes,
        session_cookie=request.session_cookie,
        authorization_header=request.authorization_header,
        settings=settings,
    )
    result = WebsiteScanner(config).run()

    if request.project_id:
        with _session_factory()() as session:
            _store_website_scan(
                session,
                request.target_url,
                request.project_id,
                result.model_dump(mode="json"),
            )
            session.commit()
    return result


# ---------------------------------------------------------------------------
# Projects + finding lifecycle (Phase 8)
# ---------------------------------------------------------------------------


@app.get("/projects", response_model=list[ProjectResponse])
def list_projects() -> list[ProjectResponse]:
    with _session_factory()() as session:
        projects = session.query(Project).order_by(Project.created_at.desc()).all()
        return [
            ProjectResponse(
                id=p.id, name=p.name, created_at=_utcnow_iso(p.created_at)
            )
            for p in projects
        ]


@app.post("/projects", response_model=ProjectResponse, status_code=201)
def create_project(request: ProjectCreate) -> ProjectResponse:
    with _session_factory()() as session:
        project = Project(name=request.name.strip())
        session.add(project)
        session.commit()
        session.refresh(project)
        return ProjectResponse(
            id=project.id, name=project.name, created_at=_utcnow_iso(project.created_at)
        )


def _require_project(session, project_id: str) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@app.get("/projects/{project_id}/scans", response_model=ProjectScansResponse)
def project_scans(project_id: str) -> ProjectScansResponse:
    with _session_factory()() as session:
        _require_project(session, project_id)
        analyses = (
            session.query(RepoAnalysis)
            .filter(RepoAnalysis.project_id == project_id)
            .order_by(RepoAnalysis.created_at.desc())
            .all()
        )
        scans = (
            session.query(WebsiteScan)
            .filter(WebsiteScan.project_id == project_id)
            .order_by(WebsiteScan.created_at.desc())
            .all()
        )
        return ProjectScansResponse(
            repo_analyses=[
                {
                    "id": a.id,
                    "repository_url": a.repository_url,
                    "created_at": _utcnow_iso(a.created_at),
                }
                for a in analyses
            ],
            website_scans=[
                {
                    "id": s.id,
                    "target_url": s.target_url,
                    "created_at": _utcnow_iso(s.created_at),
                }
                for s in scans
            ],
        )


def _findings_with_fingerprints(result: dict) -> list[dict]:
    items = []
    for f in result.get("findings", []):
        items.append({"fingerprint": finding_fingerprint(f), "finding": f})
    return items


@app.get("/analyses/{analysis_id}/findings")
def analysis_findings(analysis_id: str) -> list[dict]:
    with _session_factory()() as session:
        record = session.get(RepoAnalysis, analysis_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return _findings_with_fingerprints(json.loads(record.result_json))


@app.get("/website-scans/{scan_id}/findings")
def website_scan_findings(scan_id: str) -> list[dict]:
    with _session_factory()() as session:
        record = session.get(WebsiteScan, scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Website scan not found")
        return _findings_with_fingerprints(json.loads(record.result_json))


@app.get("/projects/{project_id}/findings/status")
def finding_statuses(project_id: str) -> list[dict]:
    with _session_factory()() as session:
        _require_project(session, project_id)
        rows = (
            session.query(FindingStatus)
            .filter(FindingStatus.project_id == project_id)
            .all()
        )
        return [
            {
                "fingerprint": r.fingerprint,
                "status": r.status,
                "updated_at": _utcnow_iso(r.updated_at),
            }
            for r in rows
        ]


@app.post("/projects/{project_id}/findings/status")
def set_finding_status(project_id: str, request: FindingStatusUpdate) -> dict:
    if request.status not in ("acknowledged", "fixed"):
        raise HTTPException(status_code=422, detail="status must be acknowledged|fixed")
    with _session_factory()() as session:
        _require_project(session, project_id)
        row = (
            session.query(FindingStatus)
            .filter(
                FindingStatus.project_id == project_id,
                FindingStatus.fingerprint == request.fingerprint,
            )
            .one_or_none()
        )
        if row is None:
            row = FindingStatus(
                project_id=project_id,
                fingerprint=request.fingerprint,
                status=request.status,
            )
            session.add(row)
        else:
            row.status = request.status
        session.commit()
        return {"fingerprint": row.fingerprint, "status": row.status}


@app.post("/projects/{project_id}/retest")
def retest_project(project_id: str, request: RetestRequest) -> dict:
    """Re-run the project's latest scan of the given kind and diff findings.

    Returns ``{new, persisting, resolved}`` — finding dicts with fingerprints.
    """
    with _session_factory()() as session:
        _require_project(session, project_id)
        if request.kind == "website_scan":
            record = (
                session.query(WebsiteScan)
                .filter(WebsiteScan.project_id == project_id)
                .order_by(WebsiteScan.created_at.desc())
                .first()
            )
            if record is None:
                raise HTTPException(
                    status_code=404, detail="No website scan recorded for this project"
                )
            old = json.loads(record.result_json)
            target_url = record.target_url
        elif request.kind == "repo_analysis":
            record = (
                session.query(RepoAnalysis)
                .filter(RepoAnalysis.project_id == project_id)
                .order_by(RepoAnalysis.created_at.desc())
                .first()
            )
            if record is None:
                raise HTTPException(
                    status_code=404, detail="No repo analysis recorded for this project"
                )
            old = json.loads(record.result_json)
            repository_url = record.repository_url
        else:
            raise HTTPException(
                status_code=422, detail="kind must be repo_analysis|website_scan"
            )

    # Re-run outside the session (network I/O must not hold a DB session).
    if request.kind == "website_scan":
        config = scan_config_from_settings(
            target_url=target_url,
            authorization_token=request.authorization_token or "",
            i_authorize_this_scan=request.i_authorize_this_scan,
            include_subdomains=False,
            path_prefix=None,
            max_pages=None,
            active_probes=True,
            session_cookie=None,
            authorization_header=None,
            settings=settings,
        )
        new_result = WebsiteScanner(config).run().model_dump(mode="json")
        with _session_factory()() as session:
            _store_website_scan(session, target_url, project_id, new_result)
            session.commit()
    else:
        ref = github_service.validate_github_url(repository_url)
        with github_service.temporary_repo_dir() as tmp:
            repo_dir = tmp / "repo"
            orchestrator.fetch_repo(repository_url, repo_dir)
            new_result = supervisor.run(repository_url, repo_dir).model_dump(mode="json")
        with _session_factory()() as session:
            _store_repo_analysis(session, repository_url, project_id, new_result)
            session.commit()

    old_fps = {finding_fingerprint(f): f for f in old.get("findings", [])}
    new_fps = {finding_fingerprint(f): f for f in new_result.get("findings", [])}
    return {
        "new": [
            {"fingerprint": fp, "finding": new_fps[fp]} for fp in new_fps if fp not in old_fps
        ],
        "persisting": [
            {"fingerprint": fp, "finding": new_fps[fp]} for fp in new_fps if fp in old_fps
        ],
        "resolved": [
            {"fingerprint": fp, "finding": old_fps[fp]} for fp in old_fps if fp not in new_fps
        ],
    }


# ---------------------------------------------------------------------------
# Remediation (FIND -> FIX -> VERIFY)
# ---------------------------------------------------------------------------


@app.post("/remediate", response_model=RemediationResult)
def remediate(request: RemediationRequest) -> RemediationResult:
    """Propose and deterministically verify a fix for one finding.

    FIND -> FIX -> VERIFY, coordinated by the supervisor: the Fix agent
    proposes a minimal patch (budgeted), the patch engine validates and
    applies it inside an isolated temporary workspace, and the
    Verification agent verifies the outcome deterministically. The
    original repository is never modified.
    """
    github_service.validate_github_url(request.repository_url)
    with github_service.temporary_repo_dir() as tmp:
        repo_dir = tmp / "repo"
        orchestrator.fetch_repo(request.repository_url, repo_dir)
        before = supervisor.run(request.repository_url, repo_dir)
        return supervisor.remediate_finding(request.finding_id, repo_dir, before)


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
        before = supervisor.run(request.repository_url, repo_dir)
        return supervisor.remediate_findings(request.finding_ids, repo_dir, before)
