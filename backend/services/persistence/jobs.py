"""Phase 7 — durable scan/analysis job queue.

Absorbs the Phase Two deferral: long analyses and website scans can run
asynchronously instead of blocking an HTTP request.

Lifecycle: ``queued -> running -> done | failed | cancelled``.
Only ``queued`` jobs can be cancelled (a running job is left to finish;
the dev worker is cooperative, not preemptive — documented).

Claiming is atomic: the worker flips ``queued -> running`` with a single
``UPDATE ... WHERE state='queued'`` and checks the affected row count, so
two workers can never claim the same job. (The dev default is a single
in-process worker; a multi-worker deployment should use
``SELECT ... FOR UPDATE`` on Postgres — documented in the module.)

The in-process background worker (``run_worker_forever``) is DEV-ONLY:
it shares the process with the API server. Production runs the worker as
a separate process (same code path via ``process_one_job``). Handlers are
registered per ``kind`` and receive the JSON-serialized request dict.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from services.persistence.models import ScanJob

logger = logging.getLogger(__name__)

JOB_KIND_REPO_ANALYSIS = "repo_analysis"
JOB_KIND_WEBSITE_SCAN = "website_scan"
JOB_KINDS = frozenset({JOB_KIND_REPO_ANALYSIS, JOB_KIND_WEBSITE_SCAN})

STATE_QUEUED = "queued"
STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"

# kind -> handler(request_dict) -> result_dict. Registered by the app layer
# (app/main.py); tests register stub handlers.
HANDLERS: dict[str, Callable[[dict], dict]] = {}


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def enqueue_job(
    session: Session,
    *,
    kind: str,
    request: dict,
    user_id: str | None = None,
    project_id: str | None = None,
    api_key_id: str | None = None,
) -> ScanJob:
    if kind not in JOB_KINDS:
        raise ValueError(f"Unknown job kind: {kind}")
    job = ScanJob(
        user_id=user_id,
        project_id=project_id,
        api_key_id=api_key_id,
        kind=kind,
        state=STATE_QUEUED,
        request_json=json.dumps(request),
    )
    session.add(job)
    session.flush()
    return job


def claim_next_job(session: Session) -> ScanJob | None:
    """Atomically claim the oldest queued job. None when the queue is empty."""
    row = session.execute(
        select(ScanJob.id)
        .where(ScanJob.state == STATE_QUEUED)
        .order_by(ScanJob.created_at)
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    updated = session.execute(
        update(ScanJob)
        .where(ScanJob.id == row, ScanJob.state == STATE_QUEUED)
        .values(state=STATE_RUNNING, started_at=_utcnow(), updated_at=_utcnow())
    ).rowcount
    session.flush()
    if updated != 1:
        # Lost the race to another worker — treat as no job claimed.
        return None
    return session.get(ScanJob, row)


def complete_job(session: Session, job_id: str, result: dict) -> None:
    session.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(
            state=STATE_DONE,
            result_json=json.dumps(result),
            finished_at=_utcnow(),
            updated_at=_utcnow(),
        )
    )


def fail_job(session: Session, job_id: str, code: str, message: str) -> None:
    # Never persist secrets in the error message: callers pass codes and
    # safe messages only (the livescan/ error discipline).
    session.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(
            state=STATE_FAILED,
            error_code=code,
            error_message=message[:1024],
            finished_at=_utcnow(),
            updated_at=_utcnow(),
        )
    )


def cancel_job(session: Session, job: ScanJob) -> bool:
    """Cancel a queued job. Returns False unless the job was queued."""
    if job.state != STATE_QUEUED:
        return False
    job.state = STATE_CANCELLED
    job.finished_at = _utcnow()
    job.updated_at = _utcnow()
    return True


def process_one_job(session_factory, handlers: dict | None = None) -> bool:
    """Claim and run a single job. Returns True when a job was processed.

    Each job runs in its own session. Handler exceptions become failed
    jobs (never crash the worker loop); BaseException is re-raised.
    """
    handlers = HANDLERS if handlers is None else handlers
    with session_factory() as session:
        job = claim_next_job(session)
        if job is None:
            session.rollback()
            return False
        job_id, kind = job.id, job.kind
        try:
            request = json.loads(job.request_json)
        except ValueError:
            request = {}
        session.commit()  # release the claim promptly

    handler = handlers.get(kind)
    try:
        if handler is None:
            raise RuntimeError(f"No handler registered for job kind {kind!r}")
        result = handler(request)
    except Exception as exc:  # noqa: BLE001 — jobs must fail, not crash workers
        logger.exception("Job %s (%s) failed", job_id, kind)
        with session_factory() as session:
            fail_job(session, job_id, type(exc).__name__, str(exc))
            session.commit()
        return True

    with session_factory() as session:
        complete_job(session, job_id, result)
        session.commit()
    return True


def run_worker_forever(
    session_factory,
    stop_event: threading.Event,
    handlers: dict | None = None,
    poll_interval: float = 1.0,
) -> None:
    """DEV-ONLY in-process worker loop. Production runs this as a separate
    process; the code path is identical (``process_one_job``)."""
    logger.warning(
        "Starting DEV-ONLY in-process job worker (production: separate worker process)"
    )
    while not stop_event.is_set():
        try:
            processed = process_one_job(session_factory, handlers)
        except Exception:  # noqa: BLE001 — the loop itself must not die
            logger.exception("Job worker iteration failed")
            processed = False
        if not processed:
            stop_event.wait(poll_interval)
