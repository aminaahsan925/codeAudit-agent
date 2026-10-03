"""Phase 7/8 — SQLAlchemy ORM models for the persistence layer.

Tables:
- ``schema_versions``: single-row schema version stamp.
- ``scan_jobs``: durable async job queue (repo analyses + website scans).
- ``projects``: user-created project containers.
- ``repo_analyses``: stored repository analysis results per project.
- ``website_scans``: stored website scan results per project.
- ``finding_statuses``: per-project finding lifecycle (acknowledged/fixed).

All primary keys are UUID hex strings so ids are safe to expose in URLs
without leaking sequence information.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class SchemaVersion(Base):
    __tablename__ = "schema_versions"

    version: Mapped[int] = mapped_column(primary_key=True)


class ScanJob(Base):
    """One async unit of work: repo analysis or website scan."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    project_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("projects.id"), nullable=True
    )
    api_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    request_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Project(Base):
    """A user-created container grouping analyses and scans."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class RepoAnalysis(Base):
    """A stored repository analysis result, optionally linked to a project."""

    __tablename__ = "repo_analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    project_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("projects.id"), nullable=True
    )
    repository_url: Mapped[str] = mapped_column(String(500), nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class WebsiteScan(Base):
    """A stored website scan result, optionally linked to a project."""

    __tablename__ = "website_scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    project_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("projects.id"), nullable=True
    )
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class FindingStatus(Base):
    """Per-project finding lifecycle: acknowledged / fixed.

    ``fingerprint`` is the deterministic finding identity computed by the
    API layer (sha256 of rule/detector + location + title).
    """

    __tablename__ = "finding_statuses"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_finding_project_fp"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    project_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("projects.id"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
