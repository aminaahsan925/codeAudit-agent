"""Phase 7 — persistence, auth, jobs, and metering for the SaaS layer.

SQLite is the dev default (``CODEAUDIT_DATABASE_URL``); the schema is
written to be Postgres-compatible (no SQLite-only SQL, portable column
types, JSON stored as TEXT). Postgres is the documented production
target.

Submodules:
- ``models``: SQLAlchemy ORM entities.
- ``database``: engine/session lifecycle, schema versioning + upgrades,
  SQLite file permissions.
- ``jobs``: durable scan/analysis job queue + dev-only in-process worker.

NOTE: ``auth`` (API-key issuance), ``repository`` (tenant-scoped DAL) and
``metering`` (usage counters) are documented next steps and are not
imported here until they land — importing this package must never fail
on a missing optional submodule.
"""

from __future__ import annotations

from services.persistence import database, jobs, models

__all__ = ["database", "jobs", "models"]
