"""Phase 7 — persistence, auth, jobs, and metering for the SaaS layer.

SQLite is the dev default (``CODEAUDIT_DATABASE_URL``); the schema is
written to be Postgres-compatible (no SQLite-only SQL, portable column
types, JSON stored as TEXT). Postgres is the documented production
target.

Submodules:
- ``models``: SQLAlchemy ORM entities.
- ``database``: engine/session lifecycle, schema versioning + upgrades,
  SQLite file permissions.
- ``auth``: API-key issuance and verification (salted hashes only).
- ``repository``: tenant-scoped data access (every query scoped by user).
- ``jobs``: durable scan/analysis job queue + dev-only in-process worker.
- ``metering``: per-API-key usage counters (billing input, Phase 11).
"""

from __future__ import annotations

from services.persistence import auth, database, jobs, metering, models, repository

__all__ = ["auth", "database", "jobs", "metering", "models", "repository"]
