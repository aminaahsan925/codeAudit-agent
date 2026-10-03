"""Phase 7 — engine/session lifecycle and schema versioning.

- ``get_engine(database_url)``: cached engine per URL. SQLite engines get
  ``check_same_thread=False`` (the dev worker runs in its own thread with
  its own sessions — sessions are never shared across threads).
- ``init_db(engine)``: create tables, stamp the schema version, and set
  ``0600`` permissions on SQLite database files (the DB can hold API-key
  hashes and scan metadata; group/other get nothing).
- ``upgrade_database(engine)``: apply pending versioned migrations.
  Today there is exactly one version; the mechanism is what matters —
  future schema changes add ``_migrate_N_to_M`` functions to
  ``MIGRATIONS`` instead of ad-hoc DDL.

Relative ``sqlite:///`` paths are resolved against the backend package
directory so the dev DB lands in a predictable place regardless of the
process working directory.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from services.persistence.models import Base, FindingStatus, SchemaVersion

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent

_engines: dict[str, Engine] = {}
_session_factories: dict[str, sessionmaker] = {}


def resolve_database_path(database_url: str) -> str:
    """Resolve a relative ``sqlite:///`` URL against the backend directory.

    Absolute sqlite paths and non-sqlite URLs pass through unchanged.
    """
    if not database_url.startswith("sqlite:///"):
        return database_url
    raw_path = database_url[len("sqlite:///"):]
    if os.path.isabs(raw_path) or raw_path == ":memory:":
        return database_url
    resolved = (_BACKEND_DIR / raw_path).resolve()
    return f"sqlite:///{resolved}"


def get_engine(database_url: str) -> Engine:
    """Return a cached engine for ``database_url`` (keyed post-resolution)."""
    resolved = resolve_database_path(database_url)
    engine = _engines.get(resolved)
    if engine is None:
        connect_args: dict = {}
        if resolved.startswith("sqlite"):
            # The dev-only worker thread needs cross-thread connections;
            # every thread still gets its own Session (never shared).
            connect_args["check_same_thread"] = False
        engine = create_engine(resolved, connect_args=connect_args, future=True)
        _engines[resolved] = engine
        _session_factories[resolved] = sessionmaker(bind=engine, expire_on_commit=False)
    return engine


def get_session_factory(database_url: str) -> sessionmaker:
    get_engine(database_url)
    return _session_factories[resolve_database_path(database_url)]


def reset_engine_cache() -> None:
    """Drop cached engines. For tests only — lets each test bind a fresh DB."""
    for engine in _engines.values():
        engine.dispose()
    _engines.clear()
    _session_factories.clear()


def _sqlite_file_for(engine: Engine) -> Path | None:
    if engine.url.drivername != "sqlite":
        return None
    db_path = urlparse(str(engine.url)).path
    if not db_path or db_path == "/:memory:":
        return None
    return Path(db_path)


def _ensure_sqlite_permissions(engine: Engine) -> None:
    """SQLite DB files hold key hashes and scan metadata: owner-only."""
    path = _sqlite_file_for(engine)
    if path is None or not path.exists():
        return
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:  # pragma: no cover — platform-specific
        logger.warning("Could not set 0600 on database file %s: %s", path, exc)


def _migration_1_initial(engine: Engine) -> None:
    """v1: create every table from the ORM metadata."""
    Base.metadata.create_all(engine)


def _migration_2_finding_status(engine: Engine) -> None:
    """v2: add the Phase 8 finding_statuses table (lifecycle tracking)."""
    FindingStatus.__table__.create(engine, checkfirst=True)


# version -> migration that brings the schema *to* that version.
MIGRATIONS: dict[int, Callable[[Engine], None]] = {
    1: _migration_1_initial,
    2: _migration_2_finding_status,
}


def _current_version(engine: Engine) -> int:
    try:
        with Session(engine) as session:
            row = session.execute(select(SchemaVersion.version)).scalar_one_or_none()
            return int(row) if row is not None else 0
    except Exception:
        # Table does not exist yet (fresh database).
        return 0


def _stamp_version(engine: Engine, version: int) -> None:
    with Session(engine) as session:
        session.merge(SchemaVersion(version=version))
        session.commit()


def upgrade_database(engine: Engine) -> int:
    """Apply pending migrations in order. Returns the resulting version."""
    current = _current_version(engine)
    for version in sorted(MIGRATIONS):
        if version > current:
            logger.info("Applying database migration to version %d", version)
            MIGRATIONS[version](engine)
            _stamp_version(engine, version)
            current = version
    _ensure_sqlite_permissions(engine)
    return current


def init_db(database_url: str) -> Engine:
    """Idempotent database initialization: engine + migrations + perms."""
    engine = get_engine(database_url)
    version = upgrade_database(engine)
    if version != SCHEMA_VERSION:  # pragma: no cover — defensive
        raise RuntimeError(
            f"Database schema version {version} != code version {SCHEMA_VERSION}"
        )
    return engine
