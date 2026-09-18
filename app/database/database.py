"""
app.database.database
======================

Engine/session lifecycle for the Pentroid SQLite database.

This module owns *connection management only*. Table-specific CRUD
(Project Manager, Analysis repository, Finding repository, etc.) is
built as its own module on top of ``session_scope()`` -- keeping this
file focused on: engine creation, schema initialization, and the
session-per-unit-of-work pattern used everywhere else in the app.

Usage
-----
    from app.database.database import init_db, session_scope
    from app.database.models import Project

    init_db()  # once, at startup

    with session_scope() as session:
        session.add(Project(name="ChatApp", ...))
        # commits automatically on clean exit, rolls back on exception
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.exceptions import DatabaseError, PentroidError
from app.core.logger import get_logger
from app.database.models import Base, Log, LogLevel

logger = get_logger(__name__)

_engine: Engine | None = None
_SessionFactory: sessionmaker | None = None
_lock = threading.Lock()


def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine, creating it on first call."""
    global _engine
    if _engine is not None:
        return _engine

    with _lock:
        if _engine is not None:  # re-check inside lock (double-checked locking)
            return _engine

        settings = get_settings()
        db_path = settings.paths.database_file
        db_path.parent.mkdir(parents=True, exist_ok=True)

        _engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            future=True,
        )

        # SQLite needs foreign_keys pragma enabled explicitly per-connection.
        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        logger.info("Database engine created at %s", db_path)
        return _engine


def get_session_factory() -> sessionmaker:
    """Return the process-wide session factory, creating it on first call."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(), autoflush=False, expire_on_commit=False, future=True
        )
    return _SessionFactory


def _migrate_schema() -> None:
    """
    Lightweight additive migration for existing databases.

    ``Base.metadata.create_all()`` creates missing *tables* but never adds
    missing *columns* to a table that already exists -- so a user upgrading
    Pentroid with an existing pentroid.db would hit "no such column" errors
    on every query touching the new reporting fields. SQLite supports
    ``ALTER TABLE ... ADD COLUMN``, which is enough for purely additive
    changes like these (no type changes, no drops, no backfill needed --
    every new column is nullable or has a default).

    Deliberately not Alembic: a single-file desktop app with additive-only
    history doesn't justify a migration framework and its version table.
    If a future change ever needs a real data migration or a destructive
    alter, that's the point to reach for Alembic rather than extend this.
    """
    from sqlalchemy import inspect, text

    engine = get_engine()
    inspector = inspect(engine)
    if "findings" not in inspector.get_table_names():
        return  # fresh database; create_all() already built it correctly

    existing = {col["name"] for col in inspector.get_columns("findings")}
    additions = {
        "impact": "TEXT",
        "reproduction_steps": "TEXT",
        "affected_components": "TEXT",
        "cwe_id": "VARCHAR(32)",
        "cvss_vector": "VARCHAR(128)",
        "cvss_score": "FLOAT",
        # SQLAlchemy's Enum type persists the member NAME ("MEDIUM"), not its
        # value ("medium") -- a lowercase default here makes every migrated row
        # unreadable with a LookupError on the next query.
        "confidence": "VARCHAR(9) DEFAULT 'MEDIUM'",
        "references": "JSON",
    }

    missing = {name: ddl for name, ddl in additions.items() if name not in existing}
    if not missing:
        return

    with engine.begin() as conn:
        for name, ddl in missing.items():
            # "references" is a reserved SQL keyword -- must be quoted.
            conn.execute(text(f'ALTER TABLE findings ADD COLUMN "{name}" {ddl}'))
    logger.info("Migrated findings table: added %d column(s) %s", len(missing), sorted(missing))


def init_db() -> None:
    """Create all tables that don't already exist. Idempotent; safe to call repeatedly."""
    try:
        Base.metadata.create_all(bind=get_engine())
        _migrate_schema()
        logger.info("Database schema initialized (%d tables)", len(Base.metadata.tables))
    except Exception as exc:
        raise DatabaseError(
            "Failed to initialize database schema", details={"error": str(exc)}
        ) from exc


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of ORM operations.

    Commits on clean exit, rolls back on any exception, and always
    closes the session. Any ``PentroidError`` subclass raised inside
    the block (e.g. a plugin/report/workflow module deliberately
    raising its own typed error for validation) is rolled back and
    re-raised unchanged -- only a genuinely unexpected exception gets
    wrapped as ``DatabaseError``. Without this distinction, a
    domain-specific error like ``ReportGenerationError`` raised inside
    a ``with session_scope()`` block would be silently replaced with a
    generic ``DatabaseError``, hiding both the real exception type and
    its message from every caller.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception as exc:
        session.rollback()
        if isinstance(exc, PentroidError):
            raise
        raise DatabaseError(
            "Database transaction failed and was rolled back",
            details={"error": str(exc)},
        ) from exc
    finally:
        session.close()


class DatabaseLogHandler(logging.Handler):
    """
    Logging handler that persists records into the ``logs`` table.

    Registered optionally (heavy analysis runs can produce thousands of
    log lines; callers may choose to attach this only for the duration
    of a specific analysis, tagging records with ``analysis_id`` via
    the ``extra={"analysis_id": ...}`` kwarg on the originating log call).
    """

    _LEVEL_MAP = {
        logging.DEBUG: LogLevel.DEBUG,
        logging.INFO: LogLevel.INFO,
        logging.WARNING: LogLevel.WARNING,
        logging.ERROR: LogLevel.ERROR,
        logging.CRITICAL: LogLevel.CRITICAL,
    }

    def emit(self, record: logging.LogRecord) -> None:
        try:
            with session_scope() as session:
                session.add(
                    Log(
                        level=self._LEVEL_MAP.get(record.levelno, LogLevel.INFO),
                        source=record.name,
                        message=record.getMessage(),
                        analysis_id=getattr(record, "analysis_id", None),
                    )
                )
        except Exception:  # pragma: no cover - never let logging crash the app
            self.handleError(record)


def get_setting(key: str, default=None):
    """Read a single runtime setting from the ``settings`` table."""
    from app.database.models import Setting  # local import avoids cycle at module load

    with session_scope() as session:
        row = session.query(Setting).filter_by(key=key).one_or_none()
        return row.value if row is not None else default


def set_setting(key: str, value) -> None:
    """Write/update a single runtime setting in the ``settings`` table."""
    from app.database.models import Setting

    with session_scope() as session:
        row = session.query(Setting).filter_by(key=key).one_or_none()
        if row is None:
            session.add(Setting(key=key, value=value))
        else:
            row.value = value
