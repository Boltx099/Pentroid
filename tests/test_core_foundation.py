"""
Unit tests for Module 1: Core Foundation
(config, logger, exceptions, database models/session).
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolated_project_root(tmp_path, monkeypatch):
    """
    Point every filesystem-backed subsystem at a temp directory so tests
    never touch the real projects/logs/database on disk, and reset all
    module-level singletons (settings cache, engine, session factory)
    between tests.
    """
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))

    import app.core.config as config_module
    config_module.get_settings.cache_clear()

    import app.database.database as db_module
    db_module._engine = None
    db_module._SessionFactory = None

    yield

    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None


def test_settings_creates_managed_directories(tmp_path):
    from app.core.config import get_settings

    settings = get_settings()
    assert settings.paths.tools_dir.exists()
    assert settings.paths.projects_dir.exists()
    assert settings.paths.logs_dir.exists()
    assert settings.paths.database_dir.exists()


def test_settings_version_validation_rejects_bad_format():
    from app.core.config import AppSettings
    from app.core.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError):
        AppSettings(version="not-a-version")


def test_logger_writes_to_rotating_file():
    from app.core.config import get_settings
    from app.core.logger import get_logger, setup_logging

    setup_logging(force=True)
    log = get_logger("tests.foundation")
    log.info("hello from test suite")

    settings = get_settings()
    log_file = settings.paths.logs_dir / "pentroid.log"
    assert log_file.exists()
    assert "hello from test suite" in log_file.read_text(encoding="utf-8")


def test_database_init_creates_all_expected_tables():
    from app.database.database import get_engine, init_db
    from sqlalchemy import inspect

    init_db()
    tables = set(inspect(get_engine()).get_table_names())
    expected = {
        "projects", "analyses", "devices", "reports",
        "plugins", "findings", "logs", "settings",
    }
    assert expected.issubset(tables)


def test_project_crud_roundtrip():
    from app.database.database import init_db, session_scope
    from app.database.models import Project, Platform, ProjectType

    init_db()
    with session_scope() as session:
        session.add(
            Project(
                name="ChatApp",
                platform=Platform.ANDROID,
                project_type=ProjectType.ANDROID_APK,
                workspace_path="/tmp/pentroid/ChatApp",
            )
        )

    with session_scope() as session:
        project = session.query(Project).filter_by(name="ChatApp").one()
        assert project.platform == Platform.ANDROID
        assert project.uuid  # auto-generated

    # cascade delete: deleting a project should remove its analyses
    with session_scope() as session:
        project = session.query(Project).filter_by(name="ChatApp").one()
        session.delete(project)

    with session_scope() as session:
        assert session.query(Project).count() == 0


def test_finding_requires_valid_severity_enum():
    from app.database.database import init_db, session_scope
    from app.database.models import (
        Project, Analysis, Finding, Platform, ProjectType,
        AnalysisType, Severity,
    )

    init_db()
    with session_scope() as session:
        project = Project(
            name="BankApp",
            platform=Platform.ANDROID,
            project_type=ProjectType.ANDROID_APK,
            workspace_path="/tmp/pentroid/BankApp",
        )
        session.add(project)
        session.flush()

        analysis = Analysis(
            project_id=project.id,
            analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default",
        )
        session.add(analysis)
        session.flush()

        session.add(
            Finding(
                analysis_id=analysis.id,
                title="Hardcoded API key in strings.xml",
                severity=Severity.HIGH,
                category="Secrets Detection",
            )
        )

    with session_scope() as session:
        finding = session.query(Finding).one()
        assert finding.severity == Severity.HIGH
        assert finding.analysis.workflow_name == "static_analysis_default"


def test_settings_table_get_and_set_roundtrip():
    from app.database.database import init_db, get_setting, set_setting

    init_db()
    assert get_setting("theme", default="dark") == "dark"
    set_setting("theme", "light")
    assert get_setting("theme") == "light"


def test_database_error_raised_on_bad_transaction():
    from app.database.database import init_db, session_scope
    from app.core.exceptions import DatabaseError
    from app.database.models import Analysis

    init_db()
    with pytest.raises(DatabaseError):
        with session_scope() as session:
            # project_id=999 violates FK -> should roll back and raise DatabaseError
            session.add(
                Analysis(
                    project_id=999_999,
                    analysis_type="static",  # invalid, not an AnalysisType member either
                    workflow_name="x",
                )
            )
            session.flush()
