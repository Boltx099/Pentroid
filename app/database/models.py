"""
app.database.models
====================

SQLAlchemy 2.0 declarative models for every table in the Pentroid
schema: Projects, Analyses, Devices, Reports, Plugins, Findings, Logs,
Settings.

Notes
-----
* All timestamps are stored as UTC-naive ``datetime`` for SQLite
  simplicity; conversion to local time happens only at the GUI layer.
* Enums are stored as native Python ``Enum`` via SQLAlchemy's ``Enum``
  type, which persists as TEXT in SQLite (portable, human-readable in
  the raw .db file, easy to inspect during debugging).
* Every table has an ``id`` integer primary key plus, where relevant,
  a ``uuid`` public identifier -- integer keys are cheap for FKs and
  joins, UUIDs are what the GUI/report engine expose externally so
  IDs never leak internal row-ordering information.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Shared declarative base for all Pentroid ORM models."""
    pass


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Platform(str, enum.Enum):
    ANDROID = "android"
    IOS = "ios"


class ProjectType(str, enum.Enum):
    ANDROID_APK = "android_apk"
    ANDROID_MALWARE = "android_malware"
    ANDROID_DYNAMIC = "android_dynamic"
    ANDROID_DEVICE = "android_device"
    IOS_IPA = "ios_ipa"
    IOS_DYNAMIC = "ios_dynamic"


class AnalysisType(str, enum.Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    MALWARE = "malware"
    IOS_STATIC = "ios_static"
    NETWORK = "network"
    PRIVACY = "privacy"


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ConnectionType(str, enum.Enum):
    USB = "usb"
    NETWORK = "network"
    ANDROID_EMULATOR = "android_emulator"
    GENYMOTION = "genymotion"
    WAYDROID = "waydroid"
    IOS_SIMULATOR = "ios_simulator"
    IOS_JAILBROKEN = "ios_jailbroken"


class DeviceStatus(str, enum.Enum):
    DISCONNECTED = "disconnected"
    UNAUTHORIZED = "unauthorized"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"


class ReportFormat(str, enum.Enum):
    HTML = "html"
    SARIF = "sarif"   # OASIS SARIF 2.1.0 -- GitHub code scanning, DefectDojo, VS Code
    PDF = "pdf"
    MARKDOWN = "markdown"
    JSON = "json"
    CSV = "csv"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, enum.Enum):
    """How sure the tool is that a finding is real -- distinct from severity,
    which is how bad it is *if* real. Both are needed to triage properly."""

    CONFIRMED = "confirmed"   # directly observed (e.g. parsed from the manifest)
    HIGH = "high"             # strong signal, minimal ambiguity
    MEDIUM = "medium"         # pattern match that usually holds
    LOW = "low"               # heuristic; expect false positives (e.g. entropy hits)


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"


class LogLevel(str, enum.Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #
class Project(Base):
    """A user-created assessment project (one target app, tracked over time)."""

    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("uuid", name="uq_projects_uuid"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), default=_new_uuid, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[Platform] = mapped_column(SAEnum(Platform), nullable=False)
    project_type: Mapped[ProjectType] = mapped_column(SAEnum(ProjectType), nullable=False)
    target_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    workspace_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)

    analyses: Mapped[list["Analysis"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        return f"<Project id={self.id} name={self.name!r} type={self.project_type}>"


class Device(Base):
    """A connected or previously-seen Android/iOS device, emulator, or simulator."""

    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("identifier", name="uq_devices_identifier"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False)  # serial / UDID
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[Platform] = mapped_column(SAEnum(Platform), nullable=False)
    connection_type: Mapped[ConnectionType] = mapped_column(SAEnum(ConnectionType), nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    api_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_rooted: Mapped[bool] = mapped_column(default=False)
    is_jailbroken: Mapped[bool] = mapped_column(default=False)
    frida_installed: Mapped[bool] = mapped_column(default=False)
    frida_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(
        SAEnum(DeviceStatus), default=DeviceStatus.DISCONNECTED
    )
    last_connected_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Device id={self.id} name={self.display_name!r} status={self.status}>"


class Analysis(Base):
    """A single execution of a workflow (static/dynamic/malware/ios) against a project."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), default=_new_uuid, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    analysis_type: Mapped[AnalysisType] = mapped_column(SAEnum(AnalysisType), nullable=False)
    workflow_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[RunStatus] = mapped_column(SAEnum(RunStatus), default=RunStatus.PENDING)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    tool_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    project: Mapped["Project"] = relationship(back_populates="analyses")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Analysis id={self.id} type={self.analysis_type} status={self.status}>"


class Plugin(Base):
    """A registered plugin (built-in or third-party) discovered by the Plugin Manager."""

    __tablename__ = "plugins"
    __table_args__ = (UniqueConstraint("plugin_id", name="uq_plugins_plugin_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plugin_id: Mapped[str] = mapped_column(String(255), nullable=False)  # stable machine name
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    entry_point: Mapped[str] = mapped_column(String(512), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    installed_at: Mapped[datetime] = mapped_column(default=_utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="plugin")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Plugin id={self.plugin_id!r} version={self.version}>"


class Finding(Base):
    """A single security finding produced by a plugin/tool during an analysis."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), default=_new_uuid, index=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    plugin_id: Mapped[int | None] = mapped_column(
        ForeignKey("plugins.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owasp_mapping: Mapped[str | None] = mapped_column(String(255), nullable=True)
    masvs_mapping: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mitre_mapping: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Professional reporting fields -------------------------------- #
    # A report is only as good as the data model behind it: without these,
    # no template change can produce impact/reproduction/affected-component
    # sections, because the information was never captured in the first place.
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    reproduction_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_components: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    # Confidence drives triage: a regex-matched "possible secret" and a
    # confirmed debuggable flag are not the same claim, and a report that
    # presents them identically wastes the reader's time.
    confidence: Mapped[Confidence] = mapped_column(
        SAEnum(Confidence), default=Confidence.MEDIUM
    )
    references: Mapped[list] = mapped_column(JSON, default=list)

    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus), default=FindingStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)

    analysis: Mapped["Analysis"] = relationship(back_populates="findings")
    plugin: Mapped["Plugin | None"] = relationship(back_populates="findings")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding id={self.id} severity={self.severity} title={self.title!r}>"


class Report(Base):
    """A generated report artifact tied to a specific analysis run."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), default=_new_uuid, index=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    format: Mapped[ReportFormat] = mapped_column(SAEnum(ReportFormat), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(default=_utcnow)

    analysis: Mapped["Analysis"] = relationship(back_populates="reports")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Report id={self.id} format={self.format} analysis_id={self.analysis_id}>"


class Log(Base):
    """Persisted application/analysis log line, mirrored from app.core.logger."""

    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(default=_utcnow, index=True)
    level: Mapped[LogLevel] = mapped_column(SAEnum(LogLevel), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Log {self.level} {self.source}: {self.message[:40]!r}>"


class Setting(Base):
    """Generic key/value application setting persisted to the database.

    Distinct from app.core.config.AppSettings (file/env-based bootstrap
    config): this table holds runtime-mutable, GUI-editable preferences
    (e.g. last-used workflow, window layout, per-project overrides).
    """

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    value: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Setting {self.key}={self.value!r}>"
