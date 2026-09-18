"""
app.core.schemas
=================

Pydantic contracts shared between the Plugin system, Workflow Engine,
Result Parser, and Database layer.

Every plugin, regardless of what external tool it wraps (JADX, YARA,
Frida, ...), must return a ``PluginOutput`` -- this is the "standard
output" contract from the architecture spec:

    {
        "tool": "",
        "status": "",
        "findings": [],
        "logs": [],
        "errors": [],
        "duration": 0
    }

The Result Aggregator (Module 2) consumes ``PluginOutput`` and converts
``findings`` into ``Finding`` ORM rows; nothing downstream ever touches
a raw dict, so a malformed plugin fails fast at the schema boundary
instead of corrupting the database.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class PluginRunStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"       # completed but with recoverable issues
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"       # e.g. step not applicable to this target


class ConfidenceLevel(str, Enum):
    """How sure we are the finding is real -- orthogonal to severity (how bad if real)."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PluginFinding(BaseModel):
    """One security finding as emitted by a plugin, pre-persistence."""

    title: str
    severity: SeverityLevel
    description: str | None = None
    category: str | None = None
    owasp_mapping: str | None = None
    masvs_mapping: str | None = None
    mitre_mapping: str | None = None
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    recommendation: str | None = None

    # A stable key into app.core.knowledge.finding_kb. When set, the Result
    # Aggregator fills impact / reproduction_steps / CWE / CVSS / references
    # from the knowledge base, so a plugin gets professional-grade reporting
    # output without each plugin author rewriting the same guidance prose.
    finding_key: str | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM

    # Explicit values here always win over knowledge-base defaults -- a plugin
    # that knows something specific about THIS instance should say so.
    impact: str | None = None
    reproduction_steps: str | None = None
    affected_components: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    references: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class PluginOutput(BaseModel):
    """
    The mandatory return contract for ``Plugin.run()``.

    ``duration`` is populated by the Plugin Manager itself (wall-clock
    seconds around the ``run()`` call), not by the plugin author, so
    timing is consistent and can't be spoofed by a misbehaving plugin.
    """

    tool: str
    status: PluginRunStatus
    findings: list[PluginFinding] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("duration")
    @classmethod
    def _duration_non_negative(cls, value: float) -> float:
        if value < 0:
            raise ValueError("duration must be >= 0")
        return value


class WorkflowStepContext(BaseModel):
    """
    Mutable context threaded through a workflow's steps.

    Each step (a plugin invocation) receives this, may read prior
    steps' outputs (e.g. JADX step reads APKTool's decompiled path),
    and returns an updated copy for the next step. Kept as a Pydantic
    model (not a bare dict) so step authors get validation + IDE
    autocomplete instead of guessing key names.
    """

    project_id: int
    analysis_id: int
    target_path: str
    workspace_path: str
    device_id: int | None = None
    step_outputs: dict[str, PluginOutput] = Field(default_factory=dict)
    shared_data: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}
