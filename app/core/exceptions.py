"""
app.core.exceptions
====================

Central exception hierarchy for Pentroid.

Every subsystem (workflow engine, plugin manager, dependency manager,
tool manager, device connection manager, database layer, report engine)
raises exceptions from this module instead of bare ``Exception`` /
built-in errors. This lets the GUI, logger, and workflow engine catch
failures at the correct granularity and present meaningful messages to
the user instead of stack traces.

Hierarchy
---------
PentroidError
├── ConfigurationError
├── DatabaseError
│   ├── RecordNotFoundError
│   └── DatabaseIntegrityError
├── DependencyError
│   ├── ToolNotFoundError
│   ├── ToolDownloadError
│   └── ChecksumMismatchError
├── DeviceConnectionError
│   ├── ADBNotFoundError
│   ├── NoDeviceFoundError
│   └── DeviceAuthorizationError
├── PluginError
│   ├── PluginNotFoundError
│   ├── PluginInitializationError
│   └── PluginExecutionError
├── WorkflowError
│   ├── WorkflowNotFoundError
│   └── WorkflowStepError
├── AnalysisError
│   ├── InvalidTargetFileError
│   └── ToolExecutionError
└── ReportGenerationError
"""

from __future__ import annotations


class PentroidError(Exception):
    """Base class for all Pentroid application errors.

    Parameters
    ----------
    message:
        Human-readable description of the failure.
    details:
        Optional dict of structured context (tool name, file path,
        exit code, etc.) that the logger / GUI can surface without
        having to parse the message string.
    """

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.details:
            return f"{self.message} | details={self.details}"
        return self.message


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
class ConfigurationError(PentroidError):
    """Raised when application configuration is missing or invalid."""


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
class DatabaseError(PentroidError):
    """Base class for database-layer failures."""


class RecordNotFoundError(DatabaseError):
    """Raised when a query for a specific row returns nothing."""


class DatabaseIntegrityError(DatabaseError):
    """Raised on constraint violations / integrity failures."""


# --------------------------------------------------------------------------- #
# Dependency Manager
# --------------------------------------------------------------------------- #
class DependencyError(PentroidError):
    """Base class for dependency-resolution failures."""


class ToolNotFoundError(DependencyError):
    """Raised when a required external tool binary cannot be located."""


class ToolDownloadError(DependencyError):
    """Raised when downloading a tool release from GitHub fails."""


class ChecksumMismatchError(DependencyError):
    """Raised when a downloaded tool's checksum does not match."""


# --------------------------------------------------------------------------- #
# Device Connection Manager
# --------------------------------------------------------------------------- #
class DeviceConnectionError(PentroidError):
    """Base class for device connectivity failures."""


class ADBNotFoundError(DeviceConnectionError):
    """Raised when the bundled ADB binary is missing or not executable."""


class NoDeviceFoundError(DeviceConnectionError):
    """Raised when no authorized device/emulator can be located."""


class DeviceAuthorizationError(DeviceConnectionError):
    """Raised when a device is detected but not authorized (RSA prompt)."""


# --------------------------------------------------------------------------- #
# Plugin System
# --------------------------------------------------------------------------- #
class PluginError(PentroidError):
    """Base class for plugin lifecycle failures."""


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin id is not registered."""


class PluginInitializationError(PluginError):
    """Raised when ``Plugin.initialize()`` fails."""


class PluginExecutionError(PluginError):
    """Raised when ``Plugin.run()`` raises or returns a fatal status."""


# --------------------------------------------------------------------------- #
# Workflow Engine
# --------------------------------------------------------------------------- #
class WorkflowError(PentroidError):
    """Base class for workflow orchestration failures."""


class WorkflowNotFoundError(WorkflowError):
    """Raised when a requested workflow definition does not exist."""


class WorkflowStepError(WorkflowError):
    """Raised when an individual workflow step fails and cannot continue."""


# --------------------------------------------------------------------------- #
# Analysis / Tool Execution
# --------------------------------------------------------------------------- #
class AnalysisError(PentroidError):
    """Base class for analysis-pipeline failures."""


class InvalidTargetFileError(AnalysisError):
    """Raised when an APK/IPA fails validation (bad magic, corrupt, etc.)."""


class ToolExecutionError(AnalysisError):
    """Raised when an external tool process exits non-zero unexpectedly."""


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
class ReportGenerationError(PentroidError):
    """Raised when HTML/PDF/JSON/CSV report generation fails."""
