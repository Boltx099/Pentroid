"""
app.core.config
================

Centralized configuration for Pentroid.

Design
------
* All paths are resolved relative to the project root and created on
  first access so every other module (logger, database, dependency
  manager, tool manager) can rely on them existing.
* Settings are layered: built-in defaults -> ``config/settings.yaml``
  (if present) -> environment variables prefixed ``PENTROID_``.
* This module is imported very early (before logging is configured),
  so it must not itself depend on the logger.

Usage
-----
    from app.core.config import get_settings

    settings = get_settings()
    print(settings.paths.tools_dir)
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.exceptions import ConfigurationError

# --------------------------------------------------------------------------- #
# Project root resolution
# --------------------------------------------------------------------------- #
# app/core/config.py -> app/core -> app -> <project root>
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]

# Nested settings (PathSettings/LoggingSettings/DeviceSettings) are plain
# BaseModel, NOT BaseSettings. Only AppSettings (the top-level object) reads
# environment variables; if these were BaseSettings too, pydantic-settings
# would try to independently resolve each one's own env/dotenv sources on
# construction, which both double-applies overrides and silently ignores
# AppSettings' env_nested_delimiter routing (e.g. PENTROID_PATHS__ROOT).


class PathSettings(BaseModel):
    """
    Filesystem layout. Every directory below is derived from ``root`` --
    only ``root`` needs to be overridden (e.g. via ``PENTROID_PATHS__ROOT``,
    or directly in tests) for the entire layout to relocate, which keeps
    test isolation and portable installs both trivial to get right.
    """

    model_config = SettingsConfigDict(frozen=True)

    root: Path = PROJECT_ROOT
    tools_dir: Path | None = None
    projects_dir: Path | None = None
    reports_dir: Path | None = None
    assets_dir: Path | None = None
    logs_dir: Path | None = None
    plugins_dir: Path | None = None
    database_dir: Path | None = None
    config_dir: Path | None = None

    @model_validator(mode="before")
    @classmethod
    def _derive_from_root(cls, data):
        """Fill any unset directory field relative to ``root`` before validation."""
        if not isinstance(data, dict):
            return data
        root = Path(data.get("root", PROJECT_ROOT))
        defaults = {
            "root": root,
            "tools_dir": root / "tools",
            "projects_dir": root / "projects",
            "reports_dir": root / "reports",
            "assets_dir": root / "assets",
            "logs_dir": root / "logs",
            # plugins_dir intentionally NOT root-relative: built-in plugins
            # ship inside the installed application's own source tree
            # (app/plugins/installed), independent of where the user's data
            # root (projects/logs/database) lives. A user-space "custom
            # plugins" directory for third-party plugins is added under the
            # data root separately once the Plugin Manager GUI supports
            # installing plugins at runtime.
            "plugins_dir": PROJECT_ROOT / "app" / "plugins",
            "database_dir": root / "database",
            "config_dir": root / "config",
        }
        for key, value in defaults.items():
            if data.get(key) is None:
                data[key] = value
        return data

    @property
    def database_file(self) -> Path:
        return self.database_dir / "pentroid.db"

    @property
    def settings_file(self) -> Path:
        return self.config_dir / "settings.yaml"

    def ensure_directories(self) -> None:
        """Create every managed directory if it does not already exist."""
        for directory in (
            self.tools_dir,
            self.projects_dir,
            self.reports_dir,
            self.assets_dir,
            self.logs_dir,
            self.plugins_dir,
            self.database_dir,
            self.config_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


class LoggingSettings(BaseModel):
    """Logging behaviour."""

    model_config = SettingsConfigDict(frozen=True)

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    max_bytes: int = 5 * 1024 * 1024  # 5 MB per log file
    backup_count: int = 10
    console_output: bool = True


class DeviceSettings(BaseModel):
    """Defaults for the Device Connection Manager."""

    model_config = SettingsConfigDict(frozen=True)

    adb_port: int = 5037
    frida_default_port: int = 27042
    device_poll_interval_seconds: float = 3.0
    connection_timeout_seconds: float = 15.0


class AppSettings(BaseSettings):
    """
    Root settings object. This is the single object every other module
    should import (`get_settings()`), rather than reading environment
    variables or YAML directly.
    """

    model_config = SettingsConfigDict(
        env_prefix="PENTROID_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app_name: str = "Pentroid"
    version: str = "3.2.0"
    theme: Literal["dark", "light"] = "dark"
    offline_first: bool = True

    paths: PathSettings = Field(default_factory=PathSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    devices: DeviceSettings = Field(default_factory=DeviceSettings)

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        parts = value.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ConfigurationError(
                f"Invalid version string in settings: {value!r} "
                "(expected 'MAJOR.MINOR.PATCH')"
            )
        return value

    @classmethod
    def load(cls) -> "AppSettings":
        """
        Build settings from, in increasing priority order:
        1. class defaults
        2. config/settings.yaml (if present)
        3. PENTROID_* environment variables (handled automatically by
           pydantic-settings during __init__)
        """
        yaml_overrides: dict = {}
        env_root = os.environ.get("PENTROID_PATHS__ROOT")
        probe_root = Path(env_root) if env_root else PROJECT_ROOT
        settings_path = PathSettings(root=probe_root).settings_file
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as fh:
                    yaml_overrides = yaml.safe_load(fh) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise ConfigurationError(
                    f"Failed to parse settings file: {settings_path}",
                    details={"error": str(exc)},
                ) from exc

        instance = cls(**yaml_overrides)
        instance.paths.ensure_directories()
        return instance

    def save_to_disk(self) -> None:
        """Persist current settings back to config/settings.yaml."""
        self.paths.config_dir.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json", exclude={"paths"})
        try:
            with open(self.paths.settings_file, "w", encoding="utf-8") as fh:
                yaml.safe_dump(data, fh, sort_keys=False)
        except OSError as exc:
            raise ConfigurationError(
                f"Failed to write settings file: {self.paths.settings_file}",
                details={"error": str(exc)},
            ) from exc


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Return the process-wide singleton ``AppSettings`` instance.

    Cached with ``lru_cache`` so every module gets the same object
    without needing a manual global / DI container for this early
    bootstrap dependency.
    """
    return AppSettings.load()


def reload_settings() -> AppSettings:
    """Clear the cache and reload settings from disk (used by Settings GUI)."""
    get_settings.cache_clear()
    return get_settings()
