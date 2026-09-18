"""
app.core.workflow.plugin_manager
=================================

Discovers, registers, and instantiates plugins.

Plugin layout on disk (matches architecture's "Auto Discover Plugins"
+ "Plugin Metadata" + "Enable/Disable Per Project" requirements)::

    app/plugins/installed/<plugin_id>/
        manifest.json   # {plugin_id, name, version, author, description,
                          entry_point, requires_device}
        plugin.py       # module containing the Plugin subclass

Discovery is a two-phase process:
1. Scan disk, parse every ``manifest.json``, upsert into the
   ``plugins`` DB table (source of truth for "installed plugins" that
   the GUI's Plugin Manager panel lists/enables/disables).
2. On demand, ``instantiate(plugin_id)`` dynamically imports the
   module named in ``entry_point`` and constructs the class -- kept
   lazy so disabled/unhealthy plugins never pay an import cost.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.core.exceptions import PluginInitializationError, PluginNotFoundError
from app.core.logger import get_logger
from app.database.database import session_scope
from app.database.models import Plugin as PluginRecord
from app.plugins.base import Plugin

logger = get_logger(__name__)

_REQUIRED_MANIFEST_KEYS = {"plugin_id", "name", "version", "entry_point"}


@dataclass(frozen=True)
class DiscoveredPlugin:
    plugin_id: str
    name: str
    version: str
    author: str
    description: str
    entry_point: str
    requires_device: bool
    manifest_path: Path


class PluginManager:
    """Discovers plugin manifests on disk and instantiates plugin classes on demand."""

    def __init__(self, plugins_root: Path | None = None) -> None:
        self._plugins_root = plugins_root or (
            get_settings().paths.plugins_dir / "installed"
        )
        self._manifest_cache: dict[str, DiscoveredPlugin] = {}

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def discover(self) -> list[DiscoveredPlugin]:
        """
        Scan ``plugins/installed/*/manifest.json``, validate each, and
        upsert a matching row into the ``plugins`` table. Returns the
        list of successfully discovered plugins. A malformed manifest
        is logged and skipped -- it must not block discovery of the
        others.
        """
        discovered: list[DiscoveredPlugin] = []

        if not self._plugins_root.exists():
            logger.warning("Plugins directory does not exist: %s", self._plugins_root)
            return discovered

        for entry in sorted(self._plugins_root.iterdir()):
            if not entry.is_dir():
                continue
            manifest_path = entry / "manifest.json"
            if not manifest_path.exists():
                continue

            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.error("Failed to parse manifest %s: %s", manifest_path, exc)
                continue

            missing = _REQUIRED_MANIFEST_KEYS - manifest.keys()
            if missing:
                logger.error(
                    "Manifest %s missing required keys: %s", manifest_path, missing
                )
                continue

            plugin = DiscoveredPlugin(
                plugin_id=manifest["plugin_id"],
                name=manifest["name"],
                version=manifest["version"],
                author=manifest.get("author", "Unknown"),
                description=manifest.get("description", ""),
                entry_point=manifest["entry_point"],
                requires_device=bool(manifest.get("requires_device", False)),
                manifest_path=manifest_path,
            )
            self._upsert_registration(plugin)
            self._manifest_cache[plugin.plugin_id] = plugin
            discovered.append(plugin)
            logger.info("Discovered plugin '%s' v%s", plugin.plugin_id, plugin.version)

        return discovered

    def _upsert_registration(self, plugin: DiscoveredPlugin) -> None:
        with session_scope() as session:
            record = (
                session.query(PluginRecord)
                .filter_by(plugin_id=plugin.plugin_id)
                .one_or_none()
            )
            if record is None:
                session.add(
                    PluginRecord(
                        plugin_id=plugin.plugin_id,
                        name=plugin.name,
                        version=plugin.version,
                        author=plugin.author,
                        description=plugin.description,
                        entry_point=plugin.entry_point,
                        enabled=True,
                        metadata_json={"requires_device": plugin.requires_device},
                    )
                )
            else:
                record.name = plugin.name
                record.version = plugin.version
                record.author = plugin.author
                record.description = plugin.description
                record.entry_point = plugin.entry_point
                record.metadata_json = {"requires_device": plugin.requires_device}

    # ------------------------------------------------------------------ #
    # Enable / disable (per-project override lives at the workflow layer;
    # this toggles the global installed-plugin default)
    # ------------------------------------------------------------------ #
    def set_enabled(self, plugin_id: str, enabled: bool) -> None:
        with session_scope() as session:
            record = (
                session.query(PluginRecord).filter_by(plugin_id=plugin_id).one_or_none()
            )
            if record is None:
                raise PluginNotFoundError(f"Unknown plugin: {plugin_id}")
            record.enabled = enabled

    def is_enabled(self, plugin_id: str) -> bool:
        with session_scope() as session:
            record = (
                session.query(PluginRecord).filter_by(plugin_id=plugin_id).one_or_none()
            )
            if record is None:
                raise PluginNotFoundError(f"Unknown plugin: {plugin_id}")
            return record.enabled

    def list_installed(self) -> list[dict]:
        with session_scope() as session:
            return [
                {
                    "plugin_id": r.plugin_id,
                    "name": r.name,
                    "version": r.version,
                    "enabled": r.enabled,
                }
                for r in session.query(PluginRecord).all()
            ]

    def catalog(self) -> list[dict]:
        """
        Full metadata for every discovered plugin, for the GUI's Plugin Center.

        Joins the on-disk manifest (description, author, requires_device)
        against the DB's enabled flag, so a plugin whose directory was removed
        but whose row survives is reported as ``missing`` rather than being
        silently listed as installed.
        """
        with session_scope() as session:
            enabled_by_id = {
                r.plugin_id: r.enabled for r in session.query(PluginRecord).all()
            }

        rows: list[dict] = []
        for plugin_id, meta in sorted(self._manifest_cache.items()):
            rows.append({
                "plugin_id": plugin_id,
                "name": meta.name,
                "version": meta.version,
                "author": meta.author,
                "description": meta.description,
                "entry_point": meta.entry_point,
                "requires_device": meta.requires_device,
                "enabled": enabled_by_id.get(plugin_id, True),
                "missing": False,
            })
        for plugin_id, enabled in sorted(enabled_by_id.items()):
            if plugin_id not in self._manifest_cache:
                rows.append({
                    "plugin_id": plugin_id, "name": plugin_id, "version": "?",
                    "author": "", "description": "Registered in the database but no "
                    "manifest.json was found on disk.", "entry_point": "",
                    "requires_device": False, "enabled": enabled, "missing": True,
                })
        return rows

    def probe_health(self, plugin_id: str) -> tuple[str, str]:
        """
        Import a plugin and ask it for its own ``health()``, returning
        ``(health_value, detail)``.

        Plugins report UNAVAILABLE when the tool they wrap isn't installed
        (jadx, apktool, quark, ...), which is exactly what the Plugin Center
        needs to show. Health is probed without going through ``instantiate``'s
        enabled check, so a disabled plugin still reports honestly instead of
        looking broken, and every failure mode is returned as a value rather
        than raised -- one unhealthy plugin must not break the whole listing.
        """
        meta = self._manifest_cache.get(plugin_id)
        if meta is None:
            return "unavailable", "Plugin not discovered on disk"

        module_name, _, class_name = meta.entry_point.partition(":")
        if not module_name or not class_name:
            return "unavailable", f"Malformed entry_point: {meta.entry_point!r}"

        try:
            module = importlib.import_module(f"app.plugins.installed.{plugin_id}.{module_name}")
            instance = getattr(module, class_name)()
            return str(instance.health().value), ""
        except Exception as exc:  # noqa: BLE001 - a broken plugin is data here, not a crash
            logger.warning("Health probe failed for plugin '%s': %s", plugin_id, exc)
            return "unavailable", str(exc)

    # ------------------------------------------------------------------ #
    # Instantiation
    # ------------------------------------------------------------------ #
    def instantiate(self, plugin_id: str) -> Plugin:
        """
        Dynamically import and construct the ``Plugin`` subclass for
        ``plugin_id``. Raises ``PluginNotFoundError`` if not
        discovered/disabled, ``PluginInitializationError`` on import
        or construction failure.
        """
        plugin_meta = self._manifest_cache.get(plugin_id)
        if plugin_meta is None:
            raise PluginNotFoundError(f"Plugin not discovered: {plugin_id}")

        if not self.is_enabled(plugin_id):
            raise PluginNotFoundError(f"Plugin is disabled: {plugin_id}")

        module_name, _, class_name = plugin_meta.entry_point.partition(":")
        if not module_name or not class_name:
            raise PluginInitializationError(
                f"Malformed entry_point for '{plugin_id}': {plugin_meta.entry_point!r} "
                "(expected 'module:ClassName')"
            )

        package = f"app.plugins.installed.{plugin_id}"
        full_module = f"{package}.{module_name}"

        try:
            module = importlib.import_module(full_module)
            plugin_cls = getattr(module, class_name)
        except (ImportError, AttributeError) as exc:
            raise PluginInitializationError(
                f"Failed to load plugin '{plugin_id}' from {full_module}:{class_name}",
                details={"error": str(exc)},
            ) from exc

        if not issubclass(plugin_cls, Plugin):
            raise PluginInitializationError(
                f"Plugin class {class_name} in '{plugin_id}' does not subclass Plugin"
            )

        try:
            instance = plugin_cls()
            instance.initialize()
        except Exception as exc:
            raise PluginInitializationError(
                f"Plugin '{plugin_id}' failed to initialize", details={"error": str(exc)}
            ) from exc

        return instance


_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    """Return the process-wide singleton PluginManager (discovers on first call)."""
    global _manager
    if _manager is None:
        _manager = PluginManager()
        _manager.discover()
    return _manager


def reset_plugin_manager() -> None:
    """Used by tests to force a fresh PluginManager with a clean manifest cache."""
    global _manager
    _manager = None
