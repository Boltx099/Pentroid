"""
app.gui.pages.plugins_page
=============================

Two views over the plugin system:

* **Plugin Center** -- the catalog. Every discovered plugin with its
  description, whether the tool it wraps is actually available, and a
  working enable/disable toggle that writes straight through to the
  ``plugins`` table. Disabling a plugin here makes ``PluginManager``
  refuse to instantiate it, so the workflows that reference it record a
  skipped step instead of running it.
* **Installed Plugins** -- the operational view: which pipelines each
  plugin participates in, its entry point, and whether it needs a
  device.

"Installed" means "discovered from ``app/plugins/installed/*/manifest.json``".
There is no plugin marketplace or remote installation in Pentroid, so
this page doesn't offer a Browse/Download button that would imply one
exists.
"""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QWidget

from app.core.workflow.plugin_manager import get_plugin_manager
from app.core.workflow.workflow_manager import WORKFLOW_REGISTRY
from app.gui.pages.common import (
    ActionRow, BasePage, card, clear_layout, empty_state, kv_row, label,
)
from app.gui.pages.workflow_page import invalidate_health_cache, probe_health_cached
from app.gui.theme import Colors

_HEALTH_STYLE = {
    "healthy": ("READY", Colors.ACCENT_GREEN),
    "degraded": ("DEGRADED", Colors.STATUS_WARNING),
    "unavailable": ("TOOL MISSING", Colors.TEXT_MUTED),
}


def workflows_using(plugin_id: str) -> list[str]:
    """Which registered workflows reference this plugin."""
    return sorted(
        name for name, definition in WORKFLOW_REGISTRY.items()
        if any(step.plugin_id == plugin_id for step in definition.steps)
    )


class _PluginRow(ActionRow):
    def __init__(self, entry: dict, on_toggle, parent=None):
        super().__init__(
            f"{entry['name']}  v{entry['version']}",
            entry["description"] or "No description in the plugin's manifest.",
            parent,
        )
        self.plugin_id = entry["plugin_id"]

        self._toggle = QCheckBox("Enabled")
        self._toggle.setChecked(bool(entry["enabled"]))
        self._toggle.toggled.connect(lambda checked: on_toggle(self.plugin_id, checked))
        if entry["missing"]:
            self._toggle.setEnabled(False)
            self._toggle.setToolTip("No manifest.json on disk for this plugin.")
        self._layout.addWidget(self._toggle)

    def apply_health(self, health: str, detail: str) -> None:
        text, color = _HEALTH_STYLE.get(health, ("UNKNOWN", Colors.TEXT_MUTED))
        self.set_status(text, color)
        if detail:
            self._status.setToolTip(detail)


class PluginCenterPage(BasePage):
    title_text = "Plugin Center"
    subtitle_text = (
        "Every analysis capability in Pentroid is a plugin. Turn one off and the workflows "
        "that use it will record a skipped step rather than running it."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._plugins = get_plugin_manager()
        self.add_header_button("Re-scan plugins", self._on_rescan)

        frame, layout = card("DISCOVERED PLUGINS")
        self._list_layout = layout
        self._list_anchor = layout.count()
        self.body.addWidget(frame)
        self.refresh()

    def _on_rescan(self) -> None:
        self._plugins.discover()
        invalidate_health_cache()
        self.refresh()
        self.set_status("Re-scanned app/plugins/installed and re-probed every plugin.",
                        Colors.ACCENT_GREEN)

    def _on_toggle(self, plugin_id: str, enabled: bool) -> None:
        try:
            self._plugins.set_enabled(plugin_id, enabled)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the page
            self.set_status(f"Could not update {plugin_id}: {exc}", Colors.STATUS_ERROR)
            return
        self.set_status(
            f"{plugin_id} {'enabled' if enabled else 'disabled'}.",
            Colors.ACCENT_GREEN if enabled else Colors.STATUS_WARNING,
        )

    def refresh(self) -> None:
        if not hasattr(self, "_list_layout"):
            return
        clear_layout(self._list_layout, keep=self._list_anchor)

        entries = self._plugins.catalog()
        if not entries:
            self._list_layout.addWidget(empty_state(
                "No plugins discovered. Expected manifest.json files under "
                "app/plugins/installed/<plugin_id>/."
            ))
            return

        enabled_count = sum(1 for e in entries if e["enabled"])
        self._list_layout.addWidget(label(
            f"{len(entries)} plugin(s) discovered, {enabled_count} enabled.",
            size=10, color=Colors.TEXT_MUTED,
        ))

        for entry in entries:
            row = _PluginRow(entry, on_toggle=self._on_toggle)
            if entry["missing"]:
                row.set_status("NO MANIFEST", Colors.STATUS_ERROR)
            else:
                row.apply_health(*probe_health_cached(entry["plugin_id"]))
            self._list_layout.addWidget(row)


class InstalledPluginsPage(BasePage):
    title_text = "Installed Plugins"
    subtitle_text = (
        "What each plugin is wired into. A plugin that no workflow references will never "
        "run, however healthy it looks."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._plugins = get_plugin_manager()
        frame, layout = card("PLUGIN DETAIL")
        self._list_layout = layout
        self._list_anchor = layout.count()
        self.body.addWidget(frame)
        self.refresh()

    def refresh(self) -> None:
        if not hasattr(self, "_list_layout"):
            return
        clear_layout(self._list_layout, keep=self._list_anchor)

        entries = self._plugins.catalog()
        if not entries:
            self._list_layout.addWidget(empty_state("No plugins discovered."))
            return

        orphans = 0
        for entry in entries:
            used_by = workflows_using(entry["plugin_id"])
            if not used_by:
                orphans += 1

            row = ActionRow(
                f"{entry['name']}  v{entry['version']}",
                entry["description"] or "No description in the plugin's manifest.",
            )
            health, detail = probe_health_cached(entry["plugin_id"])
            text, color = _HEALTH_STYLE.get(health, ("UNKNOWN", Colors.TEXT_MUTED))
            row.set_status(text, color)
            if detail:
                row._status.setToolTip(detail)
            self._list_layout.addWidget(row)

            self._list_layout.addWidget(kv_row("  Plugin ID", entry["plugin_id"]))
            self._list_layout.addWidget(kv_row("  Entry point", entry["entry_point"] or "n/a"))
            self._list_layout.addWidget(kv_row("  Author", entry["author"] or "Unknown"))
            self._list_layout.addWidget(kv_row(
                "  Needs a device", "yes" if entry["requires_device"] else "no"
            ))
            self._list_layout.addWidget(kv_row(
                "  Used by", ", ".join(used_by) if used_by else "no workflow",
                Colors.TEXT_PRIMARY if used_by else Colors.STATUS_WARNING,
            ))
            self._list_layout.addWidget(kv_row(
                "  Enabled", "yes" if entry["enabled"] else "no",
                Colors.ACCENT_GREEN if entry["enabled"] else Colors.STATUS_WARNING,
            ))

        if orphans:
            self.set_status(
                f"{orphans} plugin(s) aren't referenced by any workflow, so nothing will "
                f"ever invoke them.",
                Colors.STATUS_WARNING,
            )
