"""
app.gui.pages.workflow_page
==============================

``WorkflowPage`` is the shared implementation behind the sidebar's
ANALYSIS section: Android APK, Android Malware, Static, Dynamic and
Privacy. All five are the same interaction -- pick a project, look at
what the pipeline will actually do, run it, read the result -- against
a different entry in ``WORKFLOW_REGISTRY``, so they are configured
subclasses rather than five copies.

Two things this page does that the older Projects page didn't:

* **It shows the pipeline before you run it.** Every step is listed
  with its plugin and whether that plugin is currently healthy, so a
  missing JADX/APKTool install is visible *before* a scan silently
  skips four steps and completes with zero findings.
* **It keeps the result.** The last run for this workflow is rendered
  with its risk score, finding count and the specific steps that were
  skipped or failed, rather than a status-bar toast that scrolls away.

Architecture: this page never touches a Plugin, a Tool or
``WorkflowManager`` directly. Runs go through ``AnalysisRunner``;
blocking probes go through ``BackgroundTaskRunner``; everything else is
a read-only database query.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QProgressBar, QPushButton, QVBoxLayout, QWidget,
)

from app.core.workflow.plugin_manager import get_plugin_manager
from app.core.workflow.workflow_manager import WORKFLOW_REGISTRY
from app.database.database import session_scope
from app.database.models import (
    Analysis, Device, DeviceStatus, Finding, Platform, Project, RunStatus,
)
from app.gui.controllers.analysis_runner import get_analysis_runner
from app.gui.dialogs.findings_dialog import FindingsDialog
from app.gui.pages.common import BasePage, card, clear_layout, empty_state, kv_row, label, pill
from app.gui.theme import Colors

# Probing a plugin's health imports its module (and, for some, a heavy
# third-party package such as yara or frida). That cost is paid once per
# process rather than on every showEvent, which fires each time the user
# navigates back to one of these five pages.
_health_cache: dict[str, tuple[str, str]] = {}


def probe_health_cached(plugin_id: str) -> tuple[str, str]:
    if plugin_id not in _health_cache:
        _health_cache[plugin_id] = get_plugin_manager().probe_health(plugin_id)
    return _health_cache[plugin_id]


def invalidate_health_cache() -> None:
    """Called after a tool install so pipelines re-evaluate availability."""
    _health_cache.clear()


_HEALTH_STYLE = {
    "healthy": ("READY", Colors.ACCENT_GREEN),
    "degraded": ("DEGRADED", Colors.STATUS_WARNING),
    "unavailable": ("MISSING", Colors.TEXT_MUTED),
}


class _StepRow(QFrame):
    def __init__(self, index: int, step_name: str, plugin_id: str, required: bool, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CardAlt")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        layout.addWidget(label(f"{index}.", size=11, color=Colors.TEXT_MUTED, bold=True))

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)
        text_col.addWidget(label(step_name, size=12, bold=True))
        self._detail = label("", size=10, color=Colors.TEXT_MUTED, wrap=True)
        text_col.addWidget(self._detail)
        layout.addLayout(text_col, stretch=1)

        layout.addWidget(pill(
            "REQUIRED" if required else "OPTIONAL",
            Colors.ACCENT_CYAN if required else Colors.TEXT_MUTED,
        ))

        self._health = pill("...", Colors.TEXT_MUTED)
        layout.addWidget(self._health)
        self._plugin_id = plugin_id
        self._required = required

    def apply_health(self, health: str, detail: str) -> None:
        text, color = _HEALTH_STYLE.get(health, ("UNKNOWN", Colors.TEXT_MUTED))
        self._health.setText(text)
        self._health.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: 700; "
            f"border: 1px solid {color}; border-radius: 6px; padding: 2px 8px;"
        )
        suffix = ""
        if health != "healthy":
            suffix = (
                "  \u2014  this step will abort the run"
                if self._required else "  \u2014  this step will be skipped"
            )
            if detail:
                self._health.setToolTip(detail)
        self._detail.setText(f"plugin: {self._plugin_id}{suffix}")


class WorkflowPage(BasePage):
    """Configure via class attributes; see the subclasses at the bottom."""

    workflow_name: str = ""
    platform: Platform | None = Platform.ANDROID
    requires_device: bool = False
    target_hint: str = "Select a project with an APK target."

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._runner = get_analysis_runner()
        self._runner.progress.connect(self._on_progress)
        self._runner.completed.connect(self._on_completed)
        self._runner.failed_to_start.connect(self._on_failed_to_start)
        self._job_id: str | None = None
        self._last_analysis_id: int | None = None

        self._build_target_card()
        if self.requires_device:
            self._build_device_card()
        self._build_pipeline_card()
        self._build_result_card()

        self.refresh()

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    def _build_target_card(self) -> None:
        frame, layout = card("TARGET", self.target_hint)

        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)

        self._project_combo = QComboBox()
        self._project_combo.currentIndexChanged.connect(self._on_project_changed)
        row_layout.addWidget(self._project_combo, stretch=1)

        new_btn = QPushButton("+ New Project")
        new_btn.clicked.connect(self._on_new_project)
        row_layout.addWidget(new_btn)
        layout.addWidget(row)

        self._target_label = label("", size=10, color=Colors.TEXT_MUTED, wrap=True)
        layout.addWidget(self._target_label)

        run_row = QWidget()
        run_layout = QHBoxLayout(run_row)
        run_layout.setContentsMargins(0, 0, 0, 0)
        run_layout.setSpacing(10)
        self._run_btn = QPushButton("Run Analysis")
        self._run_btn.setProperty("class", "Primary")
        self._run_btn.clicked.connect(self._on_run)
        run_layout.addWidget(self._run_btn)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.hide()
        run_layout.addWidget(self._progress, stretch=1)

        self._step_label = label("", size=11, color=Colors.STATUS_RUNNING)
        run_layout.addWidget(self._step_label)
        layout.addWidget(run_row)

        self.body.addWidget(frame)

    def _build_device_card(self) -> None:
        frame, layout = card(
            "DEVICE",
            "This workflow installs and instruments the app on a real device or emulator. "
            "Scan for devices on the Devices page if the list is empty.",
        )
        self._device_combo = QComboBox()
        layout.addWidget(self._device_combo)
        self.body.addWidget(frame)

    def _build_pipeline_card(self) -> None:
        definition = WORKFLOW_REGISTRY.get(self.workflow_name)
        step_count = len(definition.steps) if definition else 0
        frame, layout = card(
            "PIPELINE",
            f"{step_count} step(s) in '{self.workflow_name}'. A step whose plugin is "
            f"MISSING needs its underlying tool installed \u2014 do that from Toolbox "
            f"or Dependency Manager.",
        )
        self._pipeline_layout = layout
        self._step_rows: list[_StepRow] = []

        if definition is None:
            layout.addWidget(empty_state(
                f"Workflow '{self.workflow_name}' is not in WORKFLOW_REGISTRY."
            ))
        else:
            for i, step in enumerate(definition.steps, start=1):
                row = _StepRow(i, step.name, step.plugin_id, step.required)
                self._step_rows.append(row)
                layout.addWidget(row)

        recheck = QPushButton("Re-check tool availability")
        recheck.clicked.connect(self._on_recheck)
        layout.addWidget(recheck, alignment=Qt.AlignLeft)

        self.body.addWidget(frame)

    def _build_result_card(self) -> None:
        frame, layout = card("LAST RUN")
        self._result_layout = layout
        self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    # Data
    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        self._reload_projects()
        if self.requires_device:
            self._reload_devices()
        self._apply_health()
        self._reload_result()

    def _reload_projects(self) -> None:
        with session_scope() as session:
            query = session.query(Project)
            if self.platform is not None:
                query = query.filter(Project.platform == self.platform)
            rows = [
                (p.id, p.name, p.project_type.value, p.target_path)
                for p in query.order_by(Project.updated_at.desc()).all()
            ]

        previous = self._project_combo.currentData()
        self._project_combo.blockSignals(True)
        self._project_combo.clear()
        for project_id, name, project_type, target_path in rows:
            suffix = "" if target_path else "  (no target file)"
            self._project_combo.addItem(f"{name}  \u2014  {project_type}{suffix}", project_id)
        self._project_combo.blockSignals(False)

        if previous is not None:
            index = self._project_combo.findData(previous)
            if index >= 0:
                self._project_combo.setCurrentIndex(index)

        self._projects = {r[0]: r for r in rows}
        self._on_project_changed()

    def _reload_devices(self) -> None:
        with session_scope() as session:
            rows = [
                (d.id, d.display_name, d.identifier, d.status.value)
                for d in session.query(Device)
                .filter(Device.platform == Platform.ANDROID)
                .order_by(Device.last_connected_at.desc().nullslast())
                .all()
            ]
        previous = self._device_combo.currentData()
        self._device_combo.clear()
        if not rows:
            self._device_combo.addItem("No devices detected \u2014 scan on the Devices page", None)
            self._device_combo.setEnabled(False)
        else:
            self._device_combo.setEnabled(True)
            for device_id, name, identifier, status in rows:
                ready = status == DeviceStatus.READY.value
                mark = "" if ready else f"  ({status})"
                self._device_combo.addItem(f"{name}  \u2014  {identifier}{mark}", device_id)
            if previous is not None:
                index = self._device_combo.findData(previous)
                if index >= 0:
                    self._device_combo.setCurrentIndex(index)

    def _apply_health(self) -> None:
        for row in self._step_rows:
            health, detail = probe_health_cached(row._plugin_id)
            row.apply_health(health, detail)

    def _current_project_id(self) -> int | None:
        data = self._project_combo.currentData()
        return int(data) if data is not None else None

    def _on_project_changed(self) -> None:
        project_id = self._current_project_id()
        if project_id is None:
            self._target_label.setText(
                "No matching project yet. Create one to choose an analysis target."
            )
            self._run_btn.setEnabled(False)
            return
        _, _, _, target_path = self._projects[project_id]
        if target_path:
            self._target_label.setText(f"Target: {target_path}")
            self._run_btn.setEnabled(self._job_id is None)
        else:
            self._target_label.setText(
                "This project has no target file, so there is nothing to analyse."
            )
            self._run_btn.setEnabled(False)

    def _on_new_project(self) -> None:
        from app.gui.dialogs.new_project_dialog import NewProjectDialog

        dialog = NewProjectDialog(self)
        if dialog.exec() == dialog.DialogCode.Accepted and dialog.created_project_id:
            self.set_status(
                f"Project created (id={dialog.created_project_id})", Colors.ACCENT_GREEN
            )
            self._reload_projects()
            index = self._project_combo.findData(dialog.created_project_id)
            if index >= 0:
                self._project_combo.setCurrentIndex(index)

    def _on_recheck(self) -> None:
        invalidate_health_cache()
        self._apply_health()
        self.set_status("Re-checked every plugin in this pipeline.", Colors.TEXT_SECONDARY)

    # ------------------------------------------------------------------ #
    # Running
    # ------------------------------------------------------------------ #
    def _on_run(self) -> None:
        project_id = self._current_project_id()
        if project_id is None:
            return

        with session_scope() as session:
            project = session.get(Project, project_id)
            if project is None or not project.target_path:
                self.set_status("That project no longer has a usable target.", Colors.STATUS_ERROR)
                return
            target_path, workspace_path = project.target_path, project.workspace_path

        device_id = None
        if self.requires_device:
            device_id = self._device_combo.currentData()
            if device_id is None:
                self.set_status(
                    "This workflow needs a connected device. Scan for one on the Devices page.",
                    Colors.STATUS_WARNING,
                )
                return
            device_id = int(device_id)

        job_id = self._runner.start(
            self.workflow_name, project_id, target_path, workspace_path, device_id
        )
        if not job_id:
            return

        self._job_id = job_id
        self._run_btn.setEnabled(False)
        self._progress.setValue(0)
        self._progress.show()
        self.set_status(f"Running '{self.workflow_name}'...", Colors.STATUS_RUNNING)

    def _on_progress(self, job_id: str, percent: float, step: str) -> None:
        if job_id != self._job_id:
            return
        self._progress.setValue(int(percent))
        self._step_label.setText(step or "Starting...")

    def _on_completed(self, job_id: str, status: str, risk_score: float, analysis_id: int) -> None:
        if job_id != self._job_id:
            # Another page started this run; its results still belong in our
            # "last run" card if they're for this workflow, so refresh anyway.
            self._reload_result()
            return

        self._job_id = None
        self._run_btn.setEnabled(True)
        self._progress.hide()
        self._step_label.setText("")
        self._last_analysis_id = analysis_id

        self.set_status(
            f"Run {status} \u2014 risk score {risk_score:.1f}",
            Colors.ACCENT_GREEN if status == "completed" else Colors.STATUS_ERROR,
        )
        self._reload_result()
        self.main_window.refresh_top_bar_stats()

    def _on_failed_to_start(self, message: str) -> None:
        if self._job_id is not None:
            return
        self._run_btn.setEnabled(True)
        self._progress.hide()
        self.set_status(f"Could not start the run: {message}", Colors.STATUS_ERROR)

    # ------------------------------------------------------------------ #
    # Results
    # ------------------------------------------------------------------ #
    def _reload_result(self) -> None:
        clear_layout(self._result_layout, keep=1)

        with session_scope() as session:
            analysis = (
                session.query(Analysis)
                .filter(Analysis.workflow_name == self.workflow_name)
                .order_by(Analysis.created_at.desc())
                .first()
            )
            if analysis is None:
                self._result_layout.addWidget(empty_state(
                    "This workflow hasn't been run yet. Pick a target above and click Run Analysis."
                ))
                return
            project = session.get(Project, analysis.project_id)
            finding_count = session.query(Finding).filter_by(analysis_id=analysis.id).count()
            data = {
                "id": analysis.id,
                "project": project.name if project else "Unknown project",
                "status": analysis.status,
                "risk": analysis.risk_score,
                "created": analysis.created_at,
                "notes": analysis.error_message or "",
                "findings": finding_count,
            }

        status_color = {
            RunStatus.COMPLETED: Colors.ACCENT_GREEN,
            RunStatus.FAILED: Colors.STATUS_ERROR,
            RunStatus.RUNNING: Colors.STATUS_RUNNING,
        }.get(data["status"], Colors.TEXT_MUTED)

        self._result_layout.addWidget(kv_row("Project", data["project"]))
        self._result_layout.addWidget(
            kv_row("Status", data["status"].value.upper(), status_color)
        )
        self._result_layout.addWidget(
            kv_row("Risk score", "n/a" if data["risk"] is None else f"{data['risk']:.1f} / 10")
        )
        self._result_layout.addWidget(kv_row("Findings", str(data["findings"])))
        self._result_layout.addWidget(
            kv_row("Finished", f"{data['created']:%Y-%m-%d %H:%M}")
        )

        skipped = [
            line.split("]:")[0].split("[")[-1]
            for line in data["notes"].splitlines() if line.startswith("SKIPPED")
        ]
        failed = [line for line in data["notes"].splitlines() if line.startswith("FAILED")]

        if skipped:
            self._result_layout.addWidget(label(
                f"{len(skipped)} step(s) skipped: {', '.join(skipped)}. "
                f"Install the missing tools and run again for full coverage.",
                size=10, color=Colors.STATUS_WARNING, wrap=True,
            ))
        if failed:
            self._result_layout.addWidget(label(
                "\n".join(failed), size=10, color=Colors.STATUS_ERROR, wrap=True
            ))
        if data["findings"] == 0 and not skipped and not failed:
            self._result_layout.addWidget(label(
                "0 findings with every step completing \u2014 that is a clean result, "
                "not a broken scan.",
                size=10, color=Colors.TEXT_MUTED, wrap=True,
            ))

        buttons = QWidget()
        button_row = QHBoxLayout(buttons)
        button_row.setContentsMargins(0, 0, 0, 0)
        button_row.setSpacing(10)
        if data["findings"]:
            view_btn = QPushButton(f"View {data['findings']} Finding(s)")
            view_btn.setProperty("class", "Primary")
            view_btn.clicked.connect(
                lambda _=False, aid=data["id"]: FindingsDialog(aid, self).exec()
            )
            button_row.addWidget(view_btn)
        all_btn = QPushButton("Open All Analyses")
        all_btn.clicked.connect(lambda: self.main_window.sidebar.navigate.emit("analyses"))
        button_row.addWidget(all_btn)
        button_row.addStretch()
        self._result_layout.addWidget(buttons)


# --------------------------------------------------------------------------- #
# Concrete pages. Each maps a sidebar key to one WORKFLOW_REGISTRY entry.
# --------------------------------------------------------------------------- #
class AndroidApkPage(WorkflowPage):
    title_text = "Android APK"
    subtitle_text = (
        "Full static assessment of an APK: signing certificate, manifest, network security "
        "config, hardcoded secrets, code patterns and embedded trackers."
    )
    workflow_name = "static_analysis_default"
    target_hint = "Pick an Android project. The analysis runs against its APK target file."


class StaticAnalysisPage(WorkflowPage):
    title_text = "Static Analysis"
    subtitle_text = (
        "The same static pipeline as Android APK, reachable from the generic entry point. "
        "Results appear under All Analyses either way."
    )
    workflow_name = "static_analysis_default"


class AndroidMalwarePage(WorkflowPage):
    title_text = "Android Malware"
    subtitle_text = (
        "Malware-oriented pipeline: hashing, VirusTotal reputation, YARA, APKiD packer "
        "fingerprinting, Quark behaviour scoring, IOC extraction and MITRE ATT&CK mapping."
    )
    workflow_name = "malware_analysis_default"
    target_hint = (
        "Pick the project holding the sample. Handle untrusted samples in an isolated "
        "environment \u2014 Pentroid unpacks them on this machine."
    )


class DynamicAnalysisPage(WorkflowPage):
    title_text = "Dynamic Analysis"
    subtitle_text = (
        "Installs the app on a connected device, launches it under Frida instrumentation "
        "and captures logcat output during the session."
    )
    workflow_name = "dynamic_analysis_default"
    requires_device = True


class PrivacyAnalysisPage(WorkflowPage):
    title_text = "Privacy Analysis"
    subtitle_text = (
        "Privacy-focused subset of the static pipeline: dangerous permissions, cleartext "
        "traffic policy, third-party tracking SDKs and the endpoints the app talks to."
    )
    workflow_name = "privacy_analysis_default"
