"""
app.gui.pages.toolbox_page
=============================

The Toolbox and Dependency Manager pages. Both render every entry in
``TOOL_REGISTRY`` with its live install state and a working Install
button; Toolbox groups them by what the tool is *for* (an analyst's
view), Dependency Manager lists them by how they are *installed* (an
operator's view). They share one row implementation because they are
the same data with a different grouping.

Installs are genuinely performed by ``DependencyManager.install`` --
download, checksum, extract, resolve binary -- dispatched through
``BackgroundTaskRunner`` so the network and subprocess work never
blocks the GUI thread. Nothing here shells out itself.

Status probing is also backgrounded: ``DependencyManager.status``
executes each installed binary with its ``--version`` flag, and doing
fourteen of those synchronously froze the UI for seconds on every
visit to the page.
"""

from __future__ import annotations

from PySide6.QtWidgets import QPushButton, QWidget

from app.core.dependency_manager import TOOL_REGISTRY, InstallMethod, get_dependency_manager
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.pages.common import ActionRow, BasePage, card, label
from app.gui.pages.workflow_page import invalidate_health_cache
from app.gui.theme import Colors

# Analyst-facing grouping. Every tool in TOOL_REGISTRY appears exactly once;
# anything added to the registry later without being listed here falls into
# "Other" rather than disappearing from the page.
_TOOL_GROUPS: list[tuple[str, str, list[str]]] = [
    ("DECOMPILE & UNPACK", "Turn an APK back into readable resources, smali and Java.",
     ["apktool", "jadx", "bundletool"]),
    ("MALWARE TRIAGE", "Packer fingerprinting, behaviour scoring and reputation lookups.",
     ["apkid", "quark", "virustotal"]),
    ("DEVICE & RUNTIME", "Talk to devices and instrument a running app.",
     ["adb", "frida", "frida_server_arm64", "frida_server_x86_64", "objection",
      "pymobiledevice3"]),
    ("NETWORK", "Intercept and inspect traffic from the device.",
     ["mitmproxy", "burp_suite"]),
    ("PLATFORM", "Provided by a runtime Pentroid already requires, or run as a service.",
     ["keytool", "mobsf"]),
]

_METHOD_LABEL = {
    InstallMethod.GITHUB_RELEASE: "GitHub release",
    InstallMethod.DIRECT_URL: "Vendor download",
    InstallMethod.PIP_VENV: "Isolated virtualenv",
    InstallMethod.SERVICE: "External service",
    InstallMethod.SYSTEM: "System $PATH",
}


class _ToolRow(ActionRow):
    def __init__(self, tool_name: str, on_install, parent=None):
        spec = TOOL_REGISTRY[tool_name]
        super().__init__(spec.name, spec.description, parent)
        self.tool_name = tool_name
        self._spec = spec
        self._base_description = spec.description

        self.set_status("CHECKING", Colors.TEXT_MUTED)

        self.install_btn: QPushButton | None = None
        if spec.install_method == InstallMethod.SERVICE:
            btn = self.add_button("Configure in Settings", lambda: None)
            btn.setEnabled(False)
            btn.setToolTip(
                "Not a downloadable binary. Set its endpoint and API key under Settings."
            )
        elif spec.install_method == InstallMethod.SYSTEM:
            btn = self.add_button("Provided by the JDK", lambda: None)
            btn.setEnabled(False)
            btn.setToolTip("Resolved from $PATH, same as 'java' itself.")
        else:
            self.install_btn = self.add_button("Install", lambda: on_install(self))

    def apply_status(self, installed: bool, version: str | None) -> None:
        method = _METHOD_LABEL.get(self._spec.install_method, "")
        if self._spec.install_method == InstallMethod.SERVICE:
            self.set_status("SERVICE", Colors.ACCENT_CYAN)
            self.set_description(f"{self._base_description}  \u2022  {method}")
            return
        if installed:
            self.set_status("INSTALLED", Colors.ACCENT_GREEN)
            detail = f"  \u2022  {version}" if version else ""
            self.set_description(f"{self._base_description}  \u2022  {method}{detail}")
            if self.install_btn is not None:
                self.install_btn.setText("Reinstall")
                self.install_btn.setEnabled(True)
        else:
            self.set_status("NOT INSTALLED", Colors.TEXT_MUTED)
            self.set_description(f"{self._base_description}  \u2022  {method}")
            if self.install_btn is not None:
                self.install_btn.setText("Install")
                self.install_btn.setEnabled(True)

    def set_installing(self) -> None:
        self.set_status("INSTALLING", Colors.STATUS_RUNNING)
        if self.install_btn is not None:
            self.install_btn.setEnabled(False)
            self.install_btn.setText("Installing...")

    def set_failed(self, message: str) -> None:
        self.set_status("FAILED", Colors.STATUS_ERROR)
        self.set_description(f"{self._base_description}  \u2022  {message}")
        if self.install_btn is not None:
            self.install_btn.setEnabled(True)
            self.install_btn.setText("Retry Install")


class _ToolListPage(BasePage):
    """Shared behaviour; the two concrete pages differ only in grouping."""

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._deps = get_dependency_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_task_finished)
        self._task_runner.failed.connect(self._on_task_failed)
        self._pending_installs: dict[str, _ToolRow] = {}
        self._status_job: str | None = None
        self._rows: dict[str, _ToolRow] = {}

        self.add_header_button("Refresh status", self.refresh)
        self._build_groups()
        self.refresh()

    def _groups(self) -> list[tuple[str, str, list[str]]]:
        raise NotImplementedError

    def _build_groups(self) -> None:
        for title, subtitle, tool_names in self._groups():
            present = [n for n in tool_names if n in TOOL_REGISTRY]
            if not present:
                continue
            frame, layout = card(title, subtitle)
            for tool_name in present:
                row = _ToolRow(tool_name, on_install=self._on_install)
                self._rows[tool_name] = row
                layout.addWidget(row)
            self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    # Status (backgrounded -- version probes exec each binary)
    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        if not getattr(self, "_rows", None) or self._status_job is not None:
            return
        self.set_status("Checking installed tool versions...", Colors.STATUS_RUNNING)
        self._status_job = self._task_runner.run(self._deps.status_all)

    def _apply_status_all(self, status_map: dict) -> None:
        installed = 0
        for tool_name, row in self._rows.items():
            status = status_map.get(tool_name)
            if status is None:
                continue
            row.apply_status(status.installed, status.version)
            if status.installed and TOOL_REGISTRY[tool_name].install_method not in (
                InstallMethod.SERVICE,
            ):
                installed += 1
        total = sum(
            1 for name, spec in TOOL_REGISTRY.items()
            if spec.install_method != InstallMethod.SERVICE and name in self._rows
        )
        self.set_status(
            f"{installed} of {total} installable tool(s) present.",
            Colors.ACCENT_GREEN if installed else Colors.TEXT_MUTED,
        )

    # ------------------------------------------------------------------ #
    # Install
    # ------------------------------------------------------------------ #
    def _on_install(self, row: _ToolRow) -> None:
        row.set_installing()
        self.set_status(
            f"Installing {row.tool_name} \u2014 this downloads from the internet and can "
            f"take a while for large tools.",
            Colors.STATUS_RUNNING,
        )
        job_id = self._task_runner.run(self._deps.install, row.tool_name)
        self._pending_installs[job_id] = row

    def _on_task_finished(self, job_id: str, result) -> None:
        if job_id == self._status_job:
            self._status_job = None
            self._apply_status_all(result or {})
            return

        row = self._pending_installs.pop(job_id, None)
        if row is None:
            return
        row.apply_status(result.installed, result.version)
        # A newly installed tool can flip a plugin from MISSING to READY, so the
        # analysis pages' cached health results are no longer trustworthy.
        invalidate_health_cache()
        self.set_status(
            f"{row.tool_name}: {'installed' if result.installed else 'install reported failure'}",
            Colors.ACCENT_GREEN if result.installed else Colors.STATUS_ERROR,
        )

    def _on_task_failed(self, job_id: str, error_message: str) -> None:
        if job_id == self._status_job:
            self._status_job = None
            self.set_status(f"Status check failed: {error_message}", Colors.STATUS_ERROR)
            return
        row = self._pending_installs.pop(job_id, None)
        if row is None:
            return
        row.set_failed(error_message)
        self.set_status(f"{row.tool_name} install failed: {error_message}", Colors.STATUS_ERROR)


class ToolboxPage(_ToolListPage):
    title_text = "Toolbox"
    subtitle_text = (
        "Every external tool Pentroid can drive, grouped by what it's for. Install one here "
        "and the analysis pipelines that depend on it stop skipping their steps."
    )

    def _groups(self):
        known = {name for _, _, names in _TOOL_GROUPS for name in names}
        groups = list(_TOOL_GROUPS)
        other = [name for name in sorted(TOOL_REGISTRY) if name not in known]
        if other:
            groups.append(("OTHER", "Registered tools not yet categorised.", other))
        return groups


class DependencyManagerPage(_ToolListPage):
    title_text = "Dependency Manager"
    subtitle_text = (
        "The same tools grouped by how they are installed. Downloads are checksum-verified "
        "against the hash recorded on first install (trust-on-first-use), and pip-based "
        "tools get their own virtualenv so their dependencies never collide with Pentroid's."
    )

    def _groups(self):
        by_method: dict[InstallMethod, list[str]] = {}
        for name, spec in sorted(TOOL_REGISTRY.items()):
            by_method.setdefault(spec.install_method, []).append(name)

        descriptions = {
            InstallMethod.GITHUB_RELEASE:
                "Resolved from the project's GitHub releases, asset matched per platform.",
            InstallMethod.DIRECT_URL:
                "Fetched from a fixed vendor URL (not published as a GitHub release).",
            InstallMethod.PIP_VENV:
                "PyPI package installed into an isolated virtualenv under tools/<name>/venv.",
            InstallMethod.SERVICE:
                "Not a binary at all \u2014 configure an endpoint and API key under Settings.",
            InstallMethod.SYSTEM:
                "Expected on $PATH as part of a runtime Pentroid already requires.",
        }
        return [
            (_METHOD_LABEL.get(method, method.value).upper(),
             descriptions.get(method, ""), names)
            for method, names in by_method.items()
        ]
