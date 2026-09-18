"""
app.gui.pages.reverse_engineering_page
=========================================

Unpack an APK for manual review: APKTool for resources and smali, JADX
for Java sources, both written into the project's workspace directory.

This runs the ``reverse_engineering_default`` workflow rather than
calling APKTool/JADX directly, so the decode is recorded as an
``Analysis`` row and its skipped/failed steps are reported the same way
every other pipeline's are. The workflow has no findings-producing
steps by design -- a run here finishing with 0 findings is the expected
outcome, not a broken scan -- so the page points you at the output on
disk instead of at a findings list.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import QPushButton, QWidget

from app.database.database import session_scope
from app.database.models import Project
from app.gui.pages.common import card, clear_layout, empty_state, kv_row, label
from app.gui.pages.workflow_page import WorkflowPage
from app.gui.theme import Colors


def open_in_file_manager(path: Path) -> str:
    """
    Open ``path`` in the desktop's file manager. Returns "" on success or a
    human-readable reason on failure.

    Uses the platform opener rather than QDesktopServices so the failure is
    observable: on a headless or minimal Linux box there may be no handler at
    all, and silently doing nothing would look like a broken button.
    """
    if not path.exists():
        return f"{path} does not exist"
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # noqa: S606 - Windows' documented opener
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=True, timeout=10)
        else:
            subprocess.run(["xdg-open", str(path)], check=True, timeout=10)
        return ""
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)


class ReverseEngineeringPage(WorkflowPage):
    title_text = "Reverse Engineering"
    subtitle_text = (
        "Decode an APK into resources and smali with APKTool, and decompile its dex to Java "
        "with JADX. Output lands in the project workspace for you to read."
    )
    workflow_name = "reverse_engineering_default"
    target_hint = "Pick the Android project whose APK you want to unpack."

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._build_output_card()
        self._reload_output()

    def _build_output_card(self) -> None:
        frame, layout = card(
            "WORKSPACE OUTPUT",
            "APKTool and JADX write into the selected project's workspace directory.",
        )
        self._output_layout = layout
        self._output_anchor = layout.count()
        self.body.addWidget(frame)

        open_btn = QPushButton("Open workspace folder")
        open_btn.clicked.connect(self._on_open_workspace)
        layout.addWidget(open_btn)
        self._output_anchor = layout.count()

    def _on_project_changed(self) -> None:
        super()._on_project_changed()
        if hasattr(self, "_output_layout"):
            self._reload_output()

    def _on_completed(self, job_id, status, risk_score, analysis_id) -> None:
        super()._on_completed(job_id, status, risk_score, analysis_id)
        self._reload_output()

    def _workspace(self) -> Path | None:
        project_id = self._current_project_id()
        if project_id is None:
            return None
        with session_scope() as session:
            project = session.get(Project, project_id)
            return Path(project.workspace_path) if project else None

    def _on_open_workspace(self) -> None:
        workspace = self._workspace()
        if workspace is None:
            self.set_status("Select a project first.", Colors.STATUS_WARNING)
            return
        error = open_in_file_manager(workspace)
        self.set_status(
            f"Opened {workspace}" if not error else f"Could not open {workspace}: {error}",
            Colors.ACCENT_GREEN if not error else Colors.STATUS_ERROR,
        )

    def _reload_output(self) -> None:
        clear_layout(self._output_layout, keep=self._output_anchor)
        workspace = self._workspace()
        if workspace is None:
            self._output_layout.addWidget(empty_state("Select a project to see its output."))
            return

        self._output_layout.addWidget(kv_row("Workspace", str(workspace)))
        if not workspace.exists():
            self._output_layout.addWidget(label(
                "The workspace directory no longer exists on disk.",
                size=10, color=Colors.STATUS_ERROR, wrap=True,
            ))
            return

        entries = sorted(p for p in workspace.iterdir())
        if not entries:
            self._output_layout.addWidget(label(
                "Workspace is empty. Run the decode above to populate it.",
                size=10, color=Colors.TEXT_MUTED, wrap=True,
            ))
            return

        for entry in entries[:25]:
            if entry.is_dir():
                try:
                    child_count = sum(1 for _ in entry.iterdir())
                    detail = f"directory \u2022 {child_count} item(s)"
                except OSError as exc:
                    detail = f"directory \u2022 unreadable ({exc.strerror})"
            else:
                detail = f"{entry.stat().st_size / 1024:.1f} KB"
            self._output_layout.addWidget(kv_row(entry.name, detail))

        if len(entries) > 25:
            self._output_layout.addWidget(label(
                f"...and {len(entries) - 25} more. Open the folder to see everything.",
                size=10, color=Colors.TEXT_MUTED,
            ))
