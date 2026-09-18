"""
app.gui.dialogs.new_project_dialog
=====================================

Modal dialog for creating a new Project. On accept, it:

1. Validates the form (name required, target file must exist and
   match the selected platform's extension).
2. Creates a real workspace directory under
   ``settings.paths.projects_dir``.
3. Inserts a real ``Project`` row via the database layer.

No GUI-side faking: if this dialog returns a project_id, that project
genuinely exists in the database and its workspace directory genuinely
exists on disk.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QVBoxLayout,
)

from app.core.config import get_settings
from app.database.database import session_scope
from app.database.models import Platform, Project, ProjectType
from app.gui.theme import Colors

_PROJECT_TYPES_BY_PLATFORM: dict[Platform, list[tuple[str, ProjectType]]] = {
    Platform.ANDROID: [
        ("APK (Static Analysis)", ProjectType.ANDROID_APK),
        ("Malware Analysis", ProjectType.ANDROID_MALWARE),
        ("Dynamic Analysis", ProjectType.ANDROID_DYNAMIC),
        ("Live Device", ProjectType.ANDROID_DEVICE),
    ],
    Platform.IOS: [
        ("IPA (Static Analysis)", ProjectType.IOS_IPA),
        ("Dynamic Analysis", ProjectType.IOS_DYNAMIC),
    ],
}

_EXTENSIONS_BY_PLATFORM = {
    Platform.ANDROID: (".apk",),
    Platform.IOS: (".ipa",),
}


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip()).strip("-").lower()
    return slug or "project"


class NewProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Project")
        self.setMinimumWidth(420)
        self.created_project_id: int | None = None
        self._target_path: str | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(QLabel("Project Name"))
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("e.g. ChatApp")
        layout.addWidget(self._name_edit)

        layout.addWidget(QLabel("Platform"))
        self._platform_combo = QComboBox()
        self._platform_combo.addItem("Android", Platform.ANDROID)
        self._platform_combo.addItem("iOS", Platform.IOS)
        self._platform_combo.currentIndexChanged.connect(self._on_platform_changed)
        layout.addWidget(self._platform_combo)

        layout.addWidget(QLabel("Analysis Type"))
        self._type_combo = QComboBox()
        layout.addWidget(self._type_combo)

        layout.addWidget(QLabel("Target File"))
        file_row = QHBoxLayout()
        self._file_label = QLabel("No file selected")
        self._file_label.setStyleSheet(f"color: {Colors.TEXT_MUTED};")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._on_browse)
        file_row.addWidget(self._file_label, stretch=1)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet(f"color: {Colors.STATUS_ERROR}; font-size: 11px;")
        self._error_label.setWordWrap(True)
        layout.addWidget(self._error_label)

        button_row = QHBoxLayout()
        button_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        create_btn = QPushButton("Create Project")
        create_btn.setProperty("class", "Primary")
        create_btn.clicked.connect(self._on_create)
        button_row.addWidget(cancel_btn)
        button_row.addWidget(create_btn)
        layout.addLayout(button_row)

        self._on_platform_changed()

    def _current_platform(self) -> Platform:
        # QComboBox.currentData() round-trips through QVariant, which silently degrades
        # a str-subclassed Enum (Platform(str, Enum)) back to a plain str -- reconstruct
        # explicitly so callers always get a real Platform member with .value/.name intact.
        return Platform(self._platform_combo.currentData())

    def _on_platform_changed(self) -> None:
        platform = self._current_platform()
        self._type_combo.clear()
        for label, project_type in _PROJECT_TYPES_BY_PLATFORM[platform]:
            self._type_combo.addItem(label, project_type)

    def _on_browse(self) -> None:
        platform = self._current_platform()
        exts = _EXTENSIONS_BY_PLATFORM[platform]
        filter_str = f"{platform.value.upper()} Files (*{' *'.join(exts)})"
        path, _ = QFileDialog.getOpenFileName(self, "Select Target File", "", filter_str)
        if path:
            self._target_path = path
            self._file_label.setText(Path(path).name)
            self._file_label.setStyleSheet(f"color: {Colors.TEXT_PRIMARY};")

    def _on_create(self) -> None:
        name = self._name_edit.text().strip()
        platform = self._current_platform()
        project_type = ProjectType(self._type_combo.currentData())

        if not name:
            self._error_label.setText("Project name is required.")
            return
        if not self._target_path:
            self._error_label.setText("Please select a target file.")
            return

        target_path = Path(self._target_path)
        if not target_path.exists():
            self._error_label.setText(f"Target file no longer exists: {target_path}")
            return
        allowed_exts = _EXTENSIONS_BY_PLATFORM[platform]
        if target_path.suffix.lower() not in allowed_exts:
            self._error_label.setText(
                f"Expected a {'/'.join(allowed_exts)} file for {platform.value}, got {target_path.suffix}"
            )
            return

        settings = get_settings()
        workspace_dir = settings.paths.projects_dir / f"{_slugify(name)}-{uuid.uuid4().hex[:8]}"
        try:
            workspace_dir.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            self._error_label.setText(f"Could not create workspace directory: {exc}")
            return

        try:
            with session_scope() as session:
                project = Project(
                    name=name,
                    platform=platform,
                    project_type=project_type,
                    target_path=str(target_path),
                    workspace_path=str(workspace_dir),
                )
                session.add(project)
                session.flush()
                self.created_project_id = project.id
        except Exception as exc:
            self._error_label.setText(f"Failed to create project: {exc}")
            return

        self.accept()
