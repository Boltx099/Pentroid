"""
app.gui.dialogs.setup_wizard_dialog
======================================

Displays the results of a ``DeviceSetupWizard.run()`` call: one row
per step with a pass/fail indicator and, on failure, the guidance text
the wizard produced (what the user needs to do on the physical device
-- accept an RSA prompt, install a cert, etc.).
"""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from app.gui.theme import Colors


class SetupWizardDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Device Setup Wizard")
        self.setMinimumSize(440, 420)

        layout = QVBoxLayout(self)
        self._status_label = QLabel("Running setup wizard...")
        self._status_label.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(self._status_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self._results_container = QWidget()
        self._results_layout = QVBoxLayout(self._results_container)
        self._results_layout.setSpacing(8)
        scroll.setWidget(self._results_container)
        layout.addWidget(scroll, stretch=1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def show_results(self, results: list) -> None:
        while self._results_layout.count():
            item = self._results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        final_step = results[-1] if results else None
        ready = final_step is not None and final_step.step == "Ready" and final_step.passed
        self._status_label.setText(
            "Device is ready for dynamic analysis." if ready else "Setup incomplete -- see steps below."
        )
        self._status_label.setStyleSheet(
            f"color: {Colors.ACCENT_GREEN if ready else Colors.STATUS_WARNING}; font-size: 13px; font-weight: 600;"
        )

        for result in results:
            row = QWidget()
            row_layout = QVBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(2)

            icon = "\u2713" if result.passed else "\u2717"
            color = Colors.ACCENT_GREEN if result.passed else Colors.STATUS_ERROR
            header = QLabel(f"{icon}  {result.step}")
            header.setStyleSheet(f"color: {color}; font-size: 13px; font-weight: 700;")
            row_layout.addWidget(header)

            message = QLabel(result.message)
            message.setWordWrap(True)
            message.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 11px; margin-left: 20px;")
            row_layout.addWidget(message)

            if result.guidance:
                guidance = QLabel(f"\u25C8 {result.guidance}")
                guidance.setWordWrap(True)
                guidance.setStyleSheet(f"color: {Colors.ACCENT_CYAN}; font-size: 10px; margin-left: 20px;")
                row_layout.addWidget(guidance)

            self._results_layout.addWidget(row)

    def show_error(self, message: str) -> None:
        self._status_label.setText(f"Setup wizard failed: {message}")
        self._status_label.setStyleSheet(f"color: {Colors.STATUS_ERROR}; font-size: 12px;")
