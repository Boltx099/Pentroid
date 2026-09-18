"""
app.gui.dialogs.wireless_connect_dialog
==========================================

Wireless ADB connection dialog covering both Android flows, which are
genuinely different and a common source of confusion:

* **Android 11+ (Wireless debugging)** -- a one-time pair using the
  *pairing* port + 6-digit code shown on-device, then a connect on a
  *different* port. Both values come from
  Developer options > Wireless debugging.
* **Legacy (pre-Android-11)** -- no pairing; the device must first be
  switched to TCP/IP mode over USB (`adb tcpip 5555`), then connected
  to directly.

The dialog makes the two-step nature of the modern flow explicit
rather than presenting a single "connect" box that silently fails for
anyone on Android 11+.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from app.core.device.connection_manager import get_connection_manager
from app.gui.theme import Colors, build_stylesheet


def _section_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 12px; font-weight: 700;")
    return label


def _hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
    return label


class WirelessConnectDialog(QDialog):
    def __init__(self, parent=None, connection_manager=None):
        super().__init__(parent)
        self.setWindowTitle("Wireless ADB Connection")
        self.setMinimumWidth(460)
        # Apply the app stylesheet explicitly: a dialog shown without a styled
        # parent would otherwise fall back to Qt's default light palette, making
        # the section headers (near-white on the dark theme) effectively invisible.
        self.setStyleSheet(build_stylesheet())
        self._conn = connection_manager or get_connection_manager()
        self.connected = False

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # --- Step 1: pairing (Android 11+) ---
        layout.addWidget(_section_label("Step 1 \u2014 Pair (Android 11+ only)"))
        layout.addWidget(_hint(
            "On the device: Developer options > Wireless debugging > Pair device with pairing code. "
            "Use the PAIRING port shown there (not the connect port)."
        ))

        pair_row = QHBoxLayout()
        self._pair_host = QLineEdit()
        self._pair_host.setPlaceholderText("192.168.1.50")
        self._pair_port = QSpinBox()
        self._pair_port.setRange(1, 65535)
        self._pair_port.setValue(37000)
        self._pair_code = QLineEdit()
        self._pair_code.setPlaceholderText("6-digit code")
        self._pair_code.setMaxLength(6)
        for widget in (self._pair_host, self._pair_port, self._pair_code):
            pair_row.addWidget(widget)
        pair_widget = QWidget()
        pair_widget.setLayout(pair_row)
        layout.addWidget(pair_widget)

        pair_btn = QPushButton("Pair Device")
        pair_btn.clicked.connect(self._on_pair)
        layout.addWidget(pair_btn)

        # --- Step 2: connect ---
        layout.addWidget(_section_label("Step 2 \u2014 Connect"))
        layout.addWidget(_hint(
            "Use the CONNECT port (shown as 'IP address & Port' on Android 11+). "
            "On older devices, run 'adb tcpip 5555' over USB first, then connect on 5555."
        ))

        connect_row = QHBoxLayout()
        self._connect_host = QLineEdit()
        self._connect_host.setPlaceholderText("192.168.1.50")
        self._connect_port = QSpinBox()
        self._connect_port.setRange(1, 65535)
        self._connect_port.setValue(5555)
        connect_row.addWidget(self._connect_host)
        connect_row.addWidget(self._connect_port)
        connect_widget = QWidget()
        connect_widget.setLayout(connect_row)
        layout.addWidget(connect_widget)

        self._status = QLabel("")
        self._status.setWordWrap(True)
        self._status.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 11px;")
        layout.addWidget(self._status)

        button_row = QHBoxLayout()
        button_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        connect_btn = QPushButton("Connect")
        connect_btn.setProperty("class", "Primary")
        connect_btn.clicked.connect(self._on_connect)
        button_row.addWidget(close_btn)
        button_row.addWidget(connect_btn)
        layout.addLayout(button_row)

    def _set_status(self, text: str, color: str) -> None:
        self._status.setText(text)
        self._status.setStyleSheet(f"color: {color}; font-size: 11px;")

    def _on_pair(self) -> None:
        host = self._pair_host.text().strip()
        code = self._pair_code.text().strip()
        if not host or not code:
            self._set_status("Pairing needs both an IP address and the 6-digit code.", Colors.STATUS_WARNING)
            return

        self._set_status(f"Pairing with {host}...", Colors.STATUS_RUNNING)
        try:
            paired = self._conn.pair_wireless(host, self._pair_port.value(), code)
        except Exception as exc:  # noqa: BLE001 - surface any failure instead of killing the dialog
            self._set_status(f"Pairing error: {exc}", Colors.STATUS_ERROR)
            return

        if paired:
            self._set_status("Paired successfully. Now connect using the CONNECT port below.", Colors.ACCENT_GREEN)
            if not self._connect_host.text().strip():
                self._connect_host.setText(host)
        else:
            self._set_status(
                "Pairing failed. Check the code hasn't expired and that you used the pairing port.",
                Colors.STATUS_ERROR,
            )

    def _on_connect(self) -> None:
        host = self._connect_host.text().strip()
        if not host:
            self._set_status("Enter the device IP address to connect.", Colors.STATUS_WARNING)
            return

        self._set_status(f"Connecting to {host}...", Colors.STATUS_RUNNING)
        try:
            ok = self._conn.connect_wireless(host, self._connect_port.value())
        except Exception as exc:  # noqa: BLE001
            self._set_status(f"Connection error: {exc}", Colors.STATUS_ERROR)
            return

        if ok:
            self.connected = True
            self._set_status(f"Connected to {host}.", Colors.ACCENT_GREEN)
            self.accept()
        else:
            self._set_status(
                "Connect failed. On Android 11+ you must pair first; on older devices "
                "run 'adb tcpip 5555' over USB before connecting.",
                Colors.STATUS_ERROR,
            )
