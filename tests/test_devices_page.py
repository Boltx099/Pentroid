"""
Tests for Module 8: Devices page.

Uses a fake DeviceConnectionManager (same pattern as
test_setup_wizard.py) so these tests don't depend on a real ADB
install, but the GUI <-> BackgroundTaskRunner <-> background-thread
plumbing is fully real.
"""

from __future__ import annotations

import time

import pytest

from app.core.device.adb_parser import RawDeviceEntry
from app.core.exceptions import ADBNotFoundError


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    import app.database.database as db_module
    db_module._engine = None
    db_module._SessionFactory = None
    from app.database.database import init_db
    init_db()
    yield
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None


class _FakeConnectionManager:
    def __init__(self, devices=None, raise_on_scan=None):
        self._devices = devices if devices is not None else [
            RawDeviceEntry(serial="R3CN90ABCDE", state="device", model="Pixel_7_Pro"),
        ]
        self._raise_on_scan = raise_on_scan

    def scan_and_sync(self):
        if self._raise_on_scan:
            raise self._raise_on_scan
        from app.database.database import session_scope
        from app.database.models import Device, Platform, ConnectionType, DeviceStatus
        from app.core.device.adb_parser import classify_connection_type

        with session_scope() as session:
            rows = []
            for entry in self._devices:
                record = Device(
                    identifier=entry.serial, display_name=entry.model or entry.serial,
                    platform=Platform.ANDROID, connection_type=classify_connection_type(entry),
                    status=DeviceStatus.READY,
                )
                session.add(record)
                session.flush()
                rows.append(record)
            return rows


def test_devices_page_shows_empty_state_initially(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.devices_page import DevicesPage

    window = MainWindow()
    page = DevicesPage(window)
    assert page._list_layout.count() == 1  # empty-state label
    window.deleteLater()


def test_devices_page_lists_real_device_after_refresh(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.devices_page import DevicesPage
    from app.database.database import session_scope
    from app.database.models import Device, Platform, ConnectionType, DeviceStatus

    with session_scope() as session:
        session.add(Device(
            identifier="ABC123", display_name="Pixel 7 Pro", platform=Platform.ANDROID,
            connection_type=ConnectionType.USB, status=DeviceStatus.READY,
        ))

    window = MainWindow()
    page = DevicesPage(window)
    page.refresh()
    assert page._list_layout.count() == 1
    row = page._list_layout.itemAt(0).widget()
    assert row.identifier == "ABC123"
    window.deleteLater()


def test_scan_button_triggers_real_background_scan_and_updates_list(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.devices_page import DevicesPage
    from PySide6.QtWidgets import QApplication

    window = MainWindow()
    page = DevicesPage(window)
    page._connection_manager = _FakeConnectionManager()

    assert page._scan_btn.isEnabled() is True
    page._on_scan()
    assert page._scan_btn.isEnabled() is False  # disabled while scanning

    for _ in range(30):
        QApplication.processEvents()
        time.sleep(0.05)
        if page._scan_btn.isEnabled():
            break

    assert page._scan_btn.isEnabled() is True
    assert page._list_layout.count() == 1
    row = page._list_layout.itemAt(0).widget()
    assert row.identifier == "R3CN90ABCDE"
    window.deleteLater()


def test_scan_button_shows_error_on_adb_not_found(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.devices_page import DevicesPage
    from PySide6.QtWidgets import QApplication

    window = MainWindow()
    page = DevicesPage(window)
    page._connection_manager = _FakeConnectionManager(raise_on_scan=ADBNotFoundError("adb not installed"))

    page._on_scan()
    for _ in range(30):
        QApplication.processEvents()
        time.sleep(0.05)
        if page._scan_btn.isEnabled():
            break

    assert "adb not installed" in page._note_label.text().lower()
    window.deleteLater()


def test_setup_wizard_dialog_shows_step_results(qapp):
    from app.gui.dialogs.setup_wizard_dialog import SetupWizardDialog
    from app.core.device.setup_wizard import WizardStepResult

    dialog = SetupWizardDialog()
    results = [
        WizardStepResult("Check ADB", True, "ADB server is running."),
        WizardStepResult("Detect Device", False, "No device detected.", guidance="Connect a device via USB."),
    ]
    dialog.show_results(results)
    assert dialog._results_layout.count() == 2


def test_setup_wizard_dialog_shows_error():
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from app.gui.dialogs.setup_wizard_dialog import SetupWizardDialog

    dialog = SetupWizardDialog()
    dialog.show_error("device disconnected")
    assert "device disconnected" in dialog._status_label.text()
