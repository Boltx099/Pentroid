"""
Pentroid entrypoint.

Bootstraps configuration, logging, and the database, then launches the
GUI. ``PENTROID_HEADLESS=1`` (set automatically by the test suite, or
manually for CI/offscreen rendering) skips the GUI event loop and
returns after bootstrap + page construction, so main.py stays exercised
by automated tests without requiring a real display.
"""

from __future__ import annotations

import os
import sys

from app.core.config import get_settings
from app.core.logger import get_logger, setup_logging
from app.database.database import init_db

logger = get_logger(__name__)


def bootstrap() -> None:
    """Initialize configuration, logging, and database -- in that order."""
    settings = get_settings()  # also creates managed directories
    setup_logging()
    logger.info("Starting %s v%s (theme=%s)", settings.app_name, settings.version, settings.theme)

    init_db()
    logger.info("Foundation layer ready: config OK, logging OK, database OK")


def _launch_gui() -> int:
    from PySide6.QtWidgets import QApplication
    from app.gui.main_window import MainWindow
    from app.gui.pages.adb_toolkit_page import AdbToolkitPage
    from app.gui.pages.analyses_page import AnalysesPage
    from app.gui.pages.dashboard_page import DashboardPage
    from app.gui.pages.devices_page import DevicesPage
    from app.gui.pages.frida_hub_page import FridaHubPage
    from app.gui.pages.ios_page import IOSAnalysisPage
    from app.gui.pages.logs_page import LogsPage
    from app.gui.pages.network_page import NetworkAnalysisPage
    from app.gui.pages.plugins_page import InstalledPluginsPage, PluginCenterPage
    from app.gui.pages.projects_page import ProjectsPage
    from app.gui.pages.reports_page import ReportsPage
    from app.gui.pages.reverse_engineering_page import ReverseEngineeringPage
    from app.gui.pages.settings_page import SettingsPage
    from app.gui.pages.toolbox_page import DependencyManagerPage, ToolboxPage
    from app.gui.pages.utilities_page import UtilitiesPage
    from app.gui.pages.workflow_page import (
        AndroidApkPage, AndroidMalwarePage, DynamicAnalysisPage,
        PrivacyAnalysisPage, StaticAnalysisPage,
    )

    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()

    # Keyed by the page keys Sidebar.NAV_SECTIONS emits. Every key the sidebar
    # can emit must appear here, or navigating to it lands on
    # MainWindow._UnregisteredPage. Pages are constructed eagerly so a broken
    # page surfaces at startup rather than the first time a user clicks it.
    page_classes = [
        # MAIN
        ("dashboard", DashboardPage),
        ("projects", ProjectsPage),
        ("analyses", AnalysesPage),
        ("devices", DevicesPage),
        ("reports", ReportsPage),
        # ANALYSIS
        ("android_apk", AndroidApkPage),
        ("android_malware", AndroidMalwarePage),
        ("ios_analysis", IOSAnalysisPage),
        ("dynamic_analysis", DynamicAnalysisPage),
        ("network_analysis", NetworkAnalysisPage),
        ("privacy_analysis", PrivacyAnalysisPage),
        ("static_analysis", StaticAnalysisPage),
        # TOOLS
        ("toolbox", ToolboxPage),
        ("frida_hub", FridaHubPage),
        ("adb_toolkit", AdbToolkitPage),
        ("reverse_engineering", ReverseEngineeringPage),
        ("utilities", UtilitiesPage),
        # PLUGINS
        ("plugin_center", PluginCenterPage),
        ("installed_plugins", InstalledPluginsPage),
        # SYSTEM
        ("dependency_manager", DependencyManagerPage),
        ("settings", SettingsPage),
        ("logs", LogsPage),
    ]

    for key, page_class in page_classes:
        try:
            window.register_page(key, page_class(window))
        except Exception:  # noqa: BLE001 - one bad page must not block the whole GUI
            logger.exception("Failed to construct the '%s' page; leaving it unregistered", key)

    _verify_nav_coverage(window)

    # Navigate rather than poking the stack directly, so the sidebar highlight
    # and the visible page agree. If DashboardPage itself failed to build, fall
    # back to whatever did register instead of raising a KeyError at startup.
    start_key = "dashboard" if "dashboard" in window._pages else next(iter(window._pages), None)
    if start_key:
        window._navigate(start_key)
    window.show()

    if os.environ.get("PENTROID_HEADLESS") == "1":
        logger.info("PENTROID_HEADLESS=1 set -- constructed GUI without starting event loop")
        return 0

    return app.exec()


def _verify_nav_coverage(window) -> None:
    """
    Log any sidebar destination that has no page registered.

    This is the check that was missing while sixteen nav items silently fell
    through to a "(coming soon)" placeholder: nothing ever compared what the
    sidebar offers against what the window can actually show, so the gap was
    invisible until a user clicked one.
    """
    from app.gui.widgets.sidebar import NAV_SECTIONS

    expected = {key for _, items in NAV_SECTIONS for _, _, key in items}
    missing = sorted(expected - set(window._pages))
    if missing:
        logger.error("Sidebar keys with no registered page: %s", ", ".join(missing))
    else:
        logger.info("All %d sidebar destinations have a registered page", len(expected))


def main() -> int:
    try:
        bootstrap()
    except Exception:  # noqa: BLE001 - top-level guard, always log full traceback
        logger.exception("Fatal error during startup")
        return 1
    return _launch_gui()


if __name__ == "__main__":
    sys.exit(main())
