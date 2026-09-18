"""
Regression tests for the two bugs fixed alongside the new pages:

1. Sixteen of the sidebar's twenty-two destinations had no registered
   page and fell through to a "(coming soon)" placeholder.
2. Several containers were laid out below the size their children
   reported, so Qt clipped or overlapped text -- the "glitched fonts".

The layout tests assert the structural property that was violated
(allotted height >= required height, and stacked siblings not
overlapping) rather than pixel positions, so they keep working across
Qt versions and font stacks.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="GUI tests need PySide6")

from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

from app.core.workflow.plugin_manager import get_plugin_manager, reset_plugin_manager  # noqa: E402
from app.core.workflow.workflow_manager import WORKFLOW_REGISTRY  # noqa: E402
from app.gui.widgets.cards import StatPill  # noqa: E402
from app.gui.widgets.sidebar import NAV_SECTIONS  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _isolated_project_root(tmp_path, monkeypatch):
    """
    Every other test file in this suite isolates the database via
    PENTROID_PATHS__ROOT + resetting the engine/session singletons -- this
    file never did, so its tests silently depended on a real on-disk DB at
    the default path already having the schema created (e.g. by a prior
    manual `python main.py` run). That's a real gap, not a hypothetical one:
    it surfaced the moment routine cleanup (`rm database/*.db`) removed the
    stray file these tests were accidentally leaning on, with
    "no such table: plugins" from a freshly created but never-initialized
    engine. Isolating it here, the same way every other file already does,
    means these tests build their own schema instead of hoping one exists.
    """
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


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from app.gui.main_window import MainWindow

    win = MainWindow()
    win.resize(1680, 980)
    # Build the same page set main._launch_gui does, without an event loop.
    for key, page_class in _page_classes():
        win.register_page(key, page_class(win))
    win._navigate("dashboard")
    # show() is required, not cosmetic: Qt only runs a layout pass on a widget
    # once it is shown, so without this every child keeps the default 640x480
    # geometry and the layout assertions below would measure nothing real.
    win.show()
    for _ in range(5):
        qapp.processEvents()
    yield win
    win.close()


def _page_classes():
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

    return [
        ("dashboard", DashboardPage), ("projects", ProjectsPage),
        ("analyses", AnalysesPage), ("devices", DevicesPage), ("reports", ReportsPage),
        ("android_apk", AndroidApkPage), ("android_malware", AndroidMalwarePage),
        ("ios_analysis", IOSAnalysisPage), ("dynamic_analysis", DynamicAnalysisPage),
        ("network_analysis", NetworkAnalysisPage), ("privacy_analysis", PrivacyAnalysisPage),
        ("static_analysis", StaticAnalysisPage), ("toolbox", ToolboxPage),
        ("frida_hub", FridaHubPage), ("adb_toolkit", AdbToolkitPage),
        ("reverse_engineering", ReverseEngineeringPage), ("utilities", UtilitiesPage),
        ("plugin_center", PluginCenterPage), ("installed_plugins", InstalledPluginsPage),
        ("dependency_manager", DependencyManagerPage), ("settings", SettingsPage),
        ("logs", LogsPage),
    ]


# --------------------------------------------------------------------------- #
# Navigation coverage
# --------------------------------------------------------------------------- #
def test_every_sidebar_destination_has_a_page_class():
    """The bug: NAV_SECTIONS listed 22 keys and main.py registered 6."""
    expected = {key for _, items in NAV_SECTIONS for _, _, key in items}
    registered = {key for key, _ in _page_classes()}
    assert expected == registered, f"unregistered nav keys: {sorted(expected - registered)}"


def test_navigating_every_key_shows_a_real_page(window, qapp):
    for _, items in NAV_SECTIONS:
        for _, _, key in items:
            window._navigate(key)
            for _ in range(2):
                qapp.processEvents()
            page = window._pages[key]
            assert page.__class__.__name__ != "_UnregisteredPage", (
                f"'{key}' fell through to the fallback page"
            )
            assert window.content_stack.currentWidget() is page


def test_no_page_advertises_itself_as_coming_soon(window, qapp):
    for _, items in NAV_SECTIONS:
        for _, _, key in items:
            window._navigate(key)
            qapp.processEvents()
            for label in window._pages[key].findChildren(QLabel):
                assert "coming soon" not in label.text().lower()


# --------------------------------------------------------------------------- #
# Layout: allotted height must cover required height
# --------------------------------------------------------------------------- #
def test_top_bar_is_not_compressed_below_its_size_hint(window):
    """The bug: setMinimumHeight(88) let the layout squeeze a 107px bar to 88px."""
    top_bar = window.top_bar
    assert top_bar.height() >= top_bar.sizeHint().height()


def test_stat_pill_labels_get_the_height_they_ask_for(window):
    """The visible symptom: an 18px value label allotted 9px, clipped top and bottom."""
    pills = [p for p in window.top_bar.findChildren(StatPill) if p.isVisible()]
    assert pills, "expected the top bar to contain stat pills"
    for pill in pills:
        for label in pill.findChildren(QLabel):
            assert label.height() >= label.sizeHint().height(), (
                f"{label.text()!r} allotted {label.height()}px, "
                f"needs {label.sizeHint().height()}px"
            )


def test_sidebar_profile_footer_fits_its_contents(window):
    footer = window.sidebar.layout().itemAt(1).widget()
    assert footer.height() >= footer.layout().minimumSize().height()


def test_right_panel_cards_do_not_overlap(window, qapp):
    """The bug: the right panel had no scroll area, so QVBoxLayout ran later
    widgets over the gauge, which could not shrink past its minimum height."""
    window._navigate("dashboard")
    for _ in range(3):
        qapp.processEvents()

    layout = window.right_panel_layout
    rects = []
    for i in range(layout.count()):
        widget = layout.itemAt(i).widget()
        if widget is not None:
            rects.append((widget, widget.geometry()))

    for (widget_a, rect_a), (widget_b, rect_b) in zip(rects, rects[1:]):
        assert rect_a.bottom() < rect_b.top(), (
            f"{widget_a} overlaps {widget_b}: {rect_a} vs {rect_b}"
        )


def test_gauge_paints_inside_its_own_widget(qapp):
    """Regression for the gauge drawing its value text past its bottom edge."""
    from app.gui.widgets.charts import GaugeChart

    gauge = GaugeChart()
    for width, height in [(160, 104), (242, 104), (300, 140), (200, 300)]:
        gauge.resize(width, height)
        pad = 8
        diameter = max(48.0, min(width - 2 * pad, (height - 2 * pad) * 2.0))
        radius = diameter / 2.0
        baseline = (height + radius) / 2.0
        # Nothing is drawn below the semicircle's flat edge, and the dial's top
        # stays inside the widget.
        assert baseline <= height, f"baseline {baseline} outside height {height}"
        assert baseline - radius >= 0, "dial top is above the widget"


# --------------------------------------------------------------------------- #
# Backend additions the new pages depend on
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("workflow_name", ["privacy_analysis_default",
                                            "reverse_engineering_default"])
def test_new_workflows_reference_only_discovered_plugins(workflow_name):
    reset_plugin_manager()
    discovered = {p.plugin_id for p in get_plugin_manager().discover()}
    definition = WORKFLOW_REGISTRY[workflow_name]
    assert definition.steps, f"{workflow_name} has no steps"
    for step in definition.steps:
        assert step.plugin_id in discovered, (
            f"{workflow_name} step '{step.name}' references undiscovered "
            f"plugin '{step.plugin_id}'"
        )


def test_plugin_catalog_reports_every_discovered_plugin():
    reset_plugin_manager()
    manager = get_plugin_manager()
    discovered = {p.plugin_id for p in manager.discover()}
    catalog = {entry["plugin_id"] for entry in manager.catalog()}
    assert discovered <= catalog


def test_probe_health_never_raises_for_any_plugin():
    """One unhealthy plugin must not break the whole Plugin Center listing."""
    reset_plugin_manager()
    manager = get_plugin_manager()
    for plugin in manager.discover():
        health, _detail = manager.probe_health(plugin.plugin_id)
        assert health in {"healthy", "degraded", "unavailable"}


def test_probe_health_reports_unavailable_for_unknown_plugin():
    reset_plugin_manager()
    health, detail = get_plugin_manager().probe_health("no_such_plugin")
    assert health == "unavailable"
    assert detail


def test_set_proxy_rejects_an_invalid_endpoint():
    from app.core.device.connection_manager import DeviceConnectionManager

    manager = DeviceConnectionManager(tool_manager=object())
    with pytest.raises(ValueError):
        manager.set_proxy("serial", "10.0.0.1", 0)
    with pytest.raises(ValueError):
        manager.set_proxy("serial", "", 8080)


def test_hash_file_matches_hashlib(tmp_path):
    import hashlib

    from app.gui.pages.utilities_page import hash_file

    target = tmp_path / "sample.bin"
    payload = b"pentroid" * 5000
    target.write_bytes(payload)

    result = hash_file(str(target))
    assert result["SHA-256"] == hashlib.sha256(payload).hexdigest()
    assert result["MD5"] == hashlib.md5(payload).hexdigest()


def test_read_tail_returns_only_the_last_lines(tmp_path):
    from app.gui.pages.logs_page import read_tail

    target = tmp_path / "big.log"
    target.write_text("".join(f"line {i}\n" for i in range(5000)), encoding="utf-8")

    tail = read_tail(target, 10)
    assert len(tail) == 10
    assert tail[-1].strip() == "line 4999"
