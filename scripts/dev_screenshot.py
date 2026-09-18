import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from app.gui.main_window import MainWindow
from app.gui.pages.dashboard_page import DashboardPage
from app.gui.pages.projects_page import ProjectsPage
from app.gui.pages.devices_page import DevicesPage
from app.gui.pages.reports_page import ReportsPage
from app.gui.pages.settings_page import SettingsPage

app = QApplication.instance() or QApplication(sys.argv)
window = MainWindow()
dashboard = DashboardPage(window)
projects = ProjectsPage(window)
devices = DevicesPage(window)
reports = ReportsPage(window)
settings_page = SettingsPage(window)
window.register_page("dashboard", dashboard)
window.register_page("projects", projects)
window.register_page("devices", devices)
window.register_page("reports", reports)
window.register_page("settings", settings_page)
window.content_stack.setCurrentWidget(dashboard)

window.resize(1917, 1057)
window.show()
app.processEvents()
app.processEvents()

out = sys.argv[1] if len(sys.argv) > 1 else "/home/claude/screenshot.png"
pix = window.grab()
pix.save(out)
print("saved", out, pix.size().toTuple())
