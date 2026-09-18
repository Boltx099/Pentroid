import os, sys
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from app.gui.main_window import MainWindow
from app.gui.pages.dashboard_page import DashboardPage
from app.gui.pages.projects_page import ProjectsPage
from app.gui.pages.analyses_page import AnalysesPage
from app.gui.pages.devices_page import DevicesPage
from app.gui.pages.reports_page import ReportsPage
from app.gui.pages.settings_page import SettingsPage

app = QApplication.instance() or QApplication(sys.argv)
window = MainWindow()
pages = {
    "dashboard": DashboardPage(window),
    "projects": ProjectsPage(window),
    "analyses": AnalysesPage(window),
    "devices": DevicesPage(window),
    "reports": ReportsPage(window),
    "settings": SettingsPage(window),
}
for key, page in pages.items():
    window.register_page(key, page)

window.resize(1917, 1057)
window.show()
for key in pages:
    window.content_stack.setCurrentWidget(pages[key])
    app.processEvents()
    app.processEvents()
    pix = window.grab()
    pix.save(f"/home/claude/page_{key}.png")
    print("saved", key, pix.size().toTuple())
