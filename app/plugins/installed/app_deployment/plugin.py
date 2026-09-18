"""
app.plugins.installed.app_deployment.plugin
===============================================

"Install / Launch App" step of Dynamic Analysis. Needs
``package_name`` from ``manifest_analysis``'s shared_data (must run
first in the workflow) and a selected device.
"""

from __future__ import annotations

from app.core.device.connection_manager import get_connection_manager
from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.database.database import session_scope
from app.database.models import Device
from app.plugins.base import Plugin, PluginMetadata


class AppDeploymentPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="app_deployment",
        name="App Deployment",
        version="1.0.0",
        description="Installs and launches the target APK on the selected device.",
        requires_device=True,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        if context.device_id is None:
            return PluginOutput(
                tool="app_deployment", status=PluginRunStatus.SKIPPED,
                logs=["No device selected for this analysis; dynamic analysis requires one."],
            )

        with session_scope() as session:
            device_row = session.get(Device, context.device_id)
            serial = device_row.identifier if device_row else None

        if not serial:
            return PluginOutput(
                tool="app_deployment", status=PluginRunStatus.SKIPPED,
                logs=[f"Device id {context.device_id} not found in database."],
            )

        package_name = context.shared_data.get("package_name")
        if not package_name:
            return PluginOutput(
                tool="app_deployment", status=PluginRunStatus.SKIPPED,
                logs=["No package name available (Manifest Analysis step is required first)."],
            )

        manager = get_connection_manager()
        logs = [f"Installing {context.target_path} on {serial}..."]

        if not manager.install_apk(serial, context.target_path):
            return PluginOutput(
                tool="app_deployment", status=PluginRunStatus.FAILED, logs=logs,
                errors=[f"adb install failed for {context.target_path} on device {serial}."],
            )
        logs.append("Install succeeded.")

        if not manager.launch_app(serial, package_name):
            return PluginOutput(
                tool="app_deployment", status=PluginRunStatus.FAILED, logs=logs,
                errors=[f"Failed to launch {package_name} on device {serial} (no launcher activity found?)."],
            )
        logs.append(f"Launched {package_name}.")

        finding = PluginFinding(
            title=f"App deployed and launched: {package_name}",
            severity=SeverityLevel.INFO,
            category="Dynamic Analysis",
            description=f"{package_name} was installed and its launcher activity started on device {serial}.",
        )
        return PluginOutput(tool="app_deployment", status=PluginRunStatus.SUCCESS, findings=[finding], logs=logs)
