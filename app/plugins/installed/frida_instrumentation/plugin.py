"""
app.plugins.installed.frida_instrumentation.plugin
======================================================

Spawns the target app under real Frida instrumentation and applies
the bundled hook script (SSL-pinning bypass observation,
root-detection check observation). Uses the ``frida`` Python bindings
directly (not the ``frida-tools`` CLI) for programmatic
spawn/attach/script lifecycle control.

Honesty note on verification: this is the one plugin in Pentroid that
could NOT be exercised against a real Android device in development
(no device/emulator available in this sandbox). What IS verified for
real: the ``frida`` library's exception classes and API surface
(``frida.InvalidArgumentError``, ``ProcessNotFoundError``, etc. were
confirmed by installing real ``frida`` and triggering them directly),
and the hook script's JavaScript syntax (validated with
``node --check``). The actual hook *behavior* against a running app
is standard, widely-published technique (OWASP MASTG dynamic testing)
but untested end-to-end here -- validate against a real device before
relying on it.
"""

from __future__ import annotations

import time
from pathlib import Path

from app.core.device.connection_manager import get_connection_manager
from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.database.database import session_scope
from app.database.models import Device
from app.plugins.base import Plugin, PluginHealth, PluginMetadata

_HOOK_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "runtime_hooks.js"
_MONITORING_DURATION_SECONDS = 8.0
_SPAWN_TIMEOUT_SECONDS = 10


class FridaInstrumentationPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="frida_instrumentation",
        name="Frida Runtime Instrumentation",
        version="1.0.0",
        description="Spawns the app under Frida and applies SSL-pinning/root-detection observation hooks.",
        requires_device=True,
    )

    def health(self) -> PluginHealth:
        try:
            import frida  # noqa: F401
            return PluginHealth.HEALTHY
        except ImportError:
            return PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        logs: list[str] = []

        try:
            import frida
        except ImportError:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.SKIPPED,
                logs=["frida Python bindings are not installed; skipping runtime instrumentation."],
            )

        if context.device_id is None:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.SKIPPED,
                logs=["No device selected for this analysis; dynamic analysis requires one."],
            )

        with session_scope() as session:
            device_row = session.get(Device, context.device_id)
            serial = device_row.identifier if device_row else None

        if not serial:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.SKIPPED,
                logs=[f"Device id {context.device_id} not found in database."],
            )

        connection_manager = get_connection_manager()
        if not connection_manager.check_frida_server_running(serial):
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.SKIPPED,
                logs=[f"frida-server is not running on device {serial}. Run the Device Setup Wizard first."],
            )

        package_name = context.shared_data.get("package_name")
        if not package_name:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.SKIPPED,
                logs=["No package name available (Manifest Analysis step is required first)."],
            )

        try:
            device_obj = frida.get_device(serial, timeout=_SPAWN_TIMEOUT_SECONDS)
        except frida.InvalidArgumentError as exc:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.FAILED,
                errors=[f"Frida could not find device '{serial}': {exc}"],
            )

        messages: list[dict] = []

        def _on_message(message, data):
            if message.get("type") == "send":
                messages.append(message.get("payload") or {})
            elif message.get("type") == "error":
                messages.append({"hook": "script_error", "event": "error", "description": message.get("description", "")})

        script_source = _HOOK_SCRIPT_PATH.read_text(encoding="utf-8")
        session_obj = None
        try:
            pid = device_obj.spawn([package_name])
            session_obj = device_obj.attach(pid)
            script = session_obj.create_script(script_source)
            script.on("message", _on_message)
            script.load()
            device_obj.resume(pid)
            logs.append(f"Spawned {package_name} (pid={pid}), monitoring for {_MONITORING_DURATION_SECONDS}s")
            time.sleep(_MONITORING_DURATION_SECONDS)
        except frida.ProcessNotFoundError as exc:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.FAILED,
                errors=[f"Target process not found: {exc}"],
            )
        except frida.NotSupportedError as exc:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.FAILED,
                errors=[f"Spawn/attach not supported on this device: {exc}"],
            )
        except frida.TimedOutError as exc:
            return PluginOutput(
                tool="frida_instrumentation", status=PluginRunStatus.FAILED,
                errors=[f"Timed out communicating with device: {exc}"],
            )
        finally:
            if session_obj is not None:
                try:
                    session_obj.detach()
                except Exception:  # noqa: BLE001 - best-effort cleanup, never let detach failure mask the real result
                    pass

        findings = self._build_findings(messages)
        logs.append(f"Collected {len(messages)} hook message(s)")
        return PluginOutput(tool="frida_instrumentation", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)

    def _build_findings(self, messages: list[dict]) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        ssl_bypass_events = [m for m in messages if m.get("hook") == "ssl_pinning" and "bypass" in m.get("event", "")]
        if ssl_bypass_events:
            findings.append(PluginFinding(
                title="SSL/TLS pinning implementation detected and bypassed at runtime",
                severity=SeverityLevel.HIGH,
                description=f"{len(ssl_bypass_events)} certificate-validation call(s) were intercepted by a "
                             "universal SSL-pinning-bypass hook, confirming the app performs custom certificate "
                             "validation that a runtime attacker (or MITM tooling) on a rooted device can defeat.",
                category="Dynamic Analysis",
                masvs_mapping="MASVS-NETWORK",
                recommendation="Layer pinning with additional runtime integrity/attestation checks -- pinning "
                               "alone does not stop an attacker capable of running Frida on the device.",
            ))

        root_events = [m for m in messages if m.get("hook") == "root_detection"]
        if root_events:
            paths = sorted({m.get("path") for m in root_events if m.get("path")})
            findings.append(PluginFinding(
                title=f"App queried {len(paths)} root-indicator path(s) at runtime",
                severity=SeverityLevel.INFO,
                description=f"Observed checks for: {', '.join(paths)}. Confirms the app performs some root "
                             "detection; effectiveness against a determined attacker varies by implementation.",
                category="Dynamic Analysis",
                masvs_mapping="MASVS-RESILIENCE",
            ))

        debug_events = [m for m in messages if m.get("hook") == "anti_debug"]
        if debug_events:
            findings.append(PluginFinding(
                title="App checks for an attached debugger at runtime",
                severity=SeverityLevel.INFO,
                category="Dynamic Analysis",
                masvs_mapping="MASVS-RESILIENCE",
                description="Debug.isDebuggerConnected() was called during the monitored session.",
            ))

        error_events = [m for m in messages if m.get("hook") == "script_error"]
        if error_events:
            findings.append(PluginFinding(
                title="Runtime hook script encountered errors",
                severity=SeverityLevel.INFO,
                category="Dynamic Analysis",
                description="; ".join(e.get("description", "") for e in error_events)[:500],
            ))

        return findings
