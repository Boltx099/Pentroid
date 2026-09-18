"""
app.core.device.connection_manager
=====================================

Android side of the Device Connection Manager (architecture spec):
detect ADB, start the ADB server, scan USB/emulator/Genymotion/Waydroid
devices, authorize/validate them, and check root/Frida/certificate/
proxy readiness. Every check shells out through ``ToolManager`` (never
raw ``subprocess``), so it inherits the same timeout/no-shell-injection
guarantees as every other tool invocation in Pentroid.

iOS device detection (jailbreak/simulator/SSH) is a separate module
(different tooling entirely -- ``pymobiledevice3``/``xcrun simctl``
rather than ``adb``) and is not part of this file.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from app.core.device.adb_parser import (
    RawDeviceEntry,
    classify_connection_type,
    is_root_shell_output,
    parse_cert_listing,
    parse_devices_output,
    parse_getprop_output,
    parse_ps_for_process,
)
from app.core.exceptions import (
    ADBNotFoundError,
    DeviceAuthorizationError,
    DeviceConnectionError,
    NoDeviceFoundError,
    ToolNotFoundError,
)
from app.core.logger import get_logger
from app.core.tool_manager import ToolManager, get_tool_manager
from app.database.database import session_scope
from app.database.models import ConnectionType, Device, DeviceStatus, Platform

logger = get_logger(__name__)

_USER_CERT_DIR = "/data/misc/user/0/cacerts-added/"


@dataclass
class DeviceReadiness:
    serial: str
    is_rooted: bool
    frida_server_running: bool
    proxy_configured: bool
    user_certs_installed: list[str]
    ready: bool


class DeviceConnectionManager:
    """Detects and validates Android devices/emulators over ADB."""

    def __init__(self, tool_manager: ToolManager | None = None) -> None:
        self._tools = tool_manager or get_tool_manager()

    # ------------------------------------------------------------------ #
    # ADB server lifecycle
    # ------------------------------------------------------------------ #
    def start_adb_server(self) -> None:
        """Ensure the ADB server is running (`adb start-server`)."""
        result = self._tools.run("adb", ["start-server"], timeout=20)
        if result.exit_code != 0:
            raise ADBNotFoundError(
                "Failed to start ADB server", details={"stderr": result.stderr}
            )
        logger.info("ADB server started")

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def list_devices(self) -> list[RawDeviceEntry]:
        """Return every device/emulator ADB currently sees, in any state."""
        try:
            result = self._tools.run("adb", ["devices", "-l"], timeout=20)
        except ToolNotFoundError as exc:
            raise ADBNotFoundError(
                "ADB is not installed. Install it via the Dependency Manager first."
            ) from exc

        if result.exit_code != 0:
            raise ADBNotFoundError("`adb devices` failed", details={"stderr": result.stderr})

        return parse_devices_output(result.stdout)

    def scan_and_sync(self) -> list[Device]:
        """
        Scan for devices and upsert each into the ``devices`` table
        (matching by ``identifier``/serial), classifying connection type
        and refreshing status. Returns the synced ORM rows.

        Raises ``NoDeviceFoundError`` if ADB reports zero devices at all
        (the GUI uses this to trigger the Device Setup Wizard).
        """
        entries = self.list_devices()
        if not entries:
            raise NoDeviceFoundError("No devices or emulators detected via ADB")

        synced: list[Device] = []
        with session_scope() as session:
            for entry in entries:
                conn_type = classify_connection_type(entry)
                status = self._status_for_state(entry.state)

                record = session.query(Device).filter_by(identifier=entry.serial).one_or_none()
                if record is None:
                    record = Device(
                        identifier=entry.serial,
                        display_name=entry.model or entry.device or entry.serial,
                        platform=Platform.ANDROID,
                        connection_type=conn_type,
                        status=status,
                    )
                    session.add(record)
                else:
                    record.display_name = entry.model or entry.device or entry.serial
                    record.connection_type = conn_type
                    record.status = status

                session.flush()
                synced.append(record)

        return synced

    @staticmethod
    def _status_for_state(state: str) -> DeviceStatus:
        if state == "device":
            return DeviceStatus.READY
        if state == "unauthorized":
            return DeviceStatus.UNAUTHORIZED
        if state == "offline":
            return DeviceStatus.DISCONNECTED
        return DeviceStatus.ERROR

    def require_authorized(self, serial: str) -> None:
        """Raise ``DeviceAuthorizationError`` unless the device is authorized (state=='device')."""
        entries = self.list_devices()
        match = next((e for e in entries if e.serial == serial), None)
        if match is None:
            raise NoDeviceFoundError(f"Device {serial!r} is not connected")
        if match.state == "unauthorized":
            raise DeviceAuthorizationError(
                f"Device {serial!r} is not authorized. Accept the RSA key prompt on the device."
            )
        if match.state != "device":
            raise DeviceAuthorizationError(f"Device {serial!r} is in state {match.state!r}, not ready")

    # ------------------------------------------------------------------ #
    # Wireless / network ADB
    #
    # Standard professional workflow: test a device over Wi-Fi instead of
    # tethered USB (needed when the USB port is occupied by a hardware
    # debugger, when testing physical-handling scenarios, or simply for
    # convenience during a long engagement).
    #
    # Two distinct flows, often confused:
    #   * Pre-Android-11: enable TCP/IP mode over USB (`adb tcpip`), then
    #     `adb connect <ip>:5555`. No pairing code involved.
    #   * Android 11+ "Wireless debugging": a one-time `adb pair
    #     <ip>:<pairing-port> <6-digit-code>` using the pairing port and code
    #     shown on-device, THEN `adb connect <ip>:<connect-port>` on a
    #     *different* port. Pairing and connecting are separate steps with
    #     separate ports -- a very common source of "why won't it connect".
    # ------------------------------------------------------------------ #
    def enable_tcpip(self, serial: str, port: int = 5555) -> bool:
        """Switch a USB-attached device into TCP/IP mode so it can then be connected to wirelessly."""
        result = self._tools.run("adb", ["-s", serial, "tcpip", str(port)], timeout=30)
        return result.exit_code == 0

    def connect_wireless(self, host: str, port: int = 5555) -> bool:
        """
        `adb connect host:port`. Note adb exits 0 even when the connection
        fails ("failed to connect to ..." on stdout), so success is judged
        by the output text, not the exit code alone.
        """
        target = f"{host}:{port}"
        result = self._tools.run("adb", ["connect", target], timeout=30)
        output = (result.stdout or "") + (result.stderr or "")
        success = "connected to" in output.lower() and "failed" not in output.lower()
        if success:
            logger.info("Wireless ADB connected: %s", target)
        else:
            logger.warning("Wireless ADB connect failed for %s: %s", target, output.strip())
        return success

    def disconnect_wireless(self, host: str | None = None, port: int = 5555) -> bool:
        """Disconnect one wireless device, or all of them when ``host`` is None."""
        args = ["disconnect"] if host is None else ["disconnect", f"{host}:{port}"]
        result = self._tools.run("adb", args, timeout=20)
        return result.exit_code == 0

    def pair_wireless(self, host: str, pairing_port: int, pairing_code: str) -> bool:
        """
        Android 11+ wireless-debugging pairing. ``pairing_port`` and
        ``pairing_code`` are both shown on-device under Developer options >
        Wireless debugging > Pair device with pairing code, and the pairing
        port is NOT the same port used for the subsequent connect.
        """
        result = self._tools.run(
            "adb", ["pair", f"{host}:{pairing_port}", pairing_code], timeout=60,
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = "successfully paired" in output.lower()
        if not success:
            logger.warning("Wireless ADB pairing failed for %s:%s -- %s", host, pairing_port, output.strip())
        return success

    # ------------------------------------------------------------------ #
    # App deployment (Dynamic Analysis: "Install / Launch App")
    # ------------------------------------------------------------------ #
    def install_apk(self, serial: str, apk_path: str) -> bool:
        """`adb install -r` (reinstall, keep data) the given APK. Returns True on success."""
        result = self._tools.run("adb", ["-s", serial, "install", "-r", apk_path], timeout=120)
        return result.exit_code == 0 and "Success" in result.stdout

    def uninstall_app(self, serial: str, package_name: str) -> bool:
        result = self._tools.run("adb", ["-s", serial, "uninstall", package_name], timeout=30)
        return result.exit_code == 0 and "Success" in result.stdout

    def launch_app(self, serial: str, package_name: str) -> bool:
        """
        Launch an app's default launcher activity without needing to know
        the exact Activity class name -- `monkey -c LAUNCHER 1` is the
        standard ADB technique for this (it resolves and starts whatever
        activity is registered as the app's main launcher entry point).
        """
        result = self._tools.run(
            "adb", ["-s", serial, "shell", "monkey", "-p", package_name,
                    "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=30,
        )
        return result.exit_code == 0 and "Events injected: 1" in result.stdout

    def force_stop_app(self, serial: str, package_name: str) -> None:
        self._tools.run("adb", ["-s", serial, "shell", "am", "force-stop", package_name], timeout=15)

    # ------------------------------------------------------------------ #
    # Device info
    # ------------------------------------------------------------------ #
    def get_device_properties(self, serial: str) -> dict[str, str]:
        result = self._tools.run("adb", ["-s", serial, "shell", "getprop"], timeout=15)
        return parse_getprop_output(result.stdout)

    # ------------------------------------------------------------------ #
    # Root detection
    # ------------------------------------------------------------------ #
    def check_root(self, serial: str) -> bool:
        """
        Attempt ``su -c id`` on the device; a real root grant returns
        ``uid=0`` in the output. Devices without a `su` binary at all
        simply fail the shell command (non-root, not an error).
        """
        result = self._tools.run(
            "adb", ["-s", serial, "shell", "su -c id 2>/dev/null || echo not-rooted"], timeout=15
        )
        return is_root_shell_output(result.stdout)

    # ------------------------------------------------------------------ #
    # Frida
    # ------------------------------------------------------------------ #
    def check_frida_server_running(self, serial: str) -> bool:
        result = self._tools.run("adb", ["-s", serial, "shell", "ps -A"], timeout=15)
        return parse_ps_for_process(result.stdout, "frida-server")

    _ABI_TO_FRIDA_SERVER_TOOL = {
        "arm64-v8a": "frida_server_arm64",
        "x86_64": "frida_server_x86_64",
    }
    _REMOTE_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"

    def start_frida_server(self, serial: str, dependency_manager=None) -> bool:
        """
        Push the architecture-matched frida-server binary to the device
        and launch it detached, as root. Requires the device to already
        be rooted (frida-server binds as root by default) and the
        matching ``frida_server_<abi>`` tool to already be installed via
        the Dependency Manager.
        """
        from app.core.dependency_manager import get_dependency_manager

        deps = dependency_manager or get_dependency_manager()
        props = self.get_device_properties(serial)
        abi = props.get("ro.product.cpu.abi", "")
        tool_name = self._ABI_TO_FRIDA_SERVER_TOOL.get(abi)
        if tool_name is None:
            raise DeviceConnectionError(
                f"No frida-server build registered for device ABI {abi!r}",
                details={"supported_abis": list(self._ABI_TO_FRIDA_SERVER_TOOL)},
            )

        local_binary = deps.get_binary_path(tool_name)  # raises ToolNotFoundError if not installed

        push = self._tools.run(
            "adb", ["-s", serial, "push", str(local_binary), self._REMOTE_FRIDA_SERVER_PATH], timeout=60
        )
        if push.exit_code != 0:
            raise DeviceConnectionError("Failed to push frida-server", details={"stderr": push.stderr})

        self._tools.run(
            "adb", ["-s", serial, "shell", f"chmod 755 {self._REMOTE_FRIDA_SERVER_PATH}"], timeout=15
        )

        # Launch detached as root; frida-server binds a privileged control port.
        self._tools.run(
            "adb",
            ["-s", serial, "shell", f"su -c 'nohup {self._REMOTE_FRIDA_SERVER_PATH} >/dev/null 2>&1 &'"],
            timeout=15,
        )

        time.sleep(1.0)  # brief settle before verifying
        return self.check_frida_server_running(serial)

    def stop_frida_server(self, serial: str) -> None:
        self._tools.run("adb", ["-s", serial, "shell", "su -c 'pkill -f frida-server'"], timeout=15)

    # ------------------------------------------------------------------ #
    # Certificate / proxy checks
    # ------------------------------------------------------------------ #
    def list_user_certificates(self, serial: str) -> list[str]:
        """List custom (user-added) CA certificate filenames installed on-device."""
        result = self._tools.run(
            "adb", ["-s", serial, "shell", f"ls {_USER_CERT_DIR} 2>/dev/null"], timeout=15
        )
        return parse_cert_listing(result.stdout)

    def is_certificate_installed(self, serial: str, cert_subject_hash: str) -> bool:
        """Check whether a specific CA cert (by its `openssl x509 -subject_hash_old` hash) is installed."""
        installed = self.list_user_certificates(serial)
        return any(name.startswith(cert_subject_hash) for name in installed)

    def get_proxy_settings(self, serial: str) -> str | None:
        result = self._tools.run(
            "adb", ["-s", serial, "shell", "settings get global http_proxy"], timeout=15
        )
        value = result.stdout.strip()
        return None if value in ("", "null", ":0") else value

    def set_proxy(self, serial: str, host: str, port: int) -> str:
        """
        Point the device's global HTTP proxy at ``host:port`` (an intercepting
        proxy such as mitmproxy or Burp running on the analyst's machine).

        This is the global ``settings`` proxy, so it applies to apps using the
        platform HTTP stack and is ignored by apps that pin certificates or
        open raw sockets -- traffic from those simply won't appear in the
        capture, which is a property of the target app, not a failed setting.
        Returns the value the device reports back after the write.
        """
        if not host or port <= 0 or port > 65535:
            raise ValueError(f"Invalid proxy endpoint: {host!r}:{port}")
        self._tools.run(
            "adb", ["-s", serial, "shell", "settings", "put", "global",
                    "http_proxy", f"{host}:{port}"], timeout=15,
        )
        return self.get_proxy_settings(serial) or "not set"

    def clear_proxy(self, serial: str) -> None:
        """Remove the global HTTP proxy. Uses ``:0``, which is the value the
        platform itself writes when a proxy is cleared from Settings."""
        self._tools.run(
            "adb", ["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"],
            timeout=15,
        )

    def list_packages(self, serial: str, third_party_only: bool = True) -> list[str]:
        """Return installed package names, third-party only by default (the
        ~600 system packages on a stock image are noise for app testing)."""
        args = ["-s", serial, "shell", "pm", "list", "packages"]
        if third_party_only:
            args.append("-3")
        result = self._tools.run("adb", args, timeout=30)
        return sorted(
            line.strip()[len("package:"):]
            for line in result.stdout.splitlines()
            if line.strip().startswith("package:")
        )

    # ------------------------------------------------------------------ #
    # Aggregate readiness (last step of the Device Setup Wizard)
    # ------------------------------------------------------------------ #
    def get_readiness(self, serial: str) -> DeviceReadiness:
        is_rooted = self.check_root(serial)
        frida_running = self.check_frida_server_running(serial)
        proxy = self.get_proxy_settings(serial)
        certs = self.list_user_certificates(serial)

        return DeviceReadiness(
            serial=serial,
            is_rooted=is_rooted,
            frida_server_running=frida_running,
            proxy_configured=proxy is not None,
            user_certs_installed=certs,
            ready=frida_running and len(certs) > 0,
        )


_connection_manager: DeviceConnectionManager | None = None


def get_connection_manager() -> DeviceConnectionManager:
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = DeviceConnectionManager()
    return _connection_manager
