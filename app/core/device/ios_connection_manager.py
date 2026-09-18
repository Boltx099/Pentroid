"""
app.core.device.ios_connection_manager
=========================================

iOS side of the Device Connection Manager. Uses entirely different
tooling from the Android/ADB side:

* Simulators -- ``xcrun simctl`` (macOS + Xcode Command Line Tools
  only; gated on ``platform.system() == "Darwin"``, returns an empty
  list with a clear log message everywhere else, e.g. this Linux
  sandbox).
* Physical devices -- ``pymobiledevice3`` (works cross-platform over
  USB via usbmuxd, no Xcode required).
* Jailbreak assessment -- SSH reachability + banner grab. Deliberately
  does NOT attempt any login (default-credential or otherwise): a
  connect + banner-read is passive service fingerprinting, standard
  recon practice; attempting default jailbreak SSH creds would cross
  into active exploitation and isn't something this manager does.

See ``ios_parser`` module docstring for an honest confidence note on
the ``pymobiledevice3`` output schema -- it's not verifiable from this
environment (no iOS hardware, no macOS).
"""

from __future__ import annotations

import platform
import socket
from dataclasses import dataclass

from app.core.device.ios_parser import (
    PhysicalDeviceEntry,
    SimulatorEntry,
    parse_app_list,
    parse_developer_mode_status,
    parse_lockdown_info,
    parse_profile_list,
    parse_simctl_list,
    parse_usbmux_list,
)
from app.core.exceptions import DeviceConnectionError
from app.core.logger import get_logger
from app.core.tool_manager import ToolManager, get_tool_manager

logger = get_logger(__name__)

_JAILBREAK_SSH_PORTS = (22, 44)  # 44 is used by some jailbreak SSH-over-USB tunnels


@dataclass
class IOSDeviceReadiness:
    """iOS equivalent of the Android ``DeviceReadiness`` -- same shape of answer
    ("is this device ready for dynamic analysis?"), different underlying checks."""

    udid: str
    paired: bool
    developer_mode_enabled: bool
    installed_profiles: list[str]
    frida_reachable: bool
    likely_jailbroken: bool
    ready: bool


@dataclass
class JailbreakAssessment:
    host: str
    ssh_reachable: bool
    ssh_banner: str | None
    likely_jailbroken: bool
    confidence: str  # "low" | "medium" -- this manager never claims "high" from network signals alone


class IOSConnectionManager:
    """Discovers iOS simulators (macOS) and physical devices (pymobiledevice3), and probes for jailbreak."""

    def __init__(self, tool_manager: ToolManager | None = None) -> None:
        self._tools = tool_manager or get_tool_manager()

    # ------------------------------------------------------------------ #
    # Simulators (macOS only)
    # ------------------------------------------------------------------ #
    def list_simulators(self) -> list[SimulatorEntry]:
        if platform.system() != "Darwin":
            logger.info("iOS Simulator scanning requires macOS + Xcode; skipping on %s", platform.system())
            return []

        result = self._tools.run("xcrun", ["simctl", "list", "devices", "--json"], timeout=20)
        if result.exit_code != 0:
            raise DeviceConnectionError(
                "xcrun simctl failed -- is Xcode Command Line Tools installed?",
                details={"stderr": result.stderr},
            )
        return parse_simctl_list(result.stdout)

    # ------------------------------------------------------------------ #
    # Physical devices (pymobiledevice3, cross-platform via usbmuxd)
    # ------------------------------------------------------------------ #
    def list_physical_devices(self) -> list[PhysicalDeviceEntry]:
        result = self._tools.run("pymobiledevice3", ["usbmux", "list"], timeout=20)
        if result.exit_code != 0:
            logger.warning("pymobiledevice3 usbmux list failed: %s", result.stderr)
            return []
        return parse_usbmux_list(result.stdout)

    def get_device_info(self, udid: str) -> dict[str, str]:
        result = self._tools.run("pymobiledevice3", ["lockdown", "info", "--udid", udid], timeout=20)
        if result.exit_code != 0:
            logger.warning("pymobiledevice3 lockdown info failed for %s: %s", udid, result.stderr)
            return {}
        return parse_lockdown_info(result.stdout)

    # ------------------------------------------------------------------ #
    # Jailbreak assessment -- passive network signal only
    # ------------------------------------------------------------------ #
    def check_ssh_reachable(self, host: str, port: int = 22, timeout: float = 3.0) -> tuple[bool, str | None]:
        """
        Attempt a TCP connect + banner read (no login attempt). Returns
        ``(reachable, banner)``. This is real, working network I/O --
        unlike the pymobiledevice3-based methods above, it's fully unit
        testable against a local mock listener without any iOS hardware.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                try:
                    banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    banner = None
                return True, banner or None
        except (OSError, socket.timeout):
            return False, None

    def assess_jailbreak(self, host: str) -> JailbreakAssessment:
        """
        Best-effort jailbreak signal: jailbroken iOS devices commonly
        run OpenSSH (installed via Cydia/Sileo/Zebra) listening on 22
        or a jailbreak-tool-specific port. Reachability + an
        SSH-looking banner is treated as a *medium*-confidence signal;
        reachability alone (no banner, e.g. filtered/other service) is
        *low* confidence. This can never be "high" confidence from a
        network probe alone -- a definitive check needs on-device
        filesystem/process inspection via ``pymobiledevice3`` once
        paired, which is a reasonable next step once mediumdb-confidence
        is confirmed, not something this network-only probe claims.
        """
        for port in _JAILBREAK_SSH_PORTS:
            reachable, banner = self.check_ssh_reachable(host, port=port)
            if reachable:
                looks_like_ssh = bool(banner and "ssh" in banner.lower())
                return JailbreakAssessment(
                    host=host,
                    ssh_reachable=True,
                    ssh_banner=banner,
                    likely_jailbroken=True,
                    confidence="medium" if looks_like_ssh else "low",
                )

        return JailbreakAssessment(
            host=host, ssh_reachable=False, ssh_banner=None,
            likely_jailbroken=False, confidence="low",
        )


    # ------------------------------------------------------------------ #
    # App management -- parity with the Android side's install/list/uninstall.
    # Subcommand syntax verified against a real `pymobiledevice3 --help` run
    # (apps list/install/uninstall), not assumed from documentation.
    # ------------------------------------------------------------------ #
    def list_installed_apps(self, udid: str) -> list[str]:
        """Bundle identifiers of installed apps (iOS parity with ``list_packages``)."""
        result = self._tools.run(
            "pymobiledevice3", ["apps", "list", "--udid", udid, "--no-color"], timeout=60,
        )
        if result.exit_code != 0:
            logger.warning("pymobiledevice3 apps list failed for %s: %s", udid, result.stderr)
            return []
        return parse_app_list(result.stdout)

    def install_ipa(self, udid: str, ipa_path: str) -> bool:
        """Install a local .ipa (iOS parity with ``install_apk``)."""
        result = self._tools.run(
            "pymobiledevice3", ["apps", "install", ipa_path, "--udid", udid, "--no-color"], timeout=300,
        )
        return result.exit_code == 0

    def uninstall_app(self, udid: str, bundle_id: str) -> bool:
        result = self._tools.run(
            "pymobiledevice3", ["apps", "uninstall", bundle_id, "--udid", udid, "--no-color"], timeout=60,
        )
        return result.exit_code == 0

    # ------------------------------------------------------------------ #
    # Developer Mode -- iOS 16+ blocks all developer tooling (including
    # Frida attach and debugserver) until this is enabled on-device. There
    # is no Android equivalent; it's a hard prerequisite worth surfacing
    # explicitly rather than letting later steps fail mysteriously.
    # ------------------------------------------------------------------ #
    def get_developer_mode_status(self, udid: str) -> bool | None:
        """True/False if determinable, None if the query itself failed (device locked, not paired, older iOS)."""
        result = self._tools.run(
            "pymobiledevice3", ["amfi", "developer-mode-status", "--udid", udid, "--no-color"], timeout=30,
        )
        if result.exit_code != 0:
            return None
        return parse_developer_mode_status(result.stdout)

    def enable_developer_mode(self, udid: str) -> bool:
        """
        Request Developer Mode enablement. The device must be unlocked and
        will prompt for confirmation + reboot -- this returns whether the
        *request* was accepted, not that the user has completed it.
        """
        result = self._tools.run(
            "pymobiledevice3", ["amfi", "enable-developer-mode", "--udid", udid, "--no-color"], timeout=60,
        )
        return result.exit_code == 0

    # ------------------------------------------------------------------ #
    # Configuration profiles -- iOS parity with the Android CA-certificate
    # check. A MITM proxy CA on iOS is installed as a configuration profile.
    # ------------------------------------------------------------------ #
    def list_profiles(self, udid: str) -> list[str]:
        result = self._tools.run(
            "pymobiledevice3", ["profile", "list", "--udid", udid, "--no-color"], timeout=30,
        )
        if result.exit_code != 0:
            logger.warning("pymobiledevice3 profile list failed for %s: %s", udid, result.stderr)
            return []
        return parse_profile_list(result.stdout)

    def install_certificate_profile(self, udid: str, profile_path: str) -> bool:
        """Install a .mobileconfig / CA certificate profile (e.g. a Burp or mitmproxy CA)."""
        result = self._tools.run(
            "pymobiledevice3", ["profile", "install", profile_path, "--udid", udid, "--no-color"], timeout=60,
        )
        return result.exit_code == 0

    # ------------------------------------------------------------------ #
    # Pairing -- iOS parity with Android's RSA-key authorization step.
    # ------------------------------------------------------------------ #
    def pair_device(self, udid: str) -> bool:
        """Pair with the device. Requires it to be unlocked and the user to tap 'Trust'."""
        result = self._tools.run(
            "pymobiledevice3", ["lockdown", "pair", "--udid", udid, "--no-color"], timeout=60,
        )
        return result.exit_code == 0

    def unpair_device(self, udid: str) -> bool:
        result = self._tools.run(
            "pymobiledevice3", ["lockdown", "unpair", "--udid", udid, "--no-color"], timeout=30,
        )
        return result.exit_code == 0

    def is_paired(self, udid: str) -> bool:
        """A successful lockdown info query implies a valid pairing record exists."""
        result = self._tools.run(
            "pymobiledevice3", ["lockdown", "info", "--udid", udid, "--no-color"], timeout=30,
        )
        return result.exit_code == 0

    # ------------------------------------------------------------------ #
    # Frida on iOS -- frida-server on a jailbroken device listens on 27042,
    # same default port as Android. Checked by TCP reachability rather than
    # a process listing, since we may have no shell on the device.
    # ------------------------------------------------------------------ #
    def check_frida_reachable(self, host: str, port: int = 27042, timeout: float = 3.0) -> bool:
        reachable, _ = self.check_ssh_reachable(host, port=port, timeout=timeout)
        return reachable

    # ------------------------------------------------------------------ #
    # Aggregate readiness -- iOS parity with ``DeviceConnectionManager.get_readiness``
    # ------------------------------------------------------------------ #
    def get_readiness(self, udid: str, host: str | None = None) -> IOSDeviceReadiness:
        paired = self.is_paired(udid)
        dev_mode = self.get_developer_mode_status(udid)
        profiles = self.list_profiles(udid) if paired else []

        frida_reachable = False
        likely_jailbroken = False
        if host:
            frida_reachable = self.check_frida_reachable(host)
            likely_jailbroken = self.assess_jailbreak(host).likely_jailbroken

        return IOSDeviceReadiness(
            udid=udid,
            paired=paired,
            developer_mode_enabled=bool(dev_mode),
            installed_profiles=profiles,
            frida_reachable=frida_reachable,
            likely_jailbroken=likely_jailbroken,
            ready=paired and bool(dev_mode) and len(profiles) > 0,
        )


_ios_manager: IOSConnectionManager | None = None


def get_ios_connection_manager() -> IOSConnectionManager:
    global _ios_manager
    if _ios_manager is None:
        _ios_manager = IOSConnectionManager()
    return _ios_manager
