"""
app.core.device.adb_parser
=============================

Pure parsing/classification functions for ``adb`` command output.
Deliberately has zero dependency on subprocess/ToolManager so it can
be exhaustively unit tested against real-world ``adb devices -l`` /
``getprop`` / cert-listing output samples without needing a physical
device or emulator attached.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.database.models import ConnectionType

_DEVICE_LINE_RE = re.compile(
    r"^(?P<serial>\S+)\s+(?P<state>device|unauthorized|offline|no permissions.*)\s*(?P<rest>.*)$"
)
_KV_RE = re.compile(r"(\S+):(\S+)")


@dataclass(frozen=True)
class RawDeviceEntry:
    serial: str
    state: str  # "device" (ready) | "unauthorized" | "offline"
    product: str = ""
    model: str = ""
    device: str = ""
    transport_id: str = ""


def parse_devices_output(raw: str) -> list[RawDeviceEntry]:
    """
    Parse the output of ``adb devices -l``, e.g.::

        List of devices attached
        0123456789ABCDEF       device usb:1-1 product:sunfish model:Pixel_4a device:sunfish transport_id:1
        emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emulator64_x86_64 transport_id:2
        R3CN90ABCDE             unauthorized usb:1-2 transport_id:3

    Blank lines and the header line are ignored. Malformed lines are
    skipped rather than raising, since a single unparseable line must
    not take down device discovery for every other connected device.
    """
    entries: list[RawDeviceEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("list of devices"):
            continue

        match = _DEVICE_LINE_RE.match(line)
        if not match:
            continue

        kv = dict(_KV_RE.findall(match.group("rest")))
        entries.append(
            RawDeviceEntry(
                serial=match.group("serial"),
                state=match.group("state"),
                product=kv.get("product", ""),
                model=kv.get("model", ""),
                device=kv.get("device", ""),
                transport_id=kv.get("transport_id", ""),
            )
        )
    return entries


def classify_connection_type(entry: RawDeviceEntry) -> ConnectionType:
    """
    Heuristic classification of *how* a device is connected, based on
    serial format and product/model string conventions used by each
    platform. This is inherently best-effort -- e.g. Waydroid and
    Genymotion can both present as a plain TCP-connected device -- so
    unrecognized network devices fall back to the generic ``NETWORK``
    type rather than a guessed-wrong specific one.
    """
    serial = entry.serial.lower()
    product = entry.product.lower()
    model = entry.model.lower()
    device = entry.device.lower()

    if serial.startswith("emulator-"):
        return ConnectionType.ANDROID_EMULATOR

    if "genymotion" in product or "genymotion" in model or "vbox86" in product:
        return ConnectionType.GENYMOTION

    if "waydroid" in product or "waydroid" in model or "waydroid" in device:
        return ConnectionType.WAYDROID

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", entry.serial) or entry.serial == "127.0.0.1:5555":
        return ConnectionType.NETWORK

    return ConnectionType.USB


def parse_getprop_output(raw: str) -> dict[str, str]:
    """
    Parse ``adb shell getprop`` output, formatted as::

        [ro.build.version.release]: [14]
        [ro.build.version.sdk]: [34]
        [ro.product.model]: [Pixel 7 Pro]

    Returns a flat ``{property: value}`` dict.
    """
    props: dict[str, str] = {}
    pattern = re.compile(r"^\[(?P<key>[^\]]+)\]:\s*\[(?P<value>.*)\]$")
    for line in raw.splitlines():
        match = pattern.match(line.strip())
        if match:
            props[match.group("key")] = match.group("value")
    return props


def is_root_shell_output(raw: str) -> bool:
    """True if `su -c id` output indicates a root (uid=0) shell was granted."""
    return "uid=0" in raw


def parse_ps_for_process(raw: str, process_name: str) -> bool:
    """True if ``process_name`` appears as a running process in `ps`/`ps -A` output."""
    return any(
        process_name in line for line in raw.splitlines() if not line.strip().startswith("USER")
    )


def parse_cert_listing(raw: str) -> list[str]:
    """Parse `adb shell ls <cert dir>` output into a list of filenames (cert hash.0 entries)."""
    return [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("ls:")
    ]
