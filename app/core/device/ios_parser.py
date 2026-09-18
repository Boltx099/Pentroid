"""
app.core.device.ios_parser
=============================

Pure parsing functions for iOS device discovery output, split out from
``ios_connection_manager`` for the same reason as ``adb_parser``: unit
testability without real hardware/macOS.

Honesty note on confidence level
---------------------------------
``xcrun simctl list devices --json`` is Apple's own documented,
stable CLI/JSON format -- the simulator parsing here is high
confidence. ``pymobiledevice3``'s exact CLI subcommands and JSON
field names have changed across its versions and I can't verify the
current schema against a real device from this sandbox (no iOS
hardware, no macOS). ``parse_usbmux_list`` and ``parse_lockdown_info``
are written defensively (``.get()`` with fallbacks, never crash on an
unexpected shape) precisely because of that uncertainty -- treat their
exact field mapping as a first draft to verify against
``pymobiledevice3 --help`` / real device output before relying on it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SimulatorEntry:
    udid: str
    name: str
    state: str  # "Booted" | "Shutdown" | ...
    runtime: str  # e.g. "iOS 17.4"


def parse_simctl_list(raw_json: str) -> list[SimulatorEntry]:
    """
    Parse ``xcrun simctl list devices --json`` output::

        {
          "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
              {"udid": "ABCD-1234", "name": "iPhone 15 Pro", "state": "Booted", "isAvailable": true}
            ]
          }
        }
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    entries: list[SimulatorEntry] = []
    for runtime_id, devices in data.get("devices", {}).items():
        runtime_name = _runtime_id_to_name(runtime_id)
        for device in devices:
            if not device.get("isAvailable", True):
                continue
            entries.append(
                SimulatorEntry(
                    udid=device.get("udid", ""),
                    name=device.get("name", "Unknown"),
                    state=device.get("state", "Unknown"),
                    runtime=runtime_name,
                )
            )
    return entries


def _runtime_id_to_name(runtime_id: str) -> str:
    """'com.apple.CoreSimulator.SimRuntime.iOS-17-4' -> 'iOS 17.4'"""
    marker = "SimRuntime."
    if marker not in runtime_id:
        return runtime_id
    tail = runtime_id.split(marker, 1)[1]  # "iOS-17-4"
    parts = tail.split("-")
    if len(parts) < 2:
        return tail
    platform_name, version_parts = parts[0], parts[1:]
    return f"{platform_name} {'.'.join(version_parts)}"


@dataclass(frozen=True)
class PhysicalDeviceEntry:
    udid: str
    connection_type: str  # "usb" | "network" | "unknown"


def parse_usbmux_list(raw_json: str) -> list[PhysicalDeviceEntry]:
    """
    Best-effort parse of ``pymobiledevice3 usbmux list`` JSON output
    (list of device descriptors). See module docstring re: schema
    confidence -- accepts either a bare list or a ``{"devices": [...]}``
    wrapper, and tolerates missing/renamed keys.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    items = data if isinstance(data, list) else data.get("devices", [])
    entries: list[PhysicalDeviceEntry] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        udid = item.get("Identifier") or item.get("udid") or item.get("UniqueDeviceID") or ""
        if not udid:
            continue
        conn_raw = str(item.get("ConnectionType", item.get("connection_type", ""))).lower()
        conn_type = "network" if "network" in conn_raw or "wifi" in conn_raw else "usb"
        entries.append(PhysicalDeviceEntry(udid=udid, connection_type=conn_type))
    return entries


def parse_lockdown_info(raw_json: str) -> dict[str, str]:
    """
    Best-effort parse of ``pymobiledevice3 lockdown info`` JSON into a
    flat string dict. Returns {} on any parse failure rather than
    raising -- device info is supplementary, never load-bearing for a
    workflow step.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if not isinstance(v, (dict, list))}


# --------------------------------------------------------------------------- #
# Parsers for the app/profile/developer-mode commands.
#
# Confidence note (same caveat as the rest of this module): pymobiledevice3's
# subcommand *names* were verified against a real `--help` run, but the exact
# stdout shape of each was not observable without an iOS device attached.
# Each parser therefore accepts several plausible shapes -- JSON list, JSON
# dict keyed by identifier, or plain lines -- and returns [] / None rather
# than raising on anything unexpected. Verify against real device output
# before depending on these for anything load-bearing.
# --------------------------------------------------------------------------- #

def parse_app_list(raw: str) -> list[str]:
    """Extract bundle identifiers from `pymobiledevice3 apps list` output."""
    raw = raw.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fall back to line-oriented output: pick out anything that looks like a bundle id.
        pattern = re.compile(r"\b([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+){2,})\b")
        found = []
        for line in raw.splitlines():
            match = pattern.search(line)
            if match:
                found.append(match.group(1))
        return sorted(set(found))

    if isinstance(data, dict):
        return sorted(data.keys())
    if isinstance(data, list):
        ids = []
        for item in data:
            if isinstance(item, str):
                ids.append(item)
            elif isinstance(item, dict):
                bundle_id = item.get("CFBundleIdentifier") or item.get("bundleIdentifier") or item.get("identifier")
                if bundle_id:
                    ids.append(str(bundle_id))
        return sorted(set(ids))
    return []


def parse_profile_list(raw: str) -> list[str]:
    """Extract installed configuration-profile identifiers/names from `profile list` output."""
    raw = raw.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [line.strip() for line in raw.splitlines() if line.strip()]

    # Real-world shape is typically {"OrderedIdentifiers": [...], "ProfileMetadata": {...}}
    if isinstance(data, dict):
        ordered = data.get("OrderedIdentifiers")
        if isinstance(ordered, list):
            return [str(item) for item in ordered]
        metadata = data.get("ProfileMetadata")
        if isinstance(metadata, dict):
            return sorted(metadata.keys())
        return sorted(str(k) for k in data.keys())
    if isinstance(data, list):
        return [str(item) for item in data]
    return []


def parse_developer_mode_status(raw: str) -> bool | None:
    """
    Interpret `amfi developer-mode-status` output. Returns None when the
    answer genuinely can't be determined, rather than defaulting to False
    (which would wrongly imply "confirmed disabled").
    """
    text = raw.strip().lower()
    if not text:
        return None
    if "true" in text or "enabled" in text:
        return True
    if "false" in text or "disabled" in text:
        return False
    return None
