"""
app.plugins.installed.mitre_attack_mapping.mitre_map
========================================================

Maps requested Android permissions to MITRE ATT&CK for Mobile
technique IDs (Collection tactic, TA0035). Every ID in
``PERMISSION_TO_TECHNIQUE`` was verified directly against a live fetch
of https://attack.mitre.org/tactics/TA0035/ during development --
not recalled from memory -- and permissions without a clearly
justified match to a verified technique are deliberately left
unmapped rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass

_ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str = "Collection (TA0035)"

    @property
    def url(self) -> str:
        return _ATTACK_BASE_URL + self.technique_id.replace(".", "/")


# permission short name -> MitreTechnique
PERMISSION_TO_TECHNIQUE: dict[str, MitreTechnique] = {
    "READ_CALENDAR": MitreTechnique("T1636.001", "Protected User Data: Calendar Entries"),
    "WRITE_CALENDAR": MitreTechnique("T1636.001", "Protected User Data: Calendar Entries"),
    "READ_CALL_LOG": MitreTechnique("T1636.002", "Protected User Data: Call Log"),
    "WRITE_CALL_LOG": MitreTechnique("T1636.002", "Protected User Data: Call Log"),
    "READ_CONTACTS": MitreTechnique("T1636.003", "Protected User Data: Contact List"),
    "WRITE_CONTACTS": MitreTechnique("T1636.003", "Protected User Data: Contact List"),
    "GET_ACCOUNTS": MitreTechnique("T1636.005", "Protected User Data: Accounts"),
    "SEND_SMS": MitreTechnique("T1636.004", "Protected User Data: SMS Messages"),
    "RECEIVE_SMS": MitreTechnique("T1636.004", "Protected User Data: SMS Messages"),
    "READ_SMS": MitreTechnique("T1636.004", "Protected User Data: SMS Messages"),
    "CAMERA": MitreTechnique("T1512", "Video Capture"),
    "RECORD_AUDIO": MitreTechnique("T1429", "Audio Capture"),
    "ACCESS_FINE_LOCATION": MitreTechnique("T1430", "Location Tracking"),
    "ACCESS_COARSE_LOCATION": MitreTechnique("T1430", "Location Tracking"),
    "ACCESS_BACKGROUND_LOCATION": MitreTechnique("T1430", "Location Tracking"),
    "CALL_PHONE": MitreTechnique("T1616", "Call Control"),
    "ANSWER_PHONE_CALLS": MitreTechnique("T1616", "Call Control"),
    "READ_EXTERNAL_STORAGE": MitreTechnique("T1533", "Data from Local System"),
    "WRITE_EXTERNAL_STORAGE": MitreTechnique("T1533", "Data from Local System"),
}


def map_permissions(permissions: list[str]) -> dict[str, list[str]]:
    """
    Group requested permissions by the MITRE technique they map to.
    Returns ``{"T1636.004": ["READ_SMS", "SEND_SMS"], ...}``, only for
    permissions with a verified mapping -- unmapped permissions are
    silently omitted rather than forced into a guessed category.
    """
    grouped: dict[str, list[str]] = {}
    for perm in permissions:
        technique = PERMISSION_TO_TECHNIQUE.get(perm)
        if technique is None:
            continue
        grouped.setdefault(technique.technique_id, []).append(perm)
    return grouped
