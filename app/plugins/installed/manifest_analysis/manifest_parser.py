"""
app.plugins.installed.manifest_analysis.manifest_parser
===========================================================

Pure parsing/analysis logic for a decoded ``AndroidManifest.xml``
(the plain-text XML apktool produces, not the compiled binary AXML
inside a raw APK). Kept separate from ``plugin.py`` so it can be unit
tested directly against hand-written XML fixtures, without needing a
real apktool decode.

The checks here are standard, well-established Android static
analysis: dangerous-permission usage, exported components lacking a
protecting permission, debuggable builds, and backup configuration --
the same category of checks MobSF/QARK and equivalent tools perform.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from app.core.schemas import ConfidenceLevel, PluginFinding, SeverityLevel

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Android's own public "dangerous" protection-level permission groups
# (developer.android.com/guide/topics/permissions/overview).
DANGEROUS_PERMISSIONS = {
    "READ_CALENDAR", "WRITE_CALENDAR",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "CAMERA",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS",
    "ADD_VOICEMAIL", "USE_SIP",
    "BODY_SENSORS",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
}

_EXPORTABLE_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")


def _attr(element, name: str) -> str | None:
    return element.get(f"{_ANDROID_NS}{name}")


def extract_all_permissions(xml_text: str) -> list[str]:
    """
    Return every requested permission's short name (not just the
    "dangerous" subset ``analyze_manifest`` flags), for reuse by other
    steps -- e.g. MITRE ATT&CK mapping -- without re-parsing the manifest.
    """
    root = ET.fromstring(xml_text)
    permissions = set()
    for perm_el in root.findall("uses-permission"):
        name = _attr(perm_el, "name") or ""
        short = name.rsplit(".", 1)[-1]
        if short:
            permissions.add(short)
    return sorted(permissions)


def analyze_manifest(xml_text: str) -> tuple[list[PluginFinding], list[str]]:
    """
    Parse a decoded AndroidManifest.xml string and return
    ``(findings, log_lines)``. Raises ``xml.etree.ElementTree.ParseError``
    on malformed XML -- the caller (``plugin.py``) decides how to
    report that as a ``PluginOutput``.
    """
    findings: list[PluginFinding] = []
    logs: list[str] = []

    root = ET.fromstring(xml_text)

    package = root.get("package", "unknown")
    logs.append(f"Package: {package}")

    uses_sdk = root.find("uses-sdk")
    min_sdk = _attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    target_sdk = _attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    if min_sdk or target_sdk:
        logs.append(f"minSdkVersion={min_sdk or 'unspecified'}, targetSdkVersion={target_sdk or 'unspecified'}")

    _check_dangerous_permissions(root, findings)

    application = root.find("application")
    if application is not None:
        _check_debuggable(application, findings)
        _check_allow_backup(application, findings)
        _check_exported_components(application, findings, logs)

    return findings, logs


def _check_dangerous_permissions(root, findings: list[PluginFinding]) -> None:
    requested = set()
    for perm_el in root.findall("uses-permission"):
        name = _attr(perm_el, "name") or ""
        short = name.rsplit(".", 1)[-1]
        if short in DANGEROUS_PERMISSIONS:
            requested.add(short)

    if requested:
        findings.append(
            PluginFinding(
                finding_key="android.dangerous_permissions",
                confidence=ConfidenceLevel.CONFIRMED,
                title=f"{len(requested)} dangerous permission(s) requested",
                severity=SeverityLevel.MEDIUM,
                description="Requested dangerous-protection-level permissions: " + ", ".join(sorted(requested)),
                category="Permissions",
                masvs_mapping="MASVS-PLATFORM",
                recommendation="Verify each permission is actually required for a declared feature; "
                               "drop any that aren't (least-privilege).",
            )
        )


def _check_debuggable(application, findings: list[PluginFinding]) -> None:
    if _attr(application, "debuggable") == "true":
        findings.append(
            PluginFinding(
                finding_key="android.debuggable",
                confidence=ConfidenceLevel.CONFIRMED,
                title="Application is debuggable",
                severity=SeverityLevel.HIGH,
                description='android:debuggable="true" allows attaching a debugger to the running app, '
                             "exposing internals (memory, call stack, live code execution) to an attacker "
                             "with device access.",
                category="Manifest",
                owasp_mapping="M10: Extraneous Functionality",
                masvs_mapping="MASVS-RESILIENCE",
                recommendation="Remove android:debuggable, or ensure your release build strips it "
                               "(the default Gradle release build type already does this).",
            )
        )


def _check_allow_backup(application, findings: list[PluginFinding]) -> None:
    if _attr(application, "allowBackup") != "false":
        findings.append(
            PluginFinding(
                finding_key="android.backup_enabled",
                confidence=ConfidenceLevel.CONFIRMED,
                title="Backups not explicitly disabled",
                severity=SeverityLevel.MEDIUM,
                description='android:allowBackup is not set to "false", so app data may be extractable '
                             "via `adb backup` on devices where USB debugging is enabled.",
                category="Manifest",
                owasp_mapping="M9: Insecure Data Storage",
                masvs_mapping="MASVS-STORAGE",
                recommendation='Set android:allowBackup="false" unless backups are explicitly required '
                               "and don't expose sensitive data.",
            )
        )


def _check_exported_components(application, findings: list[PluginFinding], logs: list[str]) -> None:
    for tag in _EXPORTABLE_COMPONENT_TAGS:
        for comp in application.findall(tag):
            name = _attr(comp, "name") or "unknown"
            exported_attr = _attr(comp, "exported")
            has_intent_filter = comp.find("intent-filter") is not None
            has_permission = _attr(comp, "permission") is not None

            is_exported = exported_attr == "true" or (exported_attr is None and has_intent_filter)
            if not is_exported or has_permission:
                continue

            reason = (
                "explicitly (android:exported=\"true\")" if exported_attr == "true"
                else "implicitly under pre-Android-12 rules (has an intent-filter, no explicit android:exported)"
            )
            findings.append(
                PluginFinding(
                    finding_key="android.exported_component",
                    confidence=ConfidenceLevel.CONFIRMED,
                    title=f"Exported {tag} without permission: {name}",
                    severity=SeverityLevel.HIGH,
                    description=f"{tag.title()} '{name}' is exported {reason} and has no android:permission "
                                f"attribute, so any other app on the device can interact with it directly.",
                    category="Exposed Components",
                    owasp_mapping="M1: Improper Platform Usage",
                    masvs_mapping="MASVS-PLATFORM",
                    file_path="AndroidManifest.xml",
                    recommendation='Set android:exported="false" if external access is not required, '
                                   "or protect it with a signature-level android:permission.",
                )
            )
    logs.append(f"Checked {sum(len(application.findall(t)) for t in _EXPORTABLE_COMPONENT_TAGS)} components for export/permission exposure")
