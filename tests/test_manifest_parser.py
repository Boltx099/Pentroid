"""
Tests for the manifest_parser pure functions (Module 6a).

Fixtures are hand-written XML shaped exactly like what apktool
actually outputs (android: namespace, attribute names) so these tests
exercise the real parsing logic without needing a real apktool decode.
"""

from __future__ import annotations

import pytest

from app.plugins.installed.manifest_analysis.manifest_parser import analyze_manifest

_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def _wrap(application_inner: str = "", extra_root: str = "") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />
    {extra_root}
    <application android:label="TestApp">
        {application_inner}
    </application>
</manifest>"""


def test_detects_dangerous_permissions():
    xml = _wrap(extra_root="")
    xml = xml.replace(
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />',
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />'
        '<uses-permission android:name="android.permission.READ_SMS" />'
        '<uses-permission android:name="android.permission.CAMERA" />'
        '<uses-permission android:name="android.permission.INTERNET" />',  # not dangerous
    )
    findings, logs = analyze_manifest(xml)
    perm_findings = [f for f in findings if f.category == "Permissions"]
    assert len(perm_findings) == 1
    assert "READ_SMS" in perm_findings[0].description
    assert "CAMERA" in perm_findings[0].description
    assert "INTERNET" not in perm_findings[0].description


def test_no_permission_finding_when_none_dangerous():
    xml = _wrap()
    xml = xml.replace(
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />',
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />'
        '<uses-permission android:name="android.permission.INTERNET" />',
    )
    findings, _ = analyze_manifest(xml)
    assert not any(f.category == "Permissions" for f in findings)


def test_detects_debuggable_true():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application android:debuggable="true" />
</manifest>"""
    findings, _ = analyze_manifest(xml)
    assert any("debuggable" in f.title.lower() for f in findings)
    debug_finding = next(f for f in findings if "debuggable" in f.title.lower())
    assert debug_finding.severity.value == "high"


def test_debuggable_false_no_finding():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application android:debuggable="false" />
</manifest>"""
    findings, _ = analyze_manifest(xml)
    assert not any("debuggable" in f.title.lower() for f in findings)


def test_allow_backup_absent_flagged():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application />
</manifest>"""
    findings, _ = analyze_manifest(xml)
    assert any("backup" in f.title.lower() for f in findings)


def test_allow_backup_explicitly_false_no_finding():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application android:allowBackup="false" />
</manifest>"""
    findings, _ = analyze_manifest(xml)
    assert not any("backup" in f.title.lower() for f in findings)


def test_exported_activity_explicit_without_permission_flagged():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application>
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>"""
    findings, _ = analyze_manifest(xml)
    exposed = [f for f in findings if f.category == "Exposed Components"]
    assert len(exposed) == 1
    assert ".MainActivity" in exposed[0].title
    assert "explicitly" in exposed[0].description


def test_exported_activity_with_permission_not_flagged():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application>
        <activity android:name=".AdminActivity" android:exported="true" android:permission="com.example.ADMIN" />
    </application>
</manifest>"""
    findings, _ = analyze_manifest(xml)
    assert not any(f.category == "Exposed Components" for f in findings)


def test_implicit_export_via_intent_filter_flagged():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application>
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""
    findings, _ = analyze_manifest(xml)
    exposed = [f for f in findings if f.category == "Exposed Components"]
    assert len(exposed) == 1
    assert "implicitly" in exposed[0].description
    assert ".BootReceiver" in exposed[0].title


def test_non_exported_component_without_intent_filter_not_flagged():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application>
        <service android:name=".InternalService" android:exported="false" />
        <provider android:name=".InternalProvider" />
    </application>
</manifest>"""
    findings, _ = analyze_manifest(xml)
    assert not any(f.category == "Exposed Components" for f in findings)


def test_multiple_exposed_components_all_reported():
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {_NS} package="com.example.testapp">
    <application>
        <activity android:name=".A" android:exported="true" />
        <service android:name=".B" android:exported="true" />
        <receiver android:name=".C" android:exported="true" />
        <provider android:name=".D" android:exported="true" />
    </application>
</manifest>"""
    findings, _ = analyze_manifest(xml)
    exposed_names = {f.title.split(": ")[-1] for f in findings if f.category == "Exposed Components"}
    assert exposed_names == {".A", ".B", ".C", ".D"}


def test_malformed_xml_raises_parse_error():
    import xml.etree.ElementTree as ET
    with pytest.raises(ET.ParseError):
        analyze_manifest("<manifest><unclosed>")


def test_package_and_sdk_info_logged():
    xml = _wrap()
    _, logs = analyze_manifest(xml)
    assert any("com.example.testapp" in line for line in logs)
    assert any("minSdkVersion=24" in line for line in logs)
