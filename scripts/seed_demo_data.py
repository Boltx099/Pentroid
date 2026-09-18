"""
Seed a realistic demo dataset for README screenshots.

Uses InsecureBankv2 -- a well-known, intentionally-vulnerable Android test
app (used across the community for exactly this kind of demo) -- so the
screenshots show a real category of findings without implying a real scan
of anyone's production app.
"""
import os
os.environ["PENTROID_PATHS__ROOT"] = "/tmp/pentroid_demo_root"

import sys
sys.path.insert(0, "/home/claude/work/Pentroid")

from datetime import datetime, timedelta, timezone

from main import bootstrap
bootstrap()

from app.database.database import init_db, session_scope
from app.database.models import (
    Analysis, AnalysisType, ConnectionType, Device, DeviceStatus, Finding, FindingStatus,
    Platform, Project, ProjectType, Report, ReportFormat, RunStatus, Severity,
)

init_db()

with session_scope() as s:
    project = Project(
        name="InsecureBankv2", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
        target_path="/home/demo/samples/InsecureBankv2.apk",
        workspace_path="/tmp/pentroid_demo_root/projects/insecurebankv2",
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
        updated_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    s.add(project)
    s.flush()

    analysis = Analysis(
        project_id=project.id, analysis_type=AnalysisType.STATIC,
        workflow_name="static_analysis_default", status=RunStatus.COMPLETED,
        risk_score=None,  # computed below, after findings exist
        started_at=datetime.now(timezone.utc) - timedelta(minutes=6),
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=4),
    )
    s.add(analysis)
    s.flush()
    analysis_id = analysis.id

    malware_analysis = Analysis(
        project_id=project.id, analysis_type=AnalysisType.MALWARE,
        workflow_name="malware_analysis_default", status=RunStatus.COMPLETED, risk_score=2.1,
        started_at=datetime.now(timezone.utc) - timedelta(minutes=20),
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=18),
    )
    s.add(malware_analysis)

    findings = [
        dict(title="Hardcoded AES Encryption Key", severity=Severity.CRITICAL,
             category="Cryptography", owasp_mapping="M10: Insufficient Cryptography",
             masvs_mapping="MASVS-CRYPTO-1", file_path="com/android/insecurebankv2/CryptoClass.java",
             line_number=39,
             evidence='SecretKeySpec("This is the super secret key 123".getBytes(), "AES")',
             description="A static AES key is embedded directly in source, so any holder of "
                         "the APK can decrypt data the app believes is protected.",
             recommendation="Derive the key at runtime (Android Keystore) instead of embedding it."),
        dict(title="TrustManager Does Not Validate Certificates", severity=Severity.CRITICAL,
             category="Network Security", owasp_mapping="M5: Insufficient Cryptography",
             masvs_mapping="MASVS-NETWORK-1", file_path="com/android/insecurebankv2/MyWebViewClient.java",
             line_number=27,
             evidence="checkServerTrusted(X509Certificate[] chain, String authType) { }",
             description="checkServerTrusted() has an empty body, so this custom TrustManager "
                         "accepts any certificate chain -- TLS provides no protection against MITM.",
             recommendation="Remove the custom TrustManager or implement real chain validation "
                             "with certificate pinning."),
        dict(title="Exported Activity Without Permission", severity=Severity.HIGH,
             category="Manifest", owasp_mapping="M1: Improper Platform Usage",
             masvs_mapping="MASVS-PLATFORM-1", file_path="AndroidManifest.xml", line_number=None,
             evidence='<activity android:name=".DoTransfer" android:exported="true"/>',
             description="DoTransfer is exported with no permission guard, so any other app on "
                         "the device can launch it directly.",
             recommendation="Add android:exported=\"false\" or a signature-level permission."),
        dict(title="SQL Injection via Content Provider", severity=Severity.HIGH,
             category="Code Analysis", owasp_mapping="M7: Client Code Quality",
             masvs_mapping="MASVS-CODE-4", file_path="com/android/insecurebankv2/TrackUserContentProvider.java",
             line_number=91,
             evidence='db.rawQuery("SELECT * FROM messages WHERE uid = " + uid, null)',
             description="User-controlled input is concatenated directly into a raw SQL query "
                         "with no parameterization.",
             recommendation="Use parameterized queries (selectionArgs) instead of string concatenation."),
        dict(title="Weak Hash Algorithm", severity=Severity.MEDIUM,
             category="Cryptography", owasp_mapping="M5: Insufficient Cryptography",
             masvs_mapping="MASVS-CRYPTO-1", file_path="com/android/insecurebankv2/PostLogin.java",
             line_number=112, evidence='MessageDigest.getInstance("MD5")',
             description="MD5 is cryptographically broken and unsuitable for integrity checks "
                         "or password storage.",
             recommendation="Use SHA-256 or a dedicated password hash (bcrypt/Argon2)."),
        dict(title="Cleartext HTTP URL", severity=Severity.MEDIUM,
             category="Network Security", owasp_mapping="M3: Insecure Communication",
             masvs_mapping="MASVS-NETWORK-1", file_path="com/android/insecurebankv2/DoLogin.java",
             line_number=64, evidence='"http://10.0.2.2:8888/sqlite/login"',
             description="A hardcoded cleartext HTTP endpoint transmits login credentials "
                         "unencrypted.",
             recommendation="Use HTTPS for every network endpoint, including test/dev backends."),
        dict(title="Application Data Backup Enabled", severity=Severity.LOW,
             category="Manifest", owasp_mapping="M2: Insecure Data Storage",
             masvs_mapping="MASVS-STORAGE-1", file_path="AndroidManifest.xml", line_number=None,
             evidence='android:allowBackup="true"',
             description="allowBackup is not explicitly disabled, so app data can be extracted "
                         "via adb backup on a debuggable or rooted device.",
             recommendation='Set android:allowBackup="false" unless backup is specifically needed.'),
        dict(title="6 dangerous permission(s) requested", severity=Severity.INFO,
             category="Manifest", owasp_mapping=None, masvs_mapping="MASVS-PLATFORM-1",
             file_path="AndroidManifest.xml", line_number=None,
             evidence="READ_SMS, SEND_SMS, READ_CONTACTS, WRITE_EXTERNAL_STORAGE, "
                       "READ_PHONE_STATE, GET_ACCOUNTS",
             description="These permissions expand the app's attack surface and should each "
                         "be justified by a real feature.",
             recommendation="Drop any permission not backing an active feature."),
    ]

    severity_weight = {Severity.CRITICAL: 10.0, Severity.HIGH: 7.0, Severity.MEDIUM: 4.0,
                       Severity.LOW: 1.0, Severity.INFO: 0.0}

    for i, f in enumerate(findings):
        status = FindingStatus.OPEN
        if f["title"].startswith("Weak Hash"):
            status = FindingStatus.CONFIRMED
        if f["title"].startswith("Application Data Backup"):
            status = FindingStatus.ACCEPTED_RISK
        s.add(Finding(analysis_id=analysis_id, status=status, **f))

    weighted = sorted((severity_weight[f["severity"]] for f in findings), reverse=True)
    primary, rest = weighted[0], weighted[1:]
    secondary = sum(w * (0.5 ** i) for i, w in enumerate(rest, start=1))
    analysis.risk_score = round(min(primary + secondary, 10.0), 1)

    device = Device(
        identifier="emulator-5554", display_name="Pixel_6_API_33", platform=Platform.ANDROID,
        connection_type=ConnectionType.ANDROID_EMULATOR, os_version="13", api_level=33,
        is_rooted=True, frida_installed=True, frida_version="16.1.4",
        status=DeviceStatus.READY, last_connected_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )
    s.add(device)

    s.add(Report(
        analysis_id=analysis_id, format=ReportFormat.HTML,
        file_path="/tmp/pentroid_demo_root/reports/insecurebankv2_static_report.html",
        generated_at=datetime.now(timezone.utc) - timedelta(minutes=3),
    ))

print("Seed complete.")
