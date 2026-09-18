"""
app.plugins.installed.certificate_analysis.plugin
=====================================================

Inspects the APK's signing certificate directly -- no APKTool/JADX
dependency, this step can run immediately after validation.

Tries APK Signature Scheme v2/v3 first (parsed directly from the raw
APK bytes via ``apk_signing_block`` + the ``cryptography`` package),
since that's what essentially every modern APK actually uses -- Android
Studio has defaulted to it since ~2017, and Play App Signing always
produces it. Falls back to ``keytool -printcert -jarfile`` (the legacy
v1/JAR scheme) only if no v2/v3 block is found, since keytool alone
would otherwise misreport most real-world APKs as "unsigned".

Flags: debug-signed release builds, weak signature algorithm or key
size, and expired certificates.
"""

from __future__ import annotations

from app.core.dependency_manager import get_dependency_manager
from app.core.exceptions import ToolNotFoundError
from app.core.schemas import (
    ConfidenceLevel, PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext,
)
from app.core.tool_manager import get_tool_manager
from app.plugins.base import Plugin, PluginHealth, PluginMetadata
from app.plugins.installed.certificate_analysis.apk_signing_block import extract_signing_certificates
from app.plugins.installed.certificate_analysis.cert_parser import (
    cert_info_from_der, is_debug_cert, is_expired, parse_keytool_printcert,
)


class CertificateAnalysisPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="certificate_analysis",
        name="Certificate Analysis",
        version="1.0.0",
        description="Inspects the APK signing certificate for debug-signing, weak crypto, and expiry.",
        requires_device=False,
    )

    def health(self) -> PluginHealth:
        try:
            import cryptography  # noqa: F401
            return PluginHealth.HEALTHY
        except ImportError:
            pass
        status = get_dependency_manager().status("keytool")
        return PluginHealth.HEALTHY if status.installed else PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        deps = get_dependency_manager()
        logs: list[str] = []

        cert = None
        try:
            v2v3 = extract_signing_certificates(context.target_path)
        except Exception as exc:  # noqa: BLE001 - binary parsing on untrusted input; never let this crash the step
            v2v3 = None
            logs.append(f"APK Signing Block v2/v3 parse attempt raised {exc!r}; falling back to keytool.")

        if v2v3 is not None and v2v3.certificates_der:
            try:
                cert = cert_info_from_der(v2v3.certificates_der[0])
                logs.append(f"Signing certificate found via APK Signature Scheme {v2v3.scheme} block.")
            except ImportError:
                logs.append("cryptography package not installed; can't parse the v2/v3 certificate -- "
                             "falling back to keytool (which won't see it either, but let's try).")
            except Exception as exc:  # noqa: BLE001 - malformed/unexpected cert DER shouldn't crash the step
                logs.append(f"Failed to parse extracted v2/v3 certificate: {exc!r}; falling back to keytool.")

        if cert is None:
            try:
                deps.get_binary_path("keytool")
            except ToolNotFoundError:
                logs.append("keytool is not available on $PATH (requires a JDK) -- skipping certificate analysis.")
                return PluginOutput(tool="certificate_analysis", status=PluginRunStatus.SKIPPED, logs=logs)

            tool_manager = get_tool_manager()
            result = tool_manager.run("keytool", ["-printcert", "-jarfile", context.target_path], timeout=30)

            if result.exit_code != 0:
                return PluginOutput(
                    tool="certificate_analysis", status=PluginRunStatus.FAILED, logs=logs,
                    errors=[result.stderr.strip() or "keytool exited non-zero with no stderr output"],
                )

            cert = parse_keytool_printcert(result.stdout)
            if cert is None:
                return PluginOutput(
                    tool="certificate_analysis", status=PluginRunStatus.SKIPPED, logs=logs,
                    errors=[
                        "APK does not appear to be signed under v1 (JAR), v2, or v3 signature schemes. "
                        "Note: keytool only understands the legacy v1 scheme -- a v2/v3-only APK that "
                        "genuinely has no readable signing block would end up here too."
                    ],
                )

        findings: list[PluginFinding] = []

        if is_debug_cert(cert.owner):
            findings.append(PluginFinding(
                title="APK is signed with the Android debug certificate",
                finding_key="signing.debug_certificate",
                confidence=ConfidenceLevel.CONFIRMED,
                severity=SeverityLevel.HIGH,
                description=f"Signing certificate owner is '{cert.owner}', matching Android's well-known "
                             "debug-keystore convention. This build should not be distributed.",
                category="Signing",
                masvs_mapping="MASVS-CODE",
                recommendation="Sign release builds with a proper release key, not the debug keystore.",
            ))

        if cert.signature_algorithm_weak:
            findings.append(PluginFinding(
                title=f"Weak signing algorithm: {cert.signature_algorithm}",
                finding_key="signing.weak_algorithm",
                confidence=ConfidenceLevel.CONFIRMED,
                severity=SeverityLevel.HIGH,
                description=f"The JDK's own certificate policy flags '{cert.signature_algorithm}' as weak.",
                category="Signing",
                masvs_mapping="MASVS-CRYPTO",
                recommendation="Re-sign with a modern algorithm (e.g. SHA256withRSA or stronger).",
            ))

        if cert.key_algorithm_weak:
            findings.append(PluginFinding(
                title=f"Weak signing key: {cert.key_algorithm}",
                finding_key="signing.weak_algorithm",
                confidence=ConfidenceLevel.CONFIRMED,
                severity=SeverityLevel.HIGH,
                description=f"The JDK's own certificate policy flags '{cert.key_algorithm}' as weak.",
                category="Signing",
                masvs_mapping="MASVS-CRYPTO",
                recommendation="Re-sign with at least a 2048-bit RSA key (or equivalent EC key).",
            ))

        if cert.valid_until_raw:
            expired = is_expired(cert.valid_until_raw)
            if expired is True:
                findings.append(PluginFinding(
                    title="Signing certificate has expired",
                    severity=SeverityLevel.MEDIUM,
                    description=f"Certificate expired: {cert.valid_until_raw}. Google Play requires a valid, "
                                 "non-expired signing certificate to publish updates.",
                    category="Signing",
                    masvs_mapping="MASVS-CODE",
                    recommendation="Re-sign with a certificate that has a valid expiry window going forward.",
                ))

        logs.append(f"Signing certificate owner: {cert.owner}")
        return PluginOutput(tool="certificate_analysis", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
