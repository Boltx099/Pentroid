"""
app.core.knowledge.finding_kb
================================

Central knowledge base of remediation guidance, keyed by a stable
``finding_key`` that plugins attach to what they emit.

Why this exists (architecture, not cosmetics)
---------------------------------------------
Before this, every plugin hand-wrote its own ``recommendation`` string
inline. That had three concrete problems:

1. **Report quality was capped by whatever each plugin author typed.**
   There was nowhere to put impact, reproduction steps, CWE IDs, CVSS
   vectors, or references, so reports structurally could not contain
   them.
2. **Improving guidance meant editing 19 plugin files**, and nothing
   kept tone, depth, or accuracy consistent between them.
3. **No machine-readable taxonomy** (CWE/CVSS), which is what external
   tools -- SARIF consumers, DefectDojo, ticket trackers -- key on.

Plugins now emit a ``finding_key`` and the enrichment layer supplies
the rest. A plugin can still override any field explicitly (a
finding-specific evidence string beats a generic one), so this adds a
floor to quality without taking away control.

CVSS vectors here are **base-score estimates for the generic case** of
each issue class, provided as a starting point for triage -- not a
substitute for scoring the specific instance in its real deployment
context. Environmental and temporal metrics are deliberately omitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FindingKnowledge:
    """Reusable, issue-class-level guidance attached to a finding at persistence time."""

    impact: str
    reproduction_steps: str
    recommendation: str
    cwe_id: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    references: list[str] = field(default_factory=list)


_MASTG = "https://mas.owasp.org/MASTG/"
_ANDROID_SEC = "https://developer.android.com/privacy-and-security/security-tips"

KNOWLEDGE_BASE: dict[str, FindingKnowledge] = {
    # ------------------------------------------------------------------ #
    # Manifest / platform configuration
    # ------------------------------------------------------------------ #
    "android.debuggable": FindingKnowledge(
        impact=(
            "A debuggable release build lets anyone with physical or ADB access attach a debugger "
            "to the running process. That exposes in-memory secrets (session tokens, keys, decrypted "
            "data), allows arbitrary code execution in the app's security context, and defeats most "
            "client-side controls -- including any root or tamper detection the app implements."
        ),
        reproduction_steps=(
            "1. Extract the manifest:  apktool d target.apk -o out/\n"
            "2. Inspect out/AndroidManifest.xml for android:debuggable=\"true\" on <application>.\n"
            "3. Confirm at runtime:  adb shell run-as <package> id\n"
            "   A debuggable app returns the app's uid instead of an error.\n"
            "4. Attach a debugger:  adb jdwp   (the app's pid will be listed)"
        ),
        recommendation=(
            "Remove android:debuggable from the manifest entirely. Gradle's release build type "
            "already sets it to false; an explicit \"true\" usually means it was hardcoded for "
            "debugging and never reverted. Add a CI check that fails the build if the flag is "
            "present in a release variant."
        ),
        cwe_id="CWE-489",
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=6.8,
        references=[_MASTG + "tests/android/MASVS-RESILIENCE/MASTG-TEST-0231/", _ANDROID_SEC],
    ),
    "android.backup_enabled": FindingKnowledge(
        impact=(
            "With backups permitted, an attacker with temporary physical access and USB debugging "
            "enabled can extract the app's private data directory via `adb backup` -- including "
            "databases, shared preferences, and any credentials or tokens cached there -- without "
            "root and without unlocking the app itself."
        ),
        reproduction_steps=(
            "1. Confirm android:allowBackup is not set to \"false\" in AndroidManifest.xml.\n"
            "2. adb backup -f backup.ab -noapk <package>\n"
            "3. Convert and inspect:\n"
            "   dd if=backup.ab bs=1 skip=24 | zlib-flate -uncompress > backup.tar\n"
            "   tar xf backup.tar && grep -ri 'token\\|password\\|secret' ."
        ),
        recommendation=(
            "Set android:allowBackup=\"false\" unless backup is a product requirement. If backups "
            "are required, define android:fullBackupContent (or dataExtractionRules on API 31+) to "
            "explicitly exclude credential stores, tokens, and any file holding sensitive data."
        ),
        cwe_id="CWE-530",
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=4.6,
        references=[_MASTG + "tests/android/MASVS-STORAGE/MASTG-TEST-0009/"],
    ),
    "android.exported_component": FindingKnowledge(
        impact=(
            "An exported component with no permission guard can be invoked by any other app on the "
            "device. Depending on what it does, this enables unauthorised actions in the app's "
            "context, access to internal data through an unprotected ContentProvider, intent-based "
            "injection, or bypass of the app's own authentication flow by launching a post-login "
            "Activity directly."
        ),
        reproduction_steps=(
            "1. Identify exported components without android:permission in the decoded manifest.\n"
            "2. Invoke the component from an unprivileged context:\n"
            "   adb shell am start -n <package>/<activity>\n"
            "   adb shell am startservice -n <package>/<service>\n"
            "   adb shell content query --uri content://<authority>/\n"
            "3. Observe whether the action succeeds without authentication."
        ),
        recommendation=(
            "Set android:exported=\"false\" for any component not intentionally part of the app's "
            "external interface. Where external access is required, guard it with a "
            "signature-level android:permission and validate every incoming Intent's extras as "
            "untrusted input."
        ),
        cwe_id="CWE-926",
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=7.8,
        references=[_MASTG + "tests/android/MASVS-PLATFORM/MASTG-TEST-0027/"],
    ),
    "android.dangerous_permissions": FindingKnowledge(
        impact=(
            "Dangerous-level permissions grant access to user-private data (contacts, location, "
            "SMS, camera, microphone). Beyond the direct privacy exposure, over-permissioning "
            "widens the blast radius of any other vulnerability: a code-execution or injection bug "
            "inherits every permission the app holds."
        ),
        reproduction_steps=(
            "1. List requested permissions:  aapt dump permissions target.apk\n"
            "2. Cross-reference each against the app's actual, user-visible functionality.\n"
            "3. Flag any permission with no corresponding feature."
        ),
        recommendation=(
            "Apply least privilege: remove permissions with no matching feature. Request the "
            "remaining ones at runtime, at the point of use, with a clear rationale shown to the "
            "user. Prefer scoped alternatives (Photo Picker over READ_MEDIA_IMAGES, coarse over "
            "fine location) wherever the feature allows."
        ),
        cwe_id="CWE-250",
        references=["https://developer.android.com/guide/topics/permissions/overview"],
    ),

    # ------------------------------------------------------------------ #
    # Network security
    # ------------------------------------------------------------------ #
    "android.cleartext_traffic": FindingKnowledge(
        impact=(
            "Cleartext HTTP is readable and modifiable by anyone on the network path -- hostile "
            "Wi-Fi, a compromised router, or a malicious ISP. An attacker can harvest credentials "
            "and session tokens in transit, and can alter responses to inject content or drive "
            "application logic."
        ),
        reproduction_steps=(
            "1. Confirm cleartextTrafficPermitted=\"true\" in res/xml/network_security_config.xml.\n"
            "2. Route device traffic through an intercepting proxy (Burp / mitmproxy).\n"
            "3. Exercise the app and filter captured traffic for http:// requests.\n"
            "4. Confirm request/response bodies are visible without TLS interception."
        ),
        recommendation=(
            "Set cleartextTrafficPermitted=\"false\" in the base-config and migrate all endpoints "
            "to HTTPS. If a specific legacy host genuinely cannot be migrated yet, scope the "
            "exception to that domain in a domain-config with a documented removal date rather "
            "than permitting cleartext app-wide."
        ),
        cwe_id="CWE-319",
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=6.8,
        references=["https://developer.android.com/privacy-and-security/security-config"],
    ),
    "android.user_ca_trusted": FindingKnowledge(
        impact=(
            "Trusting user-installed CAs means any certificate the device user can be convinced to "
            "install becomes valid for the app's TLS connections. This is the mechanism behind "
            "most real-world mobile MITM: a social-engineered profile, an MDM-pushed CA, or "
            "malware with settings access can silently intercept all app traffic."
        ),
        reproduction_steps=(
            "1. Confirm <certificates src=\"user\"/> appears outside <debug-overrides>.\n"
            "2. Install a proxy CA into the device's user certificate store.\n"
            "3. Proxy the app's traffic; TLS is intercepted without any app modification."
        ),
        recommendation=(
            "Remove src=\"user\" from release trust-anchors, keeping it only inside "
            "<debug-overrides> so it applies to debuggable builds only. For high-value endpoints, "
            "add certificate pinning on top -- but treat pinning as defence in depth, not a "
            "substitute for correct trust configuration."
        ),
        cwe_id="CWE-295",
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=6.4,
        references=[_MASTG + "tests/android/MASVS-NETWORK/MASTG-TEST-0020/"],
    ),
    "android.trustmanager_bypass": FindingKnowledge(
        impact=(
            "A TrustManager that accepts every certificate chain removes TLS authentication "
            "entirely. Any network attacker can present a self-signed certificate and transparently "
            "read and modify all traffic -- credentials, tokens, and API responses -- while the "
            "connection still appears encrypted to the user."
        ),
        reproduction_steps=(
            "1. Locate the custom X509TrustManager in decompiled source (empty checkServerTrusted).\n"
            "2. Proxy the device through Burp/mitmproxy using a self-signed CA that the device "
            "does NOT trust.\n"
            "3. Exercise the app: traffic is intercepted successfully, proving no validation occurs."
        ),
        recommendation=(
            "Delete the custom TrustManager and use the platform default, which performs correct "
            "chain and hostname validation. If a private CA must be trusted, add it via "
            "network_security_config trust-anchors rather than by disabling validation in code."
        ),
        cwe_id="CWE-295",
        cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.1,
        references=[_MASTG + "tests/android/MASVS-NETWORK/MASTG-TEST-0019/"],
    ),

    # ------------------------------------------------------------------ #
    # Cryptography
    # ------------------------------------------------------------------ #
    "crypto.ecb_mode": FindingKnowledge(
        impact=(
            "ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking "
            "structure and patterns in the data and providing no integrity protection. An attacker "
            "who can observe or manipulate ciphertext can infer content and splice or replay blocks "
            "without detection."
        ),
        reproduction_steps=(
            "1. Locate Cipher.getInstance(\"AES/ECB/...\") in decompiled source.\n"
            "2. Encrypt a plaintext containing a repeated 16-byte block.\n"
            "3. Observe identical repeating blocks in the ciphertext output."
        ),
        recommendation=(
            "Use an authenticated mode: AES/GCM/NoPadding with a unique random 12-byte IV per "
            "operation. Never reuse an IV with the same key. Prefer a vetted wrapper such as "
            "Jetpack Security or Google Tink over hand-rolled Cipher usage."
        ),
        cwe_id="CWE-327",
        cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
        cvss_score=5.0,
        references=[_MASTG + "tests/android/MASVS-CRYPTO/MASTG-TEST-0014/"],
    ),
    "crypto.weak_hash": FindingKnowledge(
        impact=(
            "MD5 and SHA-1 are not collision resistant. Where used for integrity or signature "
            "verification, an attacker can craft a colliding input that passes validation. Where "
            "used for password storage, the speed of these algorithms makes offline cracking of a "
            "leaked hash trivial."
        ),
        reproduction_steps=(
            "1. Locate MessageDigest.getInstance(\"MD5\"|\"SHA-1\") in decompiled source.\n"
            "2. Determine the security purpose of the digest at each call site.\n"
            "3. Non-security uses (cache keys, checksums) are acceptable; document and dismiss them."
        ),
        recommendation=(
            "Use SHA-256 or SHA-3 for integrity and signatures. For password or key derivation, use "
            "a purpose-built KDF -- Argon2id, scrypt, or PBKDF2 with a high iteration count and a "
            "per-user salt -- never a bare cryptographic hash."
        ),
        cwe_id="CWE-328",
        references=[_MASTG + "tests/android/MASVS-CRYPTO/MASTG-TEST-0014/"],
    ),

    # ------------------------------------------------------------------ #
    # Secrets / storage
    # ------------------------------------------------------------------ #
    "secrets.hardcoded_credential": FindingKnowledge(
        impact=(
            "A credential shipped inside the APK is available to every user of the app -- it can be "
            "recovered in minutes with standard tooling and cannot be rotated without shipping a "
            "new release. Depending on scope, this grants direct access to backend APIs, cloud "
            "storage, or third-party services billed to the vendor."
        ),
        reproduction_steps=(
            "1. Decompile:  jadx -d out/ target.apk\n"
            "2. Search source and resources:\n"
            "   grep -rniE '(api[_-]?key|secret|token|password)\\s*[:=]' out/\n"
            "3. Extract the candidate value and confirm it authenticates against the live service.\n"
            "4. Record the scope of access granted."
        ),
        recommendation=(
            "Treat the exposed credential as compromised and rotate it immediately -- removal from "
            "source alone does not undo exposure in already-released builds. Move secrets "
            "server-side and have the app obtain short-lived, scoped tokens at runtime after "
            "authenticating. Add automated secret scanning to CI to prevent recurrence."
        ),
        cwe_id="CWE-798",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        references=[_MASTG + "tests/android/MASVS-STORAGE/MASTG-TEST-0011/"],
    ),
    "storage.world_accessible_file": FindingKnowledge(
        impact=(
            "World-readable or world-writable files can be read or tampered with by any other app "
            "on the device. Writable files are the more serious case: an attacker-controlled file "
            "that the app later parses or trusts can drive application logic."
        ),
        reproduction_steps=(
            "1. Locate MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE usage in decompiled source.\n"
            "2. Inspect permissions on device:  adb shell run-as <package> ls -l files/\n"
            "3. Confirm the mode bits allow other-user access."
        ),
        recommendation=(
            "Use MODE_PRIVATE for all app files. Where data genuinely must be shared with another "
            "app, expose it through a FileProvider with per-URI grants rather than loosening "
            "filesystem permissions."
        ),
        cwe_id="CWE-732",
        references=[_MASTG + "tests/android/MASVS-STORAGE/MASTG-TEST-0001/"],
    ),
    "logging.sensitive_data": FindingKnowledge(
        impact=(
            "Data written to logcat persists in system logs and can be read by crash-reporting SDKs "
            "and, on older Android versions or rooted devices, by other applications. Credentials "
            "or tokens logged in production are recoverable long after the session ends."
        ),
        reproduction_steps=(
            "1. Locate Log.* calls referencing credential-like variables in decompiled source.\n"
            "2. Capture live logs:  adb logcat -v brief | grep -iE 'password|token|secret'\n"
            "3. Exercise the relevant flow (e.g. login) and confirm values appear in the output."
        ),
        recommendation=(
            "Remove sensitive values from log statements. Strip or no-op debug logging in release "
            "builds via a ProGuard/R8 rule so it cannot be re-enabled at runtime, and route any "
            "required diagnostics through a logger that redacts known-sensitive keys."
        ),
        cwe_id="CWE-532",
        references=[_MASTG + "tests/android/MASVS-STORAGE/MASTG-TEST-0003/"],
    ),

    # ------------------------------------------------------------------ #
    # WebView / platform interaction
    # ------------------------------------------------------------------ #
    "webview.js_bridge_exposed": FindingKnowledge(
        impact=(
            "addJavascriptInterface exposes native Java methods to any JavaScript the WebView "
            "loads. If the WebView can be made to load attacker-controlled content -- via a "
            "redirect, an unvalidated deep link, or MITM on a cleartext resource -- that attacker "
            "gains the ability to call into native code with the app's permissions."
        ),
        reproduction_steps=(
            "1. Identify setJavaScriptEnabled(true) together with addJavascriptInterface().\n"
            "2. Determine whether any loaded URL is externally influenceable (deep link, redirect).\n"
            "3. Load a test page invoking the bridge object and confirm the native method executes."
        ),
        recommendation=(
            "Remove the bridge if it isn't required. If it is, annotate exposed methods with "
            "@JavascriptInterface (API 17+), restrict the WebView to an allowlist of trusted "
            "origins via shouldOverrideUrlLoading, and validate every parameter crossing the "
            "boundary as untrusted input."
        ),
        cwe_id="CWE-749",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=7.3,
        references=[_MASTG + "tests/android/MASVS-PLATFORM/MASTG-TEST-0031/"],
    ),
    "webview.ssl_error_bypass": FindingKnowledge(
        impact=(
            "Calling handler.proceed() in onReceivedSslError makes the WebView load pages despite "
            "invalid, expired, or attacker-supplied certificates -- removing TLS protection for all "
            "web content in the app, including any embedded login or payment flow."
        ),
        reproduction_steps=(
            "1. Locate onReceivedSslError with a proceed() call in decompiled source.\n"
            "2. Proxy the device with an untrusted self-signed CA.\n"
            "3. Open a WebView-backed screen; content loads without a certificate warning."
        ),
        recommendation=(
            "Call handler.cancel() and surface the error to the user. Never proceed past a "
            "certificate error in a release build; if a private CA is needed for internal "
            "environments, add it to the network security config instead."
        ),
        cwe_id="CWE-295",
        cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=7.4,
        references=[_MASTG + "tests/android/MASVS-NETWORK/MASTG-TEST-0021/"],
    ),

    # ------------------------------------------------------------------ #
    # Code signing
    # ------------------------------------------------------------------ #
    "signing.debug_certificate": FindingKnowledge(
        impact=(
            "The Android debug keystore is a well-known, publicly distributed key. Anyone can sign "
            "a modified build with the same certificate, so the platform's signature check will "
            "accept a tampered APK as a legitimate update. Signature-level permissions and any "
            "signature-based integrity check are equally defeated."
        ),
        reproduction_steps=(
            "1. apksigner verify --print-certs target.apk\n"
            "2. Confirm the subject reads CN=Android Debug, O=Android, C=US.\n"
            "3. Re-sign a modified APK with the standard debug keystore and confirm it installs "
            "over the original."
        ),
        recommendation=(
            "Sign release builds with a private release key stored in a secure keystore or HSM, and "
            "enrol in Play App Signing. Ensure CI never falls back to the debug keystore for a "
            "release variant."
        ),
        cwe_id="CWE-321",
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=6.4,
        references=["https://developer.android.com/studio/publish/app-signing"],
    ),
    "signing.weak_algorithm": FindingKnowledge(
        impact=(
            "A signature over a SHA-1 digest, or a 1024-bit RSA key, no longer provides meaningful "
            "forgery resistance against a well-resourced attacker. This weakens the guarantee that "
            "an installed update genuinely originated from the vendor."
        ),
        reproduction_steps=(
            "1. apksigner verify --print-certs -v target.apk\n"
            "2. Inspect the signature algorithm and public key size in the output.\n"
            "3. Confirm whether v2/v3 signature schemes are present alongside v1."
        ),
        recommendation=(
            "Re-sign with SHA-256 or stronger over a minimum 2048-bit RSA (or 256-bit EC) key, and "
            "enable APK Signature Scheme v2/v3, which sign the whole archive rather than "
            "per-entry digests."
        ),
        cwe_id="CWE-327",
        references=["https://source.android.com/docs/security/features/apksigning"],
    ),
}


def get_knowledge(finding_key: str | None) -> FindingKnowledge | None:
    """Look up guidance for a finding key. Unknown/None keys return None (caller keeps plugin values)."""
    if not finding_key:
        return None
    return KNOWLEDGE_BASE.get(finding_key)


def known_keys() -> list[str]:
    return sorted(KNOWLEDGE_BASE)
