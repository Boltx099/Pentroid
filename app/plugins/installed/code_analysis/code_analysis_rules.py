"""
app.plugins.installed.code_analysis.code_analysis_rules
===========================================================

Pure, regex-based detection of well-established insecure Android
coding patterns in decompiled Java/Kotlin source. These check
categories (insecure crypto modes, WebView JS-bridge exposure,
TrustManager/HostnameVerifier certificate-validation bypass, insecure
file permissions, sensitive-data logging, cleartext URLs) are
documented, public Android security guidance (OWASP MASTG, Android's
own security best-practices docs) -- this is original detection logic
for those well-known issue classes, not ported from any specific
existing tool's source.

Separated from ``plugin.py`` so every rule can be unit tested directly
against hand-written source fixtures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MAX_MATCHES_PER_RULE = 10

# XML namespace URLs that legitimately start with http:// and would
# otherwise flood the cleartext-URL check with noise.
_HTTP_NAMESPACE_ALLOWLIST = ("schemas.android.com", "www.w3.org", "xmlpull.org", "schemas.xmlsoap.org")


@dataclass(frozen=True)
class CodeFinding:
    rule_name: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    masvs_mapping: str
    line_number: int
    snippet: str
    description: str
    recommendation: str
    # Optional key into the central knowledge base (app.core.knowledge.finding_kb);
    # defaulted last so it stays a non-breaking addition to existing call sites.
    finding_key: str | None = None


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _truncate(s: str, length: int = 100) -> str:
    s = s.strip().replace("\n", " ")
    return s if len(s) <= length else s[: length - 3] + "..."


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_comments(s: str) -> str:
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", s))


def _method_body_after(text: str, search_from: int, max_signature_gap: int = 200) -> str | None:
    """
    Find the next ``{`` after ``search_from`` (the end of a method signature
    match) and return the *full* balanced body between it and its matching
    ``}`` -- however many braces are nested inside (if-blocks, lambdas,
    anonymous inner classes, ...).

    This replaces a family of checks that used to span a method body with a
    single regex like ``\\{[^{}]*?return true;[^{}]*?\\}``. That works only
    when the body contains zero nested braces: a single guard clause around
    a log statement -- `if (BuildConfig.DEBUG) { Log.d(...); } return true;`,
    extremely common in real bypass code -- introduces a nested `{}` that the
    non-greedy `[^{}]*?` cannot span, so the whole match silently fails and
    the finding is missed. Extracting the real body via brace-depth counting
    has no such limit; callers then search *within* the returned body with an
    ordinary regex, which doesn't need to know about nesting at all.

    Returns None if no ``{`` is found within ``max_signature_gap`` characters
    (this signature likely has no body on this line -- an interface/abstract
    declaration, or a match on unrelated text) or if the braces never
    balance (truncated/malformed source).
    """
    brace_pos = text.find("{", search_from)
    if brace_pos == -1 or brace_pos - search_from > max_signature_gap:
        return None
    depth = 0
    body_start = None
    for i in range(brace_pos, len(text)):
        ch = text[i]
        if ch == "{":
            if depth == 0:
                body_start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[body_start:i]
    return None  # unbalanced -- truncated/malformed source, don't guess


def check_insecure_crypto_ecb(text: str) -> list[CodeFinding]:
    findings = []
    for m in list(re.finditer(r'Cipher\.getInstance\(\s*"([^"]*?/ECB[^"]*)"\s*\)', text))[:_MAX_MATCHES_PER_RULE]:
        findings.append(CodeFinding(
            rule_name="Insecure Crypto Mode (ECB)", finding_key="crypto.ecb_mode", severity="high", masvs_mapping="MASVS-CRYPTO",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description=f'ECB is a deterministic block cipher mode ("{m.group(1)}") that leaks plaintext '
                        "patterns and provides no semantic security.",
            recommendation="Use an authenticated mode such as AES/GCM/NoPadding with a random IV/nonce per encryption.",
        ))
    return findings


def check_weak_hash_algorithm(text: str) -> list[CodeFinding]:
    findings = []
    for m in list(re.finditer(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-1|SHA1)"\s*\)', text, re.IGNORECASE))[:_MAX_MATCHES_PER_RULE]:
        findings.append(CodeFinding(
            rule_name="Weak Hash Algorithm", finding_key="crypto.weak_hash", severity="medium", masvs_mapping="MASVS-CRYPTO",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description=f'"{m.group(1)}" is cryptographically broken/weak for security-sensitive hashing '
                        "(collision resistance). May be acceptable for non-security checksums -- verify usage context.",
            recommendation="Use SHA-256 or stronger for any security-relevant hashing (integrity, signatures, password storage via a KDF).",
        ))
    return findings


def check_insecure_random(text: str) -> list[CodeFinding]:
    findings = []
    for m in list(re.finditer(r'\bnew\s+Random\s*\(\s*\)', text))[:_MAX_MATCHES_PER_RULE]:
        findings.append(CodeFinding(
            rule_name="Non-Cryptographic Random", severity="low", masvs_mapping="MASVS-CRYPTO",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description="java.util.Random is not cryptographically secure. Flagged for review -- "
                        "only a real issue if this value is used for tokens, keys, or other security purposes.",
            recommendation="If used for anything security-sensitive, replace with java.security.SecureRandom.",
        ))
    return findings


def check_webview_js_bridge_exposure(text: str) -> list[CodeFinding]:
    if not re.search(r'setJavaScriptEnabled\s*\(\s*true\s*\)', text):
        return []
    matches = list(re.finditer(r'addJavascriptInterface\s*\(', text))[:_MAX_MATCHES_PER_RULE]
    return [
        CodeFinding(
            rule_name="WebView JavaScript Bridge Exposed", finding_key="webview.js_bridge_exposed", severity="high", masvs_mapping="MASVS-PLATFORM",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description="setJavaScriptEnabled(true) is combined with addJavascriptInterface() in the same file, "
                        "exposing a native Java object to any JavaScript the WebView loads.",
            recommendation="Avoid addJavascriptInterface with untrusted content, or restrict it to methods "
                            "annotated @JavascriptInterface with strict input validation, on API 17+.",
        )
        for m in matches
    ]


def check_webview_ssl_error_bypass(text: str) -> list[CodeFinding]:
    if not re.search(r'onReceivedSslError', text):
        return []
    matches = list(re.finditer(r'\.proceed\s*\(\s*\)', text))[:_MAX_MATCHES_PER_RULE]
    return [
        CodeFinding(
            rule_name="WebView SSL Error Bypass", finding_key="webview.ssl_error_bypass", severity="high", masvs_mapping="MASVS-NETWORK",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description="onReceivedSslError() is implemented alongside a .proceed() call, which can continue "
                        "loading a page despite an invalid/untrusted TLS certificate.",
            recommendation="Do not call handler.proceed() in onReceivedSslError; cancel the load and surface "
                           "the error to the user instead.",
        )
        for m in matches
    ]


def check_trust_manager_bypass(text: str) -> list[CodeFinding]:
    """
    Flags a ``checkServerTrusted`` whose body is empty (comments aside).

    Body extraction now goes through ``_method_body_after`` (brace-depth
    counting) instead of the old fixed pattern ``\\{\\s*\\}``, which required
    the body to be *literally* nothing but whitespace between the braces.
    That version already worked for the common `{}` case, but missed the
    almost-as-common `{ // trust everyone }` / `{ /* no-op */ }` variant,
    since a comment isn't whitespace. Stripping comments before checking
    for emptiness closes that gap for free, using the same body-extraction
    helper the hostname-verifier check below needs for its own, bigger fix.
    """
    findings = []
    count = 0
    for m in re.finditer(r"checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?", text):
        if count >= _MAX_MATCHES_PER_RULE:
            break
        body = _method_body_after(text, m.end())
        if body is None or _strip_comments(body).strip():
            continue  # no body found here, or the body does real work -- not a bypass
        findings.append(CodeFinding(
            rule_name="TrustManager Does Not Validate Certificates", finding_key="android.trustmanager_bypass", severity="critical", masvs_mapping="MASVS-NETWORK",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0) + " { }"),
            description="checkServerTrusted() has an empty method body (comments only, if any), meaning this "
                        "custom X509TrustManager accepts any certificate chain -- TLS provides no protection "
                        "against MITM.",
            recommendation="Remove the custom TrustManager (use the platform default) or implement real "
                            "chain/hostname validation, ideally with certificate pinning.",
        ))
        count += 1
    return findings


def check_hostname_verifier_bypass(text: str) -> list[CodeFinding]:
    """
    Flags a ``HostnameVerifier.verify()`` where every ``return`` statement in
    the method is a literal ``return true``.

    Previously this matched ``verify(...)\\{[^{}]*?return true;[^{}]*?\\}`` in
    one pass, which -- same root cause as the TrustManager check above --
    requires the *entire* method body to contain no nested braces. Real
    bypass code very often has at least one: a debug-build guard, a log
    call wrapped in an if, a try/catch. Any of those silently defeated the
    old check. Extracting the real balanced body first and then searching
    *within* it for every `return` statement has no such limit, and as a
    side benefit is also less prone to a false positive: a verify() with a
    genuine `return false` branch alongside a `return true` one (i.e. it
    actually does validate something) is correctly left alone, since not
    every return in that body is literally `true`.
    """
    findings = []
    count = 0
    return_re = re.compile(r"\breturn\s+([^;]+?)\s*;")
    for m in re.finditer(r"\bverify\s*\(\s*String\b[^)]*\)", text):
        if count >= _MAX_MATCHES_PER_RULE:
            break
        body = _method_body_after(text, m.end())
        if body is None:
            continue
        returns = [r.strip() for r in return_re.findall(body)]
        if not returns or any(r != "true" for r in returns):
            continue  # no return at all, or at least one real (non-`true`) return path
        findings.append(CodeFinding(
            rule_name="HostnameVerifier Does Not Validate Hostname", severity="high", masvs_mapping="MASVS-NETWORK",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0) + " { ... return true; ... }"),
            description="Every return path in this HostnameVerifier.verify() implementation is a literal "
                        "`return true`, accepting any hostname for the presented TLS certificate.",
            recommendation="Use the platform's default HostnameVerifier, or implement real hostname matching.",
        ))
        count += 1
    return findings


def check_world_readable_writable(text: str) -> list[CodeFinding]:
    findings = []
    for m in list(re.finditer(r'MODE_WORLD_(READABLE|WRITABLE)', text))[:_MAX_MATCHES_PER_RULE]:
        findings.append(CodeFinding(
            rule_name="Insecure File Permissions", finding_key="storage.world_accessible_file", severity="high", masvs_mapping="MASVS-STORAGE",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description=f"MODE_WORLD_{m.group(1)} makes a file readable/writable by any other app on the device "
                        "(deprecated and blocked entirely on modern Android, but indicates a design intent worth reviewing).",
            recommendation="Use MODE_PRIVATE and share data via a properly permission-scoped ContentProvider if needed.",
        ))
    return findings


def check_sensitive_data_logging(text: str) -> list[CodeFinding]:
    findings = []
    pattern = re.compile(r'Log\.[dewiv]\s*\([^;]*?(password|token|secret|api[_-]?key)[^;]*?\)', re.IGNORECASE)
    for m in list(pattern.finditer(text))[:_MAX_MATCHES_PER_RULE]:
        findings.append(CodeFinding(
            rule_name="Sensitive Data Logged", finding_key="logging.sensitive_data", severity="medium", masvs_mapping="MASVS-STORAGE",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description="A Log call includes a variable/string suggesting sensitive data "
                        f"({m.group(1)}), which persists in logcat and device logs.",
            recommendation="Remove sensitive values from log statements, especially in release builds.",
        ))
    return findings


def check_cleartext_http_url(text: str) -> list[CodeFinding]:
    findings = []
    pattern = re.compile(r'"(http://[^"]+)"')
    for m in list(pattern.finditer(text))[:_MAX_MATCHES_PER_RULE]:
        url = m.group(1)
        if any(ns in url for ns in _HTTP_NAMESPACE_ALLOWLIST):
            continue
        findings.append(CodeFinding(
            rule_name="Cleartext HTTP URL", finding_key="android.cleartext_traffic", severity="low", masvs_mapping="MASVS-NETWORK",
            line_number=_line_of(text, m.start()), snippet=_truncate(m.group(0)),
            description=f"Hardcoded cleartext HTTP URL found: {url}",
            recommendation="Use HTTPS for all network endpoints; set android:usesCleartextTraffic=\"false\" "
                           "in the manifest unless a specific domain genuinely requires an exception.",
        ))
    return findings


_ALL_RULES = (
    check_insecure_crypto_ecb,
    check_weak_hash_algorithm,
    check_insecure_random,
    check_webview_js_bridge_exposure,
    check_webview_ssl_error_bypass,
    check_trust_manager_bypass,
    check_hostname_verifier_bypass,
    check_world_readable_writable,
    check_sensitive_data_logging,
    check_cleartext_http_url,
)


def analyze_source(text: str) -> list[CodeFinding]:
    """Run every rule against ``text`` (one source file's contents) and return all findings."""
    findings: list[CodeFinding] = []
    for rule in _ALL_RULES:
        findings.extend(rule(text))
    return findings
