"""
Tests for code_analysis_rules pure functions (Module 11a).
"""

from __future__ import annotations

from app.plugins.installed.code_analysis.code_analysis_rules import analyze_source


def test_detects_ecb_mode():
    text = 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");'
    findings = analyze_source(text)
    assert any(f.rule_name == "Insecure Crypto Mode (ECB)" for f in findings)
    f = next(f for f in findings if f.rule_name == "Insecure Crypto Mode (ECB)")
    assert f.severity == "high"


def test_no_ecb_finding_for_gcm_mode():
    text = 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'
    findings = analyze_source(text)
    assert not any(f.rule_name == "Insecure Crypto Mode (ECB)" for f in findings)


def test_detects_weak_hash_md5():
    text = 'MessageDigest md = MessageDigest.getInstance("MD5");'
    findings = analyze_source(text)
    assert any(f.rule_name == "Weak Hash Algorithm" for f in findings)


def test_detects_weak_hash_sha1():
    text = 'MessageDigest md = MessageDigest.getInstance("SHA-1");'
    findings = analyze_source(text)
    assert any(f.rule_name == "Weak Hash Algorithm" for f in findings)


def test_no_weak_hash_finding_for_sha256():
    text = 'MessageDigest md = MessageDigest.getInstance("SHA-256");'
    findings = analyze_source(text)
    assert not any(f.rule_name == "Weak Hash Algorithm" for f in findings)


def test_detects_insecure_random():
    text = "Random r = new Random();"
    findings = analyze_source(text)
    assert any(f.rule_name == "Non-Cryptographic Random" for f in findings)
    f = next(f for f in findings if f.rule_name == "Non-Cryptographic Random")
    assert f.severity == "low"


def test_no_insecure_random_finding_for_securerandom():
    text = "SecureRandom r = new SecureRandom();"
    findings = analyze_source(text)
    assert not any(f.rule_name == "Non-Cryptographic Random" for f in findings)


def test_detects_webview_js_bridge_exposure_when_both_present():
    text = """
    webView.getSettings().setJavaScriptEnabled(true);
    webView.addJavascriptInterface(new JsBridge(), "Android");
    """
    findings = analyze_source(text)
    assert any(f.rule_name == "WebView JavaScript Bridge Exposed" for f in findings)


def test_no_webview_finding_when_js_disabled():
    text = 'webView.addJavascriptInterface(new JsBridge(), "Android");'  # no setJavaScriptEnabled(true) anywhere
    findings = analyze_source(text)
    assert not any(f.rule_name == "WebView JavaScript Bridge Exposed" for f in findings)


def test_detects_webview_ssl_bypass_when_both_present():
    text = """
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed();
    }
    """
    findings = analyze_source(text)
    assert any(f.rule_name == "WebView SSL Error Bypass" for f in findings)


def test_no_ssl_bypass_finding_when_cancelled_instead():
    text = """
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.cancel();
    }
    """
    findings = analyze_source(text)
    assert not any(f.rule_name == "WebView SSL Error Bypass" for f in findings)


def test_detects_trust_manager_bypass_empty_body():
    text = """
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }
    """
    findings = analyze_source(text)
    assert any(f.rule_name == "TrustManager Does Not Validate Certificates" for f in findings)
    f = next(f for f in findings if f.rule_name == "TrustManager Does Not Validate Certificates")
    assert f.severity == "critical"


def test_no_trust_manager_finding_with_real_validation_body():
    text = """
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        defaultTrustManager.checkServerTrusted(chain, authType);
    }
    """
    findings = analyze_source(text)
    assert not any(f.rule_name == "TrustManager Does Not Validate Certificates" for f in findings)


def test_detects_hostname_verifier_bypass():
    text = """
    HostnameVerifier verifier = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };
    """
    findings = analyze_source(text)
    assert any(f.rule_name == "HostnameVerifier Does Not Validate Hostname" for f in findings)


def test_detects_hostname_verifier_bypass_with_nested_braces():
    """
    Regression test for the false-negative fixed in check_hostname_verifier_bypass:
    the old pattern `\\{[^{}]*?return true;[^{}]*?\\}` couldn't span a body
    containing any nested `{}`, so a debug-log guard around the bypass --
    extremely common in real code -- made the whole check silently miss it.
    """
    text = """
    public boolean verify(String hostname, SSLSession session) {
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "bypassing hostname verification for " + hostname);
        }
        return true;
    }
    """
    findings = analyze_source(text)
    assert any(f.rule_name == "HostnameVerifier Does Not Validate Hostname" for f in findings)


def test_no_hostname_verifier_finding_with_real_validation_branch():
    """
    A verify() with a genuine conditional -- some inputs return false -- must
    not be flagged. The old regex's non-greedy span made this an unlikely
    match anyway (nested braces broke it either way); the new check makes the
    "only real code, not a bypass" case an explicit, intentional pass rather
    than an accidental one.
    """
    text = """
    public boolean verify(String hostname, SSLSession session) {
        if (hostname.equals(expectedHost)) {
            return true;
        }
        return false;
    }
    """
    findings = analyze_source(text)
    assert not any(f.rule_name == "HostnameVerifier Does Not Validate Hostname" for f in findings)


def test_detects_trust_manager_bypass_comment_only_body():
    """
    Regression test: the old pattern `\\{\\s*\\}` required the body to be
    literally nothing but whitespace, so a body containing only a comment
    (`{ // trust everyone }`) was missed even though it's an equally
    empty/no-op implementation.
    """
    text = """
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // trust everyone, ship it
    }
    """
    findings = analyze_source(text)
    assert any(f.rule_name == "TrustManager Does Not Validate Certificates" for f in findings)


def test_detects_world_readable():
    text = 'openFileOutput("data.txt", Context.MODE_WORLD_READABLE);'
    findings = analyze_source(text)
    assert any(f.rule_name == "Insecure File Permissions" for f in findings)


def test_detects_sensitive_data_logging():
    text = 'Log.d("Auth", "User password is " + password);'
    findings = analyze_source(text)
    assert any(f.rule_name == "Sensitive Data Logged" for f in findings)


def test_no_sensitive_logging_finding_for_clean_log():
    text = 'Log.d("MainActivity", "onCreate called");'
    findings = analyze_source(text)
    assert not any(f.rule_name == "Sensitive Data Logged" for f in findings)


def test_detects_cleartext_http_url():
    text = 'String url = "http://api.example.com/login";'
    findings = analyze_source(text)
    assert any(f.rule_name == "Cleartext HTTP URL" for f in findings)


def test_no_cleartext_finding_for_https():
    text = 'String url = "https://api.example.com/login";'
    findings = analyze_source(text)
    assert not any(f.rule_name == "Cleartext HTTP URL" for f in findings)


def test_no_cleartext_finding_for_xml_namespace_false_positive():
    text = 'xmlns:android="http://schemas.android.com/apk/res/android"'
    findings = analyze_source(text)
    assert not any(f.rule_name == "Cleartext HTTP URL" for f in findings)


def test_clean_file_produces_no_findings():
    text = """
    public class MainActivity extends AppCompatActivity {
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
        }
    }
    """
    assert analyze_source(text) == []


def test_multiple_issues_in_one_file_all_detected():
    text = """
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    MessageDigest md = MessageDigest.getInstance("MD5");
    String url = "http://insecure.example.com";
    """
    findings = analyze_source(text)
    rule_names = {f.rule_name for f in findings}
    assert "Insecure Crypto Mode (ECB)" in rule_names
    assert "Weak Hash Algorithm" in rule_names
    assert "Cleartext HTTP URL" in rule_names


def test_line_numbers_correct():
    text = 'line one\nline two\nCipher.getInstance("AES/ECB/PKCS5Padding");\nline four'
    findings = analyze_source(text)
    ecb = next(f for f in findings if f.rule_name == "Insecure Crypto Mode (ECB)")
    assert ecb.line_number == 3
