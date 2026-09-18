/*
 * Pentroid runtime instrumentation hooks.
 *
 * Standard, widely-published Android pentesting techniques (OWASP
 * MASTG dynamic testing chapter covers all of these): hooking
 * TrustManager/HostnameVerifier to observe and bypass certificate
 * pinning, and hooking common root/emulator-detection checks to
 * observe when an app queries them. This is instrumentation of an
 * app under test on a device the tester controls -- not an attack on
 * any remote system.
 *
 * Every hook reports back to the Python side via send() so the
 * plugin can turn "this hook fired" into a Finding; it does not
 * silently modify behavior without telling the analyst what happened.
 */

Java.perform(function () {

    // ---------------------------------------------------------------- //
    // SSL/TLS pinning: observe + bypass custom TrustManager verification
    // ---------------------------------------------------------------- //
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManagerImpl = Java.registerClass({
            name: "com.pentroid.dynamic.PinningBypassTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    send({ hook: "ssl_pinning", event: "checkServerTrusted_called_bypassed" });
                },
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });

        var SSLContext_init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
        );
        SSLContext_init.implementation = function (keyManagers, trustManagers, secureRandom) {
            send({ hook: "ssl_pinning", event: "SSLContext.init_intercepted" });
            var bypassTrustManagers = [TrustManagerImpl.$new()];
            return SSLContext_init.call(this, keyManagers, bypassTrustManagers, secureRandom);
        };
    } catch (e) {
        send({ hook: "ssl_pinning", event: "hook_error", error: e.toString() });
    }

    // ---------------------------------------------------------------- //
    // OkHttp3 CertificatePinner: many apps use this instead of a custom
    // TrustManager -- observe and neutralize independently.
    // ---------------------------------------------------------------- //
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, list) {
            send({ hook: "ssl_pinning", event: "OkHttp_CertificatePinner_check_bypassed", hostname: hostname });
        };
    } catch (e) {
        // OkHttp not present in this app -- not an error, just not applicable.
    }

    // ---------------------------------------------------------------- //
    // Root detection: observe common checks without necessarily
    // guaranteeing a bypass (root-check implementations vary widely) --
    // the point here is visibility into what the app queries at runtime.
    // ---------------------------------------------------------------- //
    try {
        var FileClass = Java.use("java.io.File");
        var SU_PATHS = [
            "/system/xbin/su", "/system/bin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/xbin/su", "/data/local/bin/su",
        ];
        FileClass.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (SU_PATHS.indexOf(path) !== -1) {
                send({ hook: "root_detection", event: "su_path_check", path: path });
                return false;
            }
            return this.exists.call(this);
        };
    } catch (e) {
        send({ hook: "root_detection", event: "hook_error", error: e.toString() });
    }

    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            send({ hook: "anti_debug", event: "isDebuggerConnected_called" });
            return false;
        };
    } catch (e) {
        // Not present/not called -- fine.
    }

    send({ hook: "instrumentation", event: "hooks_installed" });
});
