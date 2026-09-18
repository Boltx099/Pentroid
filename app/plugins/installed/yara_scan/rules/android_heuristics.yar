/*
 * Pentroid Android static heuristic rules.
 *
 * Original rules targeting well-documented Android API strings
 * associated with common malware behavior categories (dynamic code
 * loading, SMS abuse, overlay/accessibility abuse for banking-trojan
 * style credential phishing, anti-analysis evasion checks). These are
 * NOT derived from any existing tool's rule set.
 *
 * Honest scope: this is a modest starter set covering well-known
 * indicator categories, validated only against synthetic test strings
 * (no real malware corpus was used or is appropriate to use here).
 * It will not catch novel or heavily obfuscated malware -- treat hits
 * as investigative leads, not confirmed verdicts, same as any single
 * static heuristic layer in a larger analysis pipeline.
 */

rule Android_Dynamic_Code_Loading
{
    meta:
        description = "APIs used to load additional DEX code at runtime -- common for payload staging or evading static analysis of the initial APK"
        severity = "medium"
        category = "Evasion / Payload Staging"
    strings:
        $a1 = "DexClassLoader" ascii
        $a2 = "dalvik/system/DexClassLoader" ascii
        $a3 = "loadDex" ascii
        $a4 = "dalvik/system/PathClassLoader" ascii
    condition:
        any of ($a*)
}

rule Android_SMS_Abuse_APIs
{
    meta:
        description = "APIs for sending/intercepting SMS without user interaction -- common in SMS-fraud and OTP-interception malware"
        severity = "medium"
        category = "SMS Abuse"
    strings:
        $a1 = "sendTextMessage" ascii
        $a2 = "android/telephony/SmsManager" ascii
        $a3 = "SMS_RECEIVED" ascii
    condition:
        2 of ($a*)
}

rule Android_Overlay_Accessibility_Abuse
{
    meta:
        description = "Combination of screen-overlay (SYSTEM_ALERT_WINDOW) and Accessibility Service APIs -- the classic banking-trojan pattern for credential-phishing overlays and auto-granting permissions"
        severity = "high"
        category = "Overlay / Accessibility Abuse"
    strings:
        $overlay = "SYSTEM_ALERT_WINDOW" ascii
        $accessibility1 = "accessibilityservice" ascii
        $accessibility2 = "TYPE_ACCESSIBILITY_SERVICE" ascii
        $accessibility3 = "isAccessibilityServiceEnabled" ascii
    condition:
        $overlay and 1 of ($accessibility*)
}

rule Android_AntiAnalysis_Evasion_Checks
{
    meta:
        description = "Strings indicating checks for analysis/instrumentation tooling (Frida, Xposed, Magisk, su binary) -- often added by malware to detect and evade dynamic analysis"
        severity = "low"
        category = "Anti-Analysis"
    strings:
        $frida1 = "frida-server" ascii
        $frida2 = "gum-js-loop" ascii
        $xposed = "de.robv.android.xposed" ascii
        $magisk = "com.topjohnwu.magisk" ascii
        $su_check = "/system/xbin/su" ascii
    condition:
        any of them
}

rule Android_Suspicious_Permission_Combo
{
    meta:
        description = "Manifest permission strings commonly requested together by Android banking trojans and spyware (SMS interception + overlay + accessibility)"
        severity = "medium"
        category = "Suspicious Permission Combination"
    strings:
        $p1 = "android.permission.RECEIVE_SMS" ascii
        $p2 = "android.permission.READ_SMS" ascii
        $p3 = "android.permission.SYSTEM_ALERT_WINDOW" ascii
        $p4 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii
    condition:
        2 of ($p*)
}
