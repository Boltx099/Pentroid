"""
app.plugins.installed.tracker_detection.tracker_registry
============================================================

A curated list of well-known third-party analytics/advertising/
tracking SDK package prefixes -- general public knowledge about
common Android SDKs (the same kind of list Exodus Privacy and similar
tools maintain), written independently here rather than copied from
any single existing tool's data file.

Detection works off JADX's decompiled directory structure directly
(package names become nested folders under ``sources/``), which is
more reliable than regex-scanning file contents for package
declarations -- the folder layout IS the package structure.
"""

from __future__ import annotations

from pathlib import Path

# package-prefix (as a filesystem path under sources/) -> (display name, category)
KNOWN_TRACKERS: dict[str, tuple[str, str]] = {
    "com/google/firebase/analytics": ("Firebase Analytics", "Analytics"),
    "com/google/android/gms/analytics": ("Google Analytics", "Analytics"),
    "com/google/android/gms/tagmanager": ("Google Tag Manager", "Analytics"),
    "com/google/android/gms/ads": ("Google AdMob", "Advertising"),
    "com/facebook/ads": ("Facebook Audience Network", "Advertising"),
    "com/facebook/appevents": ("Facebook App Events", "Analytics"),
    "com/crashlytics": ("Crashlytics", "Crash Reporting"),
    "com/flurry": ("Flurry Analytics", "Analytics"),
    "com/appsflyer": ("AppsFlyer", "Attribution / Analytics"),
    "com/adjust/sdk": ("Adjust", "Attribution / Analytics"),
    "com/mixpanel": ("Mixpanel", "Analytics"),
    "com/amplitude": ("Amplitude", "Analytics"),
    "com/segment/analytics": ("Segment", "Analytics"),
    "com/onesignal": ("OneSignal", "Push Notifications"),
    "com/urbanairship": ("Urban Airship", "Push Notifications / Analytics"),
    "com/startapp": ("StartApp", "Advertising"),
    "com/unity3d/ads": ("Unity Ads", "Advertising"),
    "com/vungle": ("Vungle", "Advertising"),
    "com/applovin": ("AppLovin", "Advertising"),
    "com/chartboost": ("Chartboost", "Advertising"),
    "com/inmobi": ("InMobi", "Advertising"),
    "com/mopub": ("MoPub", "Advertising"),
    "com/tapjoy": ("Tapjoy", "Advertising"),
    "com/ironsource": ("ironSource", "Advertising"),
    "com/kochava": ("Kochava", "Attribution / Analytics"),
    "com/braze": ("Braze", "Marketing / Analytics"),
    "io/branch/referral": ("Branch", "Attribution / Deep Linking"),
    "com/batch/android": ("Batch", "Marketing"),
    "com/leanplum": ("Leanplum", "Marketing / Analytics"),
    "com/clevertap": ("CleverTap", "Marketing / Analytics"),
}


def detect_trackers(sources_root: Path) -> list[tuple[str, str, str]]:
    """
    Check which known tracker package directories exist under
    ``sources_root``. Returns ``(package_prefix, display_name, category)``
    tuples, sorted by display name for stable output ordering.
    """
    found = []
    for pkg_path, (name, category) in KNOWN_TRACKERS.items():
        if (sources_root / pkg_path).is_dir():
            found.append((pkg_path, name, category))
    return sorted(found, key=lambda t: t[1])
