"""
Tests for tracker_registry pure functions (Module 13b).
"""

from __future__ import annotations

from app.plugins.installed.tracker_detection.tracker_registry import KNOWN_TRACKERS, detect_trackers


def test_detects_firebase_analytics(tmp_path):
    sources = tmp_path / "sources"
    (sources / "com" / "google" / "firebase" / "analytics").mkdir(parents=True)
    detected = detect_trackers(sources)
    names = {name for _, name, _ in detected}
    assert "Firebase Analytics" in names


def test_detects_multiple_trackers(tmp_path):
    sources = tmp_path / "sources"
    (sources / "com" / "facebook" / "ads").mkdir(parents=True)
    (sources / "com" / "appsflyer").mkdir(parents=True)
    (sources / "com" / "example" / "myapp").mkdir(parents=True)  # not a tracker, must not match

    detected = detect_trackers(sources)
    names = {name for _, name, _ in detected}
    assert "Facebook Audience Network" in names
    assert "AppsFlyer" in names
    assert len(detected) == 2


def test_no_trackers_in_clean_app(tmp_path):
    sources = tmp_path / "sources"
    (sources / "com" / "example" / "cleanapp" / "ui").mkdir(parents=True)
    (sources / "com" / "example" / "cleanapp" / "data").mkdir(parents=True)
    assert detect_trackers(sources) == []


def test_results_sorted_by_display_name(tmp_path):
    sources = tmp_path / "sources"
    (sources / "com" / "vungle").mkdir(parents=True)
    (sources / "com" / "appsflyer").mkdir(parents=True)
    (sources / "com" / "amplitude").mkdir(parents=True)

    detected = detect_trackers(sources)
    names = [name for _, name, _ in detected]
    assert names == sorted(names)


def test_returns_package_path_and_category_correctly(tmp_path):
    sources = tmp_path / "sources"
    (sources / "com" / "onesignal").mkdir(parents=True)
    detected = detect_trackers(sources)
    assert detected == [("com/onesignal", "OneSignal", "Push Notifications")]


def test_registry_is_nonempty_and_well_formed():
    assert len(KNOWN_TRACKERS) > 10
    for pkg_path, (name, category) in KNOWN_TRACKERS.items():
        assert "/" in pkg_path
        assert name and category
