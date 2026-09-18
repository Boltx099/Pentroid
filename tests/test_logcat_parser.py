"""
Tests for logcat_parser pure functions (Module 17a).
"""

from __future__ import annotations

from app.plugins.installed.logcat_capture.logcat_parser import (
    find_secrets_in_lines, is_crash_line, parse_logcat_line,
)


def test_parses_real_brief_format_line():
    line = parse_logcat_line("I/ActivityManager( 1234): Displaying com.example.app/.MainActivity")
    assert line is not None
    assert line.priority == "INFO"
    assert line.tag == "ActivityManager"
    assert line.pid == 1234
    assert "Displaying" in line.message


def test_parses_error_priority_line():
    line = parse_logcat_line("E/AndroidRuntime(5678): FATAL EXCEPTION: main")
    assert line.priority == "ERROR"
    assert line.tag == "AndroidRuntime"


def test_returns_none_for_non_matching_line():
    assert parse_logcat_line("--------- beginning of main") is None
    assert parse_logcat_line("") is None


def test_is_crash_line_detects_android_runtime_error():
    line = parse_logcat_line("E/AndroidRuntime(5678): FATAL EXCEPTION: main")
    assert is_crash_line(line) is True


def test_is_crash_line_detects_stack_frame():
    line = parse_logcat_line("E/AndroidRuntime(5678):     at com.example.app.MainActivity.onCreate(MainActivity.java:42)")
    assert is_crash_line(line) is True


def test_is_crash_line_false_for_ordinary_info_line():
    line = parse_logcat_line("I/ActivityManager( 1234): Displaying com.example.app/.MainActivity")
    assert is_crash_line(line) is False


def test_find_secrets_in_lines_detects_real_secret():
    lines = [
        parse_logcat_line('D/ApiClient(1234): Using key AKIAIOSFODNN7EXAMPLE for request'),
        parse_logcat_line("I/ActivityManager( 1234): Displaying com.example.app/.MainActivity"),
    ]
    hits = find_secrets_in_lines(lines)
    assert len(hits) == 1
    assert hits[0][1] == "AWS Access Key ID"


def test_find_secrets_in_lines_empty_for_clean_logs():
    lines = [parse_logcat_line("I/ActivityManager( 1234): Displaying com.example.app/.MainActivity")]
    assert find_secrets_in_lines(lines) == []
