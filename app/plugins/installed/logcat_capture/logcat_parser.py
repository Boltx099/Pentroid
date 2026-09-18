"""
app.plugins.installed.logcat_capture.logcat_parser
======================================================

Pure parsing of ``adb logcat -v brief`` output lines (format:
``PRIORITY/Tag(PID): message``, Android's own documented brief format)
plus crash/exception and runtime-secret detection.

Runtime secret detection reuses ``secrets_detection``'s pattern
matcher directly rather than reimplementing it -- an API key logged at
runtime is the same category of problem whether found in decompiled
source or in a live log line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.plugins.installed.secrets_detection.secret_patterns import scan_text

_LOGCAT_LINE_RE = re.compile(r"^([VDIWEF])/(.+?)\(\s*(\d+)\):\s*(.*)$")
_PRIORITY_NAMES = {"V": "VERBOSE", "D": "DEBUG", "I": "INFO", "W": "WARN", "E": "ERROR", "F": "FATAL"}

_CRASH_TAGS = {"AndroidRuntime"}
_STACK_FRAME_RE = re.compile(r"^\s*at\s+[\w.$]+\(")


@dataclass(frozen=True)
class LogcatLine:
    priority: str
    tag: str
    pid: int
    message: str


def parse_logcat_line(raw_line: str) -> LogcatLine | None:
    """Parse one line of `adb logcat -v brief` output. Returns None for lines that don't match (headers, blanks)."""
    match = _LOGCAT_LINE_RE.match(raw_line.rstrip("\n"))
    if not match:
        return None
    priority, tag, pid, message = match.groups()
    return LogcatLine(priority=_PRIORITY_NAMES.get(priority, priority), tag=tag.strip(), pid=int(pid), message=message)


def is_crash_line(line: LogcatLine) -> bool:
    """True for a fatal-exception header line or a Java/Kotlin stack frame line."""
    if line.tag in _CRASH_TAGS and line.priority == "ERROR":
        return True
    return bool(_STACK_FRAME_RE.match(line.message))


def find_secrets_in_lines(lines: list[LogcatLine]) -> list[tuple[LogcatLine, str]]:
    """Returns (line, pattern_name) pairs for any logged content matching a known secret pattern."""
    findings = []
    for line in lines:
        for match in scan_text(line.message):
            findings.append((line, match.pattern_name))
    return findings
