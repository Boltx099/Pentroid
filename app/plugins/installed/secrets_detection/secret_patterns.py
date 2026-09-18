"""
app.plugins.installed.secrets_detection.secret_patterns
===========================================================

Pure regex-based secret detection, separated from ``plugin.py`` for
direct unit testing against text fixtures without needing real
decompiled output.

These are the same well-established public patterns tools like
TruffleHog, Gitleaks, and MobSF use (AWS key ID format, Google API
key format, PEM private key headers, JWT structure, generic
key/token/password variable-assignment heuristics) -- standard
defensive secret-scanning, not anything novel or sensitive.

Matched values are redacted before being stored anywhere (Finding
rows may end up in shared reports) -- this module never returns a
usable, complete secret value.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class _SecretPattern:
    name: str
    regex: re.Pattern
    severity: str  # "critical" | "high" | "medium"
    masvs_mapping: str


_PATTERNS: list[_SecretPattern] = [
    _SecretPattern(
        "AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"),
        "critical", "MASVS-STORAGE",
    ),
    _SecretPattern(
        "Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "high", "MASVS-STORAGE",
    ),
    _SecretPattern(
        "Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
        "high", "MASVS-STORAGE",
    ),
    _SecretPattern(
        "Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical", "MASVS-CRYPTO",
    ),
    _SecretPattern(
        "JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "medium", "MASVS-STORAGE",
    ),
    _SecretPattern(
        "Hardcoded Password",
        re.compile(r'(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*"([^"]{4,})"'),
        "high", "MASVS-STORAGE",
    ),
    _SecretPattern(
        "Hardcoded API Key/Secret/Token",
        re.compile(r'(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*"([a-zA-Z0-9_\-]{12,})"'),
        "medium", "MASVS-STORAGE",
    ),
]

_MAX_MATCHES_PER_PATTERN = 20


@dataclass(frozen=True)
class SecretMatch:
    pattern_name: str
    severity: str
    masvs_mapping: str
    line_number: int
    redacted_snippet: str


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


# Entropy-based detection catches secrets that don't match any known
# prefix/format pattern above -- the "unknown shape" case pattern-matching
# alone always misses. Deliberately lower-confidence (INFO/LOW severity,
# distinct pattern names) than the known-format matches above, same as
# how truffleHog/gitleaks treat entropy hits: a signal worth a human
# glance, not a confirmed finding.
_ENTROPY_MIN_LENGTH = 20
_ENTROPY_BASE64_THRESHOLD = 4.5
_ENTROPY_HEX_THRESHOLD = 3.0
_MAX_ENTROPY_MATCHES = 10

_QUOTED_CANDIDATE_RE = re.compile(r'"([A-Za-z0-9+/=_\-]{%d,})"' % _ENTROPY_MIN_LENGTH)
_HEX_SHAPE_RE = re.compile(r'^[0-9a-fA-F]+$')
_BASE64_SHAPE_RE = re.compile(r'^[A-Za-z0-9+/]+=*$')


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Higher = more random-looking (secrets, keys, hashes)."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def find_high_entropy_strings(text: str) -> list[SecretMatch]:
    """
    Scan quoted string literals for high-entropy hex/base64-shaped
    values that don't match any known secret format. Capped and
    lower-severity by design -- see module-level comment above.
    """
    matches: list[SecretMatch] = []
    for m in _QUOTED_CANDIDATE_RE.finditer(text):
        if len(matches) >= _MAX_ENTROPY_MATCHES:
            break
        value = m.group(1)

        if _HEX_SHAPE_RE.match(value) and len(value) >= 32:
            entropy = shannon_entropy(value.lower())
            # A hex string uses at most 16 symbols, so cap entropy expectations accordingly;
            # also require a healthy spread of distinct characters to avoid flagging repeats.
            if entropy >= _ENTROPY_HEX_THRESHOLD and len(set(value.lower())) >= 10:
                matches.append(SecretMatch(
                    pattern_name="High-Entropy Hex String (possible secret)",
                    severity="low", masvs_mapping="MASVS-STORAGE",
                    line_number=text.count("\n", 0, m.start()) + 1,
                    redacted_snippet=_redact(value),
                ))
                continue

        if _BASE64_SHAPE_RE.match(value) and any(c.isupper() for c in value) and any(c.islower() for c in value):
            entropy = shannon_entropy(value)
            if entropy >= _ENTROPY_BASE64_THRESHOLD:
                matches.append(SecretMatch(
                    pattern_name="High-Entropy String (possible secret)",
                    severity="low", masvs_mapping="MASVS-STORAGE",
                    line_number=text.count("\n", 0, m.start()) + 1,
                    redacted_snippet=_redact(value),
                ))

    return matches


def scan_text(text: str) -> list[SecretMatch]:
    """
    Scan ``text`` (a source file / resource file's full contents)
    against every known secret pattern. Returns redacted matches with
    1-indexed line numbers; each pattern is capped at
    ``_MAX_MATCHES_PER_PATTERN`` to avoid pathological output on a
    file that's entirely, say, base64-encoded junk.
    """
    matches: list[SecretMatch] = []
    for pattern in _PATTERNS:
        count = 0
        for match in pattern.regex.finditer(text):
            if count >= _MAX_MATCHES_PER_PATTERN:
                break
            line_number = text.count("\n", 0, match.start()) + 1
            matches.append(
                SecretMatch(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    masvs_mapping=pattern.masvs_mapping,
                    line_number=line_number,
                    redacted_snippet=_redact(match.group(0)),
                )
            )
            count += 1
    matches.extend(find_high_entropy_strings(text))
    return matches
