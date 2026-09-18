"""
app.plugins.installed.ioc_extraction.ioc_extractor
======================================================

Pure extraction of URLs/IPs/domains from decompiled source as
indicators of compromise. Domains are derived from extracted URLs
(parsed via ``urlparse``) rather than a standalone bare-domain regex --
a loose "looks like a domain" pattern would massively over-match
ordinary Android/Java package and class names (``com.example.app``
reads exactly like a domain to a naive regex).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

_URL_RE = re.compile(r'https?://[^\s"\'<>\\]+')
_IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')

# XML namespace hosts (false positives on every Android manifest/layout) and
# non-actionable loopback/broadcast addresses -- noise, not real IOCs.
_EXCLUDED_HOSTS = {"schemas.android.com", "www.w3.org", "xmlpull.org", "schemas.xmlsoap.org", "localhost"}
_EXCLUDED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

_MAX_PER_TYPE = 50


@dataclass(frozen=True)
class ExtractedIOC:
    ioc_type: str  # "url" | "ip" | "domain"
    value: str
    line_number: int


def extract_iocs(text: str) -> list[ExtractedIOC]:
    iocs: list[ExtractedIOC] = []
    seen: set[tuple[str, str]] = set()
    counts = {"url": 0, "ip": 0, "domain": 0}

    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)\"'")
        line = text.count("\n", 0, m.start()) + 1
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].split("@")[-1]

        if host.lower() not in _EXCLUDED_HOSTS:
            if counts["url"] < _MAX_PER_TYPE and ("url", url) not in seen:
                seen.add(("url", url))
                iocs.append(ExtractedIOC("url", url, line))
                counts["url"] += 1
            if host and counts["domain"] < _MAX_PER_TYPE and ("domain", host) not in seen:
                seen.add(("domain", host))
                iocs.append(ExtractedIOC("domain", host, line))
                counts["domain"] += 1

    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if ip in _EXCLUDED_IPS or counts["ip"] >= _MAX_PER_TYPE:
            continue
        if ("ip", ip) not in seen:
            seen.add(("ip", ip))
            iocs.append(ExtractedIOC("ip", ip, text.count("\n", 0, m.start()) + 1))
            counts["ip"] += 1

    return iocs
