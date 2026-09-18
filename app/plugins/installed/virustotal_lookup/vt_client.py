"""
app.plugins.installed.virustotal_lookup.vt_client
=====================================================

VirusTotal API v3 file-hash lookup: HTTP call and response parsing
kept deliberately separate (``query_virustotal`` vs. ``parse_vt_response``)
so the parsing logic -- which is what actually matters for correctness
-- can be thoroughly unit tested against realistic mocked JSON without
needing a real API key, which this development environment doesn't
have access to.

Schema verified against docs.virustotal.com/reference/files and
docs.virustotal.com/reference/file-info: ``GET /api/v3/files/{hash}``
with header ``x-apikey``, returning a File object with
``data.attributes.last_analysis_stats`` (malicious/suspicious/
undetected/harmless/timeout counts) and ``last_analysis_results``
(per-engine verdicts). A hash VT has never seen returns 404.

Honest limitation: this has NOT been exercised against a real API key
or real VirusTotal response -- only against the documented schema and
hand-built fixtures matching it. Sanity-check against a real key
before relying on it for anything important.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

_VT_FILES_URL = "https://www.virustotal.com/api/v3/files/"
_DEFAULT_TIMEOUT = 30.0


@dataclass(frozen=True)
class VTResult:
    found: bool
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    detecting_engines: list[str] = field(default_factory=list)
    permalink: str = ""


class VirusTotalError(Exception):
    """Raised for VT API failures that aren't a plain 404 (auth errors, rate limits, network issues)."""


def query_virustotal(file_hash: str, api_key: str, timeout: float = _DEFAULT_TIMEOUT) -> dict:
    """
    Real HTTP GET against VT API v3. Returns the parsed JSON body for a
    200 response, or ``{"found": False}`` for a 404 (hash not in VT's
    database -- a normal, common outcome, not an error). Raises
    ``VirusTotalError`` for anything else (auth failure, rate limit,
    network failure).
    """
    try:
        response = requests.get(
            _VT_FILES_URL + file_hash,
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error contacting VirusTotal: {exc}") from exc

    if response.status_code == 404:
        return {"found": False}
    if response.status_code == 401:
        raise VirusTotalError("VirusTotal API key was rejected (401) -- check Settings > Service API Keys.")
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit exceeded (429) -- try again later.")
    if response.status_code != 200:
        raise VirusTotalError(f"VirusTotal returned unexpected status {response.status_code}: {response.text[:200]}")

    return {"found": True, "data": response.json()}


def parse_vt_response(raw: dict) -> VTResult:
    """Parse the dict returned by ``query_virustotal`` into a ``VTResult``. Never raises."""
    if not raw.get("found"):
        return VTResult(found=False)

    attributes = raw.get("data", {}).get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    results = attributes.get("last_analysis_results", {}) or {}

    detecting_engines = [
        engine for engine, verdict in results.items()
        if isinstance(verdict, dict) and verdict.get("category") == "malicious"
    ]

    file_id = raw.get("data", {}).get("data", {}).get("id", "")
    permalink = f"https://www.virustotal.com/gui/file/{file_id}" if file_id else ""

    return VTResult(
        found=True,
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        total_engines=sum(int(v or 0) for v in stats.values()),
        detecting_engines=sorted(detecting_engines),
        permalink=permalink,
    )
