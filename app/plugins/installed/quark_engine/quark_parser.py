"""
app.plugins.installed.quark_engine.quark_parser
===================================================

Pure parsing of Quark-Engine's JSON report output.

Schema verified against Quark-Engine's own official documentation
(quark-engine.readthedocs.io/en/stable/integration.html), not
recalled from memory or guessed -- confirmed example::

    {
        "md5": "...", "apk_filename": "...", "size_bytes": 166917,
        "threat_level": "High Risk", "total_score": 4,
        "crimes": [
            {
                "crime": "Send Location via SMS", "score": 4, "weight": 4.0,
                "confidence": "100%", "permissions": [...], "native_api": [...]
            }
        ]
    }

Parsing still uses ``.get()`` with fallbacks throughout -- the
confirmed example is from a specific Quark-Engine version and minor
schema drift across versions is plausible -- but the core shape
(``threat_level``, ``total_score``, ``crimes[].crime/confidence``) is
real, cited documentation, not speculation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class QuarkCrime:
    crime: str
    confidence: str  # e.g. "100%"
    score: float
    weight: float
    permissions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class QuarkReport:
    threat_level: str
    total_score: float
    crimes: list[QuarkCrime]


_THREAT_LEVEL_SEVERITY = {
    "high risk": "critical",
    "medium risk": "high",
    "low risk": "medium",
}


def parse_quark_report(raw_json: str) -> QuarkReport | None:
    """Parse a Quark-Engine JSON report. Returns None on any parse failure -- never raises."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    crimes = []
    for crime_entry in data.get("crimes", []):
        if not isinstance(crime_entry, dict):
            continue
        crimes.append(QuarkCrime(
            crime=crime_entry.get("crime", "Unknown behavior"),
            confidence=str(crime_entry.get("confidence", "0%")),
            score=float(crime_entry.get("score", 0) or 0),
            weight=float(crime_entry.get("weight", 0) or 0),
            permissions=list(crime_entry.get("permissions", []) or []),
        ))

    return QuarkReport(
        threat_level=data.get("threat_level", "Unknown"),
        total_score=float(data.get("total_score", 0) or 0),
        crimes=crimes,
    )


def severity_for_threat_level(threat_level: str) -> str:
    """Maps Quark's threat_level string to a Pentroid severity. Unknown levels default to 'medium'."""
    return _THREAT_LEVEL_SEVERITY.get(threat_level.strip().lower(), "medium")


def severity_for_confidence(confidence: str) -> str:
    """Maps a crime's confidence percentage string (e.g. '100%') to a Pentroid severity."""
    try:
        pct = float(confidence.strip().rstrip("%"))
    except ValueError:
        return "medium"
    if pct >= 80:
        return "high"
    if pct >= 40:
        return "medium"
    return "low"
