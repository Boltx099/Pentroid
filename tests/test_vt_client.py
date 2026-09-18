"""
Tests for vt_client pure functions (Module 16a).

Fixtures match VirusTotal API v3's documented response shape exactly:
``query_virustotal`` wraps the raw HTTP JSON body (which itself has a
top-level "data" key per VT's schema) in ``{"found": True, "data": <body>}``
-- so parsing code legitimately does ``raw["data"]["data"]["attributes"]``,
which looks like a bug at a glance but isn't. This is tested explicitly
below rather than left to be confusing.
"""

from __future__ import annotations

from app.plugins.installed.virustotal_lookup.vt_client import parse_vt_response


def _real_shaped_vt_body(malicious=0, suspicious=0, undetected=60, harmless=10, results=None):
    """Builds a dict matching VT API v3's actual documented response shape."""
    return {
        "found": True,
        "data": {
            "data": {
                "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious, "suspicious": suspicious,
                        "undetected": undetected, "harmless": harmless, "timeout": 0,
                    },
                    "last_analysis_results": results or {},
                },
            }
        },
    }


def test_parse_not_found_response():
    result = parse_vt_response({"found": False})
    assert result.found is False
    assert result.malicious == 0


def test_parse_clean_file_response():
    raw = _real_shaped_vt_body(malicious=0, undetected=60, harmless=10)
    result = parse_vt_response(raw)
    assert result.found is True
    assert result.malicious == 0
    assert result.total_engines == 70  # 0+0+60+10+0


def test_parse_malicious_file_extracts_detecting_engines():
    raw = _real_shaped_vt_body(
        malicious=2, undetected=68,
        results={
            "EngineA": {"category": "malicious", "result": "Trojan.Generic"},
            "EngineB": {"category": "malicious", "result": "Android.Banker"},
            "EngineC": {"category": "undetected", "result": None},
        },
    )
    result = parse_vt_response(raw)
    assert result.malicious == 2
    assert result.detecting_engines == ["EngineA", "EngineB"]


def test_parse_builds_correct_permalink():
    raw = _real_shaped_vt_body()
    result = parse_vt_response(raw)
    assert result.permalink == "https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_parse_handles_missing_attributes_gracefully():
    raw = {"found": True, "data": {"data": {"id": "abc"}}}  # no "attributes" key at all
    result = parse_vt_response(raw)
    assert result.found is True
    assert result.malicious == 0
    assert result.total_engines == 0
