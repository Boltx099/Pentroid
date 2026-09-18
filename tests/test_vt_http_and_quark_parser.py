"""
Tests for query_virustotal (HTTP layer, mocked) and quark_parser pure
functions (Module 16b).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# --------------------------------------------------------------------------- #
# query_virustotal -- HTTP call, mocked
# --------------------------------------------------------------------------- #
def test_query_virustotal_404_returns_not_found():
    from app.plugins.installed.virustotal_lookup.vt_client import query_virustotal

    mock_response = MagicMock(status_code=404)
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        result = query_virustotal("abc123", "fake-key")
    assert result == {"found": False}


def test_query_virustotal_200_returns_parsed_body():
    from app.plugins.installed.virustotal_lookup.vt_client import query_virustotal

    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"data": {"id": "abc123", "attributes": {}}}
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        result = query_virustotal("abc123", "fake-key")
    assert result["found"] is True
    assert result["data"]["data"]["id"] == "abc123"


def test_query_virustotal_401_raises_clear_error():
    from app.plugins.installed.virustotal_lookup.vt_client import query_virustotal, VirusTotalError

    mock_response = MagicMock(status_code=401)
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        with pytest.raises(VirusTotalError, match="rejected"):
            query_virustotal("abc123", "bad-key")


def test_query_virustotal_429_raises_rate_limit_error():
    from app.plugins.installed.virustotal_lookup.vt_client import query_virustotal, VirusTotalError

    mock_response = MagicMock(status_code=429)
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        with pytest.raises(VirusTotalError, match="rate limit"):
            query_virustotal("abc123", "fake-key")


def test_query_virustotal_sends_correct_headers_and_url():
    from app.plugins.installed.virustotal_lookup.vt_client import query_virustotal

    mock_response = MagicMock(status_code=404)
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response) as mock_get:
        query_virustotal("deadbeef" * 8, "my-api-key")

    call_args = mock_get.call_args
    assert call_args[0][0] == "https://www.virustotal.com/api/v3/files/" + "deadbeef" * 8
    assert call_args[1]["headers"]["x-apikey"] == "my-api-key"


def test_query_virustotal_network_error_raises():
    import requests
    from app.plugins.installed.virustotal_lookup.vt_client import query_virustotal, VirusTotalError

    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get",
               side_effect=requests.ConnectionError("no network")):
        with pytest.raises(VirusTotalError, match="Network error"):
            query_virustotal("abc123", "fake-key")


# --------------------------------------------------------------------------- #
# quark_parser -- real documented schema
# --------------------------------------------------------------------------- #
def test_parses_real_documented_quark_schema():
    from app.plugins.installed.quark_engine.quark_parser import parse_quark_report

    # Exact example shape from Quark-Engine's own official documentation
    raw = """
    {
        "md5": "14d9f1a92dd984d6040cc41ed06e273e",
        "apk_filename": "sample.apk",
        "size_bytes": 166917,
        "threat_level": "High Risk",
        "total_score": 4,
        "crimes": [
            {
                "crime": "Send Location via SMS",
                "score": 4, "weight": 4.0, "confidence": "100%",
                "permissions": ["android.permission.SEND_SMS", "android.permission.ACCESS_FINE_LOCATION"]
            }
        ]
    }
    """
    report = parse_quark_report(raw)
    assert report is not None
    assert report.threat_level == "High Risk"
    assert report.total_score == 4
    assert len(report.crimes) == 1
    assert report.crimes[0].crime == "Send Location via SMS"
    assert report.crimes[0].confidence == "100%"
    assert "android.permission.SEND_SMS" in report.crimes[0].permissions


def test_quark_parser_returns_none_for_malformed_json():
    from app.plugins.installed.quark_engine.quark_parser import parse_quark_report
    assert parse_quark_report("not json") is None


def test_quark_severity_for_threat_level():
    from app.plugins.installed.quark_engine.quark_parser import severity_for_threat_level
    assert severity_for_threat_level("High Risk") == "critical"
    assert severity_for_threat_level("Medium Risk") == "high"
    assert severity_for_threat_level("Low Risk") == "medium"
    assert severity_for_threat_level("Something Unexpected") == "medium"  # safe default


def test_quark_severity_for_confidence():
    from app.plugins.installed.quark_engine.quark_parser import severity_for_confidence
    assert severity_for_confidence("100%") == "high"
    assert severity_for_confidence("50%") == "medium"
    assert severity_for_confidence("10%") == "low"
    assert severity_for_confidence("garbage") == "medium"  # safe default
