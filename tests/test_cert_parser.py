"""
Tests for cert_parser (Module 12b), against REAL keytool output captured
from genuine self-signed certificates generated in this sandbox with
keytool/jarsigner -- not hand-written approximations of the format.
"""

from __future__ import annotations

from pathlib import Path

from app.plugins.installed.certificate_analysis.cert_parser import (
    is_debug_cert, is_expired, parse_keytool_date, parse_keytool_printcert,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "keytool_output"


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def test_parses_real_debug_cert_output():
    cert = parse_keytool_printcert(_load("debug_cert_output.txt"))
    assert cert is not None
    assert cert.owner == "CN=Android Debug, O=Android, C=US"
    assert cert.signature_algorithm == "SHA384withRSA"
    assert cert.signature_algorithm_weak is False
    assert cert.key_algorithm_weak is False
    assert cert.sha256_fingerprint is not None
    assert len(cert.sha256_fingerprint.replace(":", "")) == 64  # 32 bytes hex


def test_real_debug_cert_detected_as_debug():
    cert = parse_keytool_printcert(_load("debug_cert_output.txt"))
    assert is_debug_cert(cert.owner) is True


def test_parses_real_release_cert_output():
    cert = parse_keytool_printcert(_load("release_cert_output.txt"))
    assert cert is not None
    assert cert.owner == "CN=MyCompany Release, O=MyCompany, C=US"
    assert cert.signature_algorithm == "SHA256withRSA"


def test_real_release_cert_not_detected_as_debug():
    cert = parse_keytool_printcert(_load("release_cert_output.txt"))
    assert is_debug_cert(cert.owner) is False


def test_parses_real_weak_cert_output_and_detects_weak_flags():
    """
    Real JDK keytool output for a SHA1withRSA/1024-bit cert -- keytool
    itself appends '(weak)' to both lines; verifies our parser reads
    that JDK-native annotation rather than needing our own weak-algo list.
    """
    cert = parse_keytool_printcert(_load("weak_cert_output.txt"))
    assert cert is not None
    assert cert.signature_algorithm == "SHA1withRSA"
    assert cert.signature_algorithm_weak is True
    assert cert.key_algorithm == "1024-bit RSA key"
    assert cert.key_algorithm_weak is True


def test_parses_real_expired_cert_and_detects_expiry():
    cert = parse_keytool_printcert(_load("expired_cert_output.txt"))
    assert cert is not None
    assert cert.valid_until_raw is not None
    assert is_expired(cert.valid_until_raw) is True


def test_non_expired_debug_cert_not_flagged_expired():
    cert = parse_keytool_printcert(_load("debug_cert_output.txt"))
    assert is_expired(cert.valid_until_raw) is False


def test_parse_keytool_date_handles_real_format():
    dt = parse_keytool_date("Sun Jul 26 17:08:51 UTC 2026")
    assert dt is not None
    assert dt.year == 2026 and dt.month == 7 and dt.day == 26


def test_parse_keytool_date_returns_none_for_garbage():
    assert parse_keytool_date("not a date at all") is None


def test_is_expired_returns_none_for_unparseable_date():
    assert is_expired("not a date at all") is None


def test_parse_keytool_printcert_returns_none_for_unrelated_text():
    assert parse_keytool_printcert("this is not keytool output") is None
