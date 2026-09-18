"""
app.plugins.installed.certificate_analysis.cert_parser
==========================================================

Pure parsing of ``keytool -printcert -jarfile <apk>`` output.

Built directly against real output captured from a genuine JDK
``keytool`` run (self-signed debug-style, release-style, expired, and
deliberately weak SHA1withRSA/1024-bit certificates), not guessed from
documentation -- see ``tests/fixtures/keytool_output/`` for the exact
captured text these functions are tested against.

Notably, modern JDK ``keytool`` already annotates weak algorithms and
key sizes with a literal ``(weak)`` suffix in its own output -- this
parser keys off that annotation rather than maintaining its own
"what counts as weak" list, so it stays current with the JDK's own
evolving security policy instead of going stale.

Timezone note: ``Valid from``/``until`` timestamps are formatted using
the JVM's default timezone, which is UTC in essentially every server/
CI/Docker environment (and was UTC when these fixtures were captured).
Exotic timezone abbreviations that Python's ``%Z`` can't parse are
handled by returning ``None`` (unknown expiry) rather than raising --
this is a real, acknowledged limitation, not a silent wrong answer.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class CertificateInfo:
    owner: str
    issuer: str
    serial_number: str
    valid_from_raw: str | None
    valid_until_raw: str | None
    signature_algorithm: str
    signature_algorithm_weak: bool
    key_algorithm: str
    key_algorithm_weak: bool
    sha256_fingerprint: str | None


_FIELD_PATTERNS = {
    "owner": re.compile(r"^Owner:\s*(.+)$", re.MULTILINE),
    "issuer": re.compile(r"^Issuer:\s*(.+)$", re.MULTILINE),
    "serial": re.compile(r"^Serial number:\s*(.+)$", re.MULTILINE),
    "valid": re.compile(r"^Valid from:\s*(.+?)\s+until:\s*(.+)$", re.MULTILINE),
    "sig_alg": re.compile(r"^Signature algorithm name:\s*(.+)$", re.MULTILINE),
    "key_alg": re.compile(r"^Subject Public Key Algorithm:\s*(.+)$", re.MULTILINE),
    "sha256": re.compile(r"SHA256:\s*([0-9A-Fa-f:]+)"),
}


def parse_keytool_printcert(raw: str) -> CertificateInfo | None:
    """Parse one certificate block from `keytool -printcert -jarfile` output. Returns None if unparseable."""
    owner_m = _FIELD_PATTERNS["owner"].search(raw)
    if owner_m is None:
        return None

    issuer_m = _FIELD_PATTERNS["issuer"].search(raw)
    serial_m = _FIELD_PATTERNS["serial"].search(raw)
    valid_m = _FIELD_PATTERNS["valid"].search(raw)
    sig_m = _FIELD_PATTERNS["sig_alg"].search(raw)
    key_m = _FIELD_PATTERNS["key_alg"].search(raw)
    sha256_m = _FIELD_PATTERNS["sha256"].search(raw)

    sig_raw = sig_m.group(1).strip() if sig_m else "unknown"
    key_raw = key_m.group(1).strip() if key_m else "unknown"

    return CertificateInfo(
        owner=owner_m.group(1).strip(),
        issuer=issuer_m.group(1).strip() if issuer_m else "",
        serial_number=serial_m.group(1).strip() if serial_m else "",
        valid_from_raw=valid_m.group(1).strip() if valid_m else None,
        valid_until_raw=valid_m.group(2).strip() if valid_m else None,
        signature_algorithm=sig_raw.replace(" (weak)", ""),
        signature_algorithm_weak="(weak)" in sig_raw,
        key_algorithm=key_raw.replace(" (weak)", ""),
        key_algorithm_weak="(weak)" in key_raw,
        sha256_fingerprint=sha256_m.group(1).strip() if sha256_m else None,
    )


def is_debug_cert(owner: str) -> bool:
    """True if the certificate's Owner/Subject matches Android's well-known debug-keystore convention."""
    return "cn=android debug" in owner.lower()


def parse_keytool_date(date_str: str) -> datetime | None:
    """Parse a keytool date like 'Sun Jul 26 17:08:51 UTC 2026'. Returns None if the format can't be parsed."""
    try:
        return datetime.strptime(date_str, "%a %b %d %H:%M:%S %Z %Y")
    except ValueError:
        return None


def is_expired(valid_until_raw: str, reference: datetime | None = None) -> bool | None:
    """
    True/False if expiry could be determined, None if the date string
    couldn't be parsed (unknown timezone abbreviation, unexpected format, etc.).
    """
    parsed = parse_keytool_date(valid_until_raw)
    if parsed is None:
        return None
    ref = reference or datetime.now(timezone.utc).replace(tzinfo=None)
    return parsed < ref


# Signature hash algorithms the JDK's own certificate security policy treats as
# weak/restricted (SHA-1 and MD5/MD2-based signatures) -- mirrors the same
# "(weak)" judgment keytool prints for v1 certs, since v2/v3 certs parsed
# directly via ``cryptography`` don't come with that annotation for free.
_WEAK_SIGNATURE_HASHES = ("sha1", "md5", "md2")
_MIN_STRONG_RSA_BITS = 2048


def cert_info_from_der(der_bytes: bytes) -> "CertificateInfo":
    """
    Build a ``CertificateInfo`` directly from a DER-encoded X.509
    certificate (as extracted from an APK Signing Block v2/v3 by
    ``apk_signing_block.extract_signing_certificates``), independent of
    keytool entirely.

    Dates are formatted into keytool's own text format so this stays a
    drop-in equivalent for every downstream function in this module
    (``is_expired`` etc.) without needing two parallel code paths.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    cert = x509.load_der_x509_certificate(der_bytes)

    def _fmt(dt: datetime) -> str:
        return dt.strftime("%a %b %d %H:%M:%S UTC %Y")

    sig_algo_name = cert.signature_algorithm_oid._name
    sig_weak = any(h in sig_algo_name.lower() for h in _WEAK_SIGNATURE_HASHES)

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algorithm = f"RSA ({pub_key.key_size} bit)"
        key_weak = pub_key.key_size < _MIN_STRONG_RSA_BITS
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algorithm = f"DSA ({pub_key.key_size} bit)"
        key_weak = True  # DSA itself is treated as legacy/weak regardless of size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algorithm = f"EC ({pub_key.curve.name})"
        key_weak = False
    else:
        key_algorithm = type(pub_key).__name__
        key_weak = False

    return CertificateInfo(
        owner=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=str(cert.serial_number),
        valid_from_raw=_fmt(cert.not_valid_before_utc),
        valid_until_raw=_fmt(cert.not_valid_after_utc),
        signature_algorithm=sig_algo_name,
        signature_algorithm_weak=sig_weak,
        key_algorithm=key_algorithm,
        key_algorithm_weak=key_weak,
        sha256_fingerprint=hashlib.sha256(der_bytes).hexdigest(),
    )
