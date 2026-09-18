"""
app.plugins.installed.certificate_analysis.apk_signing_block
================================================================

Parses the APK Signing Block directly from an APK's raw bytes to
extract the real signer X.509 certificate(s) for APK Signature Scheme
v2 (and v3, which always also writes a v2 block for backward
compatibility on pre-v2-aware Android versions, so targeting v2 covers
the overwhelming majority of real APKs).

Why this exists: ``keytool -printcert -jarfile`` only understands the
legacy v1 JAR-signing scheme (a signature file under ``META-INF/``).
Android Studio has defaulted new projects to v2+ signing since ~2017
(and Google Play App Signing / bundletool-built app bundles are always
v2+), so for most real-world APKs today, keytool reports "Not a signed
jar file" even though the APK is genuinely, correctly signed --
Android itself refuses to install an APK whose v2/v3 block doesn't
verify. Silently treating that as "unsigned" is a false negative, not
a real security finding.

Format reference: https://source.android.com/docs/security/features/apksigning/v2
(this module implements just enough of the spec to locate the block
and pull out DER-encoded certificate bytes -- it does not verify
signatures, only extracts what's already trusted by the OS having
installed the app in the first place).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_EOCD_MAGIC = b"PK\x05\x06"
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_ID_SIGNATURE_V2 = 0x7109871A
_ID_SIGNATURE_V3 = 0xF05368C0


@dataclass(frozen=True)
class SigningBlockResult:
    scheme: str  # "v2" or "v3"
    certificates_der: list[bytes]


def _find_eocd_central_dir_offset(data: bytes) -> int | None:
    # EOCD is at least 22 bytes, and may be followed by a variable-length
    # comment (max 65535 bytes) -- scan backward from the end for the magic.
    search_start = max(0, len(data) - 22 - 65535)
    idx = data.rfind(_EOCD_MAGIC, search_start)
    if idx == -1:
        return None
    # offset-of-start-of-central-directory is a 4-byte LE field 16 bytes
    # into the EOCD record.
    (cd_offset,) = struct.unpack_from("<I", data, idx + 16)
    return cd_offset


def _locate_signing_block(data: bytes) -> bytes | None:
    cd_offset = _find_eocd_central_dir_offset(data)
    if cd_offset is None or cd_offset < 24:
        return None

    footer = data[cd_offset - 24 : cd_offset]
    size_repeated, magic = footer[:8], footer[8:]
    if magic != _APK_SIG_BLOCK_MAGIC:
        return None  # no signing block present -- likely v1-only or unsigned

    (block_size,) = struct.unpack("<Q", size_repeated)
    block_start = cd_offset - block_size - 8
    if block_start < 0:
        return None

    leading_size_field = data[block_start : block_start + 8]
    (leading_size,) = struct.unpack("<Q", leading_size_field)
    if leading_size != block_size:
        return None  # malformed / doesn't round-trip -- don't guess further

    return data[block_start + 8 : cd_offset - 24]  # just the ID-value pairs region


def _iter_id_value_pairs(pairs_data: bytes):
    offset = 0
    n = len(pairs_data)
    while offset + 8 <= n:
        (pair_len,) = struct.unpack_from("<Q", pairs_data, offset)
        pair_start = offset + 8
        if pair_len < 4 or pair_start + pair_len > n:
            break
        (pair_id,) = struct.unpack_from("<I", pairs_data, pair_start)
        value = pairs_data[pair_start + 4 : pair_start + pair_len]
        yield pair_id, value
        offset = pair_start + pair_len


def _read_length_prefixed(data: bytes, offset: int) -> tuple[bytes, int]:
    """Returns (value_bytes, next_offset) for a uint32-length-prefixed field."""
    (length,) = struct.unpack_from("<I", data, offset)
    start = offset + 4
    return data[start : start + length], start + length


def _extract_certificates_from_scheme_block(block_value: bytes) -> list[bytes]:
    certs: list[bytes] = []
    signers_seq, _ = _read_length_prefixed(block_value, 0)

    offset = 0
    while offset < len(signers_seq):
        signer, offset = _read_length_prefixed(signers_seq, offset)
        s_off = 0
        signed_data, s_off = _read_length_prefixed(signer, s_off)
        # remaining fields (signatures, public key) aren't needed here

        sd_off = 0
        _digests, sd_off = _read_length_prefixed(signed_data, sd_off)
        certs_seq, sd_off = _read_length_prefixed(signed_data, sd_off)

        c_off = 0
        while c_off < len(certs_seq):
            cert_der, c_off = _read_length_prefixed(certs_seq, c_off)
            if cert_der:
                certs.append(cert_der)

    return certs


def extract_signing_certificates(apk_path: str) -> SigningBlockResult | None:
    """Best-effort extraction of DER-encoded signer certificates from an
    APK's v2 or v3 Signing Block. Returns ``None`` if no such block is
    present (genuinely v1-only, or genuinely unsigned) rather than raising
    -- callers should fall back to the keytool-based v1 path in that case.
    """
    with open(apk_path, "rb") as f:
        data = f.read()

    pairs_data = _locate_signing_block(data)
    if pairs_data is None:
        return None

    for scheme_name, scheme_id in (("v3", _ID_SIGNATURE_V3), ("v2", _ID_SIGNATURE_V2)):
        for pair_id, value in _iter_id_value_pairs(pairs_data):
            if pair_id == scheme_id:
                try:
                    certs = _extract_certificates_from_scheme_block(value)
                except (struct.error, IndexError):
                    continue
                if certs:
                    return SigningBlockResult(scheme=scheme_name, certificates_der=certs)

    return None
