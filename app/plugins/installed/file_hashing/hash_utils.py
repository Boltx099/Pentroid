"""
app.plugins.installed.file_hashing.hash_utils
================================================

Pure file-hashing logic, separated from ``plugin.py`` for direct
testing. First step of Malware Analysis ("File Information & Hashing"
/ "Sample Triage") -- every downstream step (YARA, VirusTotal lookup,
IOC correlation) keys off these hashes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class FileHashes:
    md5: str
    sha1: str
    sha256: str
    size_bytes: int


def compute_hashes(path: Path) -> FileHashes:
    """Stream the file in chunks (never loads the whole thing into memory) computing all three digests at once."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)

    return FileHashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest(), size_bytes=size)
