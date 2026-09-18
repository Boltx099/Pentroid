"""
app.plugins.installed.file_hashing.plugin
============================================

Wraps ``hash_utils.compute_hashes``. Hashes are stored via
``context.shared_data`` (for later steps like a future VirusTotal
lookup keyed on SHA256) and reported as a single INFO finding for
report visibility (analysts routinely need the hash values for
cross-referencing threat intel, not just to see a pass/fail check).
"""

from __future__ import annotations

from pathlib import Path

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.file_hashing.hash_utils import compute_hashes


class FileHashingPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="file_hashing",
        name="File Hashing",
        version="1.0.0",
        description="Computes MD5/SHA1/SHA256 hashes and basic file metadata.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        target = Path(context.target_path)
        if not target.exists():
            return PluginOutput(
                tool="file_hashing", status=PluginRunStatus.FAILED,
                errors=[f"Target file does not exist: {target}"],
            )

        hashes = compute_hashes(target)
        context.shared_data["file_hashes"] = {
            "md5": hashes.md5, "sha1": hashes.sha1, "sha256": hashes.sha256, "size_bytes": hashes.size_bytes,
        }

        finding = PluginFinding(
            title="Sample hashes",
            severity=SeverityLevel.INFO,
            description=(
                f"MD5: {hashes.md5}\nSHA1: {hashes.sha1}\nSHA256: {hashes.sha256}\n"
                f"Size: {hashes.size_bytes:,} bytes"
            ),
            category="Sample Information",
        )
        return PluginOutput(
            tool="file_hashing", status=PluginRunStatus.SUCCESS, findings=[finding],
            logs=[f"SHA256={hashes.sha256}"], metadata={"sha256": hashes.sha256},
        )
