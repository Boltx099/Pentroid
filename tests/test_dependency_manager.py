"""
Unit tests for Module 3a: Dependency Manager.

These are fast/deterministic (network and subprocess calls are
mocked). Real end-to-end downloads against GitHub/PyPI are covered
separately in ``test_dependency_manager_live.py`` (marked ``live``,
skipped by default -- see that file's docstring).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    yield
    config_module.get_settings.cache_clear()


def test_unknown_tool_raises():
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolNotFoundError

    dm = DependencyManager()
    with pytest.raises(ToolNotFoundError):
        dm.status("not_a_real_tool")


def test_uninstalled_tool_reports_not_installed(tmp_path):
    from app.core.dependency_manager import DependencyManager

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    status = dm.status("jadx")
    assert status.installed is False
    assert status.version is None


def test_get_binary_path_raises_when_not_installed(tmp_path):
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolNotFoundError

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    with pytest.raises(ToolNotFoundError):
        dm.get_binary_path("jadx")


def test_service_tools_have_no_binary_path():
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolNotFoundError

    dm = DependencyManager()
    with pytest.raises(ToolNotFoundError):
        dm.get_binary_path("mobsf")

    status = dm.status("mobsf")
    assert status.installed is True  # services are always "available" (nothing to download)
    assert status.binary_path is None


def test_service_tool_install_raises():
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolNotFoundError

    dm = DependencyManager()
    with pytest.raises(ToolNotFoundError):
        dm.install("virustotal")


def test_checksum_recorded_on_first_install_and_verified_on_second(tmp_path):
    from app.core.dependency_manager import DependencyManager

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    fake_archive = tmp_path / "fake.zip"
    fake_archive.write_bytes(b"hello world")

    dm._verify_or_record_checksum(fake_archive)
    checksum_file = fake_archive.parent / ".sha256"
    assert checksum_file.exists()
    recorded = checksum_file.read_text().strip()
    assert len(recorded) == 64  # sha256 hex digest length

    # Re-verify against the same content: should not raise
    dm._verify_or_record_checksum(fake_archive)


def test_checksum_mismatch_raises(tmp_path):
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ChecksumMismatchError

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    fake_archive = tmp_path / "fake.zip"
    fake_archive.write_bytes(b"version one")
    dm._verify_or_record_checksum(fake_archive)

    fake_archive.write_bytes(b"tampered content")
    with pytest.raises(ChecksumMismatchError):
        dm._verify_or_record_checksum(fake_archive)


def test_github_release_install_picks_matching_asset_and_extracts(tmp_path):
    """Full github_release path with requests + subprocess mocked out."""
    from app.core.dependency_manager import DependencyManager
    import zipfile

    dm = DependencyManager(tools_dir=tmp_path / "tools")

    # Build a real tiny zip that looks like a jadx release: bin/jadx script
    zip_bytes_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_bytes_path, "w") as zf:
        zf.writestr("bin/jadx", "#!/bin/sh\necho jadx-fake 1.0.0\n")
    zip_bytes = zip_bytes_path.read_bytes()

    fake_release_json = {
        "tag_name": "v1.0.0",
        "assets": [
            {"name": "jadx-1.0.0.zip", "browser_download_url": "https://example.invalid/jadx-1.0.0.zip"},
            {"name": "jadx-1.0.0-no-jre.zip", "browser_download_url": "https://example.invalid/other.zip"},
        ],
    }

    class _FakeResponse:
        def __init__(self, json_data=None, content=None):
            self._json = json_data
            self.content = content

        def raise_for_status(self):
            pass

        def json(self):
            return self._json

        def iter_content(self, chunk_size):
            yield self.content

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_get(url, **kwargs):
        if "api.github.com" in url:
            return _FakeResponse(json_data=fake_release_json)
        return _FakeResponse(content=zip_bytes)

    with patch("app.core.dependency_manager.requests.get", side_effect=_fake_get):
        dm._install_github_release(dm._require_spec("jadx"), version=None)

    status = dm.status("jadx")
    assert status.installed is True
    binary = dm.get_binary_path("jadx")
    assert binary.exists()
    assert (binary.parent.parent / ".install_metadata.json").exists()


def test_github_release_no_matching_asset_raises(tmp_path):
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolDownloadError

    dm = DependencyManager(tools_dir=tmp_path / "tools")

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"tag_name": "v1.0.0", "assets": [{"name": "unrelated-file.txt", "browser_download_url": "x"}]}

    with patch("app.core.dependency_manager.requests.get", return_value=_FakeResponse()):
        with pytest.raises(ToolDownloadError):
            dm._install_github_release(dm._require_spec("jadx"), version=None)


def test_pip_venv_install_invokes_venv_and_pip(tmp_path):
    from app.core.dependency_manager import DependencyManager

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    spec = dm._require_spec("frida")

    calls = []

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        # Simulate venv creation producing a bin/python + bin/frida
        if "venv" in cmd:
            venv_dir = Path(cmd[-1])
            (venv_dir / "bin").mkdir(parents=True, exist_ok=True)
            (venv_dir / "bin" / "python").write_text("#!/bin/sh\n")
            (venv_dir / "bin" / "frida").write_text("#!/bin/sh\necho frida 16.0.0\n")
        return result

    with patch("app.core.dependency_manager.subprocess.run", side_effect=_fake_run):
        dm._install_pip_venv(spec, version=None)

    assert any("venv" in c for c in calls)
    assert any("pip" in c for c in calls)
    binary = dm._resolve_binary_path(spec)
    assert binary.name == "frida"


def test_xz_single_binary_extraction_and_device_target_version_skip(tmp_path):
    """
    frida-server ships as a raw binary compressed with .xz (not zip/tar),
    and is built for Android -- must never be exec'd on the host to check
    its version (wrong arch/libc). Verifies both behaviors.
    """
    import lzma
    from app.core.dependency_manager import DependencyManager

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    spec = dm._require_spec("frida_server_arm64")
    assert spec.probe_version_locally is False

    dest_dir = dm._tool_dir(spec.name)
    dest_dir.mkdir(parents=True, exist_ok=True)
    fake_binary = b"\x7fELF-fake-frida-server-binary"
    archive_path = dest_dir / "frida-server-16.1.4-android-arm64.xz"
    with lzma.open(archive_path, "wb") as f:
        f.write(fake_binary)

    dm._verify_or_record_checksum(archive_path)
    dm._extract_or_place(archive_path, dest_dir, spec)
    dm._write_install_metadata(dest_dir, "16.1.4")

    binary = dm.get_binary_path("frida_server_arm64")
    assert binary.read_bytes() == fake_binary
    assert binary.stat().st_mode & 0o111  # executable bit set

    # status() must read version from metadata, never attempt local exec
    with patch("app.core.dependency_manager.subprocess.run") as mock_run:
        status = dm.status("frida_server_arm64")
        mock_run.assert_not_called()
    assert status.version == "16.1.4"


def test_mitmproxy_is_registered_as_pip_venv_not_github_release():
    """
    Regression guard for a real bug: mitmproxy was registered as
    InstallMethod.GITHUB_RELEASE with an asset_pattern matching how the
    project published binaries years ago. Recent GitHub releases (confirmed
    against v12.2.3) carry zero uploaded assets -- upstream's release notes
    point installers at https://mitmproxy.org/downloads/ and PyPI instead --
    so every install attempt failed with "No release asset matching ...
    'available_assets': []". mitmproxy ships a proper PyPI package with a
    `mitmdump` console script, so PIP_VENV is the correct method, matching
    frida/objection/quark/apkid. This test fails loudly if it's ever
    switched back.
    """
    from app.core.dependency_manager import TOOL_REGISTRY, InstallMethod

    spec = TOOL_REGISTRY["mitmproxy"]
    assert spec.install_method == InstallMethod.PIP_VENV
    assert spec.pip_package == "mitmproxy"
    assert spec.console_script == "mitmdump"


def test_mitmproxy_pip_venv_install_invokes_venv_and_pip(tmp_path):
    """Same mocked-subprocess pattern as the frida PIP_VENV test above,
    applied to mitmproxy specifically so the fixed ToolSpec is exercised
    through a real install() call, not just inspected statically."""
    from app.core.dependency_manager import DependencyManager

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    spec = dm._require_spec("mitmproxy")

    calls = []

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "venv" in cmd:
            venv_dir = Path(cmd[-1])
            (venv_dir / "bin").mkdir(parents=True, exist_ok=True)
            (venv_dir / "bin" / "python").write_text("#!/bin/sh\n")
            (venv_dir / "bin" / "mitmdump").write_text("#!/bin/sh\necho mitmdump 12.2.3\n")
        return result

    with patch("app.core.dependency_manager.subprocess.run", side_effect=_fake_run):
        dm._install_pip_venv(spec, version=None)

    assert any("venv" in c for c in calls)
    assert any("pip" in c and "mitmproxy" in c for c in calls)
    binary = dm._resolve_binary_path(spec)
    assert binary.name == "mitmdump"
