"""
app.core.dependency_manager
=============================

Detects, downloads, checksum-verifies, and extracts every external
tool Pentroid orchestrates -- JADX, APKTool, ADB, Frida, Objection,
Quark, APKiD, Bundletool, mitmproxy -- into ``tools/<name>/``.

Design
------
Three install strategies, one per how a tool is actually distributed
upstream (this is deliberately NOT a one-size-fits-all downloader --
that would be dishonest about how these ecosystems actually ship
software):

* ``GITHUB_RELEASE`` -- resolve the latest (or pinned) GitHub release
  via the API, pick the asset matching a platform-specific regex,
  download, extract, locate the binary.
* ``DIRECT_URL`` -- a fixed, vendor-documented URL template (used for
  ADB / Android platform-tools, which Google does not publish via
  GitHub releases). Same download/extract code path as
  ``GITHUB_RELEASE``, just a different URL source.
* ``PIP_VENV`` -- tools distributed as a PyPI package with a console
  script (frida-tools, objection, quark-engine, apkid) get their own
  isolated virtualenv under ``tools/<name>/venv`` so their transitive
  dependencies never collide with Pentroid's own environment, and so
  the resolved binary is a fully-qualified path -- never a bare name
  resolved via ``$PATH``.
* ``SERVICE`` -- tools that aren't a downloadable binary at all
  (MobSF runs as its own Flask/Docker service, Burp Suite is a
  separate commercial application, VirusTotal is a pure REST API).
  These are represented so the GUI's Settings/Tool Manager panel can
  show "configure endpoint + API key" instead of "download", which is
  what's actually true of them.

Checksums: GitHub/vendor release pages don't reliably publish a
machine-readable checksum for every asset across every tool, so this
manager uses trust-on-first-install (TOFU): the sha256 of whatever was
downloaded is recorded in ``tools/<name>/.sha256`` on first install,
and every subsequent install of that exact version is verified against
it -- catching corrupted downloads or tampering on re-install, which is
the realistic threat model here (this is the same trust model Homebrew
and most language package managers use for non-notarized assets).
"""

from __future__ import annotations

import hashlib
import json
import lzma
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import requests

from app.core.config import get_settings
from app.core.exceptions import ChecksumMismatchError, ToolDownloadError, ToolNotFoundError
from app.core.logger import get_logger

logger = get_logger(__name__)

_GITHUB_API = "https://api.github.com"
_DOWNLOAD_TIMEOUT = 120
_CHUNK_SIZE = 1024 * 256


class InstallMethod(str, Enum):
    GITHUB_RELEASE = "github_release"
    DIRECT_URL = "direct_url"
    PIP_VENV = "pip_venv"
    SERVICE = "service"
    SYSTEM = "system"  # assumed present on $PATH -- part of a runtime other tools already require (JDK for java/keytool)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    install_method: InstallMethod

    # GITHUB_RELEASE
    github_repo: str | None = None
    asset_pattern: str | None = None  # regex matched against release asset names

    # DIRECT_URL
    url_template: str | None = None  # may contain {platform}

    # GITHUB_RELEASE / DIRECT_URL (shared)
    binary_relative_path: str | None = None
    launch_prefix: list[str] = field(default_factory=list)  # e.g. ["java", "-jar"]
    version_args: list[str] = field(default_factory=lambda: ["--version"])
    probe_version_locally: bool = True  # False for device-target binaries (e.g. frida-server, built for Android)

    # PIP_VENV
    pip_package: str | None = None
    pip_version: str | None = None
    console_script: str | None = None

    # SERVICE
    service_doc_url: str | None = None
    service_config_keys: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Registry -- every tool listed in the architecture's "Supported Tools" panel.
# --------------------------------------------------------------------------- #
TOOL_REGISTRY: dict[str, ToolSpec] = {
    "jadx": ToolSpec(
        name="jadx",
        description="Dex-to-Java decompiler",
        install_method=InstallMethod.GITHUB_RELEASE,
        github_repo="skylot/jadx",
        asset_pattern=r"^jadx-\d.*\.zip$",
        binary_relative_path="bin/jadx",
    ),
    "apktool": ToolSpec(
        name="apktool",
        description="APK decode/rebuild (resources + smali)",
        install_method=InstallMethod.GITHUB_RELEASE,
        github_repo="iBotPeaches/Apktool",
        asset_pattern=r"^apktool_\d.*\.jar$",
        binary_relative_path="apktool.jar",
        launch_prefix=["java", "-jar"],
        version_args=["--version"],
    ),
    "bundletool": ToolSpec(
        name="bundletool",
        description="Android App Bundle (.aab) build/analysis tool",
        install_method=InstallMethod.GITHUB_RELEASE,
        github_repo="google/bundletool",
        asset_pattern=r"^bundletool-all-\d.*\.jar$",
        binary_relative_path="bundletool.jar",
        launch_prefix=["java", "-jar"],
        version_args=["version"],
    ),
    "mitmproxy": ToolSpec(
        name="mitmproxy",
        description="MITM proxy for network traffic interception/capture",
        # Was GITHUB_RELEASE with asset_pattern=r"^mitmproxy-\d.*-linux-x86_64\.tar\.gz$",
        # which matched how mitmproxy published binaries years ago (see e.g.
        # mitmproxy-11.0.2-linux-x86_64.tar.gz) but no longer matches how the
        # project distributes itself: recent GitHub releases (confirmed against
        # v12.2.3) carry zero uploaded assets at all -- the release notes
        # explicitly say "You can find the latest release packages at
        # https://mitmproxy.org/downloads/" instead. That's why installing this
        # surfaced "No release asset matching ... details={'available_assets': [],
        # 'release_tag': 'v12.2.3'}": there was nothing to match against, not a
        # regex typo. mitmproxy ships a proper PyPI package with `mitmproxy`,
        # `mitmdump` and `mitmweb` console scripts (pip install mitmproxy is
        # upstream's own current recommendation), so PIP_VENV is the correct
        # install method here -- the same pattern already used for frida/
        # objection/quark/apkid, all real CLI tools installed this way.
        install_method=InstallMethod.PIP_VENV,
        pip_package="mitmproxy",
        console_script="mitmdump",
        version_args=["--version"],
    ),
    "adb": ToolSpec(
        name="adb",
        description="Android Debug Bridge (platform-tools)",
        install_method=InstallMethod.DIRECT_URL,
        url_template="https://dl.google.com/android/repository/platform-tools-latest-{platform}.zip",
        binary_relative_path="platform-tools/adb",
        version_args=["version"],
    ),
    "frida": ToolSpec(
        name="frida",
        description="Dynamic instrumentation toolkit (CLI + server control)",
        install_method=InstallMethod.PIP_VENV,
        pip_package="frida-tools",
        console_script="frida",
        version_args=["--version"],
    ),
    "frida_server_arm64": ToolSpec(
        name="frida_server_arm64",
        description="frida-server on-device binary for arm64 physical Android devices",
        install_method=InstallMethod.GITHUB_RELEASE,
        github_repo="frida/frida",
        asset_pattern=r"^frida-server-\d.*-android-arm64\.xz$",
        binary_relative_path="frida-server",
        probe_version_locally=False,
    ),
    "frida_server_x86_64": ToolSpec(
        name="frida_server_x86_64",
        description="frida-server on-device binary for x86_64 Android emulators",
        install_method=InstallMethod.GITHUB_RELEASE,
        github_repo="frida/frida",
        asset_pattern=r"^frida-server-\d.*-android-x86_64\.xz$",
        binary_relative_path="frida-server",
        probe_version_locally=False,
    ),
    "objection": ToolSpec(
        name="objection",
        description="Runtime mobile exploration toolkit (built on Frida)",
        install_method=InstallMethod.PIP_VENV,
        pip_package="objection",
        console_script="objection",
        version_args=["version"],
    ),
    "pymobiledevice3": ToolSpec(
        name="pymobiledevice3",
        description="iOS device communication (lockdown/usbmux) without requiring Xcode",
        install_method=InstallMethod.PIP_VENV,
        pip_package="pymobiledevice3",
        console_script="pymobiledevice3",
        version_args=["version"],
    ),
    "quark": ToolSpec(
        name="quark",
        description="Quark-Engine APK malware scoring",
        install_method=InstallMethod.PIP_VENV,
        pip_package="quark-engine",
        console_script="quark",
        version_args=["--version"],
    ),
    "apkid": ToolSpec(
        name="apkid",
        description="APKiD - packer/obfuscator/anti-VM fingerprinting",
        install_method=InstallMethod.PIP_VENV,
        pip_package="apkid",
        console_script="apkid",
        version_args=["--version"],
    ),
    "mobsf": ToolSpec(
        name="mobsf",
        description="Mobile Security Framework (runs as its own service; Pentroid calls its REST API)",
        install_method=InstallMethod.SERVICE,
        service_doc_url="https://mobsf.github.io/docs/",
        service_config_keys=["base_url", "api_key"],
    ),
    "burp_suite": ToolSpec(
        name="burp_suite",
        description="Burp Suite Professional (proxy integration via REST API extension)",
        install_method=InstallMethod.SERVICE,
        service_doc_url="https://portswigger.net/burp/documentation",
        service_config_keys=["api_base_url", "api_key"],
    ),
    "virustotal": ToolSpec(
        name="virustotal",
        description="VirusTotal hash/file intelligence API",
        install_method=InstallMethod.SERVICE,
        service_doc_url="https://docs.virustotal.com/reference/overview",
        service_config_keys=["api_key"],
    ),
    "keytool": ToolSpec(
        name="keytool",
        description="JDK certificate inspection tool (used for APK signing-certificate analysis). "
                     "Ships with the JDK already required by apktool/bundletool (java -jar); resolved "
                     "via $PATH rather than downloaded, same as 'java' itself -- see DependencyManager "
                     "docstring note on SYSTEM tools.",
        install_method=InstallMethod.SYSTEM,
        version_args=["-help"],
    ),
}


@dataclass
class ToolStatus:
    name: str
    installed: bool
    version: str | None
    binary_path: Path | None
    install_method: InstallMethod


class DependencyManager:
    """Detects, installs, and resolves paths for every tool in ``TOOL_REGISTRY``."""

    def __init__(self, tools_dir: Path | None = None) -> None:
        self._tools_dir = tools_dir or get_settings().paths.tools_dir
        self._tools_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Status / resolution
    # ------------------------------------------------------------------ #
    def _tool_dir(self, name: str) -> Path:
        return self._tools_dir / name

    def get_binary_path(self, name: str) -> Path:
        """Return the fully-qualified binary path for an installed tool. Never relies on $PATH."""
        spec = self._require_spec(name)
        if spec.install_method == InstallMethod.SERVICE:
            raise ToolNotFoundError(
                f"'{name}' is a service integration, not a downloadable binary. "
                f"Configure it under Settings > Tool Manager instead."
            )

        path = self._resolve_binary_path(spec)
        if path is None or not path.exists():
            raise ToolNotFoundError(
                f"'{name}' is not installed. Run DependencyManager.install('{name}') first.",
                details={"expected_path": str(path) if path else None},
            )
        return path

    def _resolve_binary_path(self, spec: ToolSpec) -> Path | None:
        if spec.install_method == InstallMethod.SYSTEM:
            found = shutil.which(spec.name)
            return Path(found) if found else None
        if spec.install_method == InstallMethod.PIP_VENV:
            venv_bin = self._tool_dir(spec.name) / "venv" / "bin"
            return venv_bin / spec.console_script if spec.console_script else None
        if spec.binary_relative_path is None:
            return None
        return self._tool_dir(spec.name) / spec.binary_relative_path

    def status(self, name: str) -> ToolStatus:
        spec = self._require_spec(name)
        if spec.install_method == InstallMethod.SERVICE:
            return ToolStatus(name, installed=True, version=None, binary_path=None,
                               install_method=spec.install_method)

        path = self._resolve_binary_path(spec)
        installed = path is not None and path.exists()
        if not installed:
            version = None
        elif spec.probe_version_locally:
            version = self._probe_version(spec, path)
        else:
            version = self._read_installed_version(spec)
        return ToolStatus(
            name=name, installed=installed, version=version,
            binary_path=path if installed else None, install_method=spec.install_method,
        )

    def status_all(self) -> dict[str, ToolStatus]:
        return {name: self.status(name) for name in TOOL_REGISTRY}

    def _probe_version(self, spec: ToolSpec, path: Path) -> str | None:
        cmd = [*spec.launch_prefix, str(path), *spec.version_args]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, check=False,
            )
            output = (result.stdout or result.stderr or "").strip()
            if not output:
                return None
            # Use the LAST non-empty line, not the first: some tools (e.g. quark-engine)
            # print an ASCII-art banner before the actual version string. Single-line
            # outputs (jadx, apktool, frida) are unaffected since first == last there.
            lines = [line for line in output.splitlines() if line.strip()]
            return lines[-1] if lines else None
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Version probe failed for %s: %s", spec.name, exc)
            return None

    def _read_installed_version(self, spec: ToolSpec) -> str | None:
        metadata_file = self._tool_dir(spec.name) / ".install_metadata.json"
        if not metadata_file.exists():
            return None
        try:
            return json.loads(metadata_file.read_text(encoding="utf-8")).get("version")
        except (OSError, json.JSONDecodeError):
            return None

    def _require_spec(self, name: str) -> ToolSpec:
        spec = TOOL_REGISTRY.get(name)
        if spec is None:
            raise ToolNotFoundError(f"Unknown tool: {name!r} (not in TOOL_REGISTRY)")
        return spec

    # ------------------------------------------------------------------ #
    # Install
    # ------------------------------------------------------------------ #
    def install(self, name: str, version: str | None = None) -> ToolStatus:
        spec = self._require_spec(name)
        logger.info("Installing tool '%s' via %s", name, spec.install_method.value)

        if spec.install_method == InstallMethod.GITHUB_RELEASE:
            self._install_github_release(spec, version)
        elif spec.install_method == InstallMethod.DIRECT_URL:
            self._install_direct_url(spec)
        elif spec.install_method == InstallMethod.PIP_VENV:
            self._install_pip_venv(spec, version)
        elif spec.install_method == InstallMethod.SERVICE:
            raise ToolNotFoundError(
                f"'{name}' is a service integration -- nothing to install. "
                f"See {spec.service_doc_url}"
            )
        elif spec.install_method == InstallMethod.SYSTEM:
            raise ToolNotFoundError(
                f"'{name}' is expected on your system $PATH (ships with the JDK) -- nothing for "
                f"Pentroid to download. Install a JDK if `{name}` isn't already available."
            )

        return self.status(name)

    def uninstall(self, name: str) -> None:
        spec = self._require_spec(name)
        target = self._tool_dir(spec.name)
        if target.exists():
            shutil.rmtree(target)
            logger.info("Uninstalled tool '%s'", name)

    # ------------------------------------------------------------------ #
    # GITHUB_RELEASE
    # ------------------------------------------------------------------ #
    def _install_github_release(self, spec: ToolSpec, version: str | None) -> None:
        api_url = (
            f"{_GITHUB_API}/repos/{spec.github_repo}/releases/tags/{version}"
            if version
            else f"{_GITHUB_API}/repos/{spec.github_repo}/releases/latest"
        )
        headers = {"Accept": "application/vnd.github+json"}
        # Unauthenticated GitHub API calls are capped at 60/hour *per IP* --
        # easy to exhaust from a shared/corporate/VPN egress IP, or just from
        # installing several GITHUB_RELEASE tools (jadx, apktool, bundletool,
        # mitmproxy, frida_server_*...) in one "Update Tools" pass. A token
        # (no scopes needed, just needs to exist) raises that to 5000/hour.
        from app.database.database import get_setting
        try:
            token = get_setting("github_token")
        except Exception:  # noqa: BLE001 - the token is optional; a DB hiccup shouldn't block installs
            token = None
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            resp = requests.get(api_url, timeout=30, headers=headers)
            status_code = getattr(resp, "status_code", None)
            resp_headers = getattr(resp, "headers", {}) or {}
            if status_code == 403 and resp_headers.get("x-ratelimit-remaining") == "0":
                reset_ts = resp_headers.get("x-ratelimit-reset")
                reset_note = ""
                if reset_ts:
                    try:
                        reset_note = f" (resets {datetime.fromtimestamp(int(reset_ts), tz=timezone.utc):%H:%M UTC})"
                    except ValueError:
                        pass
                raise ToolDownloadError(
                    f"GitHub API rate limit hit for {spec.github_repo}{reset_note}. "
                    "Add a GitHub personal access token in Settings (no scopes needed) to raise "
                    "the limit from 60/hour to 5000/hour.",
                    details={"url": api_url, "rate_limited": True},
                )
            resp.raise_for_status()
            release = resp.json()
        except requests.RequestException as exc:
            raise ToolDownloadError(
                f"Failed to query GitHub releases for {spec.github_repo}",
                details={"error": str(exc), "url": api_url},
            ) from exc

        assets = release.get("assets", [])
        pattern = re.compile(spec.asset_pattern)
        match = next((a for a in assets if pattern.match(a["name"])), None)
        if match is None:
            available = [a["name"] for a in assets]
            raise ToolDownloadError(
                f"No release asset matching {spec.asset_pattern!r} for {spec.name}",
                details={"available_assets": available, "release_tag": release.get("tag_name")},
            )

        download_url = match["browser_download_url"]
        dest_dir = self._tool_dir(spec.name)
        dest_dir.mkdir(parents=True, exist_ok=True)
        archive_path = dest_dir / match["name"]

        self._download(download_url, archive_path)
        self._verify_or_record_checksum(archive_path)
        self._extract_or_place(archive_path, dest_dir, spec)
        self._write_install_metadata(dest_dir, release.get("tag_name", "unknown"))
        logger.info("Installed %s (%s) into %s", spec.name, release.get("tag_name"), dest_dir)

    # ------------------------------------------------------------------ #
    # DIRECT_URL
    # ------------------------------------------------------------------ #
    def _install_direct_url(self, spec: ToolSpec) -> None:
        plat = self._platform_tag()
        url = spec.url_template.format(platform=plat)
        dest_dir = self._tool_dir(spec.name)
        dest_dir.mkdir(parents=True, exist_ok=True)
        archive_path = dest_dir / Path(url).name

        self._download(url, archive_path)
        self._verify_or_record_checksum(archive_path)
        self._extract_or_place(archive_path, dest_dir, spec)
        self._write_install_metadata(dest_dir, "latest")
        logger.info("Installed %s into %s", spec.name, dest_dir)

    @staticmethod
    def _platform_tag() -> str:
        system = platform.system().lower()
        if system.startswith("win"):
            return "windows"
        if system == "darwin":
            return "darwin"
        return "linux"

    # ------------------------------------------------------------------ #
    # PIP_VENV
    # ------------------------------------------------------------------ #
    def _install_pip_venv(self, spec: ToolSpec, version: str | None) -> None:
        dest_dir = self._tool_dir(spec.name)
        venv_dir = dest_dir / "venv"

        if not venv_dir.exists():
            result = subprocess.run(
                [sys.executable, "-m", "venv", str(venv_dir)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                raise ToolDownloadError(
                    f"Failed to create virtualenv for '{spec.name}'",
                    details={"stderr": result.stderr},
                )

        venv_python = venv_dir / "bin" / "python"
        package_spec = f"{spec.pip_package}=={version}" if version else spec.pip_package
        result = subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--quiet", "--upgrade", package_spec],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise ToolDownloadError(
                f"pip install failed for '{spec.name}' ({package_spec})",
                details={"stderr": result.stderr[-2000:]},
            )

        self._write_install_metadata(dest_dir, version or "latest")
        logger.info("Installed %s into isolated venv at %s", spec.name, venv_dir)

    # ------------------------------------------------------------------ #
    # Shared: download / checksum / extract
    # ------------------------------------------------------------------ #
    def _download(self, url: str, dest_path: Path) -> None:
        try:
            with requests.get(url, stream=True, timeout=_DOWNLOAD_TIMEOUT) as resp:
                resp.raise_for_status()
                with open(dest_path, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=_CHUNK_SIZE):
                        if chunk:
                            fh.write(chunk)
        except requests.RequestException as exc:
            raise ToolDownloadError(
                f"Download failed: {url}", details={"error": str(exc)}
            ) from exc
        logger.info("Downloaded %s (%d bytes)", dest_path.name, dest_path.stat().st_size)

    def _verify_or_record_checksum(self, archive_path: Path) -> None:
        """Trust-on-first-install: record sha256 on first download, verify on re-download."""
        sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        checksum_file = archive_path.parent / ".sha256"

        if checksum_file.exists():
            expected = checksum_file.read_text(encoding="utf-8").strip()
            if expected != sha256:
                raise ChecksumMismatchError(
                    f"Checksum mismatch for {archive_path.name}: "
                    f"expected {expected}, got {sha256}",
                    details={"file": str(archive_path)},
                )
        else:
            checksum_file.write_text(sha256, encoding="utf-8")
            logger.info("Recorded sha256 for %s: %s", archive_path.name, sha256)

    def _extract_or_place(self, archive_path: Path, dest_dir: Path, spec: ToolSpec) -> None:
        if archive_path.suffix == ".jar":
            expected = dest_dir / (spec.binary_relative_path or archive_path.name)
            if archive_path != expected:
                shutil.move(str(archive_path), str(expected))
        elif zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(dest_dir)
            archive_path.unlink(missing_ok=True)
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as tf:
                tf.extractall(dest_dir)
            archive_path.unlink(missing_ok=True)
        elif archive_path.suffix == ".xz":
            # Single raw binary compressed with xz (e.g. frida-server-*-android-arm64.xz)
            expected = dest_dir / (spec.binary_relative_path or archive_path.stem)
            with lzma.open(archive_path, "rb") as src, open(expected, "wb") as dst:
                shutil.copyfileobj(src, dst)
            archive_path.unlink(missing_ok=True)
        else:
            # Single raw binary asset (no archive container)
            expected = dest_dir / (spec.binary_relative_path or archive_path.name)
            if archive_path != expected:
                shutil.move(str(archive_path), str(expected))

        binary_path = self._resolve_binary_path(spec)
        if binary_path and binary_path.exists():
            binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    @staticmethod
    def _write_install_metadata(dest_dir: Path, version: str) -> None:
        metadata = {
            "version": version,
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }
        (dest_dir / ".install_metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )


_manager: DependencyManager | None = None


def get_dependency_manager() -> DependencyManager:
    global _manager
    if _manager is None:
        _manager = DependencyManager()
    return _manager
