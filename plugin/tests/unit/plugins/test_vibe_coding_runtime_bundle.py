"""Static provenance and packaging checks for the pinned HAPI runtime."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from plugin.neko_plugin_cli.public import build_plugin


pytestmark = pytest.mark.plugin_unit

PLUGIN_DIR = Path(__file__).resolve().parents[3] / "plugins" / "vibe_coding_connector"
RUNTIME_DIR = PLUGIN_DIR / "runtime"
WINDOWS_ARCHIVE = RUNTIME_DIR / "bundles" / "hapi-v0.25.1-win32-x64.zip"
WINDOWS_SHA256 = "dfef0e27ecee40a18b59ae6e946cf7d177362f2f188d81703cc931f681550698"
WINDOWS_EXE_SHA256 = "f68c1ae3672d69f2aa31f969fa5cbc3a3173f847458e4a04d0a8f5cd09dcc99c"
HELPER_LICENSE_SHA256 = {
    "DIFFTASTIC-LICENSE-MIT.txt": (
        "76f1045e65caa521762a76bbddcc24b6e6ec2251a097d0b3975ca35de47f11e2"
    ),
    "RIPGREP-LICENSE.txt": (
        "01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f"
    ),
    "TUNWG-LICENSE-MIT.txt": (
        "d8ac11fb1304443975a04293266bc30227d0dbf01a44f9d51d9ece096aadbe36"
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stream_member_sha256(
    archive: zipfile.ZipFile,
    member: str,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with archive.open(member) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def test_pinned_manifest_and_windows_archive_match_official_release() -> None:
    manifest = json.loads((RUNTIME_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["version"] == "0.25.1"
    assert manifest["source_commit"] == "f0e7e6ad200256550a3cae35b05b9935ed10ad45"
    assert manifest["license"] == "AGPL-3.0-only"
    assert manifest["release_url"].endswith("/releases/tag/v0.25.1")
    assert manifest["checksums_url"].endswith(
        "/releases/download/v0.25.1/checksums.txt"
    )

    bundles = manifest["bundles"]
    assert set(bundles) == {
        "win32-x64",
        "darwin-arm64",
        "darwin-x64",
        "linux-arm64",
        "linux-x64-baseline",
    }
    windows = bundles["win32-x64"]
    assert windows == {
        "asset_name": "hapi-win32-x64.zip",
        "archive_path": "bundles/hapi-v0.25.1-win32-x64.zip",
        "download_url": (
            "https://github.com/tiann/hapi/releases/download/v0.25.1/hapi-win32-x64.zip"
        ),
        "archive_format": "zip",
        "executable": "hapi.exe",
        "size": 68_793_339,
        "sha256": WINDOWS_SHA256,
        "executable_sha256": WINDOWS_EXE_SHA256,
    }
    assert WINDOWS_ARCHIVE.stat().st_size == 68_793_339
    assert _sha256(WINDOWS_ARCHIVE) == WINDOWS_SHA256

    with zipfile.ZipFile(WINDOWS_ARCHIVE) as archive:
        files = [info for info in archive.infolist() if not info.is_dir()]
        assert [info.filename for info in files] == ["hapi.exe"]
        assert files[0].file_size == 149_473_792
        size, digest = _stream_member_sha256(archive, "hapi.exe")
        assert size == 149_473_792
        assert digest == WINDOWS_EXE_SHA256


def test_runtime_licenses_notices_and_builder_are_retained() -> None:
    license_path = RUNTIME_DIR / "licenses" / "HAPI-LICENSE-AGPL-3.0.txt"
    notice_path = RUNTIME_DIR / "licenses" / "HAPI-NOTICE.txt"
    assert _sha256(license_path) == (
        "9a32109537554d51dd83792f3e9d6999376e0974d1d309cb1f922acad3946d1c"
    )
    assert _sha256(notice_path) == (
        "0328f432a576f14cd30a7636675a74f13e9eac224c4c235626ed0f9b0b1dd1a0"
    )
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in license_path.read_text(
        encoding="utf-8"
    )
    notice = notice_path.read_text(encoding="utf-8")
    assert "hapi CLI" in notice
    assert "happy-cli" in notice
    licenses_dir = RUNTIME_DIR / "licenses"
    for name, expected_sha256 in HELPER_LICENSE_SHA256.items():
        helper_license = licenses_dir / name
        assert helper_license.is_file()
        assert not helper_license.is_symlink()
        assert _sha256(helper_license) == expected_sha256
    assert "Copyright (c) 2021-2025 Wilfred Hughes" in (
        licenses_dir / "DIFFTASTIC-LICENSE-MIT.txt"
    ).read_text(encoding="utf-8")
    assert "dual-licensed under the Unlicense and MIT licenses" in (
        licenses_dir / "RIPGREP-LICENSE.txt"
    ).read_text(encoding="utf-8")
    assert "Copyright (c) 2023 Nitin Jain" in (
        licenses_dir / "TUNWG-LICENSE-MIT.txt"
    ).read_text(encoding="utf-8")

    third_party = (RUNTIME_DIR / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert (
        "f0e7e6ad200256550a3cae35b05b9935ed10ad45/cli/src/runtime/embeddedAssets.bun.ts"
    ) in third_party
    assert "Difftastic (`difft.exe` on Windows): MIT License" in third_party
    assert "dual-licensed under the Unlicense and MIT" in third_party
    assert "tunwg (`tunwg.exe` on Windows): MIT License" in third_party
    assert "one byte-identical" in third_party

    official_checksums = (RUNTIME_DIR / "checksums-v0.25.1.txt").read_text(
        encoding="utf-8"
    )
    assert f"{WINDOWS_SHA256}  hapi-win32-x64.zip" in official_checksums
    builder = (RUNTIME_DIR / "prepare_bundle.py").read_text(encoding="utf-8")
    assert "releases/download/v0.25.1/" in builder
    assert "latest" not in builder.lower()


@pytest.mark.plugin_integration
def test_built_plugin_contains_verified_windows_runtime_and_notices(
    tmp_path: Path,
) -> None:
    package = tmp_path / "vibe_coding_connector.neko-plugin"
    build_plugin(PLUGIN_DIR, package)
    prefix = "payload/plugins/vibe_coding_connector/"
    runtime_member = prefix + "runtime/bundles/hapi-v0.25.1-win32-x64.zip"
    required = {
        runtime_member,
        prefix + "runtime/manifest.json",
        prefix + "runtime/checksums-v0.25.1.txt",
        prefix + "runtime/THIRD_PARTY_NOTICES.md",
        prefix + "runtime/licenses/HAPI-LICENSE-AGPL-3.0.txt",
        prefix + "runtime/licenses/HAPI-NOTICE.txt",
        *{prefix + f"runtime/licenses/{name}" for name in HELPER_LICENSE_SHA256},
    }
    with zipfile.ZipFile(package) as archive:
        names = set(archive.namelist())
        assert required <= names
        info = archive.getinfo(runtime_member)
        assert info.file_size == 68_793_339
        size, digest = _stream_member_sha256(archive, runtime_member)
        assert size == 68_793_339
        assert digest == WINDOWS_SHA256
        for name, expected_sha256 in HELPER_LICENSE_SHA256.items():
            member = prefix + f"runtime/licenses/{name}"
            _size, license_digest = _stream_member_sha256(archive, member)
            assert license_digest == expected_sha256
