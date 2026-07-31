"""Fetch one manifest-pinned HAPI release asset and verify it locally."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import urllib.request
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parent
_MANIFEST = _ROOT / "manifest.json"
_CHUNK_SIZE = 1024 * 1024
_MAX_SIZE = 128 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _load_bundle(platform_key: str) -> dict[str, Any]:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("version") != "0.25.1":
        raise RuntimeError("manifest is not pinned to HAPI 0.25.1")
    bundles = manifest.get("bundles")
    value = bundles.get(platform_key) if isinstance(bundles, dict) else None
    if not isinstance(value, dict):
        raise RuntimeError(f"unknown platform key: {platform_key}")
    return value


def _verify(path: Path, bundle: dict[str, Any]) -> None:
    expected_size = bundle.get("size")
    expected_sha256 = bundle.get("sha256")
    if (
        not isinstance(expected_size, int)
        or not 0 < expected_size <= _MAX_SIZE
        or not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
    ):
        raise RuntimeError("invalid pinned bundle metadata")
    if path.stat().st_size != expected_size:
        raise RuntimeError("downloaded byte count does not match manifest")
    if _sha256(path) != expected_sha256:
        raise RuntimeError("downloaded SHA256 does not match manifest")


def prepare(platform_key: str) -> Path:
    """Download and atomically store one locked release archive."""

    bundle = _load_bundle(platform_key)
    relative = bundle.get("archive_path")
    url = bundle.get("download_url")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or not isinstance(url, str)
        or not url.startswith(
            "https://github.com/tiann/hapi/releases/download/v0.25.1/"
        )
    ):
        raise RuntimeError("unsafe bundle path or URL")
    target = (_ROOT / relative).resolve()
    target.relative_to(_ROOT)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file():
        _verify(target, bundle)
        return target

    temporary = target.with_name(
        f".{target.name}.{secrets.token_hex(8)}.part"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "NEKO-vibe-coding-bundle-builder/0.2.0",
        },
    )
    total = 0
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            with temporary.open("xb") as handle:
                while chunk := response.read(_CHUNK_SIZE):
                    total += len(chunk)
                    if total > int(bundle["size"]) or total > _MAX_SIZE:
                        raise RuntimeError("download exceeded pinned size")
                    digest.update(chunk)
                    handle.write(chunk)
        if total != bundle["size"] or digest.hexdigest() != bundle["sha256"]:
            raise RuntimeError("download does not match pinned asset")
        os.replace(temporary, target)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    """Run the locked bundle preparation command."""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--platform",
        required=True,
        choices=(
            "win32-x64",
            "darwin-arm64",
            "darwin-x64",
            "linux-arm64",
            "linux-x64-baseline",
        ),
    )
    arguments = parser.parse_args()
    try:
        path = prepare(arguments.platform)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"bundle preparation failed: {exc}", file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
