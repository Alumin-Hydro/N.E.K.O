"""Security and compatibility tests for the managed Agent Skill loader."""

from __future__ import annotations

import inspect
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import plugin.plugins.skill_loader as skill_loader_module
import plugin.plugins.skill_loader._package as package_module
import plugin.plugins.skill_loader._runner as runner_module
import plugin.plugins.skill_loader._sandbox_runner as sandbox_runner_module
from plugin.plugins.skill_loader import (
    EMPTY_SCHEMA,
    PLUGIN_ID,
    READ_SCHEMA,
    RUN_SCHEMA,
    SkillLoaderPlugin,
    _redact,
    parse_skill_markdown,
)
from plugin.plugins.skill_loader._package import (
    DEFAULT_LIMITS,
    PackageError,
    normalize_relative_path,
    scan_skill_package,
)
from plugin.plugins.skill_loader._runner import (
    DEFAULT_RUNNER_LIMITS,
    RunnerError,
    _scan_artifacts,
    run_python_script,
)
from plugin.sdk.plugin import SdkError
from plugin.sdk.plugin.llm_tool import LLM_TOOL_META_ATTR
from plugin.sdk.shared.constants import EVENT_META_ATTR
from plugin.sdk.shared.storage.store import PluginStore

pytestmark = pytest.mark.plugin_unit

_PLUGIN_DIR = Path(__file__).resolve().parents[3] / "plugins" / "skill_loader"

_SKILL_MD = """\
---
name: Fixture Deck Skill
description: Creates a fixture artifact from managed resources.
metadata:
  author: tests
  tags:
    - deck
    - fixture
compatibility:
  claude-code: true
---

# Fixture Deck Skill

Read the [guide](references/guide.md), [editing notes](editing.md), and
[missing note](references/missing.md). Use [the template](templates/base.pptx),
[the asset](assets/cat.png), and `scripts/build.py`.
"""

_SUCCESS_SCRIPT = """\
import json
import os
import sys
from pathlib import Path

output_dir = Path(os.environ["NEKO_SKILL_OUTPUT_DIR"])
payload = {
    "argv": sys.argv[1:],
    "cwd": str(Path.cwd()),
    "root": os.environ["NEKO_SKILL_ROOT"],
    "secret": os.environ.get("UNIT_TEST_SECRET"),
}
(output_dir / "result.json").write_text(
    json.dumps(payload, ensure_ascii=False),
    encoding="utf-8",
)
print(json.dumps(payload, ensure_ascii=False))
"""


class FakeLogger:
    """Logger accepting the SDK's structured logging call shape."""

    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def info(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def warning(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def exception(self, *_args: Any, **_kwargs: Any) -> None:
        pass


class FakeStore:
    """In-memory stand-in exposing the private store primitives used by plugins."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self.data: dict[str, Any] = {}

    def _read_value(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def _write_value(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        self.data[key] = value

    async def close(self) -> None:
        return None


class FakeCtx:
    """Host-shaped context whose effective config differs from constructor state."""

    def __init__(
        self,
        effective_config: dict[str, Any],
        *,
        runtime_config: dict[str, Any] | None = None,
    ) -> None:
        self.plugin_id = PLUGIN_ID
        self.metadata: dict[str, Any] = {}
        self.logger = FakeLogger()
        self.config_path = _PLUGIN_DIR / "plugin.toml"
        self.bus = None
        self._effective_config = dict(runtime_config or {})
        self._returned_effective_config = effective_config

    async def get_own_config(self, timeout: float = 5.0) -> dict[str, Any]:
        assert timeout > 0
        return {
            "plugin_id": self.plugin_id,
            "config": self._returned_effective_config,
            "config_path": str(self.config_path),
        }


class _StatProxy:
    """Expose a real stat result with selected Windows-style field values."""

    def __init__(self, value: os.stat_result, **overrides: int) -> None:
        self._value = value
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._value, name)


class _WindowsDirEntryProxy:
    """Simulate the zero identity/link fields returned by DirEntry on Windows."""

    def __init__(self, entry: Any, stat_calls: list[int]) -> None:
        self._entry = entry
        self._stat_calls = stat_calls

    def __getattr__(self, name: str) -> Any:
        return getattr(self._entry, name)

    def stat(self, *, follow_symlinks: bool = True) -> _StatProxy:
        self._stat_calls[0] += 1
        return _StatProxy(
            self._entry.stat(follow_symlinks=follow_symlinks),
            st_dev=0,
            st_ino=0,
            st_nlink=0,
        )


class _WindowsScandirProxy:
    """Wrap a scandir iterator with Windows-style entry stat results."""

    def __init__(self, iterator: Any, stat_calls: list[int]) -> None:
        self._iterator = iterator
        self._stat_calls = stat_calls

    def __enter__(self) -> _WindowsScandirProxy:
        self._iterator.__enter__()
        return self

    def __exit__(self, *args: object) -> Any:
        return self._iterator.__exit__(*args)

    def __iter__(self) -> _WindowsScandirProxy:
        return self

    def __next__(self) -> _WindowsDirEntryProxy:
        return _WindowsDirEntryProxy(next(self._iterator), self._stat_calls)


def _store_config(enabled: Any = True) -> dict[str, Any]:
    return {"plugin": {"store": {"enabled": enabled}}}


async def _make_ready_plugin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    real_store: bool = False,
) -> SkillLoaderPlugin:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(runtime_root))
    monkeypatch.setenv("NEKO_STORAGE_ANCHOR_ROOT", str(runtime_root))
    plugin = SkillLoaderPlugin(FakeCtx(_store_config(True)))
    if not real_store:
        plugin.store = FakeStore(enabled=False)
    started = await plugin.startup()
    assert started.is_ok(), started
    assert started.value["store_ready"] is True
    return plugin


def _write_complete_skill(
    skill_root: Path,
    *,
    script_source: str = _SUCCESS_SCRIPT,
) -> Path:
    skill_root.mkdir(parents=True)
    for relative in (
        "references/empty",
        "templates",
        "assets",
        "scripts/resources",
    ):
        (skill_root / relative).mkdir(parents=True)
    (skill_root / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_root / "editing.md").write_text(
        "Editing notes from the source snapshot.",
        encoding="utf-8",
    )
    (skill_root / "LICENSE").write_text("Fixture license", encoding="utf-8")
    (skill_root / "references" / "guide.md").write_text(
        "Managed guide v1.",
        encoding="utf-8",
    )
    (skill_root / "templates" / "base.pptx").write_bytes(
        b"PK\x03\x04fixture-template\x00"
    )
    (skill_root / "assets" / "cat.png").write_bytes(b"\x89PNG\r\n\x1a\nfixture-cat\x00")
    (skill_root / "scripts" / "build.py").write_text(
        script_source,
        encoding="utf-8",
    )
    (skill_root / "scripts" / "legacy.sh").write_text(
        "#!/bin/sh\nprintf fixture\n",
        encoding="utf-8",
    )
    (skill_root / "scripts" / "resources" / "note.txt").write_text(
        "script resource",
        encoding="utf-8",
    )
    return skill_root


async def _import_directory(
    plugin: SkillLoaderPlugin,
    source_parent: Path,
    skill_root: Path,
    *,
    skill_id: str = "fixture-skill",
) -> dict[str, Any]:
    saved = await plugin.save_settings(allowed_roots=[str(source_parent)])
    assert saved.is_ok(), saved
    imported = await plugin.import_skill(
        skill_id=skill_id,
        path=str(skill_root),
    )
    assert imported.is_ok(), imported
    return imported.value


def _registry_record(
    plugin: SkillLoaderPlugin, skill_id: str = "fixture-skill"
) -> dict[str, Any]:
    registry = plugin.store._read_value("skill_registry", None)
    assert isinstance(registry, dict)
    return next(item for item in registry["skills"] if item["id"] == skill_id)


def _assert_error(result: Any, code: str) -> SdkError:
    assert result.is_err(), result
    assert isinstance(result.error, SdkError)
    assert result.error.code == code
    return result.error


def test_parse_frontmatter_and_redact() -> None:
    parsed = parse_skill_markdown(_SKILL_MD)
    assert parsed["name"] == "Fixture Deck Skill"
    assert parsed["frontmatter"]["metadata"]["tags"] == ["deck", "fixture"]
    assert "references/guide.md" in parsed["body"]

    redacted = _redact("sk-abcdefgh1234 password: hunter2 .env api_keys.json")
    assert "sk-abcdefgh1234" not in redacted
    assert "hunter2" not in redacted
    assert "api_keys.json" not in redacted


@pytest.mark.parametrize(
    ("raw_path", "expected_code"),
    [
        (r"D:\outside.txt", "absolute_path"),
        ("D:/outside.txt", "absolute_path"),
        (r"D:drive-relative.txt", "absolute_path"),
        (r"\\server\share\outside.txt", "absolute_path"),
        (r"\rooted\outside.txt", "absolute_path"),
        (r"references\guide.md", "invalid_path"),
        (r"..\outside.txt", "invalid_path"),
        ("references/../../outside.txt", "path_traversal"),
    ],
)
def test_normalize_relative_path_classifies_windows_paths_cross_platform(
    raw_path: str,
    expected_code: str,
) -> None:
    with pytest.raises(PackageError) as error:
        normalize_relative_path(raw_path)

    assert error.value.code == expected_code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("configured_value", "expected"),
    [
        (True, True),
        (False, False),
        (1, False),
        ("true", False),
        (None, False),
    ],
)
async def test_effective_config_aligns_store_only_from_explicit_boolean_true(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured_value: Any,
    expected: bool,
) -> None:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(runtime_root))
    monkeypatch.setenv("NEKO_STORAGE_ANCHOR_ROOT", str(runtime_root))
    plugin = SkillLoaderPlugin(FakeCtx(_store_config(configured_value)))
    plugin.store = FakeStore(enabled=False)

    started = await plugin.startup()

    assert started.is_ok()
    assert plugin.store.enabled is expected
    assert started.value["store_ready"] is expected


@pytest.mark.asyncio
async def test_missing_effective_store_setting_does_not_override_runtime_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(runtime_root))
    monkeypatch.setenv("NEKO_STORAGE_ANCHOR_ROOT", str(runtime_root))
    plugin = SkillLoaderPlugin(FakeCtx({"plugin": {}}))
    plugin.store = FakeStore(enabled=True)

    started = await plugin.startup()

    assert started.is_ok()
    assert plugin.store.enabled is True


@pytest.mark.asyncio
async def test_real_store_persists_across_rebuild_and_managed_source_is_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(runtime_root))
    monkeypatch.setenv("NEKO_STORAGE_ANCHOR_ROOT", str(runtime_root))
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")

    first = SkillLoaderPlugin(FakeCtx(_store_config(True)))
    assert isinstance(first.store, PluginStore)
    assert first.store.enabled is False
    started = await first.startup()
    assert started.is_ok()
    assert first.store.enabled is True
    await _import_directory(first, source_parent, skill_root)
    first_record = _registry_record(first)
    generation = first._managed_root / first_record["managed_rel"]
    assert generation.is_dir()
    (skill_root / "references" / "guide.md").unlink()
    closed = await first.store.close()
    assert closed.is_ok()

    rebuilt = SkillLoaderPlugin(FakeCtx(_store_config(True)))
    assert rebuilt.store.enabled is False
    restarted = await rebuilt.startup()
    assert restarted.is_ok()
    panel = await rebuilt.get_panel_state()
    assert panel.is_ok()
    assert panel.value["settings"]["allowed_roots"] == [str(source_parent.resolve())]
    assert [item["id"] for item in panel.value["skills"]] == ["fixture-skill"]
    read = await rebuilt.skill_loader_read(
        skill_id="fixture-skill",
        path="references/guide.md",
    )
    assert read.is_ok()
    assert read.value["content"] == "Managed guide v1."
    assert generation.is_dir()
    closed = await rebuilt.store.close()
    assert closed.is_ok()


@pytest.mark.asyncio
async def test_legacy_registry_migrates_only_persisted_snapshot_without_source_reread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    untrusted_source = tmp_path / "old-external-source"
    untrusted_source.mkdir()
    (untrusted_source / "SKILL.md").write_text(
        "# Source Changed\n\nMUST-NOT-BE-MIGRATED",
        encoding="utf-8",
    )
    snapshot = "# Legacy Snapshot\n\nPersisted safe content."
    plugin.store.data["skill_registry"] = {
        "skills": [
            {
                "id": "legacy-skill",
                "name": "Legacy Skill",
                "description": "Migrated from v0.1",
                "source": str(untrusted_source),
                "inline_content": snapshot,
                "enabled": True,
                "added_at": 1234.5,
            },
            {"id": "Bad ID", "source": str(untrusted_source)},
        ]
    }

    panel = await plugin.get_panel_state()

    assert panel.is_ok(), panel
    assert [item["id"] for item in panel.value["skills"]] == ["legacy-skill"]
    assert panel.value["migration"]["from"] == "0.1"
    assert panel.value["migration"]["imported"] == 1
    assert panel.value["migration"]["external_paths_reread"] is False
    assert panel.value["migration"]["skipped"][0]["entry"] == "legacy-2"
    migrated = _registry_record(plugin, "legacy-skill")
    assert migrated["source"]["kind"] == "legacy-snapshot"
    assert migrated["authorization"]["script_execution"] is False
    read = await plugin.skill_loader_read(skill_id="legacy-skill")
    assert read.is_ok()
    assert read.value["content"] == snapshot
    assert "MUST-NOT-BE-MIGRATED" not in repr(panel.value)


@pytest.mark.asyncio
async def test_complete_directory_import_manifest_and_managed_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")

    imported = await _import_directory(plugin, source_parent, skill_root)
    panel_skill = imported["skill"]
    record = _registry_record(plugin)
    manifest = record["manifest"]
    generation = plugin._managed_root / record["managed_rel"]
    manifest_paths = {item["path"] for item in manifest["files"]}

    assert manifest["format"] == "agent-skill-directory"
    assert manifest["frontmatter"]["metadata"]["author"] == "tests"
    assert manifest["frontmatter"]["compatibility"]["claude-code"] is True
    assert manifest["totals"]["files"] == len(manifest_paths)
    assert {
        "SKILL.md",
        "editing.md",
        "LICENSE",
        "references/guide.md",
        "templates/base.pptx",
        "assets/cat.png",
        "scripts/build.py",
        "scripts/legacy.sh",
        "scripts/resources/note.txt",
    } <= manifest_paths
    assert "references/empty" in manifest["directories"]
    assert manifest["capabilities"] == {
        **manifest["capabilities"],
        "complete_directory": True,
        "has_references": True,
        "has_templates": True,
        "has_assets": True,
        "has_scripts": True,
        "supported_script_count": 1,
        "unsupported_script_count": 1,
        "script_execution_requires_authorization": True,
    }
    assert any(
        item["path"] == "references/missing.md" and item["exists"] is False
        for item in manifest["linked_paths"]
    )
    assert any(
        item["name"] == "references/missing.md" and item["status"] == "missing"
        for item in manifest["dependencies"]
    )
    assert panel_skill["source"]["kind"] == "directory"
    assert panel_skill["authorization"]["script_execution"] is False
    assert {item["kind"] for item in panel_skill["linked_files"]} >= {
        "references",
        "templates",
        "assets",
        "scripts",
    }
    assert {item["path"] for item in panel_skill["scripts"]} == {
        "scripts/build.py",
        "scripts/legacy.sh",
    }
    for relative_path in manifest_paths:
        assert (generation / relative_path).is_file()

    (skill_root / "references" / "guide.md").write_text(
        "source changed after import",
        encoding="utf-8",
    )
    managed_read = await plugin.skill_loader_read(
        skill_id="fixture-skill",
        path="references/guide.md",
    )
    assert managed_read.is_ok()
    assert managed_read.value["content"] == "Managed guide v1."


@pytest.mark.asyncio
async def test_read_requires_canonical_manifest_member_and_hides_binary_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")
    await _import_directory(plugin, source_parent, skill_root)
    record = _registry_record(plugin)
    generation = plugin._managed_root / record["managed_rel"]
    (generation / "injected.txt").write_text("not in manifest", encoding="utf-8")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("must not be returned", encoding="utf-8")

    injected = await plugin.skill_loader_read(
        skill_id="fixture-skill",
        path="injected.txt",
    )
    _assert_error(injected, "file_not_in_manifest")
    traversal = await plugin.skill_loader_read(
        skill_id="fixture-skill",
        path="../outside-secret.txt",
    )
    _assert_error(traversal, "path_traversal")
    absolute = await plugin.skill_loader_read(
        skill_id="fixture-skill",
        path=str(outside),
    )
    _assert_error(absolute, "absolute_path")
    binary = await plugin.skill_loader_read(
        skill_id="fixture-skill",
        path="templates/base.pptx",
    )
    assert binary.is_ok()
    assert binary.value["readable"] is False
    assert binary.value["content"] == ""
    assert binary.value["size_bytes"] > 0
    assert "must not be returned" not in repr(binary.value)


@pytest.mark.asyncio
async def test_import_rejects_lexical_traversal_and_escaping_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (skill_root / "references" / "escape.txt").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")
    saved = await plugin.save_settings(allowed_roots=[str(source_parent)])
    assert saved.is_ok()

    traversal_path = str(skill_root / ".." / "fixture")
    traversed = await plugin.import_skill(
        skill_id="traversal",
        path=traversal_path,
    )
    _assert_error(traversed, "path_traversal")
    linked = await plugin.import_skill(skill_id="linked", path=str(skill_root))
    _assert_error(linked, "symlink_rejected")
    with pytest.raises(PackageError, match="traversal") as error:
        normalize_relative_path("references/../../outside.txt")
    assert error.value.code == "path_traversal"


@pytest.mark.asyncio
async def test_import_rejects_allowed_root_replaced_by_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    saved = await plugin.save_settings(allowed_roots=[str(allowed_root)])
    assert saved.is_ok()

    original_root = tmp_path / "allowed-original"
    allowed_root.rename(original_root)
    replacement_root = tmp_path / "replacement"
    _write_complete_skill(replacement_root / "fixture")
    try:
        allowed_root.symlink_to(replacement_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    imported = await plugin.import_skill(
        skill_id="root-swap",
        path=str(allowed_root / "fixture"),
    )

    _assert_error(imported, "source_not_allowed")
    registry = plugin.store._read_value("skill_registry", None)
    assert isinstance(registry, dict)
    assert registry["skills"] == []


def test_package_limits_reject_file_count_single_file_and_total_size(
    tmp_path: Path,
) -> None:
    single = tmp_path / "single"
    single.mkdir()
    (single / "SKILL.md").write_text("# Small\n", encoding="utf-8")
    (single / "large.bin").write_bytes(b"x" * 257)
    small_limits = replace(
        DEFAULT_LIMITS,
        max_file_bytes=256,
        max_total_bytes=1024,
        max_skill_md_bytes=256,
        max_read_bytes=256,
    )
    with pytest.raises(PackageError) as single_error:
        scan_skill_package(single, small_limits)
    assert single_error.value.code == "file_too_large"

    many = tmp_path / "many"
    many.mkdir()
    (many / "SKILL.md").write_text("# Many\n", encoding="utf-8")
    (many / "one.md").write_text("one", encoding="utf-8")
    (many / "two.md").write_text("two", encoding="utf-8")
    with pytest.raises(PackageError) as count_error:
        scan_skill_package(many, replace(DEFAULT_LIMITS, max_files=2))
    assert count_error.value.code == "too_many_files"

    total = tmp_path / "total"
    total.mkdir()
    (total / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (total / "payload.bin").write_bytes(b"x" * 500)
    total_limits = replace(
        DEFAULT_LIMITS,
        max_file_bytes=512,
        max_total_bytes=600,
        max_skill_md_bytes=512,
        max_read_bytes=512,
    )
    with pytest.raises(PackageError) as total_error:
        scan_skill_package(total, total_limits)
    assert total_error.value.code == "package_too_large"


def test_package_rejects_special_file_and_non_utf8_skill(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "SKILL.md").write_bytes(b"\xff\xfe")
    with pytest.raises(PackageError) as utf8_error:
        scan_skill_package(invalid)
    assert utf8_error.value.code == "invalid_utf8"

    if not hasattr(os, "mkfifo"):
        return
    special = tmp_path / "special"
    special.mkdir()
    (special / "SKILL.md").write_text("# Special\n", encoding="utf-8")
    try:
        os.mkfifo(special / "pipe")
    except OSError as exc:
        pytest.skip(f"FIFO creation is unavailable: {exc}")
    with pytest.raises(PackageError) as special_error:
        scan_skill_package(special)
    assert special_error.value.code == "special_file_rejected"


def test_windows_stat_identity_noise_does_not_define_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = _write_complete_skill(tmp_path / "fixture")
    real_stat = package_module.os.stat
    real_fstat = package_module.os.fstat
    calls = 0

    def unstable_fields(value: os.stat_result) -> _StatProxy:
        nonlocal calls
        calls += 1
        return _StatProxy(
            value,
            st_mode=(value.st_mode & ~0o777) | (0o600 if calls % 2 else 0o400),
            st_dev=calls % 3,
            st_ino=10_000 + calls,
            st_mtime_ns=20_000 + calls,
            st_ctime_ns=30_000 + calls,
        )

    def unstable_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> _StatProxy:
        return unstable_fields(
            real_stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )
        )

    def unstable_fstat(descriptor: int) -> _StatProxy:
        return unstable_fields(real_fstat(descriptor))

    monkeypatch.setattr(package_module.os, "stat", unstable_stat)
    monkeypatch.setattr(package_module.os, "fstat", unstable_fstat)

    package = scan_skill_package(skill_root)

    assert package.manifest["totals"]["files"] == 9
    assert package.manifest["skill"]["sha256"] == next(
        item.sha256 for item in package.files if item.path == "SKILL.md"
    )


def test_windows_stat_identity_noise_preserves_source_error_priority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fstat = package_module.os.fstat
    calls = 0

    def unstable_fstat(descriptor: int) -> _StatProxy:
        nonlocal calls
        calls += 1
        return _StatProxy(
            real_fstat(descriptor),
            st_dev=calls,
            st_ino=10_000 + calls,
            st_mtime_ns=20_000 + calls,
            st_ctime_ns=30_000 + calls,
        )

    monkeypatch.setattr(package_module.os, "fstat", unstable_fstat)

    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "SKILL.md").write_bytes(b"\xff\xfe")
    with pytest.raises(PackageError) as invalid_error:
        scan_skill_package(invalid)
    assert invalid_error.value.code == "invalid_utf8"

    oversized = tmp_path / "oversized"
    oversized.mkdir()
    (oversized / "SKILL.md").write_bytes(b"x" * 17)
    limits = replace(
        DEFAULT_LIMITS,
        max_file_bytes=16,
        max_total_bytes=32,
        max_skill_md_bytes=16,
        max_read_bytes=16,
    )
    with pytest.raises(PackageError) as oversized_error:
        scan_skill_package(oversized, limits)
    assert oversized_error.value.code == "file_too_large"

    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "SKILL.md").write_text("# Linked\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (linked / "escape.txt").symlink_to(outside)
    except OSError:
        return
    with pytest.raises(PackageError) as linked_error:
        scan_skill_package(linked)
    assert linked_error.value.code == "symlink_rejected"


def test_source_snapshot_rejects_same_size_content_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = tmp_path / "changing"
    skill_root.mkdir()
    skill_file = skill_root / "SKILL.md"
    skill_file.write_text("# Alpha\n", encoding="utf-8")
    real_scandir = package_module.os.scandir
    root_scans = 0

    def changing_scandir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> Any:
        nonlocal root_scans
        if Path(path) == skill_root:
            root_scans += 1
            if root_scans == 2:
                skill_file.write_text("# Bravo\n", encoding="utf-8")
        return real_scandir(path)

    monkeypatch.setattr(package_module.os, "scandir", changing_scandir)

    with pytest.raises(PackageError) as error:
        scan_skill_package(skill_root)

    assert error.value.code == "source_changed"
    assert error.value.path == "SKILL.md"


def test_source_rejects_windows_reparse_attribute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = tmp_path / "reparse"
    skill_root.mkdir()
    skill_file = skill_root / "SKILL.md"
    skill_file.write_text("# Reparse\n", encoding="utf-8")
    real_stat = package_module.os.stat
    reparse_flag = 0x400
    monkeypatch.setattr(
        package_module.stat,
        "FILE_ATTRIBUTE_REPARSE_POINT",
        reparse_flag,
        raising=False,
    )

    def reparse_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result | _StatProxy:
        value = real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if Path(path) == skill_file:
            return _StatProxy(value, st_file_attributes=reparse_flag)
        return value

    monkeypatch.setattr(package_module.os, "stat", reparse_stat)

    with pytest.raises(PackageError) as error:
        scan_skill_package(skill_root)

    assert error.value.code == "symlink_rejected"


def test_source_swap_to_escaping_symlink_before_open_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = tmp_path / "swap"
    skill_root.mkdir()
    skill_file = skill_root / "SKILL.md"
    skill_file.write_text("# Original\n", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("# Outside\n", encoding="utf-8")
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(outside)
        probe.unlink()
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")
    real_open = package_module.os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and Path(path) == skill_file:
            swapped = True
            skill_file.unlink()
            skill_file.symlink_to(outside)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(package_module.os, "open", swapping_open)

    with pytest.raises(PackageError) as error:
        scan_skill_package(skill_root)

    assert error.value.code == "symlink_rejected"
    assert error.value.path == "SKILL.md"


@pytest.mark.asyncio
async def test_llm_run_hard_rejects_unauthorized_skill_before_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")
    await _import_directory(plugin, source_parent, skill_root)

    async def forbidden_runner(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("runner must not be reached without authorization")

    monkeypatch.setattr(skill_loader_module, "run_python_script", forbidden_runner)
    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[],
    )
    _assert_error(result, "script_not_authorized")


@pytest.mark.asyncio
async def test_authorized_run_rejects_managed_script_changed_after_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")
    await _import_directory(plugin, source_parent, skill_root)
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()
    record = _registry_record(plugin)
    managed_script = (
        plugin._managed_root / record["managed_rel"] / "scripts" / "build.py"
    )
    managed_script.write_text(
        managed_script.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )

    async def forbidden_runner(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("tampered managed scripts must fail before spawn")

    monkeypatch.setattr(skill_loader_module, "run_python_script", forbidden_runner)
    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[],
    )

    _assert_error(result, "managed_file_changed")


@pytest.mark.asyncio
async def test_authorized_script_uses_argv_only_fixed_cwd_and_managed_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")
    await _import_directory(plugin, source_parent, skill_root)
    authorized = await plugin.set_script_authorization(
        skill_id="fixture-skill",
        authorized=True,
    )
    assert authorized.is_ok()
    monkeypatch.setenv("UNIT_TEST_SECRET", "must-not-be-inherited")
    original_popen = runner_module.subprocess.Popen
    popen_calls: list[dict[str, Any]] = []

    def recording_popen(*args: Any, **kwargs: Any):
        popen_calls.append(dict(kwargs))
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(runner_module.subprocess, "Popen", recording_popen)
    literal_arg = "alpha; touch should-never-run"
    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[literal_arg, "猫"],
        timeout_seconds=10,
    )

    assert result.is_ok(), result
    assert result.value["status"] == "succeeded"
    payload = json.loads(result.value["stdout"])
    assert payload["argv"] == [literal_arg, "猫"]
    assert payload["cwd"] == result.value["cwd"]
    assert payload["root"] == result.value["cwd"]
    assert payload["secret"] is None
    managed_root = plugin._managed_root.resolve()
    Path(result.value["cwd"]).resolve().relative_to(managed_root)
    output_dir = Path(result.value["output_dir"]).resolve()
    output_dir.relative_to(Path(result.value["cwd"]).resolve())
    assert result.value["artifact_count"] == 1
    artifact = result.value["artifacts"][0]
    assert artifact["relative_path"] == "result.json"
    Path(artifact["path"]).resolve().relative_to(output_dir)
    assert json.loads(Path(artifact["path"]).read_text(encoding="utf-8")) == payload

    assert len(popen_calls) == 1
    call = popen_calls[0]
    assert call["shell"] is False
    assert isinstance(call["args"], list)
    assert literal_arg in call["args"]
    assert call["cwd"] == result.value["cwd"]
    assert "UNIT_TEST_SECRET" not in call["env"]
    assert "HTTP_PROXY" not in call["env"]
    assert not any("yolo" in str(token).lower() for token in call["args"])
    assert "--dangerously-skip-permissions" not in call["args"]


@pytest.mark.asyncio
async def test_sandbox_launcher_allowance_is_exact_and_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe_script = """\
import os
import sys
from pathlib import Path

operation, target = sys.argv[1:3]
if operation == "stat":
    print(os.stat(target).st_size)
elif operation == "read":
    print(len(Path(target).read_bytes()))
elif operation == "list":
    print(len(os.listdir(target)))
elif operation == "write":
    with Path(target).open("r+", encoding="utf-8"):
        pass
else:
    raise RuntimeError("unexpected probe operation")
"""
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(
        source_parent / "fixture",
        script_source=probe_script,
    )
    await _import_directory(plugin, source_parent, skill_root)
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()

    launcher = Path(sandbox_runner_module.__file__).resolve()
    sibling_plugin_file = launcher.with_name("_runner.py")
    repository_file = _PLUGIN_DIR.parents[2] / "pyproject.toml"
    outside_secret = tmp_path / "outside-secret.txt"
    outside_secret.write_text("SECRET-MUST-NOT-LEAK", encoding="utf-8")
    assert launcher.is_file()
    assert sibling_plugin_file.is_file()
    assert repository_file.is_file()

    launcher_stat = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=["stat", str(launcher)],
        timeout_seconds=10,
    )

    assert launcher_stat.is_ok(), launcher_stat
    assert int(launcher_stat.value["stdout"].strip()) == launcher.stat().st_size

    launcher_read = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=["read", str(launcher)],
        timeout_seconds=10,
    )

    assert launcher_read.is_ok(), launcher_read
    assert int(launcher_read.value["stdout"].strip()) == launcher.stat().st_size

    denied_probes = [
        ("list", launcher.parent),
        ("stat", launcher.parent),
        ("stat", sibling_plugin_file),
        ("read", sibling_plugin_file),
        ("stat", repository_file),
        ("read", repository_file),
        ("stat", outside_secret),
        ("read", outside_secret),
        ("write", launcher),
    ]
    for operation, target in denied_probes:
        denied = await plugin.skill_loader_run_script(
            skill_id="fixture-skill",
            script_path="scripts/build.py",
            argv=[operation, str(target)],
            timeout_seconds=10,
        )
        error = _assert_error(denied, "sandbox_violation")
        assert isinstance(error.details, dict)
        assert error.details["status"] == "sandbox_violation"
        assert "SECRET-MUST-NOT-LEAK" not in repr(denied)


def test_sandbox_launcher_read_policy_is_exact_and_rejects_path_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = (tmp_path / "managed").resolve()
    output_dir = skill_root / "runs" / "fixture"
    output_dir.mkdir(parents=True)
    launcher = (tmp_path / "plugin" / "_sandbox_runner.py").resolve()
    launcher.parent.mkdir()
    launcher.write_text("# trusted launcher\n", encoding="utf-8")
    policy = sandbox_runner_module._AuditPolicy(
        skill_root=skill_root,
        output_dir=output_dir,
        system_roots=(),
        trusted_launcher_files=(launcher,),
    )

    assert policy.check_stat(launcher) == launcher
    assert policy.check_open_read(launcher) == launcher
    for event in ("os.listdir", "os.scandir", "os.lstat", "os.readlink"):
        with pytest.raises(sandbox_runner_module.SandboxViolation):
            policy.audit(event, (launcher,))

    hardlink_alias = launcher.with_name("hardlink-alias.py")
    os.link(launcher, hardlink_alias)
    with pytest.raises(sandbox_runner_module.SandboxViolation):
        policy.check_stat(hardlink_alias)
    with pytest.raises(sandbox_runner_module.SandboxViolation):
        policy.check_open_read(hardlink_alias)

    symlink_alias = launcher.with_name("symlink-alias.py")

    def resolve_alias(
        value: object,
        *,
        operation: str,
    ) -> tuple[Path, Path]:
        assert Path(value) == symlink_alias
        assert operation in {"open", "os.stat"}
        return symlink_alias, launcher

    monkeypatch.setattr(policy, "_resolved", resolve_alias)
    with pytest.raises(sandbox_runner_module.SandboxViolation):
        policy.check_stat(symlink_alias)
    with pytest.raises(sandbox_runner_module.SandboxViolation):
        policy.check_open_read(symlink_alias)


def test_sandbox_launcher_read_allowance_never_applies_to_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = (tmp_path / "managed").resolve()
    output_dir = skill_root / "runs" / "fixture"
    output_dir.mkdir(parents=True)
    launcher = (tmp_path / "plugin" / "_sandbox_runner.py").resolve()
    launcher.parent.mkdir()
    launcher.write_text("# trusted launcher\n", encoding="utf-8")
    policy = sandbox_runner_module._AuditPolicy(
        skill_root=skill_root,
        output_dir=output_dir,
        system_roots=(),
        trusted_launcher_files=(launcher,),
    )
    temporary_flag = getattr(os, "O_TEMPORARY", 1 << 29)
    monkeypatch.setattr(
        sandbox_runner_module.os,
        "O_TEMPORARY",
        temporary_flag,
        raising=False,
    )

    mutation_events = [
        ("open", (launcher, "r+", 0)),
        ("open", (launcher, None, temporary_flag)),
        ("os.remove", (launcher,)),
        ("os.unlink", (launcher,)),
        ("os.rename", (launcher, launcher.with_name("renamed.py"))),
        ("os.replace", (launcher, launcher.with_name("replaced.py"))),
        ("os.chmod", (launcher, 0o600)),
        ("os.truncate", (launcher, 0)),
    ]
    for event, args in mutation_events:
        with pytest.raises(sandbox_runner_module.SandboxViolation):
            policy.audit(event, args)


@pytest.mark.asyncio
async def test_script_timeout_is_reported_and_process_is_stopped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeout_script = """\
import os
import time
from pathlib import Path

time.sleep(10)
Path(os.environ["NEKO_SKILL_OUTPUT_DIR"], "too-late.txt").write_text(
    "not expected",
    encoding="utf-8",
)
"""
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(
        source_parent / "fixture",
        script_source=timeout_script,
    )
    await _import_directory(plugin, source_parent, skill_root)
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()

    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[],
        timeout_seconds=1,
    )

    error = _assert_error(result, "script_timeout")
    assert isinstance(error.details, dict)
    assert error.details["status"] == "timed_out"
    assert error.details["artifact_count"] == 0
    assert not (Path(error.details["output_dir"]) / "too-late.txt").exists()


@pytest.mark.asyncio
async def test_script_stdout_is_bounded_and_marked_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_script = """\
import sys

sys.stdout.write("x" * 200000)
"""
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(
        source_parent / "fixture",
        script_source=output_script,
    )
    await _import_directory(plugin, source_parent, skill_root)
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()

    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[],
        timeout_seconds=10,
    )

    assert result.is_ok(), result
    assert result.value["stdout_truncated"] is True
    assert result.value["stdout_bytes"] == 200000
    assert len(result.value["stdout"].encode("utf-8")) == 128 * 1024


@pytest.mark.asyncio
async def test_windows_direntry_stat_does_not_mask_artifact_size_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_script = """\
import os
from pathlib import Path

Path(os.environ["NEKO_SKILL_OUTPUT_DIR"], "too-large.bin").write_bytes(b"x" * 2048)
"""
    skill_root = _write_complete_skill(
        tmp_path / "managed-fixture",
        script_source=artifact_script,
    )
    limits = replace(
        DEFAULT_RUNNER_LIMITS,
        max_artifact_bytes=1024,
        max_total_artifact_bytes=2048,
    )
    real_scandir = runner_module.os.scandir
    direntry_stat_calls = [0]

    def windows_scandir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> _WindowsScandirProxy:
        return _WindowsScandirProxy(real_scandir(path), direntry_stat_calls)

    monkeypatch.setattr(runner_module.os, "scandir", windows_scandir)

    result = await run_python_script(
        skill_root,
        "scripts/build.py",
        [],
        skill_root / ".fixture-runs",
        10,
        limits,
    )

    assert result["ok"] is False
    assert result["status"] == "output_rejected"
    assert result["diagnostic"]["code"] == "artifact_too_large"
    assert direntry_stat_calls == [0]


@pytest.mark.parametrize("entry_type", ["file", "directory"])
def test_artifact_scan_rejects_windows_reparse_points(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_type: str,
) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    entry = output_dir / "reparse-entry"
    if entry_type == "file":
        entry.write_bytes(b"artifact")
    else:
        entry.mkdir()
    real_stat = runner_module.os.stat
    reparse_flag = 0x400
    monkeypatch.setattr(
        runner_module.stat,
        "FILE_ATTRIBUTE_REPARSE_POINT",
        reparse_flag,
        raising=False,
    )

    def reparse_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result | _StatProxy:
        value = real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if Path(path) == entry:
            return _StatProxy(value, st_file_attributes=reparse_flag)
        return value

    monkeypatch.setattr(runner_module.os, "stat", reparse_stat)

    with pytest.raises(RunnerError) as error:
        _scan_artifacts(
            output_dir,
            limits=DEFAULT_RUNNER_LIMITS,
            include_records=True,
        )

    assert error.value.code == "unsafe_artifact"


def test_artifact_scan_still_rejects_hard_links(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    first = output_dir / "first.bin"
    first.write_bytes(b"artifact")
    try:
        os.link(first, output_dir / "second.bin")
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(RunnerError) as error:
        _scan_artifacts(
            output_dir,
            limits=DEFAULT_RUNNER_LIMITS,
            include_records=True,
        )

    assert error.value.code == "unsafe_artifact"


@pytest.mark.asyncio
async def test_missing_dependency_returns_beginner_diagnostic_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_module = "neko_fixture_dependency_that_does_not_exist"
    dependency_script = f"import {missing_module}\nprint('unreachable')\n"
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(
        source_parent / "fixture",
        script_source=dependency_script,
    )
    imported = await _import_directory(plugin, source_parent, skill_root)
    assert any(
        item["name"] == missing_module and item["status"] == "missing"
        for item in imported["skill"]["dependencies"]
    )
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()

    async def forbidden_runner(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("known-missing dependencies must fail before spawn")

    monkeypatch.setattr(skill_loader_module, "run_python_script", forbidden_runner)
    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[],
    )

    error = _assert_error(result, "missing_dependency")
    assert missing_module in str(error)
    assert isinstance(error.details, dict)
    assert error.details["dependencies"] == [missing_module]
    assert "不会自动安装" in str(error)


@pytest.mark.asyncio
async def test_script_cannot_read_outside_managed_skill_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    escape_script = """\
import sys
from pathlib import Path

print(Path(sys.argv[1]).read_text(encoding="utf-8"))
"""
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(
        source_parent / "fixture",
        script_source=escape_script,
    )
    await _import_directory(plugin, source_parent, skill_root)
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("SECRET-MUST-NOT-LEAK", encoding="utf-8")

    result = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[str(outside)],
        timeout_seconds=10,
    )

    error = _assert_error(result, "sandbox_violation")
    assert isinstance(error.details, dict)
    assert error.details["status"] == "sandbox_violation"
    assert "SECRET-MUST-NOT-LEAK" not in repr(error.details)


@pytest.mark.asyncio
async def test_changed_refresh_replaces_copy_and_revokes_revision_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)
    source_parent = tmp_path / "allowed"
    skill_root = _write_complete_skill(source_parent / "fixture")
    await _import_directory(plugin, source_parent, skill_root)
    assert (
        await plugin.set_script_authorization(
            skill_id="fixture-skill",
            authorized=True,
        )
    ).is_ok()
    old_record = _registry_record(plugin)
    old_generation = plugin._managed_root / old_record["managed_rel"]
    script = skill_root / "scripts" / "build.py"
    script.write_text(
        script.read_text(encoding="utf-8") + "\n# revision two\n",
        encoding="utf-8",
    )
    (skill_root / "references" / "guide.md").write_text(
        "Managed guide v2.",
        encoding="utf-8",
    )

    refreshed = await plugin.update_skill(
        skill_id="fixture-skill",
        action="refresh",
    )

    assert refreshed.is_ok(), refreshed
    assert refreshed.value["changed"] is True
    assert refreshed.value["authorization_revoked"] is True
    assert refreshed.value["skill"]["authorization"]["script_execution"] is False
    assert not old_generation.exists()
    read = await plugin.skill_loader_read(
        skill_id="fixture-skill",
        path="references/guide.md",
    )
    assert read.is_ok()
    assert read.value["content"] == "Managed guide v2."
    denied = await plugin.skill_loader_run_script(
        skill_id="fixture-skill",
        script_path="scripts/build.py",
        argv=[],
    )
    _assert_error(denied, "script_not_authorized")


@pytest.mark.parametrize(
    ("method_name", "tool_name", "schema"),
    [
        ("skill_loader_list", "skill_loader_list", EMPTY_SCHEMA),
        ("skill_loader_read", "skill_loader_read", READ_SCHEMA),
        ("skill_loader_run_script", "skill_loader_run_script", RUN_SCHEMA),
    ],
)
def test_llm_tools_are_also_strict_plugin_entries_with_kwargs_compatibility(
    method_name: str,
    tool_name: str,
    schema: dict[str, Any],
) -> None:
    method = getattr(SkillLoaderPlugin, method_name)
    entry_meta = getattr(method, EVENT_META_ATTR, None)
    llm_meta = getattr(method, LLM_TOOL_META_ATTR, None)

    assert entry_meta is not None
    assert entry_meta.event_type == "plugin_entry"
    assert entry_meta.id == tool_name
    assert entry_meta.input_schema == schema
    assert llm_meta is not None
    assert llm_meta.name == tool_name
    assert llm_meta.parameters == schema
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    kwargs = inspect.signature(method).parameters["_"]
    assert kwargs.kind is inspect.Parameter.VAR_KEYWORD


@pytest.mark.asyncio
async def test_kwargs_accepts_host_context_but_rejects_unknown_model_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = await _make_ready_plugin(tmp_path, monkeypatch)

    host_call = await plugin.skill_loader_list(_ctx={"run_id": "fixture"})
    assert host_call.is_ok()
    unexpected = await plugin.skill_loader_list(undeclared=True)
    _assert_error(unexpected, "unexpected_arguments")
