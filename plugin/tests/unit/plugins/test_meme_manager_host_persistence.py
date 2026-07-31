from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import pytest

from plugin.core.context import PluginContext
from plugin.plugins.meme_manager import PLUGIN_ID, MemeManagerPlugin
from plugin.sdk.plugin import PluginStore, SdkError

pytestmark = pytest.mark.plugin_unit

_PNG_BASE64 = base64.b64encode(
    base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0l"
        "EQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
).decode("ascii")

_SYSTEM_SOURCES = {"system", "system_default", "default"}
_USER_SOURCES = {"user", "user_upload", "user_uploaded", "uploaded"}


class _NullLogger:
    def debug(self, *_args: object, **_kwargs: object) -> None:
        pass

    info = debug
    warning = debug
    error = debug
    exception = debug


@dataclass
class _Host:
    ctx: PluginContext
    plugin: MemeManagerPlugin
    runtime_root: Path
    install_root: Path


def _make_host(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    effective_config: Mapping[str, Any],
) -> _Host:
    runtime_root = tmp_path / "runtime"
    install_root = tmp_path / "installed" / PLUGIN_ID
    static_root = install_root / "static"
    static_root.mkdir(parents=True, exist_ok=True)

    manifest = install_root / "plugin.toml"
    manifest.write_text(
        "\n".join(
            (
                "[plugin]",
                f'id = "{PLUGIN_ID}"',
                'name = "表情包管理器宿主测试"',
                'version = "0.0.0"',
                "",
            )
        ),
        encoding="utf-8",
    )
    source_panel = static_root / "index.html"
    source_panel.write_text(
        '<!doctype html><meta charset="utf-8"><title>表情包管理器</title>\n',
        encoding="utf-8",
    )

    assert "表情包管理器" in manifest.read_text(encoding="utf-8")
    assert "表情包管理器" in source_panel.read_text(encoding="utf-8")

    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(runtime_root))
    monkeypatch.setenv("NEKO_STORAGE_ANCHOR_ROOT", str(runtime_root))
    ctx = PluginContext(
        plugin_id=PLUGIN_ID,
        config_path=manifest,
        logger=_NullLogger(),  # type: ignore[arg-type]
        status_queue=None,
    )
    ctx._effective_config = deepcopy(dict(effective_config))
    plugin = MemeManagerPlugin(ctx)
    ctx._instance = plugin

    assert isinstance(plugin.store, PluginStore)
    plugin.store.enabled = False
    return _Host(
        ctx=ctx,
        plugin=plugin,
        runtime_root=runtime_root,
        install_root=install_root,
    )


async def _close_host(host: _Host) -> None:
    await host.plugin.store.close()
    host.ctx.close()


def _ok_value(result: Any) -> dict[str, Any]:
    assert result.is_ok(), result
    value = result.value
    assert isinstance(value, dict)
    return value


def _saved_meme(value: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("meme", "entry", "item"):
        item = value.get(key)
        if isinstance(item, dict):
            return item
    raise AssertionError(f"save result has no meme entry: {value!r}")


def _source(item: Mapping[str, Any]) -> str:
    for key in ("source_kind", "source", "source_type", "origin", "kind"):
        value = item.get(key)
        if isinstance(value, str):
            return value.lower()
    return ""


def _entry_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _catalog_list(
    state: Mapping[str, Any],
    *,
    direct_keys: tuple[str, ...],
    sources: set[str],
) -> list[dict[str, Any]]:
    for key in direct_keys:
        entries = _entry_list(state.get(key))
        if entries or isinstance(state.get(key), list):
            return entries

    catalog = state.get("catalog")
    if isinstance(catalog, dict):
        for key in direct_keys:
            entries = _entry_list(catalog.get(key))
            if entries or isinstance(catalog.get(key), list):
                return entries

    for key in ("catalog", "items", "memes"):
        entries = _entry_list(state.get(key))
        if entries:
            tagged = [item for item in entries if _source(item) in sources]
            if tagged:
                return tagged
            if sources == _USER_SOURCES and not any(_source(item) for item in entries):
                return entries
    return []


def _user_memes(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _catalog_list(
        state,
        direct_keys=("user_memes", "user_uploaded", "uploads"),
        sources=_USER_SOURCES,
    )


def _system_memes(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _catalog_list(
        state,
        direct_keys=(
            "system_sources",
            "system_memes",
            "system_defaults",
            "defaults",
        ),
        sources=_SYSTEM_SOURCES,
    )


def _find_meme(state: Mapping[str, Any], meme_id: str) -> dict[str, Any]:
    for meme in _user_memes(state):
        if meme.get("id") == meme_id:
            return meme
    raise AssertionError(f"user meme {meme_id!r} is missing from {state!r}")


@pytest.mark.asyncio
async def test_startup_enables_real_store_and_saved_meme_survives_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = {"plugin": {"store": {"enabled": True}}}
    first = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config=effective,
    )
    try:
        assert first.plugin.store.enabled is False
        _ok_value(await first.plugin.startup())
        assert first.plugin.store.enabled is True

        saved = _saved_meme(
            _ok_value(
                await first.plugin.add_meme(
                    name="真机上传",
                    filename="tiny.png",
                    data_base64=_PNG_BASE64,
                    tags=["持久化", "宿主"],
                )
            )
        )
        meme_id = str(saved["id"])
        stored_name = str(saved["stored_name"])
        assert first.plugin.store._db_path.is_file()
        asset_path = first.plugin._asset_path(stored_name)
        assert asset_path.is_file()
        static_ui = first.plugin.get_static_ui_config()
        assert static_ui is not None
        assert asset_path.resolve().is_relative_to(
            Path(str(static_ui["directory"])).resolve()
        )
        assert first.plugin.store._db_path.resolve().is_relative_to(
            first.runtime_root.resolve()
        )
    finally:
        await _close_host(first)

    reloaded = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config=effective,
    )
    try:
        assert reloaded.plugin.store.enabled is False
        _ok_value(await reloaded.plugin.startup())
        assert reloaded.plugin.store.enabled is True

        state = _ok_value(await reloaded.plugin.get_panel_state())
        meme = _find_meme(state, meme_id)
        assert meme["name"] == "真机上传"
        assert meme["tags"] == ["持久化", "宿主"]
        assert meme["enabled"] is True
        assert meme["available"] is True
        assert reloaded.plugin._asset_path(stored_name).is_file()
    finally:
        await _close_host(reloaded)


@pytest.mark.asyncio
async def test_mutations_and_restore_defaults_survive_real_store_reloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effective = {"plugin": {"store": {"enabled": True}}}
    host = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config=effective,
    )
    try:
        _ok_value(await host.plugin.startup())
        saved = _saved_meme(
            _ok_value(
                await host.plugin.add_meme(
                    name="待修改",
                    filename="mutable.png",
                    data_base64=_PNG_BASE64,
                    tags=["旧标签"],
                )
            )
        )
        meme_id = str(saved["id"])
        _ok_value(await host.plugin.update_meme(meme_id=meme_id, action="disable"))
        await _close_host(host)

        host = _make_host(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            effective_config=effective,
        )
        _ok_value(await host.plugin.startup())
        disabled = _find_meme(
            _ok_value(await host.plugin.get_panel_state()),
            meme_id,
        )
        assert disabled["enabled"] is False
        _ok_value(
            await host.plugin.update_meme(
                meme_id=meme_id,
                action="rename",
                name="已重命名",
                tags=["新标签"],
            )
        )
        _ok_value(await host.plugin.update_meme(meme_id=meme_id, action="enable"))
        await _close_host(host)

        host = _make_host(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            effective_config=effective,
        )
        _ok_value(await host.plugin.startup())
        renamed = _find_meme(
            _ok_value(await host.plugin.get_panel_state()),
            meme_id,
        )
        assert renamed["name"] == "已重命名"
        assert renamed["tags"] == ["新标签"]
        assert renamed["enabled"] is True
        _ok_value(await host.plugin.update_meme(meme_id=meme_id, action="delete"))
        await _close_host(host)

        host = _make_host(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            effective_config=effective,
        )
        _ok_value(await host.plugin.startup())
        deleted_state = _ok_value(await host.plugin.get_panel_state())
        assert all(meme.get("id") != meme_id for meme in _user_memes(deleted_state))

        reset_candidate = _saved_meme(
            _ok_value(
                await host.plugin.add_meme(
                    name="恢复默认时移除",
                    filename="reset.png",
                    data_base64=_PNG_BASE64,
                    tags=["临时"],
                )
            )
        )
        reset_id = str(reset_candidate["id"])
        before_restore = _ok_value(await host.plugin.get_panel_state())
        system_ids = {str(meme["id"]) for meme in _system_memes(before_restore)}
        assert system_ids
        _ok_value(await host.plugin.restore_defaults())
        await _close_host(host)

        host = _make_host(
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            effective_config=effective,
        )
        _ok_value(await host.plugin.startup())
        restored = _ok_value(await host.plugin.get_panel_state())
        assert all(meme.get("id") != reset_id for meme in _user_memes(restored))
        assert {str(meme["id"]) for meme in _system_memes(restored)} == system_ids
    finally:
        await _close_host(host)


@pytest.mark.parametrize(
    "effective_config",
    [
        pytest.param(
            {"plugin": {"store": {"enabled": False}}},
            id="explicit-false",
        ),
        pytest.param({"plugin": {"store": {}}}, id="missing-enabled"),
        pytest.param({"plugin": {}}, id="missing-store"),
        pytest.param({}, id="missing-plugin"),
        pytest.param(
            {"plugin": {"store": {"enabled": "true"}}},
            id="string-true",
        ),
        pytest.param(
            {"plugin": {"store": {"enabled": 1}}},
            id="integer-one",
        ),
        pytest.param(
            {"plugin": {"store": {"enabled": None}}},
            id="null",
        ),
    ],
)
@pytest.mark.asyncio
async def test_startup_does_not_enable_store_without_literal_true(
    effective_config: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config=effective_config,
    )
    try:
        assert host.plugin.store.enabled is False
        _ok_value(await host.plugin.startup())
        assert host.plugin.store.enabled is False
    finally:
        await _close_host(host)


def test_runtime_config_refresh_keeps_store_strictly_boolean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config={"plugin": {"store": {"enabled": False}}},
    )
    try:
        host.ctx._set_effective_config_cache({"plugin": {"store": {"enabled": "true"}}})
        assert host.plugin.store.enabled is False

        host.ctx._set_effective_config_cache({"plugin": {"store": {"enabled": 1}}})
        assert host.plugin.store.enabled is False

        host.ctx._set_effective_config_cache({"plugin": {"store": {"enabled": True}}})
        assert host.plugin.store.enabled is True

        host.ctx._set_effective_config_cache({"plugin": {"store": {}}})
        assert host.plugin.store.enabled is False
    finally:
        host.ctx.close()


@pytest.mark.asyncio
async def test_startup_raises_when_runtime_ui_cannot_be_prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config={"plugin": {"store": {"enabled": True}}},
    )
    monkeypatch.setattr(
        host.plugin,
        "_prepare_runtime_ui",
        lambda: (_ for _ in ()).throw(OSError("runtime data is read-only")),
    )
    try:
        with pytest.raises(SdkError, match="runtime data is read-only"):
            await host.plugin.startup()
    finally:
        await _close_host(host)


@pytest.mark.asyncio
async def test_shutdown_closes_store_after_runtime_disable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _make_host(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        effective_config={"plugin": {"store": {"enabled": True}}},
    )
    try:
        _ok_value(await host.plugin.startup())
        host.plugin.store._write_value("opened", {"value": True})
        assert host.plugin.store._snapshot_conns()

        host.plugin.refresh_runtime_config({"plugin": {"store": {"enabled": False}}})
        assert host.plugin.store.enabled is False
        _ok_value(await host.plugin.shutdown())
        assert host.plugin.store._snapshot_conns() == []
    finally:
        await _close_host(host)
