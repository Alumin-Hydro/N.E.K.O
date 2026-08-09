"""Unified catalog and system-source tests for meme_manager."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote

import pytest

from plugin.plugins.meme_manager import PLUGIN_ID, MemeManagerPlugin

pytestmark = pytest.mark.plugin_unit

_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class FakeStore:
    def __init__(self) -> None:
        self.enabled = True
        self.data: dict[str, Any] = {}

    def _read_value(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def _write_value(self, key: str, value: Any) -> None:
        self.data[key] = value


class FakeCtx:
    plugin_id = PLUGIN_ID

    def __init__(self) -> None:
        self.pushes: list[dict[str, Any]] = []

    def push_message(self, **kwargs: Any) -> dict[str, bool]:
        self.pushes.append(kwargs)
        return {"ok": True}


@dataclass(frozen=True)
class FakeModeration:
    allowed: bool

    def __bool__(self) -> bool:
        return self.allowed


def _make_plugin(tmp_path, monkeypatch) -> tuple[MemeManagerPlugin, FakeCtx]:
    ctx = FakeCtx()
    plugin = MemeManagerPlugin(ctx)
    plugin.store = FakeStore()
    monkeypatch.setattr(type(plugin), "config_dir", property(lambda self: tmp_path))
    meme_dir = tmp_path / "static" / "memes"
    meme_dir.mkdir(parents=True)
    plugin._meme_dir = meme_dir
    monkeypatch.setattr(plugin, "push_message", ctx.push_message)

    async def fake_proxy_preflight(_url: str) -> bool:
        return True

    monkeypatch.setattr(
        plugin,
        "_system_candidate_fetchable",
        fake_proxy_preflight,
    )
    return plugin, ctx


def _source_kind(item: Mapping[str, Any]) -> str:
    return str(item.get("source_kind") or item.get("origin") or "")


def _candidate_url(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str:
    candidate = kwargs.get("candidate")
    if candidate is None:
        candidate = kwargs.get("url")
    if candidate is None and args:
        candidate = args[0]
    if isinstance(candidate, Mapping):
        return str(candidate.get("url") or "")
    return str(candidate or "")


def _system_payload(*items: dict[str, Any], source: str = "Imgflip") -> dict[str, Any]:
    return {
        "success": True,
        "data": list(items),
        "formatted_content": "fake system meme results",
        "raw_data": {"data": list(items)},
        "keyword_used": "system query",
        "source": source,
        "region": "non-china",
    }


def _system_item(url: str, *, title: str, item_id: str) -> dict[str, Any]:
    return {
        "type": "meme",
        "id": item_id,
        "url": url,
        "page_url": f"https://imgflip.com/i/{item_id}",
        "title": title,
        "source": "Imgflip",
    }


async def _add_user_meme(
    plugin: MemeManagerPlugin,
    *,
    name: str = "Happy cat",
    tags: list[str] | None = None,
) -> str:
    result = await plugin.add_meme(
        name=name,
        filename="user.png",
        data_base64=_PNG,
        tags=tags or ["happy"],
    )
    assert result.is_ok(), result
    return str(result.value["meme"]["id"])


def _assert_system_sources_unchanged(
    state: Mapping[str, Any],
    expected: list[dict[str, Any]],
) -> None:
    assert state["system_sources"] == expected
    catalog = state["catalog"]
    assert any(
        str(item.get("id", "")).startswith("system:")
        and _source_kind(item) == "system_default"
        for item in catalog
    )


@pytest.mark.asyncio
async def test_empty_user_library_still_has_system_catalog(
    tmp_path, monkeypatch
) -> None:
    plugin, _ = _make_plugin(tmp_path, monkeypatch)

    result = await plugin.get_panel_state()

    assert result.is_ok(), result
    state = result.value
    assert state["memes"] == []
    assert state["system_sources"]
    assert state["catalog"]
    for source in state["system_sources"]:
        assert str(source["id"]).startswith("system:")
        assert _source_kind(source) == "system_default"
        assert source["read_only"] is True
        assert source["can_delete"] is False
    assert "整个系统没有表情包" not in repr(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["enable", "disable", "rename", "delete"])
async def test_system_catalog_entries_are_backend_read_only(
    tmp_path,
    monkeypatch,
    action: str,
) -> None:
    plugin, _ = _make_plugin(tmp_path, monkeypatch)
    state = await plugin.get_panel_state()
    assert state.is_ok(), state
    system_id = str(state.value["system_sources"][0]["id"])
    store_before = deepcopy(plugin.store.data)

    result = await plugin.update_meme(
        meme_id=system_id,
        action=action,
        name="must not change",
        tags=["must-not-change"],
    )

    assert result.is_err(), result
    assert "系统默认" in str(result.error)
    assert "只读" in str(result.error)
    assert plugin.store.data == store_before


@pytest.mark.asyncio
async def test_user_crud_never_changes_system_sources(tmp_path, monkeypatch) -> None:
    plugin, _ = _make_plugin(tmp_path, monkeypatch)
    initial = await plugin.get_panel_state()
    assert initial.is_ok(), initial
    system_sources = deepcopy(initial.value["system_sources"])

    meme_id = await _add_user_meme(plugin)
    after_create = await plugin.get_panel_state()
    assert after_create.is_ok(), after_create
    _assert_system_sources_unchanged(after_create.value, system_sources)
    user_card = next(
        item for item in after_create.value["catalog"] if item.get("id") == meme_id
    )
    assert _source_kind(user_card) == "user_upload"
    assert user_card["read_only"] is False
    assert user_card["can_delete"] is True

    renamed = await plugin.update_meme(
        meme_id=meme_id,
        action="rename",
        name="Renamed cat",
        tags=["renamed"],
    )
    assert renamed.is_ok(), renamed
    after_update = await plugin.get_panel_state()
    assert after_update.is_ok(), after_update
    _assert_system_sources_unchanged(after_update.value, system_sources)
    assert (
        next(item for item in after_update.value["memes"] if item["id"] == meme_id)[
            "name"
        ]
        == "Renamed cat"
    )

    disabled = await plugin.update_meme(meme_id=meme_id, action="disable")
    assert disabled.is_ok(), disabled
    after_disable = await plugin.get_panel_state()
    assert after_disable.is_ok(), after_disable
    _assert_system_sources_unchanged(after_disable.value, system_sources)
    assert (
        next(item for item in after_disable.value["memes"] if item["id"] == meme_id)[
            "enabled"
        ]
        is False
    )

    enabled = await plugin.update_meme(meme_id=meme_id, action="enable")
    assert enabled.is_ok(), enabled
    after_enable = await plugin.get_panel_state()
    assert after_enable.is_ok(), after_enable
    _assert_system_sources_unchanged(after_enable.value, system_sources)

    deleted = await plugin.update_meme(meme_id=meme_id, action="delete")
    assert deleted.is_ok(), deleted
    after_delete = await plugin.get_panel_state()
    assert after_delete.is_ok(), after_delete
    _assert_system_sources_unchanged(after_delete.value, system_sources)
    assert after_delete.value["memes"] == []
    assert all(item.get("id") != meme_id for item in after_delete.value["catalog"])


@pytest.mark.asyncio
async def test_exact_user_match_does_not_fetch_system_source(
    tmp_path, monkeypatch
) -> None:
    plugin, ctx = _make_plugin(tmp_path, monkeypatch)
    await _add_user_meme(plugin, name="Pat the cat", tags=["comfort"])
    fetch_calls = 0

    async def fail_if_fetched(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal fetch_calls
        fetch_calls += 1
        raise AssertionError(f"unexpected system fetch: {args!r} {kwargs!r}")

    monkeypatch.setattr(plugin, "_fetch_system_content", fail_if_fetched)

    result = await plugin.meme_send(query="Pat the cat")

    assert result.is_ok(), result
    assert fetch_calls == 0
    assert result.value["source_kind"] == "user_upload"
    assert f"/plugin/{PLUGIN_ID}/ui/memes/" in result.value["image_url"]
    assert ctx.pushes


@pytest.mark.asyncio
@pytest.mark.parametrize("with_unmatched_upload", [False, True])
async def test_no_user_match_uses_moderated_system_proxy(
    tmp_path,
    monkeypatch,
    with_unmatched_upload: bool,
) -> None:
    plugin, ctx = _make_plugin(tmp_path, monkeypatch)
    if with_unmatched_upload:
        await _add_user_meme(plugin, name="Happy cat", tags=["happy"])

    raw_url = "https://i.imgflip.com/system-choice.jpg?token=one&size=large"
    item = _system_item(raw_url, title="System cat", item_id="system-choice")
    fetch_calls: list[str] = []
    moderation_calls: list[str] = []

    async def fake_fetch(query: str = "", **_: Any) -> dict[str, Any]:
        fetch_calls.append(query)
        return _system_payload(item)

    async def fake_moderation(*args: Any, **kwargs: Any) -> FakeModeration:
        moderation_calls.append(_candidate_url(args, kwargs))
        return FakeModeration(True)

    monkeypatch.setattr(plugin, "_fetch_system_content", fake_fetch)
    monkeypatch.setattr(plugin, "_moderate_system_candidate", fake_moderation)

    result = await plugin.meme_send(query="System cat")

    assert result.is_ok(), result
    value = result.value
    expected_proxy = "/api/meme/proxy-image?url=" + quote(raw_url, safe="")
    assert fetch_calls == ["System cat"]
    assert moderation_calls == [raw_url]
    assert value["sent"] is True
    assert value["source_kind"] == "system_default"
    assert value["source"] == "Imgflip"
    assert value["image_url"] == expected_proxy
    assert expected_proxy in value["display_markdown"]
    assert raw_url not in value["display_markdown"]
    assert expected_proxy in repr(ctx.pushes)
    assert raw_url not in repr(ctx.pushes)


@pytest.mark.asyncio
async def test_blocked_system_candidate_falls_through_to_next_result(
    tmp_path,
    monkeypatch,
) -> None:
    plugin, ctx = _make_plugin(tmp_path, monkeypatch)
    blocked_url = "https://i.imgflip.com/blocked-first.jpg"
    allowed_url = "https://i.imgflip.com/allowed-second.jpg"
    blocked = _system_item(blocked_url, title="Blocked first", item_id="blocked")
    allowed = _system_item(allowed_url, title="Allowed second", item_id="allowed")
    moderation_calls: list[str] = []

    async def fake_fetch(*_: Any, **__: Any) -> dict[str, Any]:
        return _system_payload(blocked, allowed)

    async def fake_moderation(*args: Any, **kwargs: Any) -> FakeModeration:
        url = _candidate_url(args, kwargs)
        moderation_calls.append(url)
        return FakeModeration(url == allowed_url)

    monkeypatch.setattr(plugin, "_fetch_system_content", fake_fetch)
    monkeypatch.setattr(plugin, "_moderate_system_candidate", fake_moderation)

    result = await plugin.meme_send(query="fallback")

    assert result.is_ok(), result
    expected_proxy = "/api/meme/proxy-image?url=" + quote(allowed_url, safe="")
    assert moderation_calls == [blocked_url, allowed_url]
    assert result.value["source_kind"] == "system_default"
    assert result.value["source"] == "Imgflip"
    assert result.value["image_url"] == expected_proxy
    assert "Allowed second" in result.value["display_markdown"]
    assert blocked_url not in repr(result.value)
    assert blocked_url not in repr(ctx.pushes)


@pytest.mark.asyncio
async def test_proxy_unfetchable_candidate_falls_through_to_next_result(
    tmp_path,
    monkeypatch,
) -> None:
    plugin, ctx = _make_plugin(tmp_path, monkeypatch)
    missing_url = "https://i.imgflip.com/proxy-missing.jpg"
    available_url = "https://i.imgflip.com/proxy-available.jpg"
    missing = _system_item(missing_url, title="Missing first", item_id="missing")
    available = _system_item(
        available_url,
        title="Available second",
        item_id="available",
    )
    preflight_calls: list[str] = []

    async def fake_fetch(*_: Any, **__: Any) -> dict[str, Any]:
        return _system_payload(missing, available)

    async def fake_moderation(*_: Any, **__: Any) -> FakeModeration:
        return FakeModeration(True)

    async def fake_proxy_preflight(url: str) -> bool:
        preflight_calls.append(url)
        return url == available_url

    monkeypatch.setattr(plugin, "_fetch_system_content", fake_fetch)
    monkeypatch.setattr(plugin, "_moderate_system_candidate", fake_moderation)
    monkeypatch.setattr(
        plugin,
        "_system_candidate_fetchable",
        fake_proxy_preflight,
    )

    result = await plugin.meme_send(query="proxy fallback")

    assert result.is_ok(), result
    assert preflight_calls == [missing_url, available_url]
    assert result.value["source_kind"] == "system_default"
    assert result.value["image_url"] == (
        "/api/meme/proxy-image?url=" + quote(available_url, safe="")
    )
    assert missing_url not in repr(result.value)
    assert missing_url not in repr(ctx.pushes)


@pytest.mark.asyncio
async def test_system_source_failure_has_clear_non_global_empty_message(
    tmp_path,
    monkeypatch,
) -> None:
    plugin, ctx = _make_plugin(tmp_path, monkeypatch)

    async def fake_fetch(*_: Any, **__: Any) -> dict[str, Any]:
        return {
            "success": False,
            "data": [],
            "formatted_content": "",
            "raw_data": {"data": []},
            "keyword_used": "missing",
            "source": "",
            "region": "non-china",
            "error": "controlled source failure",
        }

    async def fail_if_moderated(*args: Any, **kwargs: Any) -> FakeModeration:
        raise AssertionError(f"unexpected moderation: {args!r} {kwargs!r}")

    monkeypatch.setattr(plugin, "_fetch_system_content", fake_fetch)
    monkeypatch.setattr(plugin, "_moderate_system_candidate", fail_if_moderated)

    result = await plugin.meme_send(query="missing")

    assert result.is_ok(), result
    assert result.value["sent"] is False
    message = str(result.value["message"])
    assert "系统默认" in message or "在线表情" in message
    assert any(hint in message for hint in ("暂时", "稍后", "未找到"))
    assert "整个系统没有表情包" not in message
    assert "表情包库是空的" not in message
    assert ctx.pushes == []
