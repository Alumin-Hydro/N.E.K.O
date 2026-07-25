"""Unit and static-panel coverage for the N.E.K.O Hitokoto plugin."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

import plugin.plugins.hitokoto as hitokoto_module
from plugin.plugins.hitokoto import (
    API_URL,
    CATEGORIES,
    RANDOM_QUOTE_SCHEMA,
    USER_AGENT,
    HitokotoPlugin,
    _fetch_hitokoto,
    _format_quote,
    _new_http_client,
    _parse_hitokoto_payload,
)
from plugin.sdk.plugin import Err, Ok, SdkError
from plugin.sdk.plugin.llm_tool import LLM_TOOL_META_ATTR
from plugin.sdk.shared.constants import EVENT_META_ATTR

pytestmark = pytest.mark.plugin_unit

PLUGIN_DIR = Path(__file__).resolve().parents[3] / "plugins" / "hitokoto"
PLUGIN_TOML = PLUGIN_DIR / "plugin.toml"
PANEL_HTML = PLUGIN_DIR / "static" / "index.html"


class FakeLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, tuple[Any, ...]]] = []

    def _record(self, level: str, *args: Any, **_kwargs: Any) -> None:
        self.records.append((level, args))

    def debug(self, *args: Any, **kwargs: Any) -> None:
        self._record("debug", *args, **kwargs)

    def info(self, *args: Any, **kwargs: Any) -> None:
        self._record("info", *args, **kwargs)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        self._record("warning", *args, **kwargs)

    def error(self, *args: Any, **kwargs: Any) -> None:
        self._record("error", *args, **kwargs)

    def exception(self, *args: Any, **kwargs: Any) -> None:
        self._record("exception", *args, **kwargs)

    def rendered(self) -> str:
        return "\n".join(
            " ".join(str(item) for item in args)
            for _level, args in self.records
        )


class FakeStore:
    def __init__(
        self,
        *,
        enabled: bool = True,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.enabled = enabled
        self.data = dict(data or {})
        self.get_calls: list[str] = []
        self.set_calls: list[tuple[str, Any]] = []
        self.delete_calls: list[str] = []
        self.fail_get = False
        self.fail_set = False
        self.fail_delete = False
        self.raise_get: BaseException | None = None
        self.raise_set: BaseException | None = None
        self.raise_delete: BaseException | None = None

    async def get(self, key: str, default: Any = None):
        self.get_calls.append(key)
        if self.raise_get is not None:
            raise self.raise_get
        if self.fail_get:
            return Err(SdkError("store read details must stay private"))
        return Ok(self.data.get(key, default))

    async def set(self, key: str, value: Any):
        self.set_calls.append((key, value))
        if self.raise_set is not None:
            raise self.raise_set
        if self.fail_set:
            return Err(SdkError("store write details must stay private"))
        self.data[key] = value
        return Ok(None)

    async def delete(self, key: str):
        self.delete_calls.append(key)
        if self.raise_delete is not None:
            raise self.raise_delete
        if self.fail_delete:
            return Err(SdkError("store delete details must stay private"))
        existed = key in self.data
        self.data.pop(key, None)
        return Ok(existed)


class FakeContext:
    plugin_id = "hitokoto"
    metadata: dict[str, Any] = {}
    bus = None

    def __init__(
        self,
        *,
        config: dict[str, Any] | None = None,
        config_path: Path = PLUGIN_TOML,
    ) -> None:
        self.logger = FakeLogger()
        self.config_path = config_path
        self.config = config or {
            "plugin": {"store": {"enabled": True}},
            "hitokoto": {
                "timeout_seconds": 10.0,
                "default_category": "",
                "max_length": 80,
                "daily_cache": True,
                "daily_greeting": True,
            },
        }
        self._effective_config = self.config
        self.pushed: list[dict[str, Any]] = []
        self.status_updates: list[dict[str, Any]] = []

    async def get_own_config(self, timeout: float = 5.0) -> dict[str, Any]:
        del timeout
        return {"config": self.config}

    def push_message(self, **kwargs: Any) -> dict[str, bool]:
        self.pushed.append(kwargs)
        return {"ok": True}

    def update_status(self, status: dict[str, Any]) -> None:
        self.status_updates.append(status)


class FakeResponse:
    def __init__(
        self,
        payload: Any,
        *,
        status_code: int = 200,
    ) -> None:
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", API_URL)
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "request failed",
                request=request,
                response=response,
            )

    def json(self) -> Any:
        return self.payload


class FakeClient:
    def __init__(
        self,
        payloads: list[Any] | None = None,
        *,
        error: BaseException | None = None,
        close_error: BaseException | None = None,
        delay: float = 0.0,
    ) -> None:
        self.payloads = list(payloads or [])
        self.error = error
        self.close_error = close_error
        self.delay = delay
        self.calls: list[dict[str, Any]] = []
        self.is_closed = False

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any],
        timeout: float,
    ) -> FakeResponse:
        self.calls.append(
            {"url": url, "params": dict(params), "timeout": timeout}
        )
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if not self.payloads:
            raise AssertionError("fake client ran out of payloads")
        payload = self.payloads.pop(0)
        if isinstance(payload, FakeResponse):
            return payload
        return FakeResponse(payload)

    async def aclose(self) -> None:
        if self.close_error is not None:
            raise self.close_error
        self.is_closed = True


def api_payload(
    *,
    sentence: str = "星光不问赶路人。",
    type_code: str = "k",
    quote_id: int = 42,
    uuid: str = "abc-123",
    author: Any = "某人",
    work: Any = "某书",
) -> dict[str, Any]:
    return {
        "id": quote_id,
        "uuid": uuid,
        "hitokoto": sentence,
        "type": type_code,
        "from_who": author,
        "from": work,
    }


def normalized_quote(**overrides: Any) -> dict[str, Any]:
    payload = api_payload(**overrides)
    return _parse_hitokoto_payload(payload)


@pytest.fixture(autouse=True)
def isolate_runtime_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "NEKO_STORAGE_SELECTED_ROOT",
        str(tmp_path / "runtime"),
    )
    monkeypatch.setattr(
        hitokoto_module,
        "_local_date",
        lambda: "2026-07-25",
    )
    monkeypatch.setattr(
        hitokoto_module,
        "_local_timestamp",
        lambda: "2026-07-25T09:30:00+08:00",
    )


def make_plugin(
    *,
    store: FakeStore | None = None,
    config: dict[str, Any] | None = None,
) -> tuple[HitokotoPlugin, FakeContext, FakeStore]:
    ctx = FakeContext(config=config)
    plugin = HitokotoPlugin(ctx)
    fake_store = store or FakeStore()
    plugin.store = fake_store
    return plugin, ctx, fake_store


# ---------------------------------------------------------------------------
# Independent decorator metadata
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method_name", "entry_id"),
    [
        ("random_quote", "random_quote"),
        ("daily_quote", "daily_quote"),
    ],
)
def test_quote_methods_have_independent_plugin_entry_metadata(
    method_name: str,
    entry_id: str,
) -> None:
    meta = getattr(getattr(HitokotoPlugin, method_name), EVENT_META_ATTR)
    assert meta.event_type == "plugin_entry"
    assert meta.id == entry_id
    assert meta.input_schema["type"] == "object"


def test_random_quote_has_exact_llm_tool_metadata() -> None:
    meta = getattr(HitokotoPlugin.random_quote, LLM_TOOL_META_ATTR)
    assert meta.name == "hitokoto_random_quote"
    assert meta.parameters == RANDOM_QUOTE_SCHEMA
    assert meta.parameters["properties"]["category"]["enum"] == [
        "",
        *CATEGORIES.keys(),
    ]
    assert "default" not in meta.parameters["properties"]["category"]


def test_daily_quote_has_exact_llm_tool_metadata() -> None:
    meta = getattr(HitokotoPlugin.daily_quote, LLM_TOOL_META_ATTR)
    assert meta.name == "hitokoto_daily_quote"
    assert meta.parameters == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }


@pytest.mark.parametrize(
    ("method_name", "lifecycle_id"),
    [("startup", "startup"), ("shutdown", "shutdown")],
)
def test_lifecycle_metadata(method_name: str, lifecycle_id: str) -> None:
    meta = getattr(getattr(HitokotoPlugin, method_name), EVENT_META_ATTR)
    assert meta.event_type == "lifecycle"
    assert meta.id == lifecycle_id
    assert meta.kind == "lifecycle"


def test_daily_greeting_message_metadata() -> None:
    meta = getattr(HitokotoPlugin.on_chat_message, EVENT_META_ATTR)
    assert meta.event_type == "message"
    assert meta.id == "hitokoto_daily_greeting"
    assert meta.kind == "consumer"
    assert meta.metadata["source"] == "chat"


@pytest.mark.parametrize(
    "method_name",
    [
        "get_panel_state",
        "save_settings",
        "reset_settings",
        "test_api",
        "clear_daily_cache",
    ],
)
def test_panel_entries_are_plugin_entries_but_not_llm_tools(
    method_name: str,
) -> None:
    method = getattr(HitokotoPlugin, method_name)
    entry_meta = getattr(method, EVENT_META_ATTR)
    assert entry_meta.event_type == "plugin_entry"
    if method_name == "test_api":
        assert entry_meta.timeout == 35.0
    assert getattr(method, LLM_TOOL_META_ATTR, None) is None


# ---------------------------------------------------------------------------
# API construction, parsing, formatting, and client configuration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_constructs_exact_request_without_category() -> None:
    client = FakeClient([api_payload()])
    result = await _fetch_hitokoto(
        client,
        timeout=7.5,
        max_length=123,
    )

    assert result["sentence"] == "星光不问赶路人。"
    assert client.calls == [
        {
            "url": API_URL,
            "params": {
                "encode": "json",
                "charset": "utf-8",
                "max_length": 123,
            },
            "timeout": 7.5,
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("category", list(CATEGORIES))
async def test_fetch_passes_every_official_category(category: str) -> None:
    client = FakeClient([api_payload(type_code=category)])
    await _fetch_hitokoto(
        client,
        category=category,
        timeout=11,
        max_length=80,
    )
    assert client.calls[0]["params"]["c"] == category


@pytest.mark.asyncio
async def test_fetch_rejects_invalid_category_instead_of_coercing() -> None:
    client = FakeClient([api_payload()])
    with pytest.raises(SdkError, match="未知"):
        await _fetch_hitokoto(client, category="z")
    assert client.calls == []


def test_real_client_configuration_has_required_user_agent() -> None:
    client = _new_http_client()
    try:
        assert client.follow_redirects is True
        assert client.headers["User-Agent"] == USER_AGENT
    finally:
        asyncio.run(client.aclose())


def test_parse_full_payload_and_traceable_uuid_link() -> None:
    result = _parse_hitokoto_payload(api_payload())
    assert result == {
        "sentence": "星光不问赶路人。",
        "author": "某人",
        "work": "某书",
        "source": "某人 《某书》",
        "type_code": "k",
        "type_label": "哲学",
        "category_code": "k",
        "category": "哲学",
        "id": 42,
        "uuid": "abc-123",
        "url": "https://hitokoto.cn?uuid=abc-123",
        "formatted": (
            "星光不问赶路人。\n"
            "—— 某人 《某书》\n"
            "https://hitokoto.cn?uuid=abc-123"
        ),
    }


@pytest.mark.parametrize(
    ("author", "work", "expected"),
    [
        (None, None, "佚名"),
        (None, "某书", "《某书》"),
        ("某人", None, "某人"),
    ],
)
def test_parse_null_author_and_work(
    author: Any,
    work: Any,
    expected: str,
) -> None:
    result = _parse_hitokoto_payload(
        api_payload(author=author, work=work)
    )
    assert result["source"] == expected


def test_parse_missing_type_is_unknown() -> None:
    payload = api_payload()
    payload.pop("type")
    result = _parse_hitokoto_payload(payload)
    assert result["type_code"] == ""
    assert result["type_label"] == "未知"


@pytest.mark.parametrize("sentence", ["", "   ", None])
def test_parse_empty_sentence_is_rejected(sentence: Any) -> None:
    payload = api_payload()
    payload["hitokoto"] = sentence
    with pytest.raises(SdkError, match="空句子"):
        _parse_hitokoto_payload(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", None, "ID"),
        ("id", True, "ID"),
        ("id", "   ", "ID"),
        ("uuid", None, "UUID"),
        ("uuid", "   ", "UUID"),
    ],
)
def test_parse_requires_traceable_id_and_uuid(
    field: str,
    value: Any,
    message: str,
) -> None:
    payload = api_payload()
    payload[field] = value
    with pytest.raises(SdkError, match=message):
        _parse_hitokoto_payload(payload)


def test_format_quote_uses_safe_normalized_fields() -> None:
    quote = {
        "sentence": "hello",
        "source": "world",
        "url": "https://hitokoto.cn?uuid=x",
    }
    assert _format_quote(quote) == (
        "hello\n—— world\nhttps://hitokoto.cn?uuid=x"
    )


# ---------------------------------------------------------------------------
# Random quote entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_random_quote_uses_saved_default_category_when_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    plugin._settings_overrides = {"default_category": "i"}
    client = FakeClient([api_payload(type_code="i")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.random_quote()

    assert result.is_ok()
    assert client.calls[0]["params"]["c"] == "i"


@pytest.mark.asyncio
async def test_random_quote_explicit_empty_category_means_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    plugin._settings_overrides = {"default_category": "i"}
    client = FakeClient([api_payload(type_code="a")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.random_quote(category="")

    assert result.is_ok()
    assert "c" not in client.calls[0]["params"]


@pytest.mark.asyncio
@pytest.mark.parametrize("category", list(CATEGORIES))
async def test_random_quote_accepts_each_category(
    category: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    client = FakeClient([api_payload(type_code=category)])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    result = await plugin.random_quote(category=category)
    assert result.is_ok()
    assert result.value["type_code"] == category


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "category",
    ["z", "anime", "A", " a ", " ", 3, True],
)
async def test_random_quote_invalid_explicit_category_returns_readable_err(
    category: Any,
) -> None:
    plugin, _ctx, _store = make_plugin()
    result = await plugin.random_quote(category=category)
    assert result.is_err()
    assert isinstance(result.error, SdkError)
    assert "类型" in str(result.error)


@pytest.mark.asyncio
async def test_random_quote_network_failure_exposes_only_exception_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    client = FakeClient(
        error=RuntimeError("proxy=/secret/path token=do-not-expose")
    )
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.random_quote()

    assert result.is_err()
    error_text = str(result.error)
    assert "RuntimeError" in error_text
    assert "secret" not in error_text
    assert "token" not in plugin.logger.rendered()


def test_quote_text_is_not_logged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    sentence = "PRIVATE QUOTE BODY"
    client = FakeClient([api_payload(sentence=sentence)])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    result = asyncio.run(plugin.random_quote())
    assert result.is_ok()
    assert sentence not in plugin.logger.rendered()


# ---------------------------------------------------------------------------
# Daily cache and concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_daily_quote_fresh_fetch_writes_complete_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, store = make_plugin()
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.daily_quote()

    assert result.is_ok()
    assert result.value["cached"] is False
    record = store.data["daily_quote"]
    assert record["date"] == "2026-07-25"
    assert record["quote"]["uuid"] == "abc-123"
    assert record["quote"]["url"] == "https://hitokoto.cn?uuid=abc-123"


@pytest.mark.asyncio
async def test_daily_quote_same_day_hits_cache_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    first = await plugin.daily_quote()
    second = await plugin.daily_quote()

    assert first.is_ok() and second.is_ok()
    assert second.value["cached"] is True
    assert second.value["sentence"] == first.value["sentence"]
    assert second.value["uuid"] == first.value["uuid"]
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_daily_quote_stale_cache_refetches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = {
        "date": "2026-07-24",
        "quote": normalized_quote(sentence="旧句"),
    }
    plugin, _ctx, store = make_plugin(
        store=FakeStore(data={"daily_quote": stale})
    )
    client = FakeClient([api_payload(sentence="新句")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.daily_quote()

    assert result.is_ok()
    assert result.value["sentence"] == "新句"
    assert store.data["daily_quote"]["date"] == "2026-07-25"
    assert len(client.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corrupt",
    [
        "garbage",
        {"date": "2026-07-25"},
        {"date": "2026-07-25", "quote": {"sentence": "  "}},
        {"date": "2026-07-25", "quote": {"sentence": "字段不完整"}},
    ],
)
async def test_daily_quote_corrupt_cache_refetches(
    corrupt: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin(
        store=FakeStore(data={"daily_quote": corrupt})
    )
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    result = await plugin.daily_quote()
    assert result.is_ok()
    assert result.value["cached"] is False
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_malformed_future_cache_is_overwritten_and_then_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, store = make_plugin(
        store=FakeStore(
            data={
                "daily_quote": {
                    "date": "2099-01-01",
                    "quote": {"sentence": "   "},
                }
            }
        )
    )
    client = FakeClient([api_payload(sentence="修复后的今日句")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    first = await plugin.daily_quote()
    second = await plugin.daily_quote()

    assert first.is_ok() and second.is_ok()
    assert second.value["sentence"] == "修复后的今日句"
    assert second.value["cached"] is True
    assert store.data["daily_quote"]["date"] == "2026-07-25"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_valid_future_cache_is_replaced_and_today_is_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    future_record = {
        "date": "2026-07-26",
        "quote": normalized_quote(
            sentence="明日句",
            quote_id=43,
            uuid="future-uuid",
        ),
    }
    plugin, _ctx, store = make_plugin(
        store=FakeStore(data={"daily_quote": future_record})
    )
    client = FakeClient([api_payload(sentence="今日句")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    first = await plugin.daily_quote()
    second = await plugin.daily_quote()

    assert first.is_ok() and second.is_ok()
    assert first.value["sentence"] == "今日句"
    assert second.value["sentence"] == "今日句"
    assert second.value["cached"] is True
    assert store.data["daily_quote"]["date"] == "2026-07-25"
    assert store.data["daily_quote"]["quote"]["sentence"] == "今日句"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_malformed_cache_date_is_replaced_with_today(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, store = make_plugin(
        store=FakeStore(
            data={
                "daily_quote": {
                    "date": "not-a-date",
                    "quote": normalized_quote(sentence="无效日期句"),
                }
            }
        )
    )
    client = FakeClient([api_payload(sentence="今日句")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.daily_quote()

    assert result.is_ok()
    assert result.value["sentence"] == "今日句"
    assert store.data["daily_quote"]["date"] == "2026-07-25"
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_daily_quote_store_disabled_uses_safe_memory_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, store = make_plugin(store=FakeStore(enabled=False))
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    first = await plugin.daily_quote()
    second = await plugin.daily_quote()

    assert first.is_ok() and second.is_ok()
    assert second.value["cached"] is True
    assert len(client.calls) == 1
    assert store.data == {}


@pytest.mark.asyncio
async def test_daily_cache_disabled_reads_and_writes_no_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = {
        "date": "2026-07-25",
        "quote": normalized_quote(sentence="不应读取"),
    }
    plugin, _ctx, store = make_plugin(
        store=FakeStore(data={"daily_quote": existing})
    )
    plugin._settings_overrides = {"daily_cache": False}
    client = FakeClient(
        [
            api_payload(sentence="第一次"),
            api_payload(sentence="第二次", quote_id=43, uuid="uuid-2"),
        ]
    )
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    first = await plugin.daily_quote()
    second = await plugin.daily_quote()

    assert first.is_ok() and second.is_ok()
    assert first.value["sentence"] == "第一次"
    assert second.value["sentence"] == "第二次"
    assert len(client.calls) == 2
    assert store.data["daily_quote"] == existing
    assert "daily_quote" not in store.get_calls
    assert not any(key == "daily_quote" for key, _value in store.set_calls)


@pytest.mark.asyncio
async def test_concurrent_daily_calls_are_single_flight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    client = FakeClient([api_payload()], delay=0.03)
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    results = await asyncio.wait_for(
        asyncio.gather(*[plugin.daily_quote() for _ in range(8)]),
        timeout=2,
    )

    assert all(result.is_ok() for result in results)
    assert {result.value["uuid"] for result in results} == {"abc-123"}
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_concurrent_cache_disabled_calls_share_request_without_cache_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, store = make_plugin()
    plugin._settings_overrides = {"daily_cache": False}
    client = FakeClient([api_payload()], delay=0.03)
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    results = await asyncio.wait_for(
        asyncio.gather(*[plugin.daily_quote() for _ in range(8)]),
        timeout=2,
    )

    assert all(result.is_ok() for result in results)
    assert all(result.value["cached"] is False for result in results)
    assert len(client.calls) == 1
    assert "daily_quote" not in store.data


@pytest.mark.asyncio
async def test_cancelled_daily_leader_allows_follower_to_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    first_started = asyncio.Event()
    call_count = 0

    async def controlled_fetch(_category: str) -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            first_started.set()
            await asyncio.Event().wait()
        return normalized_quote(
            sentence="接替请求成功",
            quote_id=44,
            uuid="replacement-uuid",
        )

    monkeypatch.setattr(plugin, "_fetch_remote", controlled_fetch)
    leader = asyncio.create_task(
        plugin._daily_quote_data(local_date="2026-07-25")
    )
    await asyncio.wait_for(first_started.wait(), timeout=1)
    follower = asyncio.create_task(
        plugin._daily_quote_data(local_date="2026-07-25")
    )
    await asyncio.sleep(0.03)

    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader
    quote, cached = await asyncio.wait_for(follower, timeout=2)

    assert quote["sentence"] == "接替请求成功"
    assert cached is False
    assert call_count == 2


def test_cross_loop_daily_calls_share_single_flight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    client = FakeClient([api_payload()], delay=0.05)
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    barrier = threading.Barrier(2)
    results: list[Any] = []

    def runner() -> None:
        barrier.wait(timeout=1)
        results.append(asyncio.run(plugin.daily_quote()))

    threads = [threading.Thread(target=runner) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 2
    assert all(result.is_ok() for result in results)
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_store_read_failure_degrades_to_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore()
    store.fail_get = True
    plugin, _ctx, _store = make_plugin(store=store)
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    result = await plugin.daily_quote()
    assert result.is_ok()
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_clear_cache_wins_against_an_inflight_store_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BlockingReadStore(FakeStore):
        def __init__(self) -> None:
            super().__init__(
                data={
                    "daily_quote": {
                        "date": "2026-07-25",
                        "quote": normalized_quote(sentence="已清除的旧句"),
                    }
                }
            )
            self.read_started = asyncio.Event()
            self.release_read = asyncio.Event()
            self.block_once = True

        async def get(self, key: str, default: Any = None):
            self.get_calls.append(key)
            snapshot = self.data.get(key, default)
            if key == "daily_quote" and self.block_once:
                self.block_once = False
                self.read_started.set()
                await self.release_read.wait()
            return Ok(snapshot)

    store = BlockingReadStore()
    plugin, _ctx, _store = make_plugin(store=store)
    client = FakeClient([api_payload(sentence="清除后的新句")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    daily_task = asyncio.create_task(plugin.daily_quote())
    await asyncio.wait_for(store.read_started.wait(), timeout=1)
    cleared = await plugin.clear_daily_cache()
    store.release_read.set()
    result = await asyncio.wait_for(daily_task, timeout=2)

    assert cleared.is_ok()
    assert result.is_ok()
    assert result.value["sentence"] == "清除后的新句"
    assert plugin._memory_daily["quote"]["sentence"] == "清除后的新句"
    assert len(client.calls) == 1


# ---------------------------------------------------------------------------
# Daily first-chat greeting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_chat_pushes_character_response_instruction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, store = make_plugin()
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.on_chat_message(text="arbitrary user content")

    assert result.is_ok()
    assert result.value["status"] == "pushed"
    assert store.data["greeting_attempted_date"] == "2026-07-25"
    assert len(ctx.pushed) == 1
    pushed = ctx.pushed[0]
    assert pushed["visibility"] == []
    assert pushed["ai_behavior"] == "respond"
    assert pushed["parts"][0]["type"] == "text"
    assert "{MASTER_NAME}" in pushed["parts"][0]["text"]
    assert "自己的角色口吻" in pushed["parts"][0]["text"]


@pytest.mark.asyncio
async def test_same_day_greeting_only_attempts_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, _store = make_plugin()
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    first = await plugin.on_chat_message()
    second = await plugin.on_chat_message()
    assert first.value["status"] == "pushed"
    assert second.value["status"] == "already_attempted"
    assert len(ctx.pushed) == 1
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_daily_greeting_disabled_does_nothing() -> None:
    plugin, ctx, store = make_plugin()
    plugin._settings_overrides = {"daily_greeting": False}
    result = await plugin.on_chat_message()
    assert result.value == {"status": "disabled", "pushed": False}
    assert ctx.pushed == []
    assert store.data == {}


@pytest.mark.asyncio
async def test_greeting_reuses_daily_cache_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached = {
        "date": "2026-07-25",
        "quote": normalized_quote(sentence="缓存句"),
    }
    plugin, ctx, _store = make_plugin(
        store=FakeStore(data={"daily_quote": cached})
    )

    def no_client() -> Any:
        raise AssertionError("cached greeting must not create a client")

    monkeypatch.setattr(plugin, "_get_client", no_client)
    result = await plugin.on_chat_message()
    assert result.is_ok()
    assert result.value["cached"] is True
    assert len(ctx.pushed) == 1
    assert "缓存句" in ctx.pushed[0]["parts"][0]["text"]


@pytest.mark.asyncio
async def test_failed_greeting_fetch_still_marks_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, store = make_plugin()
    client = FakeClient(error=RuntimeError("offline"))
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    first = await plugin.on_chat_message()
    second = await plugin.on_chat_message()
    assert first.value["status"] == "attempted_fetch_failed"
    assert second.value["status"] == "already_attempted"
    assert store.data["greeting_attempted_date"] == "2026-07-25"
    assert len(client.calls) == 1
    assert ctx.pushed == []


@pytest.mark.asyncio
async def test_concurrent_chat_messages_claim_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, _store = make_plugin()
    client = FakeClient([api_payload()], delay=0.03)
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    results = await asyncio.wait_for(
        asyncio.gather(*[plugin.on_chat_message() for _ in range(10)]),
        timeout=2,
    )

    assert sum(result.value["status"] == "pushed" for result in results) == 1
    assert len(ctx.pushed) == 1
    assert len(client.calls) == 1


def test_cross_loop_chat_messages_claim_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, _store = make_plugin()
    client = FakeClient([api_payload()], delay=0.03)
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    barrier = threading.Barrier(2)
    results: list[Any] = []

    def runner() -> None:
        barrier.wait(timeout=1)
        results.append(asyncio.run(plugin.on_chat_message()))

    threads = [threading.Thread(target=runner) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 2
    assert sum(result.value["status"] == "pushed" for result in results) == 1
    assert len(ctx.pushed) == 1
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_corrupt_persisted_greeting_date_is_ignored_and_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, store = make_plugin(
        store=FakeStore(data={"greeting_attempted_date": "not-a-date"})
    )
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    result = await plugin.on_chat_message()

    assert result.is_ok()
    assert result.value["status"] == "pushed"
    assert store.data["greeting_attempted_date"] == "2026-07-25"
    assert len(ctx.pushed) == 1


@pytest.mark.asyncio
async def test_adjacent_day_greeting_claim_does_not_regress_persisted_date() -> None:
    plugin, _ctx, store = make_plugin()

    newest_claim = await plugin._claim_daily_greeting("2026-07-25")
    delayed_old_claim = await plugin._claim_daily_greeting("2026-07-24")

    assert newest_claim[0] is True
    assert delayed_old_claim[0] is False
    assert store.data["greeting_attempted_date"] == "2026-07-25"


@pytest.mark.asyncio
async def test_push_failure_is_also_marked_and_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, _store = make_plugin()
    client = FakeClient([api_payload()])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    def fail_push(**_kwargs: Any) -> None:
        raise RuntimeError("push offline")

    monkeypatch.setattr(plugin, "push_message", fail_push)
    first = await plugin.on_chat_message()
    second = await plugin.on_chat_message()
    assert first.value["status"] == "attempted_push_failed"
    assert second.value["status"] == "already_attempted"
    assert ctx.pushed == []
    assert plugin._api_state == "ok"


# ---------------------------------------------------------------------------
# Panel settings and actions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_panel_state_contains_settings_status_cache_and_preview() -> None:
    cached_quote = normalized_quote(sentence="面板缓存句")
    plugin, _ctx, _store = make_plugin(
        store=FakeStore(
            data={
                "daily_quote": {
                    "date": "2026-07-25",
                    "quote": cached_quote,
                }
            }
        )
    )
    plugin._runtime_started = True
    result = await plugin.get_panel_state()
    assert result.is_ok()
    state = result.value
    assert state["running"] is True
    assert state["api_state"] == "idle"
    assert state["settings"]["max_length"] == 80
    assert state["daily_cache"]["date"] == "2026-07-25"
    assert state["recent_quote"]["sentence"] == "面板缓存句"
    assert len(state["categories"]) == 13


@pytest.mark.asyncio
async def test_panel_state_hides_malformed_cache_date() -> None:
    plugin, _ctx, _store = make_plugin(
        store=FakeStore(
            data={
                "daily_quote": {
                    "date": "not-a-date",
                    "quote": normalized_quote(),
                }
            }
        )
    )

    result = await plugin.get_panel_state()

    assert result.is_ok()
    assert result.value["daily_cache"]["date"] is None


@pytest.mark.asyncio
async def test_save_settings_clamps_persists_and_applies_immediately() -> None:
    plugin, _ctx, store = make_plugin()
    result = await plugin.save_settings(
        default_category="I",
        timeout_seconds=99,
        max_length=999,
        daily_cache=False,
        daily_greeting=False,
    )
    assert result.is_ok()
    assert result.value["settings"] == {
        "timeout_seconds": 30.0,
        "default_category": "i",
        "max_length": 200,
        "daily_cache": False,
        "daily_greeting": False,
    }
    assert store.data["settings_overrides"] == result.value["settings"]
    assert plugin._settings_snapshot()["default_category"] == "i"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "default_category": "z",
            "timeout_seconds": 10,
            "max_length": 80,
            "daily_cache": True,
            "daily_greeting": True,
        },
        {
            "default_category": "",
            "timeout_seconds": "fast",
            "max_length": 80,
            "daily_cache": True,
            "daily_greeting": True,
        },
        {
            "default_category": "",
            "timeout_seconds": 10,
            "max_length": 1.5,
            "daily_cache": True,
            "daily_greeting": True,
        },
        {
            "default_category": "",
            "timeout_seconds": 10,
            "max_length": 80,
            "daily_cache": "yes",
            "daily_greeting": True,
        },
    ],
)
async def test_save_settings_invalid_values_return_readable_err(
    kwargs: dict[str, Any],
) -> None:
    plugin, _ctx, store = make_plugin()
    result = await plugin.save_settings(**kwargs)
    assert result.is_err()
    assert isinstance(result.error, SdkError)
    assert "settings_overrides" not in store.data


@pytest.mark.asyncio
async def test_save_settings_requires_enabled_store() -> None:
    plugin, _ctx, _store = make_plugin(store=FakeStore(enabled=False))
    result = await plugin.save_settings(
        default_category="",
        timeout_seconds=10,
        max_length=80,
        daily_cache=True,
        daily_greeting=True,
    )
    assert result.is_err()
    assert "存储已禁用" in str(result.error)


@pytest.mark.asyncio
async def test_startup_loads_persisted_settings_overlay() -> None:
    config = {
        "plugin": {"store": {"enabled": True}},
        "hitokoto": {
            "timeout_seconds": 4,
            "default_category": "d",
            "max_length": 50,
            "daily_cache": True,
            "daily_greeting": True,
        },
    }
    store = FakeStore(
        data={
            "settings_overrides": {
                "timeout_seconds": 9.0,
                "default_category": "k",
                "max_length": 120,
                "daily_cache": False,
                "daily_greeting": False,
            }
        }
    )
    plugin, _ctx, _store = make_plugin(store=store, config=config)
    result = await plugin.startup()
    assert result.is_ok()
    assert plugin._settings_snapshot() == {
        "timeout_seconds": 9.0,
        "default_category": "k",
        "max_length": 120,
        "daily_cache": False,
        "daily_greeting": False,
    }


@pytest.mark.asyncio
async def test_startup_enables_store_from_effective_manifest_config() -> None:
    store = FakeStore(
        enabled=False,
        data={
            "settings_overrides": {
                "default_category": "i",
            }
        },
    )
    plugin, _ctx, _store = make_plugin(store=store)

    result = await plugin.startup()

    assert result.is_ok()
    assert store.enabled is True
    assert plugin._settings_snapshot()["default_category"] == "i"


@pytest.mark.asyncio
async def test_startup_ignores_corrupt_settings_overlay() -> None:
    store = FakeStore(
        data={"settings_overrides": {"default_category": "invalid"}}
    )
    plugin, _ctx, _store = make_plugin(store=store)
    result = await plugin.startup()
    assert result.is_ok()
    assert plugin._settings_snapshot()["default_category"] == ""


@pytest.mark.asyncio
async def test_reset_settings_deletes_overlay_and_restores_defaults() -> None:
    store = FakeStore(
        data={
            "settings_overrides": {
                "default_category": "i",
                "timeout_seconds": 9.0,
                "max_length": 100,
                "daily_cache": False,
                "daily_greeting": False,
            }
        }
    )
    plugin, _ctx, _store = make_plugin(store=store)
    plugin._settings_overrides = dict(store.data["settings_overrides"])
    result = await plugin.reset_settings()
    assert result.is_ok()
    assert "settings_overrides" not in store.data
    assert result.value["settings"]["default_category"] == ""
    assert result.value["settings"]["daily_cache"] is True


@pytest.mark.asyncio
async def test_clear_daily_cache_clears_memory_and_store() -> None:
    record = {
        "date": "2026-07-25",
        "quote": normalized_quote(),
    }
    store = FakeStore(data={"daily_quote": record})
    plugin, _ctx, _store = make_plugin(store=store)
    plugin._memory_daily = record
    result = await plugin.clear_daily_cache()
    assert result.is_ok()
    assert "daily_quote" not in store.data
    assert plugin._memory_daily is None


@pytest.mark.asyncio
async def test_clear_daily_cache_store_failure_is_readable() -> None:
    store = FakeStore(data={"daily_quote": {"date": "2026-07-25"}})
    store.fail_delete = True
    plugin, _ctx, _store = make_plugin(store=store)
    result = await plugin.clear_daily_cache()
    assert result.is_err()
    assert "StoreError" in str(result.error)


@pytest.mark.asyncio
async def test_test_api_action_uses_current_settings_without_daily_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, store = make_plugin()
    plugin._settings_overrides = {
        "default_category": "l",
        "timeout_seconds": 3.5,
        "max_length": 33,
    }
    client = FakeClient([api_payload(type_code="l")])
    monkeypatch.setattr(plugin, "_get_client", lambda: client)
    result = await plugin.test_api()
    assert result.is_ok()
    assert result.value["quote"]["type_code"] == "l"
    assert client.calls[0]["params"]["c"] == "l"
    assert client.calls[0]["params"]["max_length"] == 33
    assert client.calls[0]["timeout"] == 3.5
    assert "daily_quote" not in store.data


# ---------------------------------------------------------------------------
# Lifecycle/host simulation and per-loop client reconstruction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_entry_message_shutdown_host_simulation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, ctx, _store = make_plugin()
    client = FakeClient(
        [
            api_payload(sentence="随机句"),
            api_payload(sentence="今日句", quote_id=43, uuid="daily-uuid"),
        ]
    )
    monkeypatch.setattr(plugin, "_get_client", lambda: client)

    started = await plugin.startup()
    random_result = await plugin.random_quote(category="a")
    greeting_result = await plugin.on_chat_message()
    stopped = await plugin.shutdown()

    assert started.is_ok()
    assert random_result.is_ok()
    assert greeting_result.is_ok()
    assert stopped.is_ok()
    assert plugin.logger is ctx.logger
    assert len(ctx.pushed) == 1


def test_client_rebuilds_for_each_event_loop_and_shutdown_is_best_effort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    created: list[FakeClient] = []

    def factory() -> FakeClient:
        client = FakeClient([])
        created.append(client)
        return client

    monkeypatch.setattr(hitokoto_module, "_new_http_client", factory)

    async def get_client() -> FakeClient:
        return plugin._get_client()  # type: ignore[return-value]

    first = asyncio.run(get_client())
    second = asyncio.run(get_client())
    shutdown = asyncio.run(plugin.shutdown())

    assert first is not second
    assert created == [first, second]
    assert first.is_closed is True
    assert second.is_closed is True
    assert shutdown.is_ok()


def test_client_shutdown_tolerates_cross_loop_close_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin, _ctx, _store = make_plugin()
    failing = FakeClient([], close_error=RuntimeError("wrong loop"))
    monkeypatch.setattr(
        hitokoto_module,
        "_new_http_client",
        lambda: failing,
    )

    async def create() -> None:
        plugin._get_client()

    asyncio.run(create())
    result = asyncio.run(plugin.shutdown())
    assert result.is_ok()
    assert result.value["close_failures"] == 1
    assert plugin.logger is not None


# ---------------------------------------------------------------------------
# Manifest, i18n, and static management panel
# ---------------------------------------------------------------------------


def test_manifest_enables_store_runtime_ui_and_i18n() -> None:
    import tomllib

    with PLUGIN_TOML.open("rb") as stream:
        manifest = tomllib.load(stream)
    assert manifest["plugin"]["id"] == "hitokoto"
    assert manifest["plugin"]["entry"] == (
        "plugin.plugins.hitokoto:HitokotoPlugin"
    )
    assert manifest["plugin"]["type"] == "plugin"
    assert manifest["plugin"]["version"] == "0.1.0"
    assert manifest["plugin"]["author"]["name"] == "Alumin-Hydro"
    assert manifest["plugin"]["store"]["enabled"] is True
    assert manifest["plugin"]["ui"]["enabled"] is True
    assert manifest["plugin"]["ui"]["panel"][0]["title"] == (
        "Hitokoto Quotes · 一言"
    )
    assert manifest["plugin_runtime"] == {
        "enabled": True,
        "auto_start": True,
    }
    assert manifest["plugin"]["i18n"]["default_locale"] == "zh-CN"
    assert manifest["hitokoto"]["daily_greeting"] is True


def test_i18n_bundles_cover_all_supported_locales_with_matching_keys() -> None:
    locales = ("zh-CN", "zh-TW", "en", "ja", "ko", "es", "pt", "ru")
    bundles: dict[str, dict[str, str]] = {}
    for locale in locales:
        payload = json.loads(
            (PLUGIN_DIR / "i18n" / f"{locale}.json").read_text(
                encoding="utf-8"
            )
        )
        assert payload["plugin.name"]
        assert payload["plugin.description"]
        assert payload["ui.action.save"]
        assert payload["ui.action.test"]
        assert all(isinstance(value, str) and value.strip() for value in payload.values())
        bundles[locale] = payload

    reference_keys = set(bundles["zh-CN"])
    assert reference_keys
    for locale in locales:
        assert set(bundles[locale]) == reference_keys


def test_static_panel_exists_with_all_required_testids_and_controls() -> None:
    assert PANEL_HTML.is_file()
    html = PANEL_HTML.read_text(encoding="utf-8")
    required_testids = {
        "plugin-title",
        "running-status",
        "api-status",
        "latest-request",
        "cache-date",
        "quote-preview",
        "default-category",
        "timeout-seconds",
        "max-length",
        "daily-cache-toggle",
        "daily-greeting-toggle",
        "save-settings-button",
        "reset-settings-button",
        "random-quote-button",
        "daily-quote-button",
        "test-api-button",
        "clear-cache-button",
        "status-message",
    }
    for testid in required_testids:
        assert f'data-testid="{testid}"' in html


def test_static_panel_uses_runs_poll_export_and_i18n_routes() -> None:
    html = PANEL_HTML.read_text(encoding="utf-8")
    assert 'const RUNS_URL = "/runs"' in html
    assert "fetch(RUNS_URL" in html
    assert "`${RUNS_URL}/${runId}`" in html
    assert "`${RUNS_URL}/${runId}/export`" in html
    assert "/ui-api/locale" in html
    assert "/ui-api/i18n/${locale}.json" in html


def test_static_panel_renders_api_quote_content_with_text_content_only() -> None:
    html = PANEL_HTML.read_text(encoding="utf-8")
    assert 'data-i18n="ui.quote.empty"' in html
    assert 'element("quoteText").textContent' in html
    assert 'element("quoteSource").textContent' in html
    assert "innerHTML" not in html


def test_static_panel_hides_empty_quote_metadata_pill() -> None:
    html = PANEL_HTML.read_text(encoding="utf-8")
    assert ".pill[hidden]" in html
    assert "display: none !important;" in html


def test_static_panel_has_responsive_and_accessible_basics() -> None:
    html = PANEL_HTML.read_text(encoding="utf-8")
    assert "@media (max-width: 520px)" in html
    assert 'aria-live="polite"' in html
    assert 'role="status"' in html
    assert '<label for="defaultCategory"' in html
    assert 'type="submit"' in html


def test_static_panel_keeps_controls_disabled_when_initial_state_load_fails() -> None:
    html = PANEL_HTML.read_text(encoding="utf-8")
    assert "let initialLoadSucceeded = false;" in html
    assert "initialLoadSucceeded = true;" in html
    assert "setBusy(!initialLoadSucceeded);" in html
