"""Unit tests for the Discord adapter plugin.

Covers pure helpers (mention cleaning, session keys, reply splitting,
markdown image extraction), gateway payload builders, permission rules,
attachment classification and gating, trigger decisions, and the plugin
entry metadata wiring.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from plugin.plugins.discord_adapter import (
    DiscordAdapterPlugin,
    build_session_key,
    clean_mentions,
    extract_markdown_images,
    split_reply_text,
)
from plugin.plugins.discord_adapter.attachment import (
    MAX_INLINE_IMAGE_BYTES,
    AttachmentProcessor,
    classify_attachment,
    decode_text_document,
    extract_document_text,
)
from plugin.plugins.discord_adapter.gateway_client import (
    INTENTS,
    DiscordGatewayClient,
)
from plugin.plugins.discord_adapter.permission import PermissionManager
from plugin.plugins.discord_adapter.rest_client import (
    AttachmentDownloadError,
    DiscordRestClient,
)

pytestmark = pytest.mark.plugin_unit

BOT_ID = "999888777"
TOKEN = "fake-token-for-tests"


def _make_dm_message(**overrides):
    msg = {
        "id": "1",
        "channel_id": "111",
        "author": {"id": "42", "username": "alice", "bot": False},
        "content": "hello",
        "attachments": [],
    }
    msg.update(overrides)
    return msg


def _make_guild_message(**overrides):
    msg = _make_dm_message(
        guild_id="555",
        channel_id="222",
        content=f"hi <@{BOT_ID}>",
    )
    msg.update(overrides)
    return msg


def _make_plugin(tmp_path: Path, **settings_overrides) -> DiscordAdapterPlugin:
    """Build a plugin instance without the SDK context machinery."""
    from plugin.plugins.discord_adapter.config_store import DiscordConfigStore

    plugin = object.__new__(DiscordAdapterPlugin)
    plugin.ctx = SimpleNamespace(plugin_id="discord_adapter")
    plugin.config_store = DiscordConfigStore(tmp_path)
    plugin._settings = plugin.config_store.default_config()
    plugin._settings.update(settings_overrides)
    plugin._running = False
    plugin._gateway_task = None
    plugin._session_housekeeping_task = None
    plugin._handler_tasks = set()
    plugin._lifecycle_lock = asyncio.Lock()
    plugin._channel_sessions = {}
    plugin._session_locks = {}
    plugin._session_lock_refs = {}
    plugin._session_locks_guard = asyncio.Lock()
    plugin._max_concurrent_messages = 3
    plugin._message_concurrency = asyncio.Semaphore(3)
    plugin._ai_connect_timeout_seconds = 10.0
    plugin._ai_turn_timeout_seconds = 60.0
    plugin._handler_shutdown_timeout_seconds = 10.0
    plugin._permission_mode = "allow_list"
    plugin._trigger_mode = "mention"
    plugin._bot_user_id = BOT_ID
    plugin._bot_username = "NekoBot"
    plugin._stats = {
        "connected": False,
        "bot_username": "",
        "guild_count": 0,
        "messages_today": 0,
        "last_error": "",
    }
    plugin.gateway_client = None
    plugin.rest_client = None
    plugin.attachment_processor = None
    plugin.permission_mgr = PermissionManager([])
    logger = MagicMock()
    plugin.logger = logger
    return plugin


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestMentionCleaning:
    def test_strips_user_mention(self):
        assert clean_mentions(f"hi <@{BOT_ID}> there") == "hi  there"

    def test_strips_nickname_mention(self):
        assert clean_mentions(f"<@!{BOT_ID}> hello") == "hello"

    def test_strips_role_mention(self):
        assert clean_mentions("<@&123> ping") == "ping"

    def test_strips_mixed_mentions(self):
        out = clean_mentions(f"<@{BOT_ID}> <@!1> <@&2> text <@3>")
        assert out == "text"

    def test_no_mention_passthrough(self):
        assert clean_mentions("plain text") == "plain text"

    def test_empty_and_none(self):
        assert clean_mentions("") == ""
        assert clean_mentions(None) == ""


class TestSessionKey:
    def test_guild_channel_key(self):
        assert build_session_key("42", is_dm=False) == "discord:42"

    def test_dm_key_has_distinct_prefix(self):
        assert build_session_key("42", is_dm=True) == "discord:dm:42"


class TestReplySplitting:
    def test_short_text_single_chunk(self):
        assert split_reply_text("hello") == ["hello"]

    def test_empty_text_returns_empty(self):
        assert split_reply_text("") == []

    def test_long_text_split_within_limit(self):
        text = "\n\n".join(f"paragraph-{i} " + "x" * 200 for i in range(30))
        chunks = split_reply_text(text, limit=1950)
        assert len(chunks) > 1
        for chunk in chunks:
            assert len(chunk) <= 1950
        assert "".join(chunks).replace("\n", "") == text.replace("\n", "")

    def test_no_newline_hard_cut(self):
        chunks = split_reply_text("y" * 5000, limit=1950)
        assert all(len(c) <= 1950 for c in chunks)
        assert "".join(chunks) == "y" * 5000


class TestMarkdownImageExtraction:
    def test_single_image_becomes_embed(self):
        text, embeds = extract_markdown_images("look ![cat](https://cdn.discordapp.com/x.png) done")
        assert text == "look  done"
        assert embeds == [{"image": {"url": "https://cdn.discordapp.com/x.png"}, "title": "cat"}]

    def test_no_images_no_embeds(self):
        text, embeds = extract_markdown_images("plain")
        assert text == "plain"
        assert embeds == []

    def test_empty_alt_omits_title(self):
        _, embeds = extract_markdown_images("![](https://example.com/a.png)")
        assert embeds == [{"image": {"url": "https://example.com/a.png"}}]

    def test_embed_cap_at_ten(self):
        md = " ".join(f"![i{i}](https://example.com/{i}.png)" for i in range(15))
        _, embeds = extract_markdown_images(md)
        assert len(embeds) == 10


# ---------------------------------------------------------------------------
# Gateway payload builders and protocol state
# ---------------------------------------------------------------------------


class TestGatewayPayloads:
    def test_intents_value(self):
        # GUILDS | GUILD_MESSAGES | DIRECT_MESSAGES | MESSAGE_CONTENT
        assert INTENTS == 1 | 512 | 4096 | 32768

    def test_identify_payload_shape(self):
        payload = DiscordGatewayClient.build_identify_payload(TOKEN)
        assert payload["op"] == 2
        assert payload["d"]["token"] == TOKEN
        assert payload["d"]["intents"] == INTENTS
        assert "os" in payload["d"]["properties"]

    def test_resume_payload_shape(self):
        payload = DiscordGatewayClient.build_resume_payload(TOKEN, "sess", 7)
        assert payload == {
            "op": 6,
            "d": {"token": TOKEN, "session_id": "sess", "seq": 7},
        }


class _FakeWebSocket:
    """Scripted websocket: yields queued payloads, records sent frames."""

    def __init__(self, incoming: list[dict]):
        self._incoming = [json.dumps(p) for p in incoming]
        self.sent: list[dict] = []
        self.closed = False

    async def send(self, data: str) -> None:
        self.sent.append(json.loads(data))

    async def recv(self) -> str:
        if not self._incoming:
            await asyncio.sleep(3600)
        return self._incoming.pop(0)

    async def close(self) -> None:
        self.closed = True

    def __aiter__(self):
        return self._aiter()

    async def _aiter(self):
        for raw in self._incoming:
            yield raw


@pytest.mark.asyncio
class TestGatewayProtocol:
    async def test_invalid_session_not_resumable_clears_session(self):
        client = DiscordGatewayClient(
            TOKEN,
            on_message_create=AsyncMock(),
            max_reconnect_attempts=1,
        )
        client._session_id = "old-session"
        client._seq = 10
        client._resume_url = "wss://resume.example"

        ws = _FakeWebSocket([{"op": 9, "d": False}])
        await client._event_loop(ws)

        assert client._session_id is None
        assert client._seq is None
        assert client._resume_url is None

    async def test_invalid_session_resumable_keeps_session(self):
        client = DiscordGatewayClient(
            TOKEN,
            on_message_create=AsyncMock(),
            max_reconnect_attempts=1,
        )
        client._session_id = "keep-me"
        client._seq = 5

        ws = _FakeWebSocket([{"op": 9, "d": True}])
        await client._event_loop(ws)

        assert client._session_id == "keep-me"
        assert client._seq == 5

    async def test_ready_dispatch_updates_state_and_fires_callback(self):
        on_ready = AsyncMock()
        on_state = AsyncMock()
        client = DiscordGatewayClient(
            TOKEN,
            on_message_create=AsyncMock(),
            on_ready=on_ready,
            on_state_change=on_state,
            max_reconnect_attempts=1,
        )
        ws = _FakeWebSocket([
            {"op": 0, "t": "READY", "s": 3, "d": {
                "session_id": "s-1",
                "resume_gateway_url": "wss://gw.example",
                "user": {"id": BOT_ID},
                "guilds": [],
            }},
        ])
        await client._event_loop(ws)

        assert client._session_id == "s-1"
        assert client._resume_url == "wss://gw.example"
        assert client._seq == 3
        assert client.connected is True
        await asyncio.sleep(0)
        on_ready.assert_awaited_once()
        on_state.assert_awaited_with("connected", "")

    async def test_message_create_dispatch_invokes_callback(self):
        on_message = AsyncMock()
        client = DiscordGatewayClient(
            TOKEN, on_message_create=on_message, max_reconnect_attempts=1
        )
        payload = {"op": 0, "t": "MESSAGE_CREATE", "s": 9, "d": {"id": "m1"}}
        ws = _FakeWebSocket([payload])
        await client._event_loop(ws)
        await asyncio.sleep(0)
        on_message.assert_awaited_once_with({"id": "m1"})
        assert client._seq == 9

    async def test_server_heartbeat_request_is_answered(self):
        client = DiscordGatewayClient(
            TOKEN, on_message_create=AsyncMock(), max_reconnect_attempts=1
        )
        client._seq = 11
        ws = _FakeWebSocket([{"op": 1}])
        await client._event_loop(ws)
        assert {"op": 1, "d": 11} in ws.sent

    async def test_reconnect_opcode_returns_to_supervisor(self):
        client = DiscordGatewayClient(
            TOKEN, on_message_create=AsyncMock(), max_reconnect_attempts=1
        )
        ws = _FakeWebSocket([{"op": 7}])
        await client._event_loop(ws)  # must return, not raise


# ---------------------------------------------------------------------------
# REST client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRestAttachmentGates:
    async def test_non_cdn_host_rejected(self):
        client = DiscordRestClient(TOKEN)
        with pytest.raises(AttachmentDownloadError):
            await client.download_attachment("https://evil.example.com/x.png")

    async def test_cdn_host_allowed_list(self):
        client = DiscordRestClient(TOKEN)
        for host in ("cdn.discordapp.com", "media.discordapp.net"):
            fake_response = AsyncMock()
            fake_response.status_code = 200

            async def _aiter(_chunk=65536):
                yield b"data"

            fake_response.aiter_bytes = _aiter

            class _StreamCtx:
                async def __aenter__(self):
                    return fake_response

                async def __aexit__(self, *args):
                    return False

            mock_http = MagicMock()
            mock_http.is_closed = False
            mock_http.stream = MagicMock(return_value=_StreamCtx())
            client._client = mock_http
            client._client_loop = asyncio.get_running_loop()

            data = await client.download_attachment(f"https://{host}/attachments/1/2/x.png")
            assert data == b"data"
            client._client = None


# ---------------------------------------------------------------------------
# Attachment pipeline
# ---------------------------------------------------------------------------


class TestAttachmentClassification:
    def test_image_by_mime(self):
        assert classify_attachment("photo.png", "image/png") == "image"

    def test_document_by_extension(self):
        for name in ("report.pdf", "deck.pptx", "notes.md", "page.html", "a.txt", "sheet.xlsx", "doc.docx"):
            assert classify_attachment(name, "application/octet-stream") == "document"

    def test_unknown_falls_to_other(self):
        assert classify_attachment("movie.mp4", "video/mp4") == "other"
        assert classify_attachment("archive.zip", "") == "other"

    def test_text_decode_strips_html(self):
        text = decode_text_document(b"<p>Hello <b>world</b></p>", "page.html")
        assert text == "Hello world"


@pytest.mark.asyncio
class TestDocumentBridge:
    async def test_markdown_document_inlined(self):
        block = await extract_document_text("notes.md", "text/markdown", b"# Title\n\nbody text")
        assert block.startswith("[用户发送了文件 notes.md")
        assert "body text" in block

    async def test_empty_document_reports_failure(self):
        block = await extract_document_text("empty.md", "text/markdown", b"")
        assert "解析失败" in block


@pytest.mark.asyncio
class TestAttachmentProcessorGates:
    def _rest(self, payload: bytes = b"x"):
        rest = MagicMock()
        rest.download_attachment = AsyncMock(return_value=payload)
        return rest

    async def test_image_within_inline_limit_becomes_b64(self):
        proc = AttachmentProcessor(self._rest(b"\x89png-data"))
        result = await proc.process([{
            "filename": "a.png",
            "content_type": "image/png",
            "url": "https://cdn.discordapp.com/attachments/1/2/a.png",
            "size": 100,
        }])
        assert len(result.images_b64) == 1
        assert result.text_blocks == []

    async def test_image_over_inline_limit_degrades_to_link(self):
        proc = AttachmentProcessor(self._rest())
        result = await proc.process([{
            "filename": "big.png",
            "content_type": "image/png",
            "url": "https://cdn.discordapp.com/attachments/1/2/big.png",
            "size": MAX_INLINE_IMAGE_BYTES + 1,
        }])
        assert result.images_b64 == []
        assert any("链接" in block for block in result.text_blocks)

    async def test_count_overflow_adds_notice(self):
        proc = AttachmentProcessor(self._rest(), max_attachments_per_message=1)
        result = await proc.process([
            {"filename": "a.zip", "content_type": "", "url": "", "size": 1},
            {"filename": "b.zip", "content_type": "", "url": "", "size": 1},
        ])
        assert any("未处理" in block for block in result.text_blocks)

    async def test_oversized_attachment_skipped(self):
        proc = AttachmentProcessor(self._rest(), max_attachment_bytes=10)
        result = await proc.process([{
            "filename": "huge.pdf",
            "content_type": "application/pdf",
            "url": "https://cdn.discordapp.com/attachments/1/2/huge.pdf",
            "size": 1000,
        }])
        assert result.images_b64 == []
        assert any("[附件 huge.pdf" in block for block in result.text_blocks)


# ---------------------------------------------------------------------------
# Permission manager
# ---------------------------------------------------------------------------


class TestPermissionManager:
    def test_levels_roundtrip(self):
        mgr = PermissionManager([{"uid": "1", "level": "admin"}, {"uid": "2", "level": "trusted"}])
        assert mgr.get_permission_level("1") == "admin"
        assert mgr.get_permission_level("2") == "trusted"
        assert mgr.get_permission_level("3") == "none"

    def test_should_process_modes(self):
        mgr = PermissionManager([{"uid": "1", "level": "trusted"}])
        assert mgr.should_process("1", "allow_list") is True
        assert mgr.should_process("2", "allow_list") is False
        assert mgr.should_process("2", "open") is True

    def test_nickname(self):
        mgr = PermissionManager([])
        mgr.add_user("7", "trusted", "bob")
        assert mgr.get_nickname("7") == "bob"


# ---------------------------------------------------------------------------
# Trigger decisions
# ---------------------------------------------------------------------------


class TestTriggerDecisions:
    def test_mention_mode_dm_always_triggers(self, tmp_path):
        plugin = _make_plugin(tmp_path, trigger_mode="mention")
        plugin._apply_runtime_settings()
        assert plugin._should_trigger(_make_dm_message()) is True

    def test_mention_mode_guild_requires_mention(self, tmp_path):
        plugin = _make_plugin(tmp_path, trigger_mode="mention")
        plugin._apply_runtime_settings()
        assert plugin._should_trigger(_make_guild_message()) is True
        assert plugin._should_trigger(_make_guild_message(content="no mention")) is False

    def test_nickname_mention_format_triggers(self, tmp_path):
        plugin = _make_plugin(tmp_path, trigger_mode="mention")
        plugin._apply_runtime_settings()
        assert plugin._should_trigger(_make_guild_message(content=f"<@!{BOT_ID}> yo")) is True

    def test_bot_author_filtered(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        plugin._apply_runtime_settings()
        msg = _make_dm_message(author={"id": "9", "username": "botty", "bot": True})
        assert plugin._should_trigger(msg) is False

    def test_dm_only_mode(self, tmp_path):
        plugin = _make_plugin(tmp_path, trigger_mode="dm_only")
        plugin._apply_runtime_settings()
        assert plugin._should_trigger(_make_dm_message()) is True
        assert plugin._should_trigger(_make_guild_message()) is False

    def test_all_mode_requires_channel_whitelist(self, tmp_path):
        plugin = _make_plugin(
            tmp_path, trigger_mode="all", channel_whitelist="222"
        )
        plugin._apply_runtime_settings()
        assert plugin._should_trigger(_make_guild_message(content="anything")) is True
        assert plugin._should_trigger(_make_guild_message(channel_id="333", content="x")) is False
        assert plugin._should_trigger(_make_dm_message()) is True


# ---------------------------------------------------------------------------
# Entry metadata wiring (each host call path needs an assertion)
# ---------------------------------------------------------------------------


class TestEntryWiring:
    def _meta(self, fn):
        return getattr(fn, "__neko_event_meta__", None) or getattr(
            fn, "__neko_entry_meta__", None
        )

    def test_startup_lifecycle_registered(self):
        assert self._meta(DiscordAdapterPlugin.startup) is not None

    def test_shutdown_lifecycle_registered(self):
        assert self._meta(DiscordAdapterPlugin.shutdown) is not None

    def test_panel_entries_registered(self):
        for name in (
            "get_dashboard_state",
            "save_settings",
            "start_listening",
            "stop_listening",
            "add_trusted_user",
            "remove_trusted_user",
            "test_connection",
        ):
            assert self._meta(getattr(DiscordAdapterPlugin, name)) is not None, name

    def test_test_connection_hidden_from_agent(self):
        meta = self._meta(DiscordAdapterPlugin.test_connection)
        assert getattr(meta, "metadata", {}).get("agent_hidden") is True


# ---------------------------------------------------------------------------
# Host-sim lifecycle smoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_sim_startup_and_shutdown(tmp_path):
    """Run the real shutdown path on a manually constructed instance."""
    plugin = object.__new__(DiscordAdapterPlugin)
    plugin.ctx = MagicMock()
    plugin.logger = MagicMock()
    plugin.gateway_client = None
    plugin.rest_client = None
    plugin.attachment_processor = None
    plugin.permission_mgr = PermissionManager([])
    plugin._running = False
    plugin._gateway_task = None
    plugin._session_housekeeping_task = None
    plugin._handler_tasks = set()
    plugin._lifecycle_lock = asyncio.Lock()
    plugin._channel_sessions = {}
    plugin._session_locks = {}
    plugin._session_lock_refs = {}
    plugin._session_locks_guard = asyncio.Lock()
    plugin._stats = {
        "connected": False,
        "bot_username": "",
        "guild_count": 0,
        "messages_today": 0,
        "last_error": "",
    }

    result = await plugin.shutdown()
    assert result.is_ok()
    assert plugin.logger is not None
