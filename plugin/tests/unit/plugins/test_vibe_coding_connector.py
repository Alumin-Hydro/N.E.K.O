from __future__ import annotations

import asyncio
import base64
import gzip
import json
import re
import threading
import tomllib
from collections.abc import AsyncIterator, Callable
from decimal import Decimal
from html.parser import HTMLParser
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import plugin.plugins.vibe_coding_connector as vibe_coding_module
from plugin.plugins.vibe_coding_connector import VibeCodingConnectorPlugin
from plugin.plugins.vibe_coding_connector.client import (
    HapiClient,
    HapiClientConfig,
    HapiClientError,
    SSEEvent,
    _SSEParser,
    extract_permissions,
)
from plugin.plugins.vibe_coding_connector.security import (
    ConnectorSettings,
    PolicyError,
    SecurityPolicy,
    canonical_workspace,
    redact_sensitive,
    validate_base_url,
    validate_identifier,
)
from plugin.sdk.shared.constants import EVENT_META_ATTR
from plugin.sdk.shared.models import Err, Ok


pytestmark = pytest.mark.plugin_unit

PLUGIN_DIR = Path(__file__).resolve().parents[3] / "plugins" / "vibe_coding_connector"
LOCALES = ("zh-CN", "zh-TW", "en", "ja", "ko", "es", "pt", "ru")
MODEL_ENTRIES = {
    "connection_status": "vibe_coding_status",
    "list_sessions": "vibe_coding_list_sessions",
    "inspect_session": "vibe_coding_inspect_session",
    "create_session": "vibe_coding_create_session",
    "send_instruction": "vibe_coding_send_instruction",
    "read_activity": "vibe_coding_read_activity",
    "stop_session": "vibe_coding_stop_session",
    "list_approvals": "vibe_coding_list_approvals",
    "respond_approval": "vibe_coding_respond_approval",
}


class _Logger:
    def __init__(self) -> None:
        self.records: list[str] = []

    def _record(self, *args: object, **_kwargs: object) -> None:
        self.records.append(" ".join(str(item) for item in args))

    debug = _record
    info = _record
    warning = _record
    error = _record
    exception = _record


class _Context:
    plugin_id = "vibe_coding_connector"
    bus = None

    def __init__(self, plugin_dir: Path) -> None:
        self.config_path = plugin_dir / "plugin.toml"
        self.metadata = {
            "config_path": str(self.config_path),
            "i18n": {"default_locale": "zh-CN", "locales_dir": "i18n"},
        }
        self.logger = _Logger()
        self.message_queue = None
        self.config = {
            "plugin": {"store": {"enabled": True}, "database": {"enabled": False}},
            "plugin_state": {"backend": "off"},
        }
        self._effective_config = self.config
        self.pushed: list[dict[str, object]] = []

    def push_message(self, **kwargs: object) -> dict[str, object]:
        self.pushed.append(dict(kwargs))
        return {"ok": True}

    async def get_own_config(self, timeout: float = 5.0) -> dict[str, object]:
        del timeout
        return {"config": self.config}


class _ByteStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, on_close: Callable[[], None] | None = None) -> None:
        self._chunks = chunks
        self._on_close = on_close

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            await asyncio.sleep(0)
            yield chunk

    async def aclose(self) -> None:
        if self._on_close is not None:
            self._on_close()


class _SilentByteStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.started.set()
        await self.release.wait()
        if False:  # pragma: no cover - keep this an async byte iterator
            yield b""

    async def aclose(self) -> None:
        self.closed = True
        self.release.set()


class _PanelNumberInputParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inputs: dict[str, dict[str, str | None]] = {}

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        input_id = attributes.get("id")
        if tag == "input" and attributes.get("type") == "number" and input_id:
            self.inputs[input_id] = attributes


def _client_config(**overrides: object) -> HapiClientConfig:
    values: dict[str, object] = {}
    fields = getattr(HapiClientConfig, "__dataclass_fields__", {})
    defaults = {
        "base_url": "http://127.0.0.1:3006",
        "token": "access-secret-1234",
        "api_token": "access-secret-1234",
        "access_token": "access-secret-1234",
        "timeout_seconds": 1.0,
        "timeout": 1.0,
        "sse_reconnect_delay_seconds": 0.25,
        "reconnect_delay_seconds": 0.25,
        "max_response_bytes": 32_768,
        "allow_remote": False,
    }
    for name in fields:
        if name in defaults:
            values[name] = defaults[name]
    values.update(overrides)
    return HapiClientConfig(**values)


def _public(value: object) -> dict[str, object]:
    if isinstance(value, Ok):
        value = value.value
    assert isinstance(value, dict)
    return value


def _encrypt_settings_document(
    envelope: dict[str, object],
    document: dict[str, object],
    *,
    entry_id: str = "vibe_coding_save_settings",
) -> dict[str, str]:
    key_id = envelope["key_id"]
    public_key_b64 = envelope["public_key_spki_b64"]
    assert isinstance(key_id, str)
    assert isinstance(public_key_b64, str)
    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_b64, validate=True)
    )
    content_key = AESGCM.generate_key(bit_length=256)
    iv = b"\x01" * 12
    binding = f"vibe_coding_connector:{entry_id}:{key_id}".encode()
    plaintext = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    ciphertext = AESGCM(content_key).encrypt(iv, plaintext, binding)
    wrapped_key = public_key.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=binding,
        ),
    )
    outer = {
        "v": 1,
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return {
        "encrypted_payload": base64.b64encode(
            json.dumps(outer, separators=(",", ":")).encode()
        ).decode(),
        "key_id": key_id,
    }


async def _save_encrypted_settings(
    plugin: VibeCodingConnectorPlugin,
    *,
    settings: dict[str, object] | None = None,
    token: str = "",
    clear_token: bool = False,
) -> object:
    envelope = await plugin._issue_secret_envelope()
    return await plugin.save_settings(
        **_encrypt_settings_document(
            envelope,
            {
                "settings": settings or plugin._settings.to_store(),
                "token": token,
                "clear_token": clear_token,
            },
        )
    )


def _assert_no_secret_fields(value: object, *, allowed: set[str] | None = None) -> None:
    allowed = allowed or {"token_configured"}
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if key not in allowed:
                assert not any(
                    marker in lowered
                    for marker in ("token", "secret", "password", "authorization", "credential", "jwt")
                )
            _assert_no_secret_fields(item, allowed=allowed)
    elif isinstance(value, list):
        for item in value:
            _assert_no_secret_fields(item, allowed=allowed)


def _recording_transport(
    responder: Callable[[httpx.Request], httpx.Response],
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return responder(request)

    return httpx.MockTransport(handler), requests


def test_manifest_declares_runtime_store_ui_and_exact_identity() -> None:
    manifest = tomllib.loads((PLUGIN_DIR / "plugin.toml").read_text(encoding="utf-8"))

    assert manifest["plugin"]["id"] == "vibe_coding_connector"
    assert manifest["plugin"]["version"] == "0.2.0"
    assert manifest["plugin"]["entry"].endswith(":VibeCodingConnectorPlugin")
    assert manifest["plugin"]["store"]["enabled"] is True
    assert manifest["plugin"]["ui"]["enabled"] is True
    assert manifest["plugin_runtime"]["enabled"] is True
    panel = manifest["plugin"]["ui"]["panel"][0]
    assert panel["entry"] == "static/index.html"
    assert panel["context"] == "dashboard"


def test_model_operations_are_dual_decorated_with_narrow_results() -> None:
    for method_name, entry_id in MODEL_ENTRIES.items():
        method = getattr(VibeCodingConnectorPlugin, method_name)
        entry_meta = getattr(method, EVENT_META_ATTR)
        llm_meta = getattr(method, "__neko_llm_tool_meta__")

        assert entry_meta.id == entry_id
        assert entry_meta.llm_result_fields == ["summary"]
        assert llm_meta.name == entry_id
        assert llm_meta.parameters.get("type") == "object"
        assert isinstance(llm_meta.description, str) and llm_meta.description.strip()


def test_lifecycle_and_panel_entries_are_declared() -> None:
    assert getattr(VibeCodingConnectorPlugin.startup, EVENT_META_ATTR).id == "startup"
    assert getattr(VibeCodingConnectorPlugin.shutdown, EVENT_META_ATTR).id == "shutdown"
    assert callable(getattr(VibeCodingConnectorPlugin, "_on_command_loop_start"))

    for name in ("save_settings", "reset_settings", "clear_token"):
        meta = getattr(getattr(VibeCodingConnectorPlugin, name), EVENT_META_ATTR)
        assert meta.id == f"vibe_coding_{name}"
        assert not hasattr(getattr(VibeCodingConnectorPlugin, name), "__neko_llm_tool_meta__")
    panel_meta = getattr(VibeCodingConnectorPlugin.panel_state, EVENT_META_ATTR)
    assert panel_meta.id == "vibe_coding_panel_state"
    panel_entries = {
        "panel_connection_status": "vibe_coding_panel_status",
        "panel_list_sessions": "vibe_coding_panel_list_sessions",
        "panel_create_session": "vibe_coding_panel_create_session",
        "panel_read_activity": "vibe_coding_panel_read_activity",
        "panel_list_approvals": "vibe_coding_panel_list_approvals",
    }
    for method_name, entry_id in panel_entries.items():
        method = getattr(VibeCodingConnectorPlugin, method_name)
        assert getattr(method, EVENT_META_ATTR).id == entry_id
        assert not hasattr(method, "__neko_llm_tool_meta__")
    assert hasattr(VibeCodingConnectorPlugin.dashboard_context, "__neko_ui_context__")


@pytest.mark.asyncio
async def test_startup_enables_manifest_store_before_load_and_settings_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    ctx = _Context(PLUGIN_DIR)
    ctx._effective_config = {
        "plugin": {"store": {"enabled": False}, "database": {"enabled": False}},
        "plugin_state": {"backend": "off"},
    }
    plugin = VibeCodingConnectorPlugin(ctx)
    assert plugin.store.enabled is False

    try:
        started = await plugin.startup()
        assert started.is_ok()
        assert plugin.store.enabled is True

        saved = await _save_encrypted_settings(
            plugin,
            token="access-secret-1234",
        )
        assert saved.is_ok()
    finally:
        await plugin.shutdown()


def test_default_settings_are_secure_and_public_shape_never_echoes_token() -> None:
    settings = ConnectorSettings()
    public = settings.to_public()
    serialized = json.dumps(public, ensure_ascii=False)

    assert validate_base_url(settings.base_url, allow_remote=False).startswith("http://127.")
    assert not settings.allowed_workspace_roots
    assert set(settings.allowed_providers) <= {"claude", "codex", "opencode"}
    assert settings.allow_create is False
    assert settings.allow_send is False
    assert settings.allow_stop is False
    assert settings.allow_approval is False
    assert settings.sse_enabled is False
    assert settings.auto_approve is False
    assert "access-secret" not in serialized
    _assert_no_secret_fields(public)


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("http://127.0.0.1:3006/", "http://127.0.0.1:3006"),
        ("http://localhost:3006/", "http://localhost:3006"),
        ("http://[::1]:3006/", "http://[::1]:3006"),
    ),
)
def test_base_url_normalizes_safe_loopback(raw: str, expected: str) -> None:
    assert validate_base_url(raw, allow_remote=False) == expected


@pytest.mark.parametrize(
    "raw",
    (
        "ftp://127.0.0.1:3006",
        "http://user:pass@127.0.0.1:3006",
        "http://127.0.0.1:3006/path?token=secret",
        "http://127.0.0.1:3006/#fragment",
        "http://0.0.0.0:3006",
        "http://192.168.1.8:3006",
        "http://example.test:3006",
        "",
    ),
)
def test_base_url_rejects_unsafe_or_remote_without_opt_in(raw: str) -> None:
    with pytest.raises(PolicyError):
        validate_base_url(raw, allow_remote=False)


def test_remote_url_needs_explicit_opt_in_and_normalizes() -> None:
    assert (
        validate_base_url("https://hapi.example.test:8443/", allow_remote=True)
        == "https://hapi.example.test:8443"
    )


def test_remote_url_rejects_plain_http_even_with_explicit_opt_in() -> None:
    with pytest.raises(PolicyError) as caught:
        validate_base_url("http://hapi.example.test:3006", allow_remote=True)

    assert caught.value.code == "remote_https_required"
    assert (
        validate_base_url("http://127.0.0.1:3006", allow_remote=False)
        == "http://127.0.0.1:3006"
    )


def test_client_config_revalidates_remote_opt_in_at_request_boundary() -> None:
    with pytest.raises(PolicyError):
        _client_config(base_url="https://hapi.example.test", allow_remote=False)
    config = _client_config(
        base_url="https://hapi.example.test/",
        allow_remote=True,
    )
    assert config.base_url == "https://hapi.example.test"


def test_client_config_token_is_bounded_trimmed_and_hidden_from_repr() -> None:
    config = _client_config(token="  access-secret-1234  ")
    assert config.token == "access-secret-1234"
    assert "access-secret-1234" not in repr(config)
    with pytest.raises(ValueError):
        _client_config(token="x" * 8_193)
    with pytest.raises(ValueError):
        _client_config(token=123)


def test_workspace_requires_configured_canonical_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)

    assert Path(canonical_workspace(str(nested), [str(root)])) == nested.resolve()
    with pytest.raises(PolicyError, match="(?i)(root|工作区|allow)"):
        canonical_workspace(str(nested), [])
    with pytest.raises(PolicyError):
        canonical_workspace(str(root / "nested" / ".." / "nested"), [str(root)])
    with pytest.raises(PolicyError):
        canonical_workspace("nested", [str(root)])


def test_workspace_rejects_nonexistent_and_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    escape = root / "escape"
    try:
        escape.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(PolicyError):
        canonical_workspace(str(escape), [str(root)])
    with pytest.raises(PolicyError):
        canonical_workspace(str(root / "missing"), [str(root)])


def test_workspace_rejects_nested_symlink_sibling_prefix_file_and_nul(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    sibling = tmp_path / "allowed-evil"
    outside_child = sibling / "child"
    root.mkdir()
    outside_child.mkdir(parents=True)
    regular_file = root / "file.txt"
    regular_file.write_text("x", encoding="utf-8")
    link = root / "link"
    try:
        link.symlink_to(sibling, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")

    for candidate in (
        outside_child,
        link / "child",
        regular_file,
        Path(str(root) + "\x00"),
    ):
        with pytest.raises(PolicyError):
            canonical_workspace(str(candidate), [str(root)])


def test_workspace_rejects_stored_root_replaced_by_symlink(tmp_path: Path) -> None:
    configured_root = tmp_path / "configured"
    configured_child = configured_root / "project"
    configured_child.mkdir(parents=True)
    settings = ConnectorSettings.from_mapping(
        {"allowed_workspace_roots": [str(configured_root)]}
    )
    stored_root = settings.allowed_workspace_roots[0]

    moved_root = tmp_path / "moved-root"
    configured_root.rename(moved_root)
    replacement = tmp_path / "replacement"
    replacement_child = replacement / "project"
    replacement_child.mkdir(parents=True)
    try:
        configured_root.symlink_to(replacement, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(PolicyError, match="(?i)(root|工作区|符号链接)"):
        canonical_workspace(str(configured_child), [stored_root])


def test_identifier_validation_is_strict_and_lossless() -> None:
    identifier = "Session.Mixed_CASE-123:node"
    maximum_length_identifier = "S" + ("a" * 255)

    assert validate_identifier(identifier, kind="会话 ID") == identifier
    assert (
        validate_identifier(maximum_length_identifier, kind="会话 ID")
        == maximum_length_identifier
    )
    for unsafe in (" session", "session ", "session/child", ".", "..", "会话"):
        with pytest.raises(PolicyError):
            validate_identifier(unsafe, kind="会话 ID")


def test_redaction_removes_bearer_access_token_and_sensitive_values() -> None:
    dirty = {
        "Authorization": "Bearer jwt.super.secret",
        "nested": {"accessToken": "hapi-token-1234"},
        "safe": "status",
    }
    clean = redact_sensitive(dirty)

    assert isinstance(clean, dict)
    assert clean["Authorization"] == "[REDACTED]"
    assert clean["nested"]["accessToken"] == "[REDACTED]"
    assert clean["safe"] == "status"
    assert "hapi-token-1234" not in json.dumps(clean)
    assert "jwt.super.secret" not in json.dumps(clean)


def test_settings_parser_limits_providers_and_never_enables_auto_approve() -> None:
    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping({"allowed_providers": ["claude", "arbitrary-shell"]})
    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping({"auto_approve": True})

    settings = ConnectorSettings.from_mapping({"allowed_providers": ["claude", "codex"]})
    assert settings.allowed_providers == ("claude", "codex")
    assert settings.auto_approve is False


@pytest.mark.parametrize(
    "field",
    (
        "allow_remote",
        "allow_create",
        "allow_send",
        "allow_stop",
        "allow_approval",
        "sse_enabled",
        "notifications_enabled",
    ),
)
def test_settings_toggle_values_are_strict_booleans(field: str) -> None:
    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping({field: "true"})


@pytest.mark.parametrize(
    "update",
    (
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": float("inf")},
        {"max_response_size": True},
        {"max_instruction_chars": 255},
        {"max_output_chars": 64_001},
        {"rate_limit_per_minute": 0},
        {"max_concurrency": 11},
    ),
)
def test_settings_numeric_bounds_reject_invalid_values(update: dict[str, object]) -> None:
    with pytest.raises(PolicyError):
        ConnectorSettings.from_mapping(update)


def test_security_policy_enforces_provider_toggles_and_bounds(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    settings = ConnectorSettings.from_mapping(
        {
            "allowed_workspace_roots": [str(root)],
            "allowed_providers": ["codex"],
            "allow_create": True,
            "allow_send": False,
            "max_instruction_chars": 256,
            "max_output_chars": 1_000,
        }
    )
    policy = SecurityPolicy(settings)

    assert policy.validate_provider("codex") == "codex"
    with pytest.raises(PolicyError):
        policy.validate_provider("claude")
    assert Path(policy.validate_workspace(str(root))) == root.resolve()
    with pytest.raises(PolicyError):
        policy.require_tool("send")
    assert policy.validate_instruction("fix tests") == "fix tests"
    with pytest.raises(PolicyError):
        policy.validate_instruction("x" * 257)


@pytest.mark.asyncio
async def test_security_policy_rate_and_concurrency_limits() -> None:
    settings = ConnectorSettings.from_mapping(
        {"rate_limit_per_minute": 2, "max_concurrency": 1}
    )
    policy = SecurityPolicy(settings)

    async with policy.permit():
        with pytest.raises(PolicyError, match="(?i)(concurr|并发|busy)"):
            async with policy.permit():
                pass
    async with policy.permit():
        pass
    with pytest.raises(PolicyError, match="(?i)(rate|频繁|limit)"):
        async with policy.permit():
            pass


@pytest.mark.asyncio
async def test_security_policy_releases_concurrency_after_failure() -> None:
    policy = SecurityPolicy(
        ConnectorSettings.from_mapping(
            {"rate_limit_per_minute": 3, "max_concurrency": 1}
        )
    )

    with pytest.raises(RuntimeError):
        async with policy.permit():
            raise RuntimeError("boom")
    async with policy.permit():
        pass


@pytest.mark.asyncio
async def test_client_authenticates_and_uses_exact_session_routes() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/auth":
            assert json.loads(request.content) == {"accessToken": "access-secret-1234"}
            assert "authorization" not in request.headers
            return httpx.Response(200, json={"token": "jwt-session-token", "user": {"id": "u"}})
        assert request.headers["authorization"] == "Bearer jwt-session-token"
        if path == "/api/machines":
            return httpx.Response(200, json={"machines": [{"id": "m1", "active": True}]})
        if path == "/api/sessions":
            return httpx.Response(200, json={"sessions": [{"id": "s1", "active": True}]})
        if path == "/api/sessions/s1":
            return httpx.Response(200, json={"session": {"id": "s1", "metadata": {"path": "/repo"}}})
        if path == "/api/sessions/s1/messages":
            assert request.url.params["limit"] == "7"
            return httpx.Response(200, json={"messages": [{"id": "msg1", "text": "ok"}]})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    transport, requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        assert (await client.list_machines())[0]["id"] == "m1"
        assert (await client.list_sessions())[0]["id"] == "s1"
        assert (await client.get_session("s1"))["id"] == "s1"
        assert (await client.list_messages("s1", limit=7))[0]["id"] == "msg1"
    finally:
        await client.aclose()

    assert [(request.method, request.url.path) for request in requests] == [
        ("POST", "/api/auth"),
        ("GET", "/api/machines"),
        ("GET", "/api/sessions"),
        ("GET", "/api/sessions/s1"),
        ("GET", "/api/sessions/s1/messages"),
    ]
    assert all("access-secret-1234" not in str(request.url) for request in requests)


@pytest.mark.asyncio
async def test_client_health_is_unauthenticated_and_accepts_protocol_version() -> None:
    transport, requests = _recording_transport(
        lambda request: httpx.Response(200, json={"status": "ok", "protocolVersion": 1})
    )
    client = HapiClient(_client_config(), transport=transport)
    try:
        health = await client.health()
    finally:
        await client.aclose()

    assert health["status"] == "ok"
    assert health["protocol_version"] == 1
    assert requests[0].url.path == "/health"
    assert "authorization" not in requests[0].headers


@pytest.mark.asyncio
async def test_client_disables_environment_proxies_and_redirects() -> None:
    captured: dict[str, object] = {}
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"status": "ok"})
    )

    def factory(**kwargs: object) -> httpx.AsyncClient:
        captured.update(kwargs)
        kwargs["transport"] = transport
        return httpx.AsyncClient(**kwargs)

    client = HapiClient(_client_config(), client_factory=factory)
    try:
        await client.health()
    finally:
        await client.aclose()

    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False


def test_client_reuses_within_loop_but_isolates_clients_between_event_loops() -> None:
    created: list[httpx.AsyncClient] = []
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"status": "ok"})
    )

    def factory(**kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        client = httpx.AsyncClient(**kwargs)
        created.append(client)
        return client

    client = HapiClient(_client_config(), client_factory=factory)

    async def use_twice() -> None:
        await client.health()
        await client.health()

    asyncio.run(use_twice())
    assert len(created) == 1
    asyncio.run(client.health())
    assert len(created) == 2
    asyncio.run(client.aclose())
    assert all(item.is_closed for item in created)


@pytest.mark.asyncio
async def test_managed_runtime_actual_endpoint_and_token_configure_hapi_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "NEKO_STORAGE_SELECTED_ROOT",
        str(tmp_path / "runtime"),
    )
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    plugin._settings = ConnectorSettings.from_mapping(
        {"backend_mode": "managed_hapi"}
    )
    plugin._policy.update(plugin._settings)
    plugin._loaded = True

    class _Runtime:
        base_url = "http://127.0.0.1:43123"
        access_token = "managed-runtime-access-token"

    plugin._managed_runtime = _Runtime()  # type: ignore[assignment]

    async def fake_ensure_managed_runtime(
        *,
        force_restart: bool = False,
        raise_errors: bool = False,
    ) -> dict[str, object]:
        assert force_restart is False
        assert raise_errors is True
        return {
            "state": "ready",
            "actual_port": 43123,
            "base_url": _Runtime.base_url,
        }

    monkeypatch.setattr(
        plugin,
        "_ensure_managed_runtime",
        fake_ensure_managed_runtime,
    )
    captured: list[HapiClientConfig] = []

    class _Client:
        def __init__(self, config: HapiClientConfig) -> None:
            captured.append(config)

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(vibe_coding_module, "HapiClient", _Client)

    try:
        client = await plugin._get_client()
        assert isinstance(client, _Client)
        assert len(captured) == 1
        assert captured[0].base_url == "http://127.0.0.1:43123"
        assert captured[0].token == "managed-runtime-access-token"
        assert captured[0].auth_mode == "access_token"
        assert captured[0].allow_remote is False
    finally:
        await plugin._invalidate_client()


@pytest.mark.asyncio
async def test_absent_hapi_returns_friendly_credential_free_error() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "connection failed with access-secret-1234",
            request=request,
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        with pytest.raises(HapiClientError) as caught:
            await client.health()
    finally:
        await client.aclose()

    assert caught.value.code == "connection_failed"
    assert "access-secret-1234" not in str(caught.value)
    assert "HAPI" in str(caught.value)


@pytest.mark.asyncio
async def test_bearer_mode_never_calls_access_token_auth_route() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/sessions"
        assert request.headers["authorization"] == "Bearer access-secret-1234"
        return httpx.Response(200, json={"sessions": []})

    transport, requests = _recording_transport(responder)
    client = HapiClient(_client_config(auth_mode="bearer"), transport=transport)
    try:
        assert await client.list_sessions() == []
    finally:
        await client.aclose()

    assert [request.url.path for request in requests] == ["/api/sessions"]


@pytest.mark.asyncio
async def test_access_token_401_refreshes_once_then_retries_original_request() -> None:
    auth_count = 0
    session_count = 0

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal auth_count, session_count
        if request.url.path == "/api/auth":
            auth_count += 1
            return httpx.Response(200, json={"token": f"jwt-{auth_count}"})
        session_count += 1
        if session_count == 1:
            assert request.headers["authorization"] == "Bearer jwt-1"
            return httpx.Response(401, json={"error": "expired access-secret-1234"})
        assert request.headers["authorization"] == "Bearer jwt-2"
        return httpx.Response(200, json={"sessions": []})

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        assert await client.list_sessions() == []
    finally:
        await client.aclose()

    assert (auth_count, session_count) == (2, 2)


@pytest.mark.asyncio
async def test_client_create_send_stop_and_permission_payload_contract() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        if request.url.path == "/api/machines/machine-1/spawn":
            assert request.method == "POST"
            assert json.loads(request.content) == {
                "directory": "/safe/repo",
                "agent": "codex",
                "sessionType": "simple",
                "yolo": False,
                "permissionMode": "default",
            }
            return httpx.Response(200, json={"type": "success", "sessionId": "s1"})
        if request.url.path == "/api/sessions/s1/messages":
            assert json.loads(request.content) == {"text": "fix tests"}
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/api/sessions/s1/abort":
            assert json.loads(request.content) == {}
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/api/sessions/s1/permissions/r1/approve":
            assert json.loads(request.content) == {"answers": {"0": ["once"]}}
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/api/sessions/s1/permissions/r2/deny":
            assert json.loads(request.content) == {}
            return httpx.Response(200, json={"ok": True})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    transport, requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        assert await client.create_session("machine-1", "/safe/repo", "codex") == "s1"
        assert await client.send_instruction("s1", "fix tests") is None
        assert await client.abort_session("s1") is None
        assert await client.approve_permission("s1", "r1", answers={"0": ["once"]}) is None
        assert await client.deny_permission("s1", "r2") is None
    finally:
        await client.aclose()

    assert len([request for request in requests if request.url.path == "/api/auth"]) == 1


@pytest.mark.asyncio
async def test_client_resume_uses_current_route_then_404_reopen_fallback() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        assert request.method == "POST"
        assert json.loads(request.content) == {"permissionMode": "plan"}
        if request.url.path == "/api/sessions/s1/resume":
            return httpx.Response(404, json={"error": "unsupported"})
        if request.url.path == "/api/sessions/s1/reopen":
            return httpx.Response(200, json={"session": {"id": "s2"}})
        raise AssertionError(f"unexpected route: {request.url.path}")

    transport, requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        assert await client.resume_session("s1", "plan") == "s2"
    finally:
        await client.aclose()

    assert [request.url.path for request in requests] == [
        "/api/auth",
        "/api/sessions/s1/resume",
        "/api/sessions/s1/reopen",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected"),
    (
        ([{"id": "s1"}], "s1"),
        ({"data": [{"id": "s2"}]}, "s2"),
        ({"data": {"sessions": [{"id": "s3"}]}}, "s3"),
    ),
)
async def test_client_accepts_documented_list_response_variants(
    payload: object, expected: str
) -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(200, json=payload)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        sessions = await client.list_sessions()
    finally:
        await client.aclose()

    assert sessions[0]["id"] == expected


@pytest.mark.asyncio
async def test_client_normalizes_current_hapi_session_summary_shape() -> None:
    payload = {
        "sessions": [
            {
                "id": "s1",
                "active": True,
                "metadata": {
                    "path": "/safe/repo",
                    "flavor": "codex",
                    "machineId": "m1",
                },
                "pendingRequestsCount": 2,
            }
        ]
    }

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(200, json=payload)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        session = (await client.list_sessions())[0]
    finally:
        await client.aclose()

    assert session["directory"] == "/safe/repo"
    assert session["provider"] == "codex"
    assert session["machine_id"] == "m1"
    assert session["pending_count"] == 2


def test_permission_extraction_rejects_mismatched_or_missing_request_ids() -> None:
    mapping_permissions = extract_permissions(
        {
            "requests": {
                "map-good": {
                    "id": "map-good",
                    "tool": "read_file",
                    "arguments": {"path": "README.md"},
                },
                "map-mismatch": {
                    "id": "different-id",
                    "tool": "write_file",
                    "arguments": {"path": "unsafe.txt"},
                },
            }
        }
    )
    assert [item["id"] for item in mapping_permissions] == ["map-good"]

    list_permissions = extract_permissions(
        {
            "requests": [
                {
                    "tool": "write_file",
                    "arguments": {"path": "missing-id.txt"},
                },
                {
                    "requestId": "list-good",
                    "tool": "read_file",
                    "arguments": {"path": "README.md"},
                },
            ]
        }
    )
    assert [item["id"] for item in list_permissions] == ["list-good"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content_envelope", "expected_text"),
    (
        (
            {
                "role": "assistant",
                "content": [{"type": "text", "text": "direct envelope"}],
            },
            "direct envelope",
        ),
        (
            {
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "message envelope"}],
                }
            },
            "message envelope",
        ),
        (
            {
                "data": {
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": "data envelope"}],
                    }
                }
            },
            "data envelope",
        ),
        (
            {
                "payload": {
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": "payload envelope"}],
                    }
                }
            },
            "payload envelope",
        ),
    ),
)
async def test_client_normalizes_all_official_message_content_envelopes(
    content_envelope: dict[str, object],
    expected_text: str,
) -> None:
    payload = {
        "messages": [
            {
                "id": "msg1",
                "seq": 1,
                "createdAt": 123,
                "content": content_envelope,
            }
        ]
    }

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(200, json=payload)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        message = (await client.list_messages("s1", limit=1))[0]
    finally:
        await client.aclose()

    assert message["role"] == "assistant"
    assert expected_text in json.dumps(message["content"], ensure_ascii=False)


@pytest.mark.asyncio
async def test_client_preserves_generic_codex_data_message_content() -> None:
    payload = {
        "messages": [
            {
                "id": "msg-codex",
                "content": {
                    "role": "assistant",
                    "content": {
                        "type": "codex",
                        "data": {
                            "type": "message",
                            "message": "generic codex output",
                        },
                    },
                },
            }
        ]
    }

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(200, json=payload)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        message = (await client.list_messages("s1", limit=1))[0]
    finally:
        await client.aclose()

    assert message["role"] == "assistant"
    assert "generic codex output" in json.dumps(
        message["content"],
        ensure_ascii=False,
    )


@pytest.mark.asyncio
async def test_client_treats_hapi_success_status_error_shape_as_failure() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(
            200,
            json={"type": "error", "message": "failed with access-secret-1234 at /private/repo"},
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        with pytest.raises(HapiClientError) as caught:
            await client.create_session("m1", "/safe/repo", "codex")
    finally:
        await client.aclose()

    public_error = str(caught.value)
    assert "access-secret-1234" not in public_error
    assert "/private/repo" not in public_error
    assert len(public_error) < 300


@pytest.mark.asyncio
async def test_client_rejects_oversized_remote_error_without_leaking_body() -> None:
    long_secret_error = {
        "error": "Authorization: Bearer jwt.super.secret token=access-secret-1234 "
        + ("x" * 20_000)
    }

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt.super.secret"})
        return httpx.Response(500, json=long_secret_error)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(max_response_bytes=16_384), transport=transport)
    try:
        with pytest.raises(HapiClientError) as caught:
            await client.list_sessions()
    finally:
        await client.aclose()

    error = str(caught.value)
    assert "jwt.super.secret" not in error
    assert "access-secret-1234" not in error
    assert len(error) < 300


@pytest.mark.asyncio
async def test_client_rejects_oversized_success_response() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(
            200,
            json={"sessions": [{"id": "s1", "padding": "x" * 20_000}]},
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(max_response_bytes=16_384), transport=transport)
    try:
        with pytest.raises(HapiClientError) as caught:
            await client.list_sessions()
    finally:
        await client.aclose()

    assert caught.value.code == "response_too_large"


@pytest.mark.asyncio
async def test_client_rejects_compressed_http_before_decompression() -> None:
    compressed = gzip.compress(
        json.dumps(
            {"sessions": [{"id": "s1", "padding": "x" * 200_000}]}
        ).encode()
    )

    def responder(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
            content=compressed,
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(
        _client_config(auth_mode="bearer", max_response_bytes=16_384),
        transport=transport,
    )
    try:
        with pytest.raises(HapiClientError) as caught:
            await client.list_sessions()
    finally:
        await client.aclose()

    assert caught.value.code == "unsupported_content_encoding"


@pytest.mark.asyncio
async def test_client_redacts_derived_bearer_from_http_and_sse_values() -> None:
    derived = "opaque-derived-bearer-7890"

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": derived})
        if request.url.path == "/api/sessions":
            return httpx.Response(
                200,
                json={
                    "sessions": [
                        {
                            "id": "s1",
                            "status": derived,
                            "provider": "codex",
                            "directory": "/safe/repo",
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_ByteStream(
                [
                    (
                        f'data: {{"type":"{derived}","sessionId":"s1",'
                        f'"text":"prefix {derived} suffix"}}\n\n'
                    ).encode()
                ]
            ),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        sessions = await client.list_sessions()
        events = [
            event
            async for event in client.iter_events(reconnect=False)
        ]
    finally:
        await client.aclose()

    assert derived not in json.dumps(sessions)
    assert derived not in json.dumps(
        [
            {"event": event.event, "id": event.event_id, "data": event.data}
            for event in events
        ]
    )


@pytest.mark.asyncio
async def test_client_redacts_configured_token_echoed_as_json_scalars() -> None:
    secret = "12345678"

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(
                200,
                json={"status": secret, "protocolVersion": int(secret)},
            )
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "derived-bearer"})
        if request.url.path == "/api/sessions":
            return httpx.Response(
                200,
                json={
                    "sessions": [
                        {
                            "id": "s1",
                            "status": "active",
                            "updatedAt": int(secret),
                        }
                    ]
                },
            )
        raise AssertionError(request.url.path)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(token=secret), transport=transport)
    try:
        health = await client.health()
        sessions = await client.list_sessions()
    finally:
        await client.aclose()

    assert secret not in json.dumps(
        {"health": health, "sessions": sessions},
        ensure_ascii=False,
    )


@pytest.mark.asyncio
async def test_client_rejects_mapping_values_in_scalar_remote_fields() -> None:
    machine_secret = "opaque-machine-secret"
    status_secret = "opaque-status-secret"
    tool_secret = "opaque-tool-secret"

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "derived-bearer"})
        if request.url.path == "/api/machines":
            return httpx.Response(
                200,
                json={
                    "machines": [
                        {
                            "id": "m1",
                            "name": {"credential": machine_secret},
                            "online": True,
                        }
                    ]
                },
            )
        if request.url.path == "/api/sessions":
            return httpx.Response(
                200,
                json={
                    "sessions": [
                        {
                            "id": "s1",
                            "status": {"credential": status_secret},
                            "active": True,
                        }
                    ]
                },
            )
        raise AssertionError(request.url.path)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        machines = await client.list_machines()
        sessions = await client.list_sessions()
    finally:
        await client.aclose()
    permissions = extract_permissions(
        {
            "requests": {
                "r1": {
                    "tool": {"authorization": tool_secret},
                    "arguments": {},
                }
            }
        }
    )

    serialized = json.dumps(
        {
            "machines": machines,
            "sessions": sessions,
            "permissions": permissions,
        },
        ensure_ascii=False,
    )
    for secret in (machine_secret, status_secret, tool_secret):
        assert secret not in serialized
    assert machines[0]["name"] == "m1"
    assert sessions[0]["status"] == "active"
    assert permissions[0]["tool"] == "unknown"


@pytest.mark.asyncio
async def test_client_treats_remote_lifecycle_flags_as_strict_booleans() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "derived-bearer"})
        if request.url.path == "/api/machines":
            return httpx.Response(
                200,
                json={
                    "machines": [
                        {"id": "m1", "online": False},
                        {"id": "m2", "online": "false"},
                    ]
                },
            )
        if request.url.path == "/api/sessions":
            return httpx.Response(
                200,
                json={
                    "sessions": [
                        {
                            "id": "s1",
                            "active": False,
                            "thinking": False,
                            "agentState": {"running": False},
                        },
                        {
                            "id": "s2",
                            "active": "false",
                            "thinking": "false",
                            "agentState": {"running": "false"},
                        },
                    ]
                },
            )
        raise AssertionError(request.url.path)

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(token="false"), transport=transport)
    try:
        machines = await client.list_machines()
        sessions = await client.list_sessions()
    finally:
        await client.aclose()

    assert all(machine["online"] is False for machine in machines)
    assert all(session["active"] is False for session in sessions)
    assert all(session["thinking"] is False for session in sessions)


@pytest.mark.asyncio
async def test_client_rejects_path_injection_identifiers() -> None:
    transport, requests = _recording_transport(
        lambda request: (
            httpx.Response(200, json={"token": "jwt"})
            if request.url.path == "/api/auth"
            else httpx.Response(200, json={"session": {"id": "safe"}})
        )
    )
    client = HapiClient(_client_config(), transport=transport)
    try:
        with pytest.raises((PolicyError, HapiClientError, ValueError)):
            await client.get_session("../secret?token=x")
    finally:
        await client.aclose()

    assert all(".." not in request.url.path for request in requests)
    assert all(request.url.query == b"" for request in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args"),
    (
        ("get_session", ("bad/id",)),
        ("list_messages", ("..", 3)),
        ("create_session", ("machine%2fid", "/safe", "codex")),
        ("send_instruction", ("session\nid", "fix")),
        ("abort_session", ("session?id=x",)),
        ("abort_session", ("session\\id",)),
        ("approve_permission", ("s1", "../r1")),
        ("deny_permission", ("s1", "r1" * 200)),
    ),
)
async def test_all_client_routes_reject_unsafe_identifiers_before_network(
    method: str, args: tuple[object, ...]
) -> None:
    transport, requests = _recording_transport(
        lambda request: httpx.Response(500, json={"error": "must not be called"})
    )
    client = HapiClient(_client_config(), transport=transport)
    try:
        with pytest.raises((PolicyError, HapiClientError, ValueError)):
            await getattr(client, method)(*args)
    finally:
        await client.aclose()
    assert requests == []


@pytest.mark.asyncio
async def test_sse_parser_handles_multiline_data_heartbeat_and_bounds() -> None:
    closed = False

    def mark_closed() -> None:
        nonlocal closed
        closed = True

    body = _ByteStream(
        [
            b": connected\n\n",
            b"id: evt-1\nevent: session-updated\n",
            b'data: {"type":"session-updated",\n',
            b'data: "sessionId":"s1"}\n\n',
            b"event: heartbeat\ndata: {}\n\n",
        ],
        on_close=mark_closed,
    )

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        assert request.url.path == "/api/events"
        assert request.url.params["all"] == "1"
        assert request.extensions["timeout"]["read"] is None
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=body,
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    events: list[SSEEvent] = []
    try:
        async for event in client.iter_events(reconnect=False):
            events.append(event)
    finally:
        await client.aclose()

    assert events
    assert events[0].event == "session-updated"
    assert events[0].data["sessionId"] == "s1"
    assert closed


def test_sse_parser_bounds_empty_data_lines_and_recovers_next_frame() -> None:
    parser = _SSEParser(64)

    for _ in range(100):
        parser.feed(b"data:\n")
    assert len(parser._data_lines) <= 64

    parser.feed(b"\n")
    events = parser.feed(b'data: {"type":"session-ended","sessionId":"s1"}\n\n')
    assert [event.event for event in events] == ["session-ended"]


@pytest.mark.asyncio
async def test_sse_stop_event_closes_a_silent_stream_without_external_cancellation() -> None:
    stop = asyncio.Event()
    stream = _SilentByteStream()
    transport, _requests = _recording_transport(
        lambda request: httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=stream,
        )
    )
    client = HapiClient(
        _client_config(auth_mode="bearer"),
        transport=transport,
    )

    async def consume() -> None:
        async for _event in client.iter_events(stop_event=stop):
            pass

    task = asyncio.create_task(consume())
    try:
        await asyncio.wait_for(stream.started.wait(), timeout=1.0)
        stop.set()
        await asyncio.wait_for(task, timeout=1.0)
        assert stream.closed is True
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.aclose()


@pytest.mark.asyncio
async def test_sse_authentication_failure_is_not_reconnected_forever() -> None:
    attempts = 0

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(401, json={"error": "unauthorized"})

    transport, _requests = _recording_transport(responder)
    client = HapiClient(
        _client_config(auth_mode="bearer", reconnect_delay_seconds=0.01),
        transport=transport,
    )
    try:
        with pytest.raises(HapiClientError) as caught:
            await asyncio.wait_for(anext(client.iter_events()), timeout=1.0)
    finally:
        await client.aclose()

    assert caught.value.code == "authentication_failed"
    assert attempts == 1


@pytest.mark.asyncio
async def test_sse_refreshes_expired_derived_bearer_once() -> None:
    auth_attempts = 0
    stream_attempts = 0

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal auth_attempts, stream_attempts
        if request.url.path == "/api/auth":
            auth_attempts += 1
            return httpx.Response(200, json={"token": f"derived-jwt-{auth_attempts}"})
        assert request.url.path == "/api/events"
        stream_attempts += 1
        if stream_attempts == 1:
            assert request.headers["authorization"] == "Bearer derived-jwt-1"
            return httpx.Response(401, json={"error": "expired"})
        assert request.headers["authorization"] == "Bearer derived-jwt-2"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_ByteStream(
                [b'data: {"type":"session-ended","sessionId":"s1"}\n\n']
            ),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        event = await asyncio.wait_for(
            anext(client.iter_events(reconnect=False)),
            timeout=1.0,
        )
    finally:
        await client.aclose()

    assert event.event == "session-ended"
    assert auth_attempts == 2
    assert stream_attempts == 2


@pytest.mark.asyncio
async def test_sse_reconnects_after_transient_auth_transport_failure() -> None:
    auth_attempts = 0

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal auth_attempts
        if request.url.path == "/api/auth":
            auth_attempts += 1
            if auth_attempts == 1:
                raise httpx.ConnectError("temporary auth outage", request=request)
            return httpx.Response(200, json={"token": "derived-jwt"})
        assert request.url.path == "/api/events"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_ByteStream(
                [b'data: {"type":"session-ended","sessionId":"s1"}\n\n']
            ),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(
        _client_config(reconnect_delay_seconds=0.01),
        transport=transport,
    )
    try:
        event = await asyncio.wait_for(anext(client.iter_events()), timeout=1.0)
    finally:
        await client.aclose()

    assert event.event == "session-ended"
    assert auth_attempts == 2


@pytest.mark.asyncio
async def test_sse_rejects_compressed_stream_before_decompression() -> None:
    compressed = gzip.compress(
        b'data: {"type":"message","text":"' + (b"x" * 200_000) + b'"}\n\n'
    )

    def responder(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={
                "content-type": "text/event-stream",
                "content-encoding": "gzip",
            },
            content=compressed,
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(
        _client_config(auth_mode="bearer", max_response_bytes=16_384),
        transport=transport,
    )
    try:
        with pytest.raises(HapiClientError) as caught:
            await anext(client.iter_events(reconnect=False))
    finally:
        await client.aclose()

    assert caught.value.code == "unsupported_content_encoding"


@pytest.mark.asyncio
async def test_sse_stop_event_cancels_stream_cleanly() -> None:
    stop = asyncio.Event()

    class _EndlessStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b'data: {"type":"session-updated","sessionId":"s1"}\n\n'
            while not stop.is_set():
                await asyncio.sleep(0.005)

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_EndlessStream(),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)

    async def consume() -> list[SSEEvent]:
        result: list[SSEEvent] = []
        async for event in client.iter_events(stop_event=stop):
            result.append(event)
            stop.set()
        return result

    try:
        events = await asyncio.wait_for(consume(), timeout=1)
    finally:
        await client.aclose()

    assert len(events) == 1


@pytest.mark.asyncio
async def test_cancelling_silent_sse_consumer_closes_response_stream() -> None:
    started = asyncio.Event()
    closed = False

    class _SilentStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            started.set()
            while True:
                await asyncio.sleep(1)
                yield b": heartbeat\n\n"

        async def aclose(self) -> None:
            nonlocal closed
            closed = True

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_SilentStream(),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)

    async def consume() -> None:
        async for _event in client.iter_events(reconnect=False):
            pass

    task = asyncio.create_task(consume())
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await client.aclose()

    assert closed


@pytest.mark.asyncio
async def test_sse_drops_oversized_frame_and_continues_with_next_event() -> None:
    chunks = [
        b"event: message-received\ndata: " + (b"x" * 70_000) + b"\n\n",
        b'event: heartbeat\ndata: {"type":"heartbeat"}\n\n',
    ]

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_ByteStream(chunks),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(), transport=transport)
    try:
        events = [
            event
            async for event in client.iter_events(reconnect=False)
        ]
    finally:
        await client.aclose()

    assert [event.event for event in events] == ["heartbeat"]


@pytest.mark.asyncio
async def test_sse_reconnects_after_failure_and_can_be_stopped() -> None:
    attempts = 0
    stop = asyncio.Event()

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"token": "jwt"})
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, json={"error": "temporary access-secret-1234"})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_ByteStream(
                [b'data: {"type":"session-ended","sessionId":"s1"}\n\n']
            ),
        )

    transport, _requests = _recording_transport(responder)
    client = HapiClient(_client_config(reconnect_delay_seconds=0.25), transport=transport)
    events: list[SSEEvent] = []
    try:
        async for event in client.iter_events(stop_event=stop):
            events.append(event)
            stop.set()
    finally:
        await client.aclose()

    assert attempts == 2
    assert [event.event for event in events] == ["session-ended"]


@pytest.mark.asyncio
async def test_startup_drops_persisted_records_from_other_or_unknown_connection_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    defaults = ConnectorSettings.from_mapping(
        {"backend_mode": "hapi_external"}
    )
    current_url = defaults.base_url
    current_auth = defaults.auth_mode

    assert (
        await plugin.store.set("settings_v1", defaults.to_store())
    ).is_ok()
    assert (
        await plugin.store.set(
            "recent_events_v1",
            [
                {
                    "type": "session-ended",
                    "session_id": "valid-event",
                    "base_url": current_url,
                    "auth_mode": current_auth,
                },
                {
                    "type": "session-ended",
                    "session_id": "wrong-url",
                    "base_url": "http://127.0.0.1:3999",
                    "auth_mode": current_auth,
                },
                {
                    "type": "session-ended",
                    "session_id": "missing-url",
                    "auth_mode": current_auth,
                },
                {
                    "type": "session-ended",
                    "session_id": "wrong-auth",
                    "base_url": current_url,
                    "auth_mode": "bearer",
                },
                {
                    "type": "session-ended",
                    "session_id": "missing-auth",
                    "base_url": current_url,
                },
            ],
        )
    ).is_ok()
    assert (
        await plugin.store.set(
            "recent_sessions_v1",
            [
                {
                    "id": "valid-session",
                    "provider": "codex",
                    "base_url": current_url,
                    "auth_mode": current_auth,
                },
                {
                    "id": "wrong-url",
                    "provider": "codex",
                    "base_url": "http://127.0.0.1:3999",
                    "auth_mode": current_auth,
                },
                {
                    "id": "missing-url",
                    "provider": "codex",
                    "auth_mode": current_auth,
                },
                {
                    "id": "wrong-auth",
                    "provider": "codex",
                    "base_url": current_url,
                    "auth_mode": "bearer",
                },
                {
                    "id": "missing-auth",
                    "provider": "codex",
                    "base_url": current_url,
                },
            ],
        )
    ).is_ok()

    try:
        started = await plugin.startup()
        assert started.is_ok()
        assert [item["session_id"] for item in plugin._recent_events] == [
            "valid-event"
        ]
        assert [item["id"] for item in plugin._recent_sessions] == [
            "valid-session"
        ]
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_startup_fails_closed_when_credential_is_embedded_in_public_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    secret = "https://credential-must-not-be-public.example"
    compromised_settings = {
        **ConnectorSettings().to_store(),
        "base_url": secret,
        "allow_remote": True,
    }
    assert (await plugin.store.set("settings_v1", compromised_settings)).is_ok()
    assert (await plugin.store.set("credential_v1", secret)).is_ok()
    assert (
        await plugin.store.set(
            "recent_events_v1",
            [
                {
                    "type": "session-ended",
                    "session_id": "s1",
                    "summary": secret,
                    "base_url": secret,
                    "auth_mode": "access_token",
                }
            ],
        )
    ).is_ok()

    try:
        assert (await plugin.startup()).is_ok()
        state = _public(await plugin.panel_state())
        assert plugin._token is None
        assert plugin._settings == ConnectorSettings()
        assert secret not in json.dumps(state, ensure_ascii=False)
        assert secret not in "\n".join(plugin.logger.records)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_startup_drops_credential_when_persisted_settings_are_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    secret = "must-not-be-rebound-to-default-endpoint"
    invalid_settings = {
        **ConnectorSettings().to_store(),
        "allowed_providers": ["untrusted-provider"],
    }
    assert (await plugin.store.set("settings_v1", invalid_settings)).is_ok()
    assert (await plugin.store.set("credential_v1", secret)).is_ok()

    try:
        assert (await plugin.startup()).is_ok()
        state = _public(await plugin.panel_state())
        stored_token = await plugin.store.get("credential_v1", default=None)

        assert plugin._settings == ConnectorSettings()
        assert plugin._token is None
        assert isinstance(stored_token, Ok)
        assert stored_token.value is None
        assert secret not in json.dumps(state, ensure_ascii=False)
        assert secret not in "\n".join(plugin.logger.records)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_startup_does_not_rebind_token_when_settings_read_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    secret = "remote-endpoint-credential"
    assert (await plugin.store.set("credential_v1", secret)).is_ok()
    original_get = plugin.store.get

    async def fail_settings_read(key: str, default: object = None):
        if key == "settings_v1":
            return Err(RuntimeError("synthetic settings read failure"))
        return await original_get(key, default=default)

    monkeypatch.setattr(plugin.store, "get", fail_settings_read)
    try:
        assert (await plugin.startup()).is_ok()
        assert plugin._settings == ConnectorSettings()
        assert plugin._token is None
        stored_token = await original_get("credential_v1", default=None)
        assert isinstance(stored_token, Ok)
        assert stored_token.value == secret
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_save_after_unknown_configuration_requires_visible_refresh_before_rebind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    old_secret = "old-secret-must-not-rebind"
    old_settings = {
        **ConnectorSettings().to_store(),
        "base_url": "https://original.example",
        "allow_remote": True,
    }
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    assert (await plugin.store.set("settings_v1", old_settings)).is_ok()
    assert (await plugin.store.set("credential_v1", old_secret)).is_ok()
    original_get = plugin.store.get
    fail_once = True

    async def fail_first_settings_read(key: str, default: object = None):
        nonlocal fail_once
        if key == "settings_v1" and fail_once:
            fail_once = False
            return Err(RuntimeError("synthetic settings read failure"))
        return await original_get(key, default=default)

    monkeypatch.setattr(plugin.store, "get", fail_first_settings_read)
    plugin2: VibeCodingConnectorPlugin | None = None
    try:
        assert (await plugin.startup()).is_ok()
        assert plugin._token is None

        save = await _save_encrypted_settings(
            plugin,
            settings={
                **ConnectorSettings().to_store(),
                "base_url": "https://attacker.example",
                "allow_remote": True,
            },
            token="",
        )
        assert save.is_err()
        assert save.error["error"]["code"] == "configuration_refresh_required"

        persisted_settings = await original_get("settings_v1")
        persisted_token = await original_get("credential_v1")
        assert isinstance(persisted_settings, Ok)
        assert isinstance(persisted_token, Ok)
        assert persisted_settings.value["base_url"] == "https://original.example"
        assert persisted_token.value == old_secret

        plugin2 = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
        assert (await plugin2.startup()).is_ok()
        assert plugin2._settings.base_url == "https://original.example"
        assert plugin2._token == old_secret
    finally:
        await plugin.shutdown()
        if plugin2 is not None:
            await plugin2.shutdown()


@pytest.mark.asyncio
async def test_failed_invalid_configuration_cleanup_cannot_resurrect_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    secret = "must-remain-quarantined"
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    invalid_settings = {
        **ConnectorSettings().to_store(),
        "allowed_providers": ["untrusted-provider"],
    }
    assert (await plugin.store.set("settings_v1", invalid_settings)).is_ok()
    assert (await plugin.store.set("credential_v1", secret)).is_ok()
    original_delete = plugin.store.delete

    async def fail_credential_delete(key: str):
        if key == "credential_v1":
            return Err(RuntimeError("synthetic credential delete failure"))
        return await original_delete(key)

    monkeypatch.setattr(plugin.store, "delete", fail_credential_delete)
    plugin2: VibeCodingConnectorPlugin | None = None
    try:
        assert (await plugin.startup()).is_ok()
        assert plugin._token is None
        persisted_settings = await plugin.store.get("settings_v1")
        assert isinstance(persisted_settings, Ok)
        assert persisted_settings.value["allowed_providers"] == [
            "untrusted-provider"
        ]

        save = await _save_encrypted_settings(
            plugin,
            settings={
                **ConnectorSettings().to_store(),
                "base_url": "https://attacker.example",
                "allow_remote": True,
            },
            token="",
        )
        assert save.is_err()
        assert save.error["error"]["code"] == "configuration_refresh_required"

        plugin2 = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
        assert (await plugin2.startup()).is_ok()
        assert plugin2._token is None
    finally:
        await plugin.shutdown()
        if plugin2 is not None:
            await plugin2.shutdown()


@pytest.mark.asyncio
async def test_startup_removes_non_string_persisted_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    assert (await plugin.store.set("settings_v1", ConnectorSettings().to_store())).is_ok()
    assert (
        await plugin.store.set(
            "credential_v1",
            {"token": "nested-credential"},
        )
    ).is_ok()

    try:
        assert (await plugin.startup()).is_ok()
        stored_token = await plugin.store.get("credential_v1", default=None)
        assert plugin._token is None
        assert isinstance(stored_token, Ok)
        assert stored_token.value is None
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_startup_detects_credential_in_structured_public_settings_before_json_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    public_secret_path = tmp_path / "credential\\segment"
    public_secret_path.mkdir(parents=True)
    secret = str(public_secret_path.resolve())
    assert "\\" in secret
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    compromised_settings = {
        **ConnectorSettings().to_store(),
        "allowed_workspace_roots": [secret],
    }
    assert (await plugin.store.set("settings_v1", compromised_settings)).is_ok()
    assert (await plugin.store.set("credential_v1", secret)).is_ok()

    try:
        assert (await plugin.startup()).is_ok()
        state = _public(await plugin.panel_state())
        assert plugin._settings == ConnectorSettings()
        assert plugin._token is None
        assert secret not in json.dumps(state, ensure_ascii=False)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_encrypted_settings_envelope_is_bound_single_use_and_secret_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    ctx = _Context(PLUGIN_DIR)
    plugin = VibeCodingConnectorPlugin(ctx)
    await plugin.startup()
    secret = "panel-access-secret-7890"

    try:
        state = _public(await plugin.panel_state())
        envelope = state["secret_envelope"]
        assert isinstance(envelope, dict)
        args = _encrypt_settings_document(
            envelope,
            {
                "settings": plugin._settings.to_store(),
                "token": secret,
                "clear_token": False,
            },
        )
        assert secret not in json.dumps(args)

        first, replay = await asyncio.gather(
            plugin.save_settings(**args),
            plugin.save_settings(**args),
        )
        outcomes = (first, replay)
        assert sum(result.is_ok() for result in outcomes) == 1
        assert sum(result.is_err() for result in outcomes) == 1

        public_state = _public(await plugin.panel_state())
        serialized = json.dumps(public_state, ensure_ascii=False)
        assert public_state["token"] == {"configured": True}
        assert secret not in serialized
        assert secret not in "\n".join(ctx.logger.records)

        replay_error = next(result for result in outcomes if result.is_err())
        assert replay_error.error["error"]["code"] in {
            "secret_envelope_expired_or_used",
            "configuration_busy",
        }
    finally:
        await plugin.shutdown()


def test_token_state_never_exposes_credential_fragments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    plugin._token = "short-jwt-secret"

    state = plugin._token_state()

    assert state == {"configured": True}
    assert "cret" not in json.dumps(state)


@pytest.mark.asyncio
async def test_encrypted_save_rejects_credential_in_structured_public_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    public_secret_path = tmp_path / "credential\\segment"
    public_secret_path.mkdir(parents=True)
    secret = str(public_secret_path.resolve())
    assert "\\" in secret
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    try:
        result = await _save_encrypted_settings(
            plugin,
            settings={
                **plugin._settings.to_store(),
                "allowed_workspace_roots": [secret],
            },
            token=secret,
        )
        assert result.is_err()
        assert result.error["error"]["code"] == "invalid_token"
        state = _public(await plugin.panel_state())
        assert secret not in json.dumps(state, ensure_ascii=False)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_encrypted_save_rejects_previous_credential_in_new_public_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    old_secret = "https://old-credential.example"
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    assert (
        await _save_encrypted_settings(
            plugin,
            token=old_secret,
        )
    ).is_ok()

    try:
        result = await _save_encrypted_settings(
            plugin,
            settings={
                **plugin._settings.to_store(),
                "base_url": old_secret,
                "allow_remote": True,
            },
            token="replacement-credential",
        )
        assert result.is_err()
        assert result.error["error"]["code"] == "invalid_token"
        state = _public(await plugin.panel_state())
        assert old_secret not in json.dumps(state, ensure_ascii=False)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ("false", "100", "15.0"))
async def test_encrypted_save_rejects_credential_matching_public_json_scalar(
    secret: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    try:
        result = await _save_encrypted_settings(
            plugin,
            token=secret,
        )
        assert result.is_err()
        assert result.error["error"]["code"] == "invalid_token"
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_encrypted_settings_rejects_wrong_entry_binding_and_plaintext_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    secret = "must-never-enter-run-args"
    settings = plugin._settings.to_store()

    try:
        plaintext = await plugin.save_settings(settings=settings, token=secret)
        assert plaintext.is_err()
        assert plaintext.error["error"]["code"] == "encrypted_settings_required"

        envelope = await plugin._issue_secret_envelope()
        wrong_binding = _encrypt_settings_document(
            envelope,
            {
                "settings": settings,
                "token": secret,
                "clear_token": False,
            },
            entry_id="some_other_entry",
        )
        rejected = await plugin.save_settings(**wrong_binding)
        assert rejected.is_err()
        assert rejected.error["error"]["code"] == "encrypted_settings_invalid"

        replay_with_correct_binding = await plugin.save_settings(
            **_encrypt_settings_document(
                envelope,
                {
                    "settings": settings,
                    "token": secret,
                    "clear_token": False,
                },
            )
        )
        assert replay_with_correct_binding.is_err()
        assert (
            replay_with_correct_binding.error["error"]["code"]
            == "secret_envelope_expired_or_used"
        )
        assert plugin._token is None
        assert secret not in "\n".join(plugin.logger.records)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_encrypted_settings_envelope_expires_and_shutdown_discards_pending_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    monkeypatch.setattr(
        vibe_coding_module,
        "_SECRET_ENVELOPE_TTL_SECONDS",
        0,
    )
    envelope = await plugin._issue_secret_envelope()
    args = _encrypt_settings_document(
        envelope,
        {
            "settings": plugin._settings.to_store(),
            "token": "expired-secret",
            "clear_token": False,
        },
    )

    expired = await plugin.save_settings(**args)
    assert expired.is_err()
    assert (
        expired.error["error"]["code"]
        == "secret_envelope_expired_or_used"
    )

    monkeypatch.setattr(
        vibe_coding_module,
        "_SECRET_ENVELOPE_TTL_SECONDS",
        300,
    )
    await plugin._issue_secret_envelope()
    assert plugin._secret_envelopes
    await plugin.shutdown()
    assert not plugin._secret_envelopes


@pytest.mark.asyncio
async def test_encrypted_settings_ttl_is_checked_after_acquiring_envelope_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    monkeypatch.setattr(
        vibe_coding_module,
        "_SECRET_ENVELOPE_TTL_SECONDS",
        0.05,
    )
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    envelope = await plugin._issue_secret_envelope()
    encrypted = _encrypt_settings_document(
        envelope,
        {
            "settings": ConnectorSettings().to_store(),
            "token": "",
            "clear_token": False,
        },
    )
    sampled = threading.Event()
    original_monotonic = vibe_coding_module.time.monotonic

    def observed_monotonic() -> float:
        sampled.set()
        return original_monotonic()

    monkeypatch.setattr(
        vibe_coding_module.time,
        "monotonic",
        observed_monotonic,
    )
    plugin._envelope_lock.acquire()
    consume_task = asyncio.create_task(
        asyncio.to_thread(
            lambda: asyncio.run(
                plugin._consume_encrypted_settings(**encrypted)
            )
        )
    )
    try:
        await asyncio.to_thread(sampled.wait, 0.2)
        await asyncio.sleep(0.08)
    finally:
        plugin._envelope_lock.release()

    with pytest.raises(PolicyError) as caught:
        await consume_task
    assert caught.value.code == "secret_envelope_expired_or_used"
    await plugin.shutdown()


@pytest.mark.asyncio
async def test_settings_second_key_failure_rolls_back_and_never_publishes_new_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    old_token = "old-secret-1111"
    new_token = "new-secret-2222"
    old_settings = {
        **plugin._settings.to_store(),
        "base_url": "http://127.0.0.1:3006",
        "auth_mode": "access_token",
    }
    initial = await _save_encrypted_settings(
        plugin,
        settings=old_settings,
        token=old_token,
    )
    assert initial.is_ok()

    original_set = plugin.store.set
    failed_new_token = False

    async def fail_new_credential(key: str, value: object):
        nonlocal failed_new_token
        if (
            key == "credential_v1"
            and value == new_token
            and not failed_new_token
        ):
            failed_new_token = True
            return Err(RuntimeError("synthetic second-key failure"))
        return await original_set(key, value)

    monkeypatch.setattr(plugin.store, "set", fail_new_credential)
    new_url = "http://127.0.0.1:4555"
    attempted_settings = {
        **old_settings,
        "base_url": new_url,
        "auth_mode": "bearer",
    }

    try:
        failed = await _save_encrypted_settings(
            plugin,
            settings=attempted_settings,
            token=new_token,
        )
        assert failed.is_err()
        assert failed.error["error"]["code"] == "store_write_failed"
        assert failed_new_token is True
        assert plugin._settings.base_url == old_settings["base_url"]
        assert plugin._settings.auth_mode == old_settings["auth_mode"]
        assert plugin._token == old_token

        state = _public(await plugin.panel_state())
        serialized = json.dumps(state)
        assert state["settings"]["base_url"] == old_settings["base_url"]
        assert state["settings"]["auth_mode"] == old_settings["auth_mode"]
        assert state["token"] == {"configured": True}
        assert new_url not in serialized
        assert new_token not in serialized

        stored_settings = await plugin.store.get("settings_v1")
        stored_token = await plugin.store.get("credential_v1")
        assert isinstance(stored_settings, Ok)
        assert isinstance(stored_token, Ok)
        assert stored_settings.value["base_url"] == old_settings["base_url"]
        assert stored_settings.value["auth_mode"] == old_settings["auth_mode"]
        assert stored_token.value == old_token
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_completed_configuration_transition_rejects_stale_snapshot_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    external_settings = ConnectorSettings.from_mapping(
        {"backend_mode": "hapi_external"}
    )
    assert (
        await plugin.store.set("settings_v1", external_settings.to_store())
    ).is_ok()
    await plugin.startup()

    try:
        old_client, old_settings, _policy, _credential = (
            await plugin._operation_snapshot()
        )
        changed_settings = {
            **old_settings.to_store(),
            "timeout_seconds": old_settings.timeout_seconds + 1,
        }
        saved = await _save_encrypted_settings(
            plugin,
            settings=changed_settings,
        )
        assert saved.is_ok()
        assert plugin._settings is not old_settings

        with pytest.raises(PolicyError) as caught:
            async with plugin._operation_permit(
                expected_client=old_client,
                expected_settings=old_settings,
            ):
                pytest.fail("stale snapshot must not enter the operation permit")
        assert caught.value.code == "configuration_changed"
        assert plugin._active_operations == 0
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_token_save_keep_and_explicit_clear_persist_without_echo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_root = tmp_path / "runtime"
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(data_root))
    first_ctx = _Context(PLUGIN_DIR)
    plugin = VibeCodingConnectorPlugin(first_ctx)

    await plugin.startup()
    safe_settings = plugin._settings.to_store()
    saved = _public(
        await _save_encrypted_settings(
            plugin,
            settings=safe_settings,
            token="first-secret-7890",
        )
    )
    assert saved["token"] == {"configured": True}
    assert "first-secret-7890" not in json.dumps(saved)

    kept = _public(
        await _save_encrypted_settings(
            plugin,
            settings=safe_settings,
            token="",
        )
    )
    assert kept["token"] == {"configured": True}

    second_ctx = _Context(PLUGIN_DIR)
    plugin2 = VibeCodingConnectorPlugin(second_ctx)
    await plugin2.startup()
    state = _public(await plugin2.panel_state())
    assert state["token"] == {"configured": True}
    assert "first-secret-7890" not in json.dumps(state)

    cleared = _public(await plugin2.clear_token(confirm=True))
    assert cleared["token"]["configured"] is False
    assert "first-secret-7890" not in json.dumps(cleared)
    assert "first-secret-7890" not in "\n".join(first_ctx.logger.records + second_ctx.logger.records)
    await plugin.shutdown()
    await plugin2.shutdown()


@pytest.mark.asyncio
async def test_remote_session_fields_are_redacted_before_panel_llm_and_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    provider_secret = "Bearer eyJremote.provider.secret"
    directory_secret = "/tmp/ghp_remoteDirectorySecret"

    class _SecretSessionClient:
        async def list_sessions(self) -> list[dict[str, object]]:
            return [
                {
                    "id": "s1",
                    "provider": provider_secret,
                    "directory": directory_secret,
                    "status": "inactive",
                    "active": False,
                    "permission_mode": "default",
                }
            ]

        async def aclose(self) -> None:
            return None

    plugin.set_client_for_testing(_SecretSessionClient())
    try:
        model_result = _public(await plugin.list_sessions())
        panel_result = _public(await plugin.panel_list_sessions())
        state = _public(await plugin.panel_state())
        serialized = json.dumps(
            [model_result, panel_result, state, plugin._recent_sessions],
            ensure_ascii=False,
        )
        assert provider_secret not in serialized
        assert directory_secret not in serialized
    finally:
        await plugin.shutdown()


def test_message_and_approval_text_redaction_covers_common_secret_syntax(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    raw = (
        "curl -H 'Authorization: Basic c2VjcmV0LXZhbHVl' "
        "--api-token opaque-api-token-123 token=opaque-token-456"
    )

    output = plugin._messages_output(
        [{"role": "assistant", "content": raw}],
        maximum=4_000,
    )

    assert "c2VjcmV0LXZhbHVl" not in output
    assert "opaque-api-token-123" not in output
    assert "opaque-token-456" not in output


def test_message_redaction_removes_complete_quoted_secret_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    raw = (
        'password="very secret value" '
        "api_key='opaque secret material' "
        '--token "cli secret with spaces" '
        "OPENAI_API_KEY=opaquevalue123 "
        "DATABASE_PASSWORD=hunter222 "
        "passwd=hunter333 "
        "passphrase=correcthorse "
        "AUTH=Basic QVVUSFNFQ1JFVA== "
        'authentication="Basic QVVUSEVOVElDQVRJT04=" '
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE "
        "credential='opaque credential material' "
        "jwt=opaque.jwt.material "
        "Basic U1RBTkRBTU9ORVNFQ1JFVA=="
    )

    output = plugin._messages_output(
        [{"role": "assistant", "content": raw}],
        maximum=4_000,
    )

    assert "very secret value" not in output
    assert "secret material" not in output
    assert "cli secret with spaces" not in output
    assert "opaquevalue123" not in output
    assert "hunter222" not in output
    assert "hunter333" not in output
    assert "correcthorse" not in output
    assert "QVVUSFNFQ1JFVA==" not in output
    assert "QVVUSEVOVElDQVRJT04=" not in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output
    assert "credential material" not in output
    assert "opaque.jwt.material" not in output
    assert "U1RBTkRBTU9ORVNFQ1JFVA==" not in output


def test_permission_redaction_treats_auth_alias_keys_as_sensitive() -> None:
    for key in (
        "auth",
        "authentication",
        "basic_auth",
        "proxy_authentication",
        "bearer",
        "db_passwd",
        "ssh_passphrase",
    ):
        permissions = extract_permissions(
            {
                "requests": {
                    "r1": {
                        "status": "pending",
                        "tool": "Bash",
                        "arguments": {key: "Basic dXNlcjpwYXNz"},
                    }
                }
            }
        )

        assert permissions[0]["arguments"][key] == "[REDACTED]"
        assert permissions[0]["arguments_truncated"] is True


def test_permission_redaction_checks_full_key_before_bounding_it() -> None:
    secret = "opaque-long-key-secret"
    long_key = ("a" * 129) + "apiKey"
    permissions = extract_permissions(
        {
            "requests": {
                "r1": {
                    "status": "pending",
                    "tool": "Bash",
                    "arguments": {long_key: secret},
                }
            }
        }
    )

    serialized = json.dumps(permissions, ensure_ascii=False)
    assert secret not in serialized
    assert "[REDACTED]" in serialized
    assert permissions[0]["arguments_truncated"] is True


@pytest.mark.asyncio
async def test_startup_redacts_nested_sensitive_keys_in_persisted_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    secret = "opaque-persisted-secret"
    defaults = ConnectorSettings.from_mapping(
        {"backend_mode": "hapi_external"}
    )
    assert (await plugin.store.set("settings_v1", defaults.to_store())).is_ok()
    assert (
        await plugin.store.set(
            "recent_events_v1",
            [
                {
                    "type": "session-ended",
                    "session_id": "s1",
                    "summary": {"apiKey": secret},
                    "base_url": defaults.base_url,
                    "auth_mode": defaults.auth_mode,
                }
            ],
        )
    ).is_ok()

    try:
        assert (await plugin.startup()).is_ok()
        state = _public(await plugin.panel_state())
        serialized = json.dumps(state, ensure_ascii=False)
        assert secret not in serialized
        assert "[REDACTED]" in serialized
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_dynamic_llm_callback_returns_summary_while_panel_gets_details_and_permissions_are_tri_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    sessions = [
        {
            "id": "safe",
            "active": True,
            "provider": "codex",
            "directory": str(repo.resolve()),
            "status": "active",
            "permission_mode": "default",
        },
        {
            "id": "unknown",
            "active": True,
            "provider": "codex",
            "directory": str(repo.resolve()),
            "status": "active",
            "permission_mode": "",
        },
        {
            "id": "dangerous",
            "active": True,
            "provider": "codex",
            "directory": str(repo.resolve()),
            "status": "active",
            "permission_mode": "bypassPermissions",
        },
    ]

    class _SessionClient:
        def __init__(self) -> None:
            self.writes: list[tuple[str, str]] = []

        async def list_sessions(self) -> list[dict[str, object]]:
            return [dict(item) for item in sessions]

        async def get_session(self, session_id: str) -> dict[str, object]:
            return next(dict(item) for item in sessions if item["id"] == session_id)

        async def send_instruction(self, session_id: str, text: str) -> None:
            self.writes.append((session_id, text))

        async def aclose(self) -> None:
            return None

    result = await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(repo)],
            "allowed_providers": ["codex"],
            "allow_send": True,
        }
    )
    assert result.is_ok()
    fake = _SessionClient()
    plugin.set_client_for_testing(fake)

    try:
        dynamic_entry = plugin._dynamic_entries[
            "__llm_tool__vibe_coding_list_sessions"
        ]
        model_result = _public(await dynamic_entry["handler"]())
        assert set(model_result) == {"summary"}
        assert all(session_id in model_result["summary"] for session_id in ("safe", "unknown", "dangerous"))

        panel_result = _public(await plugin.panel_list_sessions())
        assert set(panel_result) >= {"summary", "sessions"}
        by_id = {item["id"]: item for item in panel_result["sessions"]}
        assert by_id["safe"]["permission_safe"] is True
        assert by_id["safe"]["requires_permission_check"] is False
        assert by_id["unknown"]["permission_safe"] is None
        assert by_id["unknown"]["requires_permission_check"] is True
        assert by_id["unknown"]["manageable"] is True
        assert by_id["dangerous"]["permission_safe"] is False
        assert by_id["dangerous"]["manageable"] is False

        rejected = await plugin.send_instruction(
            session_id="unknown",
            instruction="do not send this",
        )
        assert rejected.is_err()
        assert rejected.error["error"]["code"] == "permission_mode_unknown"
        assert fake.writes == []
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_session_tools_enforce_policy_and_return_bounded_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_root = tmp_path / "runtime"
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(data_root))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    class _FakeClient:
        async def list_machines(self) -> list[dict[str, object]]:
            return [{"id": "m1", "online": True, "status": "online"}]

        async def create_session(
            self, machine_id: str, directory: str, provider: str
        ) -> str:
            assert (machine_id, directory, provider) == ("m1", str(repo.resolve()), "codex")
            return "s1"

        async def get_session(self, session_id: str) -> dict[str, object]:
            assert session_id == "s1"
            return {
                "id": "s1",
                "active": True,
                "provider": "codex",
                "directory": str(repo.resolve()),
                "permission_mode": "default",
                "agent_state": {
                    "requests": {
                        "r1": {
                            "status": "pending",
                            "tool": "read_file",
                            "arguments": {"path": "README.md"},
                        },
                        "r2": {
                            "status": "pending",
                            "tool": "read_file",
                            "arguments": {"secret": "NOPE"},
                        },
                    }
                },
            }

        async def send_instruction(self, session_id: str, text: str) -> bool:
            return True

        async def resume_session(
            self, session_id: str, permission_mode: str
        ) -> str:
            assert permission_mode == "default"
            return session_id

        async def abort_session(self, session_id: str) -> bool:
            return True

        async def approve_permission(
            self, session_id: str, request_id: str, answers: object = None
        ) -> bool:
            return True

        async def deny_permission(self, session_id: str, request_id: str) -> bool:
            return True

        async def aclose(self) -> None:
            return None

    await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(repo)],
            "allowed_providers": ["codex"],
            "allow_create": True,
            "allow_send": True,
            "allow_stop": True,
            "allow_approval": True,
        },
    )
    plugin.set_client_for_testing(_FakeClient())

    try:
        created = _public(
            await plugin.panel_create_session(
                provider="codex", working_directory=str(repo), machine_id="m1"
            )
        )
        assert created["session_id"] == "s1"
        assert "summary" in created
        assert "raw" not in created

        sent = _public(await plugin.send_instruction(session_id="s1", instruction="fix tests"))
        assert len(sent["summary"]) <= plugin._settings.max_output_chars
        assert "fix tests" not in sent["summary"]

        approvals = _public(await plugin.panel_list_approvals(session_id="s1"))
        dumped = json.dumps(approvals)
        assert "NOPE" not in dumped
        assert approvals["auto_approve"] is False

        approved = _public(
            await plugin.respond_approval(
                session_id="s1", request_id="r1", decision="approve"
            )
        )
        assert set(approved) == {"summary"}
        assert "r1" in approved["summary"]
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_send_refuses_inactive_session_instead_of_unsafe_auto_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    saved = await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(repo)],
            "allowed_providers": ["codex"],
            "allow_send": True,
        },
    )
    assert saved.is_ok()

    class _InactiveClient:
        def __init__(self) -> None:
            self.resumes = 0
            self.sends = 0

        async def get_session(self, session_id: str) -> dict[str, object]:
            return {
                "id": session_id,
                "provider": "codex",
                "directory": str(repo.resolve()),
                "status": "inactive",
                "active": False,
                "permission_mode": "default",
            }

        async def resume_session(
            self,
            session_id: str,
            permission_mode: str,
        ) -> str:
            self.resumes += 1
            return session_id

        async def send_instruction(self, session_id: str, text: str) -> None:
            self.sends += 1

        async def aclose(self) -> None:
            return None

    fake = _InactiveClient()
    plugin.set_client_for_testing(fake)
    try:
        result = await plugin.send_instruction(
            session_id="s1",
            instruction="fix tests",
        )
        assert result.is_err()
        assert (
            result.error["error"]["code"]
            == "inactive_session_requires_manual_resume"
        )
        assert fake.resumes == 0
        assert fake.sends == 0
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_status_does_not_advertise_unsafe_automatic_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    class _StatusClient:
        async def health(self) -> dict[str, object]:
            return {"status": "ok", "protocol_version": 1}

        async def list_machines(self) -> list[dict[str, object]]:
            return []

        async def aclose(self) -> None:
            return None

    plugin.set_client_for_testing(_StatusClient())
    try:
        result = _public(await plugin.panel_connection_status())
        capabilities = result["capabilities"]
        assert capabilities["session_messages"] is True
        assert capabilities["session_resume"] is False
        assert "session_messages_and_resume" not in capabilities
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_secret_key_redaction_marks_approval_unapprovable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    class _SecretApprovalClient:
        def __init__(self) -> None:
            self.approved: list[tuple[str, str, object]] = []

        async def get_session(self, session_id: str) -> dict[str, object]:
            return {
                "id": session_id,
                "active": True,
                "provider": "codex",
                "directory": str(repo.resolve()),
                "permission_mode": "default",
                "agent_state": {
                    "requests": {
                        "secret-request": {
                            "id": "secret-request",
                            "status": "pending",
                            "tool": "read_file",
                            "arguments": {
                                "path": "README.md",
                                "api_token": "must-not-be-approved",
                                "apiKey": "opaque-api-key-123",
                                "privateKey": "opaque-private-key-456",
                                "cookie": "opaque-cookie-789",
                            },
                        }
                    }
                },
            }

        async def approve_permission(
            self,
            session_id: str,
            request_id: str,
            answers: object = None,
        ) -> None:
            self.approved.append((session_id, request_id, answers))

        async def aclose(self) -> None:
            return None

    saved = await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(repo)],
            "allowed_providers": ["codex"],
            "allow_approval": True,
        }
    )
    assert saved.is_ok()
    fake = _SecretApprovalClient()
    plugin.set_client_for_testing(fake)

    try:
        detail = _public(
            await plugin.panel_list_approvals(session_id="s1")
        )["approvals"][0]
        serialized = json.dumps(detail)
        assert "must-not-be-approved" not in serialized
        assert "opaque-api-key-123" not in serialized
        assert "opaque-private-key-456" not in serialized
        assert "opaque-cookie-789" not in serialized
        assert "[REDACTED]" in serialized
        assert detail["details_withheld"] is True
        assert detail["approvable_without_answers"] is False

        rejected = await plugin.respond_approval(
            session_id="s1",
            request_id="secret-request",
            decision="approve",
        )
        assert rejected.is_err()
        assert rejected.error["error"]["code"] == "approval_details_withheld"
        assert fake.approved == []
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_question_and_truncated_approvals_fail_closed_but_deny_remains_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()

    class _ApprovalClient:
        def __init__(self) -> None:
            self.current = "question"
            self.approved: list[tuple[str, str, object]] = []
            self.denied: list[tuple[str, str]] = []

        async def get_session(self, session_id: str) -> dict[str, object]:
            if self.current == "question":
                request_id = "question-1"
                request = {
                    "status": "pending",
                    "tool": "AskUserQuestion",
                    "arguments": {
                        "questions": [
                            {
                                "question": "Proceed?",
                                "options": [{"label": "yes"}, {"label": "no"}],
                            }
                        ]
                    },
                }
            else:
                request_id = "truncated-1"
                request = {
                    "status": "pending",
                    "tool": "run_tool",
                    "arguments": {"command": "x" * 600},
                }
            return {
                "id": session_id,
                "active": True,
                "provider": "codex",
                "directory": str(repo.resolve()),
                "permission_mode": "default",
                "agent_state": {"requests": {request_id: request}},
            }

        async def approve_permission(
            self,
            session_id: str,
            request_id: str,
            answers: object = None,
        ) -> None:
            self.approved.append((session_id, request_id, answers))

        async def deny_permission(self, session_id: str, request_id: str) -> None:
            self.denied.append((session_id, request_id))

        async def aclose(self) -> None:
            return None

    saved = await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(repo)],
            "allowed_providers": ["codex"],
            "allow_approval": True,
        }
    )
    assert saved.is_ok()
    fake = _ApprovalClient()
    plugin.set_client_for_testing(fake)

    try:
        question_details = _public(
            await plugin.panel_list_approvals(session_id="s1")
        )["approvals"][0]
        assert question_details["requires_answers"] is True
        assert question_details["approvable_without_answers"] is False

        missing_answers = await plugin.respond_approval(
            session_id="s1",
            request_id="question-1",
            decision="approve",
        )
        assert missing_answers.is_err()
        assert missing_answers.error["error"]["code"] == "approval_answers_required"
        assert fake.approved == []

        answered = _public(
            await plugin.respond_approval(
                session_id="s1",
                request_id="question-1",
                decision="approve",
                answers={"0": ["yes"]},
            )
        )
        assert set(answered) == {"summary"}
        assert fake.approved == [("s1", "question-1", {"0": ["yes"]})]

        fake.current = "truncated"
        truncated_details = _public(
            await plugin.panel_list_approvals(session_id="s1")
        )["approvals"][0]
        assert truncated_details["details_withheld"] is True
        assert truncated_details["approvable_without_answers"] is False

        blind_approve = await plugin.respond_approval(
            session_id="s1",
            request_id="truncated-1",
            decision="approve",
        )
        assert blind_approve.is_err()
        assert blind_approve.error["error"]["code"] == "approval_details_withheld"
        assert len(fake.approved) == 1

        denied = _public(
            await plugin.respond_approval(
                session_id="s1",
                request_id="truncated-1",
                decision="deny",
            )
        )
        assert set(denied) == {"summary"}
        assert fake.denied == [("s1", "truncated-1")]
        assert plugin._settings.auto_approve is False
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_existing_session_mutations_reauthorize_workspace_before_hapi_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(runtime))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    result = await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(allowed)],
            "allowed_providers": ["codex"],
            "allow_send": True,
            "allow_stop": True,
            "allow_approval": True,
        }
    )
    assert result.is_ok()

    class _OutOfPolicyClient:
        def __init__(self) -> None:
            self.writes: list[str] = []

        async def get_session(self, session_id: str) -> dict[str, object]:
            return {
                "id": session_id,
                "provider": "codex",
                "directory": str(outside),
                "active": True,
                "permission_mode": "default",
                "agent_state": {
                    "requests": {"r1": {"tool": "write", "arguments": {}}}
                },
            }

        async def send_instruction(self, *_args: object) -> None:
            self.writes.append("send")

        async def abort_session(self, *_args: object) -> None:
            self.writes.append("stop")

        async def approve_permission(self, *_args: object) -> None:
            self.writes.append("approve")

        async def deny_permission(self, *_args: object) -> None:
            self.writes.append("deny")

        async def aclose(self) -> None:
            return None

    fake = _OutOfPolicyClient()
    plugin.set_client_for_testing(fake)
    try:
        assert (await plugin.send_instruction(session_id="s1", instruction="fix")).is_err()
        assert (await plugin.stop_session(session_id="s1")).is_err()
        assert (
            await plugin.respond_approval(
                session_id="s1",
                request_id="r1",
                decision="approve",
            )
        ).is_err()
        assert fake.writes == []
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_pending_sse_approval_is_never_auto_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    saved = await _save_encrypted_settings(
        plugin,
        settings={
            **plugin._settings.to_store(),
            "allowed_workspace_roots": [str(repo)],
            "allowed_providers": ["codex"],
        }
    )
    assert saved.is_ok()

    class _ApprovalProbe:
        approvals = 0

        async def get_session(self, session_id: str) -> dict[str, object]:
            return {
                "id": session_id,
                "provider": "codex",
                "directory": str(repo.resolve()),
                "active": True,
                "permission_mode": "default",
                "agent_state": {
                    "requests": {"r1": {"tool": "write_file", "arguments": {}}}
                },
            }

        async def approve_permission(self, *_args: object) -> None:
            self.approvals += 1

        async def aclose(self) -> None:
            return None

    fake = _ApprovalProbe()
    plugin.set_client_for_testing(fake)
    event = SSEEvent(
        event="session-updated",
        event_id="approval-event",
        data={
            "type": "session-updated",
            "sessionId": "s1",
            "session": {
                "agentState": {
                    "requests": {"r1": {"tool": "write_file", "arguments": {}}}
                }
            },
        },
    )
    try:
        await plugin._handle_sse_event(event)
        assert fake.approvals == 0
        assert plugin._known_approvals
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_sse_thinking_transition_pushes_completion_once_and_pending_suppresses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    ctx = _Context(PLUGIN_DIR)
    plugin = VibeCodingConnectorPlugin(ctx)
    await plugin.startup()
    plugin._settings = ConnectorSettings.from_mapping(
        {
            **plugin._settings.to_store(),
            "notifications_enabled": True,
            "notification_visibility": ["hud"],
            "notification_ai_behavior": "read",
        }
    )

    async def no_discovered_approvals(
        _event: SSEEvent,
        _session_id: str,
    ) -> list[str]:
        return []

    monkeypatch.setattr(
        plugin,
        "_discover_event_approvals",
        no_discovered_approvals,
    )

    def session_update(
        event_id: str,
        session_id: str,
        *,
        thinking: bool,
        pending: int,
    ) -> SSEEvent:
        return SSEEvent(
            event="session-updated",
            event_id=event_id,
            data={
                "type": "session-updated",
                "sessionId": session_id,
                "session": {
                    "id": session_id,
                    "thinking": thinking,
                    "active": thinking,
                    "pendingRequestsCount": pending,
                },
            },
        )

    try:
        await plugin._handle_sse_event(
            session_update("s1-thinking", "s1", thinking=True, pending=0)
        )
        await plugin._handle_sse_event(
            session_update("s1-idle", "s1", thinking=False, pending=0)
        )
        await plugin._handle_sse_event(
            session_update("s1-idle-again", "s1", thinking=False, pending=0)
        )

        await plugin._handle_sse_event(
            session_update("s2-thinking", "s2", thinking=True, pending=0)
        )
        await plugin._handle_sse_event(
            session_update("s2-pending", "s2", thinking=False, pending=1)
        )

        assert len(ctx.pushed) == 1
        pushed = ctx.pushed[0]
        assert pushed["metadata"]["kind"] == "completion"
        assert pushed["metadata"]["session_id"] == "s1"
        assert pushed["metadata"]["no_feedback"] is True
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_sse_dedupe_ttl_and_event_flood_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    await plugin.startup()
    plugin._settings = ConnectorSettings.from_mapping(
        {
            **plugin._settings.to_store(),
            "rate_limit_per_minute": 2,
            "notifications_enabled": False,
        }
    )
    clock = [100.0]
    monkeypatch.setattr(
        "plugin.plugins.vibe_coding_connector.time.monotonic",
        lambda: clock[0],
    )

    repeated = SSEEvent(
        event="toast",
        event_id="",
        data={"type": "toast", "status": "same"},
    )
    try:
        await plugin._handle_sse_event(repeated)
        clock[0] = 101.0
        await plugin._handle_sse_event(repeated)
        assert len(plugin._recent_events) == 1

        clock[0] = 103.1
        await plugin._handle_sse_event(repeated)
        assert len(plugin._recent_events) == 2

        plugin._recent_events.clear()
        plugin._event_dedupe.clear()
        plugin._sse_event_times.clear()
        clock[0] = 200.0
        for index in range(65):
            clock[0] = 200.0 + (index / 100)
            await plugin._handle_sse_event(
                SSEEvent(
                    event="toast",
                    event_id=f"event-{index}",
                    data={"type": "toast", "status": str(index)},
                )
            )
        assert len(plugin._recent_events) == 60
        assert len(plugin._sse_event_times) == 60
        assert len(plugin._event_dedupe) <= 512
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_sse_pushes_are_rate_limited_and_never_request_ai_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    ctx = _Context(PLUGIN_DIR)
    plugin = VibeCodingConnectorPlugin(ctx)
    await plugin.startup()
    plugin._settings = ConnectorSettings.from_mapping(
        {
            **plugin._settings.to_store(),
            "rate_limit_per_minute": 2,
            "notifications_enabled": True,
            "notification_visibility": ["hud"],
            "notification_ai_behavior": "read",
        }
    )
    clock = [300.0]
    monkeypatch.setattr(
        "plugin.plugins.vibe_coding_connector.time.monotonic",
        lambda: clock[0],
    )

    try:
        await plugin._push_synthesized(kind="completion", session_id="s1", count=0)
        await plugin._push_synthesized(kind="completion", session_id="s2", count=0)
        clock[0] = 301.1
        await plugin._push_synthesized(kind="approval", session_id="s3", count=1)
        clock[0] = 302.2
        await plugin._push_synthesized(kind="completion", session_id="s4", count=0)

        assert len(ctx.pushed) == 2
        assert all(item["ai_behavior"] != "respond" for item in ctx.pushed)
        assert all(item["metadata"]["no_feedback"] is True for item in ctx.pushed)
    finally:
        await plugin.shutdown()


@pytest.mark.asyncio
async def test_managed_listener_reconnects_when_actual_port_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(tmp_path / "runtime"))
    plugin = VibeCodingConnectorPlugin(_Context(PLUGIN_DIR))
    plugin._loaded = True
    plugin._settings = ConnectorSettings()

    class _Runtime:
        base_url = "http://127.0.0.1:31001"

    class _EndpointClient:
        def __init__(self, started: asyncio.Event) -> None:
            self.started = started

        async def iter_events(
            self,
            *,
            stop_event: asyncio.Event,
            reconnect: bool,
        ) -> AsyncIterator[SSEEvent]:
            assert reconnect is True
            self.started.set()
            await stop_event.wait()
            if False:  # pragma: no cover - keep this an async iterator
                yield SSEEvent(event="unused", data={})

    runtime = _Runtime()
    plugin._managed_runtime = runtime  # type: ignore[assignment]
    first_started = asyncio.Event()
    second_started = asyncio.Event()
    clients = [
        _EndpointClient(first_started),
        _EndpointClient(second_started),
    ]
    calls = 0

    async def get_client() -> _EndpointClient:
        nonlocal calls
        client = clients[min(calls, len(clients) - 1)]
        calls += 1
        return client

    monkeypatch.setattr(plugin, "_get_client", get_client)
    listener_stop = asyncio.Event()
    task = asyncio.create_task(plugin._listener_main(listener_stop))
    try:
        await asyncio.wait_for(first_started.wait(), timeout=1.0)
        runtime.base_url = "http://127.0.0.1:31002"
        await asyncio.wait_for(second_started.wait(), timeout=2.0)
        assert calls >= 2
    finally:
        listener_stop.set()
        await asyncio.wait_for(task, timeout=1.0)


@pytest.mark.asyncio
async def test_listener_deduplicates_and_pushes_only_important_events_without_feedback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_root = tmp_path / "runtime"
    monkeypatch.setenv("NEKO_STORAGE_SELECTED_ROOT", str(data_root))
    ctx = _Context(PLUGIN_DIR)
    plugin = VibeCodingConnectorPlugin(ctx)
    await plugin.startup()
    plugin._settings = ConnectorSettings.from_mapping(
        {
            **plugin._settings.to_store(),
            "notifications_enabled": True,
            "notification_visibility": ["hud"],
            "notification_ai_behavior": "read",
        }
    )

    completed = SSEEvent(
        event="session-ended",
        data={"type": "session-ended", "sessionId": "s1"},
        event_id="same",
    )
    ordinary = SSEEvent(
        event="message-received",
        data={"type": "message-received", "sessionId": "s1", "text": "secret output"},
        event_id="m1",
    )
    await plugin._handle_sse_event(completed)
    await plugin._handle_sse_event(completed)
    await plugin._handle_sse_event(ordinary)

    assert len(ctx.pushed) == 1
    pushed = ctx.pushed[0]
    assert pushed["source"] == "vibe_coding_connector"
    assert pushed["ai_behavior"] != "respond"
    assert pushed["visibility"] == ["hud"]
    assert "secret output" not in json.dumps(pushed)
    assert pushed["metadata"]["no_feedback"] is True
    assert len(plugin._recent_events) <= plugin._settings.max_recent_events
    await plugin.shutdown()


def test_static_panel_uses_real_run_bridge_and_has_no_external_assets_or_demo_data() -> None:
    html = (PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8")

    assert "/runs" in html
    assert re.search(r"RUNS_URL.*?/export", html, flags=re.DOTALL)
    assert "const RUN_TIMEOUT_MS = 195000;" in html
    for entry_id in (
        "vibe_coding_panel_status",
        "vibe_coding_panel_list_sessions",
        "vibe_coding_panel_create_session",
        "vibe_coding_panel_read_activity",
        "vibe_coding_panel_list_approvals",
    ):
        assert f'"{entry_id}"' in html
    assert 'callPlugin("vibe_coding_status"' not in html
    assert 'callPlugin("vibe_coding_list_sessions"' not in html
    assert 'callPlugin("vibe_coding_create_session"' not in html
    assert 'callPlugin("vibe_coding_read_activity"' not in html
    assert 'callPlugin("vibe_coding_list_approvals"' not in html
    assert '<option value="respond">' not in html
    assert "approval.requires_answers === true" in html
    assert "approval.details_withheld === true" in html
    assert "approval.approvable_without_answers !== true" in html
    assert "approve.dataset.approvalBlockedReason = approveBlockedReason;" in html
    assert 'deny.dataset.approvalBlockedReason = "";' in html
    assert "https://cdn." not in html
    assert "unpkg.com" not in html
    assert "mock session" not in html.lower()
    assert "demo data" not in html.lower()
    assert "<label" in html
    assert "aria-live" in html
    assert 'type="password"' in html
    assert ".value = state.settings.token" not in html


def test_static_panel_numeric_constraints_accept_backend_defaults() -> None:
    parser = _PanelNumberInputParser()
    parser.feed((PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8"))
    parser.close()
    defaults = ConnectorSettings()
    inputs_by_setting = {
        "preferred_port": "preferredPort",
        "timeout_seconds": "timeoutSeconds",
        "sse_reconnect_delay": "reconnectDelay",
        "max_response_size": "maxResponseSize",
        "max_instruction_chars": "maxInstructionChars",
        "max_output_chars": "maxOutputChars",
        "max_concurrency": "maxConcurrency",
        "rate_limit_per_minute": "rateLimit",
    }

    for setting_name, input_id in inputs_by_setting.items():
        attributes = parser.inputs[input_id]
        assert all(attributes.get(name) is not None for name in ("min", "max", "step"))
        minimum = Decimal(attributes["min"] or "")
        maximum = Decimal(attributes["max"] or "")
        step = Decimal(attributes["step"] or "")
        default = Decimal(str(getattr(defaults, setting_name)))

        assert minimum <= default <= maximum, setting_name
        assert step > 0, setting_name
        assert (default - minimum) % step == 0, setting_name


def test_settings_save_never_places_plaintext_token_in_run_args() -> None:
    html = (PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8")

    assert (
        'callPlugin("vibe_coding_save_settings", { settings, token })'
        not in html
    )
    assert "async function encryptSavePayload(" in html
    assert "async function saveWithFreshEnvelope(" in html
    assert 'invoke("vibe_coding_fresh_secret_envelope", {})' in html
    assert 'invoke("vibe_coding_save_settings", encryptedArgs)' in html

    meta = getattr(VibeCodingConnectorPlugin.save_settings, EVENT_META_ATTR)
    schema = meta.input_schema
    assert set(schema["properties"]) == {"encrypted_payload", "key_id"}
    assert schema["required"] == ["encrypted_payload", "key_id"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["encrypted_payload"]["writeOnly"] is True
    assert schema["properties"]["encrypted_payload"]["x-sensitive"] is True


def test_encrypted_save_fetches_fresh_envelope_and_retries_only_once() -> None:
    html = (PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8")

    save_block = re.search(
        r"async function saveWithFreshEnvelope\((.*?)(?:\n    function setNotice)",
        html,
        flags=re.DOTALL,
    )
    assert save_block is not None
    source = save_block.group(1)
    assert "attempt < 2" in source
    assert source.index("await freshSecretEnvelope(invoke)") < source.index(
        "const encryptedArgs = await encrypt(savePayload)"
    )
    assert source.index("const encryptedArgs = await encrypt(savePayload)") < source.index(
        'invoke("vibe_coding_save_settings", encryptedArgs)'
    )
    assert "attempt === 0 && retryableEnvelopeError(error)" in source
    assert "throw error;" in source


def test_save_notice_only_claims_token_was_kept_for_blank_input() -> None:
    html = (PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8")
    save_block = re.search(
        r"async function saveSettings\(event\)(.*?)(?:\n    async function resetSettings)",
        html,
        flags=re.DOTALL,
    )
    assert save_block is not None
    source = save_block.group(1)
    assert re.search(
        r"if \(!token\) \{.*?panel\.message\.tokenKept",
        source,
        flags=re.DOTALL,
    )


def test_static_panel_has_csp_safe_narrow_layout_and_lossless_settings_roundtrip() -> None:
    html = (PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8")

    assert 'http-equiv="Content-Security-Policy"' in html
    for directive in (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
        "connect-src 'self'",
    ):
        assert directive in html
    for field in ("max_recent_events", "max_recent_sessions", "auto_approve"):
        assert field in html
    assert re.search(
        r"\.activity-output\s*\{[^}]*overflow-wrap:\s*anywhere",
        html,
        flags=re.DOTALL,
    )
    assert re.search(
        r"\.tag\s*\{[^}]*max-width:\s*60%[^}]*overflow:\s*hidden"
        r"[^}]*text-overflow:\s*ellipsis",
        html,
        flags=re.DOTALL,
    )
    assert re.search(
        r"\.health-detail\s*\{[^}]*min-width:\s*0",
        html,
        flags=re.DOTALL,
    )
    assert "HAPI 报告的提供商" not in html
    assert "连接器本地允许的提供商" in html
    assert "末四位" not in html


def test_readme_matches_encrypted_save_https_and_manual_resume_policy() -> None:
    readme = (PLUGIN_DIR / "README.md").read_text(encoding="utf-8")

    assert "RSA-OAEP" in readme
    assert "AES-GCM" in readme
    assert "非本机 HAPI" in readme and "必须使用 HTTPS" in readme
    assert "不会自动恢复" in readme
    assert "自动确定性选择" in readme
    assert "末四位" not in readme
    assert "token 经 N.E.K.O 的 `/runs` 管理通道写入" not in readme


def test_all_eight_locale_bundles_have_identical_nonempty_key_sets() -> None:
    bundles = {
        locale: json.loads((PLUGIN_DIR / "i18n" / f"{locale}.json").read_text(encoding="utf-8"))
        for locale in LOCALES
    }
    key_sets = {locale: set(bundle) for locale, bundle in bundles.items()}

    assert len(set(map(frozenset, key_sets.values()))) == 1
    assert len(next(iter(key_sets.values()))) >= 12
    for locale, bundle in bundles.items():
        assert all(isinstance(key, str) and key.strip() for key in bundle), locale
        assert all(isinstance(value, str) and value.strip() for value in bundle.values()), locale

    html = (PLUGIN_DIR / "static" / "index.html").read_text(encoding="utf-8")
    panel_keys = {
        key
        for key in bundles["en"]
        if key.startswith("panel.")
    }
    assert panel_keys
    assert all(key in html for key in panel_keys)
    assert "data-i18n-placeholder" in html
    assert 'querySelectorAll("[data-i18n-placeholder]")' in html


def test_source_has_no_local_command_execution_or_auto_approval_path() -> None:
    plugin_sources = {
        path: path.read_text(encoding="utf-8")
        for path in PLUGIN_DIR.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    python_source = "\n".join(plugin_sources.values())
    lowered = python_source.lower()

    # Process execution is confined to the explicit compatibility backend and
    # the managed HAPI supervisor.
    process_files = {"local.py", "managed_runtime.py"}
    for path, source in plugin_sources.items():
        if path.name in process_files:
            continue
        source_lower = source.lower()
        assert "import subprocess" not in source_lower, path
        assert "from subprocess" not in source_lower, path
        assert "create_subprocess" not in source_lower, path
        assert "subprocess.popen" not in source_lower, path

    assert "os.system(" not in lowered
    assert re.search(
        r"""["']?shell["']?\s*[:=]\s*true""",
        lowered,
    ) is None
    assert '"yolo": true' not in lowered
    assert "'yolo': true' " not in lowered
    assert "auto_approve = true" not in lowered
    assert "--dangerously-skip-permissions" not in lowered

    local_source = (PLUGIN_DIR / "local.py").read_text(encoding="utf-8").lower()
    assert "create_subprocess_exec" in local_source
    assert "create_subprocess_shell" not in local_source
    assert "shell=true" not in local_source
    for dangerous in ("--dangerously-skip-permissions", "--yolo", "--full-auto"):
        assert dangerous not in local_source

    managed_source = (PLUGIN_DIR / "managed_runtime.py").read_text(
        encoding="utf-8"
    )
    assert '"shell": False' in managed_source
    assert "subprocess.Popen(list(argv), **popen_kwargs)" in managed_source
    assert managed_source.count("subprocess.Popen(") == 1
    assert re.search(
        r"def _spawn_owned\([^)]*argv: tuple\[str, \.\.\.\]",
        managed_source,
        flags=re.DOTALL,
    )
