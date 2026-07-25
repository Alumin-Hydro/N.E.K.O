"""Typed asynchronous client for the public HAPI HTTP/SSE contract.

Protocol-shape compatibility lives here so the plugin policy and entry handlers
do not need to know whether a HAPI release wraps payloads in ``data`` or returns
them directly.
"""

from __future__ import annotations

import asyncio
import json
import math
import weakref
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Mapping, NotRequired, TypedDict
from urllib.parse import quote

import httpx

from .security import PolicyError, redact_sensitive, validate_base_url, validate_identifier


class HealthInfo(TypedDict):
    status: str
    protocol_version: int | None


class MachineInfo(TypedDict):
    id: str
    name: str
    online: bool
    metadata: dict[str, Any]


class SessionInfo(TypedDict):
    id: str
    machine_id: str
    provider: str
    directory: str
    status: str
    active: bool
    thinking: bool
    permission_mode: str
    updated_at: str | int | float | None
    pending_count: int
    agent_state: NotRequired[dict[str, Any]]
    permission_requests: NotRequired[list["PermissionInfo"]]


class MessageInfo(TypedDict):
    id: str
    role: str
    created_at: str | int | float | None
    content: Any


class PermissionInfo(TypedDict):
    id: str
    tool: str
    created_at: str | int | float | None
    arguments: Any
    arguments_truncated: bool


@dataclass(frozen=True, slots=True)
class SSEEvent:
    event: str
    data: dict[str, Any]
    event_id: str = ""


@dataclass(frozen=True, slots=True)
class HapiClientConfig:
    base_url: str = "http://127.0.0.1:3006"
    token: str | None = field(default=None, repr=False)
    auth_mode: str = "access_token"
    timeout_seconds: float = 15.0
    reconnect_delay_seconds: float = 5.0
    max_response_bytes: int = 262_144
    allow_remote: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "base_url",
            validate_base_url(self.base_url, allow_remote=self.allow_remote),
        )
        if self.auth_mode not in {"access_token", "bearer"}:
            raise ValueError("auth_mode must be access_token or bearer")
        if self.token is not None:
            if not isinstance(self.token, str):
                raise ValueError("token must be a string")
            token = self.token.strip()
            if len(token) > 8192:
                raise ValueError("token is too large")
            object.__setattr__(self, "token", token or None)
        if not 1.0 <= float(self.timeout_seconds) <= 120.0:
            raise ValueError("timeout_seconds is out of range")
        if not 0.01 <= float(self.reconnect_delay_seconds) <= 120.0:
            raise ValueError("reconnect_delay_seconds is out of range")
        if not 16_384 <= int(self.max_response_bytes) <= 2_097_152:
            raise ValueError("max_response_bytes is out of range")


class HapiClientError(RuntimeError):
    """A credential-free, response-body-free HAPI error."""

    def __init__(
        self,
        public_message: str,
        *,
        code: str = "hapi_error",
        status_code: int | None = None,
    ) -> None:
        super().__init__(public_message)
        self.public_message = public_message
        self.code = code
        self.status_code = status_code


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _unwrap_key(value: Any, key: str) -> Any:
    """Accept current HAPI and a few bounded historical wrapper variants."""

    if isinstance(value, Mapping):
        if key in value:
            return value[key]
        data = value.get("data")
        if isinstance(data, Mapping) and key in data:
            return data[key]
        if key == "session" and "id" in value:
            return value
        if key == "sessions" and isinstance(data, list):
            return data
        if key == "machines" and isinstance(data, list):
            return data
        if key == "messages" and isinstance(data, list):
            return data
    if isinstance(value, list) and key in {"sessions", "machines", "messages"}:
        return value
    return None


def _text(value: Any, *, maximum: int = 4096) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\x00", "")
    return value[:maximum]


def _protocol_identifier(value: Any, *, kind: str) -> str:
    """Validate an identity losslessly; never truncate or clean it."""

    if not isinstance(value, str) or value != value.strip():
        return ""
    try:
        normalized = validate_identifier(value, kind=kind)
    except PolicyError:
        return ""
    return normalized if normalized == value else ""


def _protocol_string(value: Any, *, maximum: int) -> str:
    """Return a bounded protocol/security string without altering its value."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        return ""
    return value


def _first(raw: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return default


def _timestamp(value: Any) -> str | int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:128]
    return None


def _normalize_machine(value: Any) -> MachineInfo | None:
    raw = _as_mapping(value)
    metadata_raw = _as_mapping(_first(raw, "metadata", "info", default={}))
    machine_id = _protocol_identifier(
        _first(raw, "id", "machineId", "machine_id"),
        kind="机器 ID",
    )
    if not machine_id:
        return None
    status = _text(_first(raw, "status", "connectionStatus"), maximum=64).lower()
    online_value = _first(raw, "online", "isOnline", "connected", "active")
    online = bool(online_value) if online_value is not None else status in {
        "online",
        "connected",
        "ready",
    }
    metadata = redact_sensitive(
        metadata_raw,
        max_string=512,
    )
    return {
        "id": machine_id,
        "name": _text(
            _first(
                raw,
                "name",
                "displayName",
                default=_first(metadata_raw, "displayName", "name", default=machine_id),
            ),
            maximum=256,
        ),
        "online": online,
        "metadata": metadata if isinstance(metadata, dict) else {},
    }


def _extract_provider(raw: Mapping[str, Any]) -> str:
    direct = _first(raw, "provider", "agent", "agentType", "flavor", default="")
    if isinstance(direct, Mapping):
        direct = _first(direct, "type", "provider", "name", default="")
    if not direct:
        metadata = _as_mapping(raw.get("metadata"))
        direct = _first(metadata, "provider", "agent", "flavor", default="")
    provider = _protocol_string(direct, maximum=64)
    if provider != provider.strip():
        return ""
    return provider.lower()


def _extract_directory(raw: Mapping[str, Any]) -> str:
    direct = _first(raw, "directory", "workingDirectory", "working_directory", "cwd", default="")
    if not direct:
        metadata = _as_mapping(raw.get("metadata"))
        direct = _first(
            metadata,
            "path",
            "directory",
            "cwd",
            "workingDirectory",
            default="",
        )
    return _protocol_string(direct, maximum=4096)


def extract_permissions(agent_state: Any) -> list[PermissionInfo]:
    state = _as_mapping(agent_state)
    requests = _first(
        state,
        "requests",
        "permissionRequests",
        "pendingPermissions",
        default=[],
    )
    pairs: list[tuple[str, Any]]
    if isinstance(requests, Mapping):
        pairs = []
        for key, request in list(requests.items())[:100]:
            request_id = _protocol_identifier(key, kind="权限请求 ID")
            if not request_id:
                continue
            raw = _as_mapping(request)
            embedded = _first(raw, "id", "requestId", "request_id")
            if embedded is not None:
                embedded_id = _protocol_identifier(
                    embedded,
                    kind="权限请求 ID",
                )
                if embedded_id != request_id:
                    continue
            pairs.append((request_id, request))
    elif isinstance(requests, list):
        pairs = []
        for request in requests[:100]:
            raw = _as_mapping(request)
            request_id = _protocol_identifier(
                _first(raw, "id", "requestId", "request_id"),
                kind="权限请求 ID",
            )
            if request_id:
                pairs.append((request_id, request))
    else:
        return []

    result: list[PermissionInfo] = []
    for fallback_id, request in pairs:
        raw = _as_mapping(request)
        request_status = _text(
            _first(raw, "status", "state", default="pending"),
            maximum=32,
        ).lower()
        if request_status in {
            "approved",
            "denied",
            "rejected",
            "resolved",
            "completed",
            "cancelled",
            "canceled",
        }:
            continue
        request_id = fallback_id
        raw_arguments = _first(raw, "arguments", "args", "input", default={})
        arguments = redact_sensitive(
            raw_arguments,
            max_string=512,
        )
        result.append(
            {
                "id": request_id,
                "tool": _text(
                    _first(raw, "tool", "toolName", "name", "permission", default="unknown"),
                    maximum=128,
                ),
                "created_at": _timestamp(
                    _first(raw, "createdAt", "created_at", "timestamp")
                ),
                "arguments": arguments,
                "arguments_truncated": _permission_arguments_would_truncate(
                    raw_arguments
                )
                or _permission_arguments_would_redact(raw_arguments),
            }
        )
    return result


def _normalize_session(value: Any, *, include_state: bool = False) -> SessionInfo | None:
    raw = _as_mapping(value)
    session_id = _protocol_identifier(
        _first(raw, "id", "sessionId", "session_id"),
        kind="会话 ID",
    )
    if not session_id:
        return None
    metadata = _as_mapping(raw.get("metadata"))
    thinking = bool(_first(raw, "thinking", default=False))
    active_value = _first(raw, "active", "isActive", "running")
    if active_value is None:
        active = thinking
    else:
        active = bool(active_value)
    agent_state = _as_mapping(_first(raw, "agentState", "agent_state", default={}))
    if bool(_first(agent_state, "thinking", default=False)):
        thinking = True
    if not active and bool(_first(agent_state, "thinking", "running", default=False)):
        active = True
    status_raw = _first(
        raw,
        "status",
        "state",
        default=_first(metadata, "lifecycleState", "lifecycle_state", default=""),
    )
    status = _text(status_raw, maximum=64).lower()
    if not status:
        status = "thinking" if thinking else ("active" if active else "inactive")
    pending = extract_permissions(agent_state)
    pending_raw = _first(
        raw,
        "pendingRequestsCount",
        "pending_count",
        "pendingCount",
        default=len(pending),
    )
    try:
        pending_count = max(len(pending), min(max(int(pending_raw), 0), 100))
    except (TypeError, ValueError):
        pending_count = len(pending)
    permission_mode = _protocol_string(
        _first(
            raw,
            "permissionMode",
            "permission_mode",
            default=_first(metadata, "permissionMode", "permission_mode", default=""),
        ),
        maximum=64,
    )
    result: SessionInfo = {
        "id": session_id,
        "machine_id": _protocol_identifier(
            _first(
                raw,
                "machineId",
                "machine_id",
                "machine",
                default=_first(metadata, "machineId", "machine_id", default=""),
            ),
            kind="机器 ID",
        ),
        "provider": _extract_provider(raw),
        "directory": _extract_directory(raw),
        "status": status,
        "active": active,
        "thinking": thinking,
        "permission_mode": permission_mode,
        "updated_at": _timestamp(
            _first(raw, "updatedAt", "updated_at", "lastActiveAt")
        ),
        "pending_count": pending_count,
    }
    if include_state:
        sanitized = redact_sensitive(agent_state, max_string=1024)
        result["agent_state"] = sanitized if isinstance(sanitized, dict) else {}
        result["permission_requests"] = pending
    return result


def _normalize_message(value: Any) -> MessageInfo | None:
    outer = _as_mapping(value)
    raw = outer
    # Match HAPI's exact role-wrapper variants.  Do not generically unwrap
    # ``data`` because agent content records also use that key.
    roots = [outer]
    outer_content = outer.get("content")
    if isinstance(outer_content, Mapping):
        roots.append(_as_mapping(outer_content))
    elif (
        isinstance(outer_content, str)
        and len(outer_content) <= 32_768
        and outer_content[:1] in {"{", "["}
    ):
        try:
            decoded_content = json.loads(outer_content)
        except (ValueError, TypeError, RecursionError):
            decoded_content = None
        if isinstance(decoded_content, Mapping):
            roots.append(_as_mapping(decoded_content))
    wrapped_candidates: list[dict[str, Any]] = []
    for root in roots:
        wrapped_candidates.extend(
            [
                root,
                _as_mapping(root.get("message")),
                _as_mapping(_as_mapping(root.get("data")).get("message")),
                _as_mapping(_as_mapping(root.get("payload")).get("message")),
            ]
        )
    for candidate in wrapped_candidates:
        if (
            any(key in candidate for key in ("role", "sender"))
            and any(key in candidate for key in ("content", "text", "parts"))
        ):
            raw = candidate
            break
    message_id = _text(
        _first(
            raw,
            "id",
            "messageId",
            "message_id",
            default=_first(outer, "id", "messageId", "message_id"),
        ),
        maximum=256,
    )
    if not message_id:
        message_id = _text(
            _first(
                raw,
                "localId",
                "uuid",
                default=_first(outer, "localId", "uuid", default=""),
            ),
            maximum=256,
        )
    content_raw = _first(raw, "content", "text", "message", "parts", default="")
    if content_raw == "" and any(key in raw for key in ("data", "payload")):
        content_raw = raw
    content_envelope: dict[str, Any] = {}
    if isinstance(content_raw, Mapping):
        content_envelope = _as_mapping(content_raw)
    elif isinstance(content_raw, str) and content_raw[:1] in {"{", "["}:
        try:
            decoded = json.loads(content_raw)
        except (ValueError, TypeError, RecursionError):
            decoded = None
        if isinstance(decoded, Mapping):
            content_envelope = _as_mapping(decoded)
            content_raw = decoded
    content = redact_sensitive(content_raw, max_string=4096)
    role = _first(raw, "role", "sender", "type")
    if not role:
        role = _first(content_envelope, "role", "sender", "type", default="unknown")
    return {
        "id": message_id,
        "role": _text(role, maximum=64),
        "created_at": _timestamp(
            _first(
                raw,
                "createdAt",
                "created_at",
                "timestamp",
                default=_first(outer, "createdAt", "created_at", "timestamp"),
            )
        ),
        "content": content,
    }


def _permission_arguments_would_truncate(value: Any, *, depth: int = 0) -> bool:
    if depth > 5:
        return True
    if isinstance(value, str):
        return len(value) > 512
    if isinstance(value, Mapping):
        if len(value) > 64:
            return True
        if any(
            not isinstance(key, str) or len(key) > 128
            for key in value
        ):
            return True
        return any(
            _permission_arguments_would_truncate(item, depth=depth + 1)
            for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        if len(value) > 64:
            return True
        return any(
            _permission_arguments_would_truncate(item, depth=depth + 1)
            for item in value
        )
    return not (value is None or isinstance(value, (bool, int, float)))


def _permission_arguments_would_redact(value: Any, *, depth: int = 0) -> bool:
    if depth > 5:
        return True
    if isinstance(value, Mapping):
        for key, item in list(value.items())[:65]:
            lowered = str(key).lower()
            if any(
                part in lowered
                for part in (
                    "token",
                    "secret",
                    "password",
                    "authorization",
                    "credential",
                    "jwt",
                )
            ):
                return True
            if _permission_arguments_would_redact(item, depth=depth + 1):
                return True
        return len(value) > 64
    if isinstance(value, (list, tuple)):
        return len(value) > 64 or any(
            _permission_arguments_would_redact(item, depth=depth + 1)
            for item in value[:64]
        )
    return False


class _SSEParser:
    def __init__(self, max_event_bytes: int) -> None:
        self._max_event_bytes = max_event_bytes
        self._buffer = bytearray()
        self._data_lines: list[str] = []
        self._data_size = 0
        self._event = ""
        self._event_id = ""
        self._oversized = False

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        if len(self._buffer) + len(chunk) > self._max_event_bytes * 2:
            self._reset_frame()
            self._buffer.clear()
            return []
        self._buffer.extend(chunk)
        output: list[SSEEvent] = []
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                break
            line = bytes(self._buffer[:newline])
            del self._buffer[: newline + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            parsed = self._line(line)
            if parsed is not None:
                output.append(parsed)
        return output

    def finish(self) -> list[SSEEvent]:
        output: list[SSEEvent] = []
        if self._buffer:
            parsed = self._line(bytes(self._buffer).rstrip(b"\r"))
            self._buffer.clear()
            if parsed is not None:
                output.append(parsed)
        if self._data_lines or self._oversized:
            parsed = self._dispatch()
            if parsed is not None:
                output.append(parsed)
        return output

    def _line(self, raw_line: bytes) -> SSEEvent | None:
        if not raw_line:
            return self._dispatch()
        if raw_line.startswith(b":"):
            return None
        field, separator, value = raw_line.partition(b":")
        if separator and value.startswith(b" "):
            value = value[1:]
        if field == b"data":
            self._data_size += len(value)
            if self._data_size > self._max_event_bytes:
                self._oversized = True
                self._data_lines.clear()
            elif not self._oversized:
                self._data_lines.append(value.decode("utf-8", errors="replace"))
        elif field == b"event":
            self._event = value.decode("utf-8", errors="replace")[:128]
        elif field == b"id":
            self._event_id = value.decode("utf-8", errors="replace")[:256]
        return None

    def _dispatch(self) -> SSEEvent | None:
        if self._oversized:
            self._reset_frame()
            return None
        if not self._data_lines:
            self._reset_frame()
            return None
        raw = "\n".join(self._data_lines)
        try:
            value = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
            self._reset_frame()
            return None
        if not isinstance(value, Mapping):
            value = {"value": value}
        data = redact_sensitive(value, max_string=2048)
        event_name = self._event or _text(value.get("type"), maximum=128) or "message"
        event = SSEEvent(
            event=event_name,
            data=data if isinstance(data, dict) else {},
            event_id=self._event_id,
        )
        self._reset_frame()
        return event

    def _reset_frame(self) -> None:
        self._data_lines.clear()
        self._data_size = 0
        self._event = ""
        self._event_id = ""
        self._oversized = False


class HapiClient:
    """Per-event-loop httpx client with bounded HTTP and SSE parsing."""

    def __init__(
        self,
        config: HapiClientConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        client_factory: Callable[..., httpx.AsyncClient] | None = None,
    ) -> None:
        self.config = config
        self._transport = transport
        self._client_factory = client_factory or httpx.AsyncClient
        self._clients: dict[int, httpx.AsyncClient] = {}
        self._loops: dict[int, weakref.ReferenceType[asyncio.AbstractEventLoop]] = {}
        self._bearer_tokens: dict[int, str] = {}

    def _client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        loop_id = id(loop)
        current = self._clients.get(loop_id)
        loop_ref = self._loops.get(loop_id)
        if (
            current is not None
            and not current.is_closed
            and loop_ref is not None
            and loop_ref() is loop
        ):
            return current
        if current is not None:
            self._clients.pop(loop_id, None)
            self._loops.pop(loop_id, None)
            self._bearer_tokens.pop(loop_id, None)
        kwargs: dict[str, Any] = {
            "base_url": self.config.base_url,
            "timeout": httpx.Timeout(self.config.timeout_seconds),
            "follow_redirects": False,
            "trust_env": False,
            "headers": {
                "Accept": "application/json",
                "User-Agent": "NEKO-vibe-coding-connector/0.1.0",
            },
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        current = self._client_factory(**kwargs)
        self._clients[loop_id] = current
        self._loops[loop_id] = weakref.ref(loop)
        return current

    async def authenticate(self, *, force: bool = False) -> str | None:
        token = self.config.token
        if not token:
            return None
        if self.config.auth_mode == "bearer":
            return token
        loop_id = id(asyncio.get_running_loop())
        if not force and loop_id in self._bearer_tokens:
            return self._bearer_tokens[loop_id]
        payload = await self._request_json(
            "POST",
            "/api/auth",
            json_body={"accessToken": token},
            protected=False,
        )
        mapping = _as_mapping(payload)
        nested = _as_mapping(mapping.get("data"))
        bearer = _first(mapping, "token", "bearerToken", "jwt")
        if not bearer:
            bearer = _first(nested, "token", "bearerToken", "jwt")
        if not isinstance(bearer, str) or not bearer.strip() or len(bearer) > 16_384:
            raise HapiClientError(
                "HAPI 身份验证响应无效",
                code="invalid_auth_response",
            )
        self._bearer_tokens[loop_id] = bearer.strip()
        return bearer.strip()

    async def _auth_headers(self, *, force: bool = False) -> dict[str, str]:
        bearer = await self.authenticate(force=force)
        return {"Authorization": f"Bearer {bearer}"} if bearer else {}

    async def _read_response(self, response: httpx.Response) -> bytes:
        header = response.headers.get("content-length")
        if header:
            try:
                if int(header) > self.config.max_response_bytes:
                    raise HapiClientError(
                        "HAPI 响应超过安全大小上限",
                        code="response_too_large",
                        status_code=response.status_code,
                    )
            except ValueError:
                pass
        content = bytearray()
        async for chunk in response.aiter_bytes():
            if len(content) + len(chunk) > self.config.max_response_bytes:
                raise HapiClientError(
                    "HAPI 响应超过安全大小上限",
                    code="response_too_large",
                    status_code=response.status_code,
                )
            content.extend(chunk)
        return bytes(content)

    async def _request_json(
        self,
        method: str,
        route: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        protected: bool = True,
        retry_auth: bool = True,
    ) -> Any:
        client = self._client()
        headers: dict[str, str] = {}
        if protected:
            headers.update(await self._auth_headers())
        try:
            async with client.stream(
                method,
                route,
                headers=headers,
                json=dict(json_body) if json_body is not None else None,
            ) as response:
                body = await self._read_response(response)
                status = response.status_code
        except HapiClientError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            raise HapiClientError(
                "无法连接 HAPI；请确认服务已启动且地址、网络和令牌配置正确",
                code="connection_failed",
            ) from exc
        except httpx.HTTPError as exc:
            raise HapiClientError(
                "HAPI 网络请求失败",
                code="network_error",
            ) from exc

        if (
            status == 401
            and protected
            and retry_auth
            and self.config.token
            and self.config.auth_mode == "access_token"
        ):
            self._bearer_tokens.pop(id(asyncio.get_running_loop()), None)
            return await self._request_json(
                method,
                route,
                json_body=json_body,
                protected=protected,
                retry_auth=False,
            )
        if status == 401:
            raise HapiClientError(
                "HAPI 身份验证失败；请在面板中检查令牌",
                code="authentication_failed",
                status_code=status,
            )
        if status == 403:
            raise HapiClientError(
                "HAPI 拒绝访问此资源",
                code="forbidden",
                status_code=status,
            )
        if status == 404:
            raise HapiClientError(
                "当前 HAPI 版本不支持此端点，或资源不存在",
                code="not_found",
                status_code=status,
            )
        if status < 200 or status >= 300:
            raise HapiClientError(
                f"HAPI 请求失败（HTTP {status}）",
                code="remote_error",
                status_code=status,
            )
        if not body:
            return {}
        try:
            return json.loads(body)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise HapiClientError(
                "HAPI 返回了无效的 JSON 响应",
                code="invalid_response",
                status_code=status,
            ) from exc

    async def health(self) -> HealthInfo:
        payload = await self._request_json("GET", "/health", protected=False)
        raw = _as_mapping(payload)
        data = _as_mapping(raw.get("data"))
        source = data or raw
        version = _first(source, "protocolVersion", "protocol_version", "version")
        if isinstance(version, bool) or not isinstance(version, (int, float, str)):
            protocol_version: int | None = None
        else:
            try:
                protocol_version = int(version)
            except (TypeError, ValueError):
                protocol_version = None
        return {
            "status": _text(_first(source, "status", default="unknown"), maximum=64),
            "protocol_version": protocol_version,
        }

    async def list_machines(self) -> list[MachineInfo]:
        payload = await self._request_json("GET", "/api/machines")
        raw = _unwrap_key(payload, "machines")
        if not isinstance(raw, list):
            raise HapiClientError("HAPI 机器列表响应无效", code="invalid_response")
        result: list[MachineInfo] = []
        for item in raw[:100]:
            machine = _normalize_machine(item)
            if machine is not None:
                result.append(machine)
        return result

    async def list_sessions(self) -> list[SessionInfo]:
        payload = await self._request_json("GET", "/api/sessions")
        raw = _unwrap_key(payload, "sessions")
        if not isinstance(raw, list):
            raise HapiClientError("HAPI 会话列表响应无效", code="invalid_response")
        result: list[SessionInfo] = []
        for item in raw[:100]:
            session = _normalize_session(item)
            if session is not None:
                result.append(session)
        return result

    async def get_session(self, session_id: str) -> SessionInfo:
        session_id = validate_identifier(session_id, kind="会话 ID")
        route = f"/api/sessions/{quote(session_id, safe='')}"
        payload = await self._request_json("GET", route)
        raw = _unwrap_key(payload, "session")
        session = _normalize_session(raw, include_state=True)
        if session is None:
            raise HapiClientError("HAPI 会话详情响应无效", code="invalid_response")
        if session["id"] != session_id:
            raise HapiClientError("HAPI 会话详情 ID 不匹配", code="invalid_response")
        return session

    async def list_messages(self, session_id: str, limit: int = 20) -> list[MessageInfo]:
        session_id = validate_identifier(session_id, kind="会话 ID")
        safe_limit = max(1, min(int(limit), 200))
        route = f"/api/sessions/{quote(session_id, safe='')}/messages?limit={safe_limit}"
        payload = await self._request_json("GET", route)
        raw = _unwrap_key(payload, "messages")
        if not isinstance(raw, list):
            raise HapiClientError("HAPI 消息列表响应无效", code="invalid_response")
        result: list[MessageInfo] = []
        for item in raw[:safe_limit]:
            message = _normalize_message(item)
            if message is not None:
                result.append(message)
        return result

    async def create_session(
        self,
        machine_id: str,
        directory: str,
        provider: str,
    ) -> str:
        machine_id = validate_identifier(machine_id, kind="机器 ID")
        route = f"/api/machines/{quote(machine_id, safe='')}/spawn"
        payload = await self._request_json(
            "POST",
            route,
            json_body={
                "directory": directory,
                "agent": provider,
                "sessionType": "simple",
                "yolo": False,
                "permissionMode": "default",
            },
        )
        raw = _as_mapping(payload)
        nested = _as_mapping(raw.get("data"))
        if _text(raw.get("type"), maximum=32).lower() == "error":
            raise HapiClientError(
                "HAPI 拒绝创建会话；请检查机器、目录和提供商配置",
                code="spawn_rejected",
            )
        if raw.get("success") is False or raw.get("ok") is False:
            raise HapiClientError("HAPI 拒绝创建会话", code="spawn_rejected")
        session_id = _first(raw, "sessionId", "session_id", "id")
        if not session_id:
            session_id = _first(nested, "sessionId", "session_id", "id")
        session_id = _protocol_identifier(session_id, kind="创建后的会话 ID")
        if not session_id:
            raise HapiClientError("HAPI 创建会话响应无效", code="invalid_response")
        return session_id

    async def send_instruction(self, session_id: str, text: str) -> None:
        session_id = validate_identifier(session_id, kind="会话 ID")
        route = f"/api/sessions/{quote(session_id, safe='')}/messages"
        payload = await self._request_json("POST", route, json_body={"text": text})
        self._ensure_mutation_ok(payload, action="发送指令")

    async def resume_session(
        self,
        session_id: str,
        permission_mode: str = "default",
    ) -> str:
        """Resume an inactive session, using ``reopen`` as a version fallback."""

        session_id = validate_identifier(session_id, kind="会话 ID")
        permission_mode = _protocol_string(permission_mode, maximum=64)
        if not permission_mode or permission_mode != permission_mode.strip():
            raise PolicyError("权限模式无效", code="dangerous_permission_mode")
        routes = (
            f"/api/sessions/{quote(session_id, safe='')}/resume",
            f"/api/sessions/{quote(session_id, safe='')}/reopen",
        )
        payload: Any = None
        for index, route in enumerate(routes):
            try:
                payload = await self._request_json(
                    "POST",
                    route,
                    json_body={"permissionMode": permission_mode},
                )
                break
            except HapiClientError as exc:
                if index == 0 and exc.status_code == 404:
                    continue
                raise
        raw = _as_mapping(payload)
        nested = _as_mapping(raw.get("data"))
        session = _as_mapping(raw.get("session"))
        nested_session = _as_mapping(nested.get("session"))
        if (
            raw.get("ok") is False
            or raw.get("success") is False
            or _text(raw.get("type"), maximum=32).lower() == "error"
        ):
            raise HapiClientError(
                "HAPI 拒绝恢复会话",
                code="resume_rejected",
            )
        resumed_id = _first(raw, "sessionId", "session_id", "id")
        if not resumed_id:
            resumed_id = _first(nested, "sessionId", "session_id", "id")
        if not resumed_id:
            resumed_id = _first(session, "id") or _first(nested_session, "id")
        resumed_id = _protocol_identifier(
            resumed_id or session_id,
            kind="恢复后的会话 ID",
        )
        if not resumed_id:
            raise HapiClientError("HAPI 恢复会话响应无效", code="invalid_response")
        return resumed_id

    async def abort_session(self, session_id: str) -> None:
        session_id = validate_identifier(session_id, kind="会话 ID")
        route = f"/api/sessions/{quote(session_id, safe='')}/abort"
        payload = await self._request_json("POST", route, json_body={})
        self._ensure_mutation_ok(payload, action="停止会话")

    async def approve_permission(
        self,
        session_id: str,
        request_id: str,
        answers: Mapping[str, Any] | None = None,
    ) -> None:
        session_id = validate_identifier(session_id, kind="会话 ID")
        request_id = validate_identifier(request_id, kind="权限请求 ID")
        if answers is not None:
            if len(answers) > 64:
                raise PolicyError("审批 answers 字段过多", code="invalid_answers")
            nested_representation: bool | None = None
            for key, raw_answers in answers.items():
                if not isinstance(key, str) or not key or len(key) > 128:
                    raise PolicyError("审批 answer 字段名无效", code="invalid_answers")
                if isinstance(raw_answers, Mapping):
                    if set(raw_answers) != {"answers"}:
                        raise PolicyError(
                            "审批 answer 对象只允许 answers 字段",
                            code="invalid_answers",
                        )
                    answer_list = raw_answers.get("answers")
                    nested = True
                else:
                    answer_list = raw_answers
                    nested = False
                if nested_representation is None:
                    nested_representation = nested
                elif nested_representation is not nested:
                    raise PolicyError(
                        "同一审批的 answers 不能混用两种 HAPI 表示",
                        code="invalid_answers",
                    )
                if not isinstance(answer_list, list) or len(answer_list) > 64:
                    raise PolicyError(
                        "每个审批 answer 必须是有界字符串数组",
                        code="invalid_answers",
                    )
                if any(
                    not isinstance(item, str) or not item or len(item) > 2_048
                    for item in answer_list
                ):
                    raise PolicyError(
                        "审批 answer 必须是非空有界字符串",
                        code="invalid_answers",
                    )
            try:
                encoded_answers = json.dumps(
                    answers,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            except (TypeError, ValueError, RecursionError) as exc:
                raise PolicyError("审批 answers 必须是 JSON 数据", code="invalid_answers") from exc
            if len(encoded_answers) > 8_192:
                raise PolicyError("审批 answers 超过安全大小上限", code="invalid_answers")
        route = (
            f"/api/sessions/{quote(session_id, safe='')}/permissions/"
            f"{quote(request_id, safe='')}/approve"
        )
        body: dict[str, Any] = {}
        if answers is not None:
            body["answers"] = answers
        payload = await self._request_json("POST", route, json_body=body)
        self._ensure_mutation_ok(payload, action="批准权限请求")

    async def deny_permission(self, session_id: str, request_id: str) -> None:
        session_id = validate_identifier(session_id, kind="会话 ID")
        request_id = validate_identifier(request_id, kind="权限请求 ID")
        route = (
            f"/api/sessions/{quote(session_id, safe='')}/permissions/"
            f"{quote(request_id, safe='')}/deny"
        )
        payload = await self._request_json("POST", route, json_body={})
        self._ensure_mutation_ok(payload, action="拒绝权限请求")

    @staticmethod
    def _ensure_mutation_ok(payload: Any, *, action: str) -> None:
        if payload in ({}, None):
            return
        raw = _as_mapping(payload)
        nested = _as_mapping(raw.get("data"))
        if (
            raw.get("ok") is True
            or raw.get("success") is True
            or nested.get("ok") is True
            or nested.get("success") is True
        ):
            return
        if _text(raw.get("type"), maximum=32).lower() == "success":
            return
        raise HapiClientError(f"HAPI 未确认{action}", code="mutation_not_confirmed")

    async def _stream_once(self) -> AsyncIterator[SSEEvent]:
        client = self._client()
        headers = {"Accept": "text/event-stream"}
        headers.update(await self._auth_headers())
        try:
            async with client.stream(
                "GET",
                "/api/events?all=1",
                headers=headers,
                timeout=httpx.Timeout(
                    connect=self.config.timeout_seconds,
                    read=None,
                    write=self.config.timeout_seconds,
                    pool=self.config.timeout_seconds,
                ),
            ) as response:
                if response.status_code == 401:
                    self._bearer_tokens.pop(id(asyncio.get_running_loop()), None)
                    raise HapiClientError(
                        "HAPI SSE 身份验证失败",
                        code="authentication_failed",
                        status_code=401,
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise HapiClientError(
                        f"HAPI SSE 连接失败（HTTP {response.status_code}）",
                        code="sse_connection_failed",
                        status_code=response.status_code,
                    )
                content_type = response.headers.get("content-type", "").lower()
                if content_type and "text/event-stream" not in content_type:
                    raise HapiClientError(
                        "HAPI SSE 返回了不支持的内容类型",
                        code="invalid_sse_response",
                    )
                parser = _SSEParser(
                    min(self.config.max_response_bytes, 65_536),
                )
                async for chunk in response.aiter_bytes():
                    for event in parser.feed(chunk):
                        yield event
                for event in parser.finish():
                    yield event
        except asyncio.CancelledError:
            raise
        except HapiClientError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            raise HapiClientError(
                "HAPI SSE 连接中断",
                code="sse_connection_failed",
            ) from exc
        except httpx.HTTPError as exc:
            raise HapiClientError("HAPI SSE 请求失败", code="sse_connection_failed") from exc

    async def iter_events(
        self,
        *,
        stop_event: asyncio.Event | None = None,
        reconnect: bool = True,
    ) -> AsyncIterator[SSEEvent]:
        """Yield parsed events, reconnecting until cancelled or explicitly stopped."""

        while stop_event is None or not stop_event.is_set():
            try:
                async for event in self._stream_once():
                    yield event
                    if stop_event is not None and stop_event.is_set():
                        return
                if not reconnect:
                    return
            except asyncio.CancelledError:
                raise
            except HapiClientError:
                if not reconnect:
                    raise
            if stop_event is not None and stop_event.is_set():
                return
            try:
                if stop_event is None:
                    await asyncio.sleep(self.config.reconnect_delay_seconds)
                else:
                    await asyncio.wait_for(
                        stop_event.wait(),
                        timeout=self.config.reconnect_delay_seconds,
                    )
                    return
            except asyncio.TimeoutError:
                pass

    async def aclose(self) -> None:
        """Best-effort close clients created by any lifecycle event loop."""

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        items = list(self._clients.items())
        loops = dict(self._loops)
        self._clients.clear()
        self._loops.clear()
        self._bearer_tokens.clear()
        for loop_id, client in items:
            if client.is_closed:
                continue
            owner_ref = loops.get(loop_id)
            owner = owner_ref() if owner_ref is not None else None
            try:
                if current_loop is not None and owner is current_loop:
                    await client.aclose()
                elif current_loop is not None and owner is not None and owner.is_running():
                    future = asyncio.run_coroutine_threadsafe(client.aclose(), owner)
                    await asyncio.wait_for(
                        asyncio.wrap_future(future),
                        timeout=2.0,
                    )
                # A client whose owning loop is already closed cannot be
                # safely awaited from another loop.  Its references are
                # dropped above; shutdown remains bounded and deterministic.
            except (asyncio.TimeoutError, RuntimeError, httpx.HTTPError):
                continue


__all__ = [
    "HapiClient",
    "HapiClientConfig",
    "HapiClientError",
    "HealthInfo",
    "MachineInfo",
    "MessageInfo",
    "PermissionInfo",
    "SSEEvent",
    "SessionInfo",
    "extract_permissions",
]
