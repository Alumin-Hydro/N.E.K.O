"""Security policy and persisted settings for the Vibe Coding connector.

This module deliberately has no HAPI or N.E.K.O dependencies.  Keeping the
policy checks small and pure makes it harder for a panel or an LLM tool to
accidentally bypass them.
"""

from __future__ import annotations

import ipaddress
import math
import re
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, fields
from pathlib import Path, PurePath
from typing import Any, AsyncIterator, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit


SUPPORTED_PROVIDERS = frozenset({"claude", "codex", "opencode"})
SUPPORTED_AUTH_MODES = frozenset({"access_token", "bearer"})
SUPPORTED_AI_BEHAVIORS = frozenset({"read", "blind"})
SUPPORTED_VISIBILITY = frozenset({"chat", "hud"})
SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "authorization",
    "credential",
    "jwt",
    "apikey",
    "privatekey",
    "cookie",
    "bearer",
    "passwd",
    "passphrase",
)
SENSITIVE_EXACT_KEYS = frozenset(
    {
        "auth",
        "authentication",
    }
)
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
DEFAULT_BASE_URL = "http://127.0.0.1:3006"
DEFAULT_AUTH_MODE = "access_token"
DEFAULT_PROVIDERS = ("claude", "codex", "opencode")
DEFAULT_NOTIFICATION_BEHAVIOR = "read"
DEFAULT_NOTIFICATION_VISIBILITY = ("hud",)


class PolicyError(ValueError):
    """A safe-to-display policy validation error."""

    def __init__(self, message: str, *, code: str = "policy_rejected") -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message


def is_sensitive_key(value: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(value).lower())
    return (
        normalized in SENSITIVE_EXACT_KEYS
        or normalized.endswith("auth")
        or normalized.endswith("authentication")
        or any(part in normalized for part in SENSITIVE_KEY_PARTS)
    )


def _bounded_int(
    value: Any,
    *,
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"{name} 必须是整数", code="invalid_settings")
    parsed = int(value)
    if parsed != value or not minimum <= parsed <= maximum:
        raise PolicyError(
            f"{name} 必须在 {minimum} 到 {maximum} 之间",
            code="invalid_settings",
        )
    return parsed


def _bounded_float(
    value: Any,
    *,
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"{name} 必须是数字", code="invalid_settings")
    parsed = float(value)
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise PolicyError(
            f"{name} 必须在 {minimum:g} 到 {maximum:g} 之间",
            code="invalid_settings",
        )
    return parsed


def _strict_bool(value: Any, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise PolicyError(f"{name} 必须是布尔值", code="invalid_settings")
    return value


def _is_explicit_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_base_url(base_url: str, allow_remote: bool = False) -> str:
    """Validate and normalize a HAPI base URL without making DNS requests."""

    if not isinstance(base_url, str):
        raise PolicyError("HAPI 地址必须是字符串", code="invalid_url")
    candidate = base_url.strip()
    if candidate != base_url or any(ord(character) <= 32 or ord(character) == 127 for character in base_url):
        raise PolicyError("HAPI 地址不能包含空白或控制字符", code="invalid_url")
    if not candidate or len(candidate) > 2048:
        raise PolicyError("HAPI 地址为空或过长", code="invalid_url")
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise PolicyError("HAPI 地址格式无效", code="invalid_url") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise PolicyError("HAPI 地址只允许 http 或 https", code="invalid_url")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise PolicyError("HAPI 地址不能包含凭据，且必须包含主机名", code="invalid_url")
    if parsed.query or parsed.fragment:
        raise PolicyError("HAPI 地址不能包含查询参数或片段", code="invalid_url")
    if parsed.path not in {"", "/"}:
        raise PolicyError("HAPI 地址不能包含路径", code="invalid_url")
    try:
        port = parsed.port
    except ValueError as exc:
        raise PolicyError("HAPI 地址端口无效", code="invalid_url") from exc
    if port is not None and not 1 <= port <= 65_535:
        raise PolicyError("HAPI 地址端口无效", code="invalid_url")
    loopback = _is_explicit_loopback(parsed.hostname)
    if not loopback and not allow_remote:
        raise PolicyError(
            "非本机 HAPI 地址需要在面板中明确启用远程端点",
            code="remote_opt_in_required",
        )
    if not loopback and parsed.scheme.lower() != "https":
        raise PolicyError(
            "非本机 HAPI 地址必须使用 HTTPS，避免令牌在网络中明文传输",
            code="remote_https_required",
        )
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", "")).rstrip("/")


def _normalize_roots(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        if len(value) > 131_072:
            raise PolicyError("工作区根目录设置过长", code="invalid_settings")
        values: Sequence[Any] = value.splitlines()
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        raise PolicyError("允许的工作区根目录必须是列表", code="invalid_settings")
    if len(values) > 32:
        raise PolicyError("最多可配置 32 个工作区根目录", code="invalid_settings")
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise PolicyError("工作区根目录必须是字符串", code="invalid_settings")
        item = item.strip()
        if not item:
            continue
        if "\x00" in item or len(item) > 4096:
            raise PolicyError("工作区根目录无效", code="invalid_workspace")
        path = Path(item)
        if not path.is_absolute():
            raise PolicyError("工作区根目录必须是绝对路径", code="invalid_workspace")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PolicyError("工作区根目录不存在或无法访问", code="invalid_workspace") from exc
        if not resolved.is_dir():
            raise PolicyError("工作区根目录必须是目录", code="invalid_workspace")
        normalized = str(resolved)
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    if len(result) > 32:
        raise PolicyError("最多可配置 32 个工作区根目录", code="invalid_settings")
    return tuple(result)


def canonical_workspace(path_value: str, allowed_roots: Sequence[str]) -> str:
    """Return a canonical allowed directory or reject traversal/symlink escape."""

    if not isinstance(path_value, str):
        raise PolicyError("工作目录必须是字符串", code="invalid_workspace")
    raw = path_value
    if raw != raw.strip():
        raise PolicyError("工作目录不能包含首尾空白", code="invalid_workspace")
    if not raw or "\x00" in raw or len(raw) > 4096:
        raise PolicyError("工作目录为空或无效", code="invalid_workspace")
    path = Path(raw)
    if not path.is_absolute():
        raise PolicyError("工作目录必须是绝对路径", code="invalid_workspace")
    if ".." in PurePath(raw).parts:
        raise PolicyError("工作目录不能包含 .. 路径段", code="workspace_traversal")
    if not allowed_roots:
        raise PolicyError(
            "尚未配置允许的工作区根目录，执行功能保持禁用",
            code="workspace_roots_required",
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PolicyError("工作目录不存在或无法访问", code="invalid_workspace") from exc
    if not resolved.is_dir():
        raise PolicyError("工作目录必须是现有目录", code="invalid_workspace")

    canonical_roots: list[Path] = []
    for root in allowed_roots:
        stored_root = Path(root)
        try:
            root_path = stored_root.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        # Settings persist already-canonical roots.  If an allowed root or
        # one of its ancestors is later replaced by a symlink, resolving the
        # same lexical string must not silently authorize the new target.
        if root_path == stored_root and root_path.is_dir():
            canonical_roots.append(root_path)
    for root in canonical_roots:
        if resolved == root or root in resolved.parents:
            return str(resolved)
    raise PolicyError(
        "工作目录不在允许的根目录内，或符号链接逃逸了根目录",
        code="workspace_not_allowed",
    )


def validate_identifier(value: Any, *, kind: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{kind} 必须是字符串", code="invalid_identifier")
    normalized = value.strip()
    if (
        not normalized
        or normalized != value
        or len(normalized) > maximum
        or normalized in {".", ".."}
        or SAFE_IDENTIFIER_RE.fullmatch(normalized) is None
    ):
        raise PolicyError(f"{kind} 无效", code="invalid_identifier")
    return normalized


def redact_sensitive(value: Any, *, max_string: int = 512, depth: int = 0) -> Any:
    """Recursively redact secret-shaped values and keep the result bounded."""

    if depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 64:
                result["_truncated"] = True
                break
            sensitive = is_sensitive_key(key)
            text_key = str(key)[:128]
            if sensitive:
                result[text_key] = "[REDACTED]"
            else:
                result[text_key] = redact_sensitive(
                    item,
                    max_string=max_string,
                    depth=depth + 1,
                )
        return result
    if isinstance(value, (list, tuple)):
        return [
            redact_sensitive(item, max_string=max_string, depth=depth + 1)
            for item in value[:64]
        ]
    if isinstance(value, str):
        return value if len(value) <= max_string else value[:max_string] + "…"
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(type(value).__name__)


@dataclass(frozen=True, slots=True)
class ConnectorSettings:
    """Validated persisted configuration.

    The credential is intentionally not a field.  It is stored under a separate
    PluginStore key and is never returned by :meth:`to_public`.
    """

    base_url: str = "http://127.0.0.1:3006"
    auth_mode: str = "access_token"
    allow_remote: bool = False
    allowed_workspace_roots: tuple[str, ...] = ()
    allowed_providers: tuple[str, ...] = ("claude", "codex", "opencode")
    allow_create: bool = False
    allow_send: bool = False
    allow_stop: bool = False
    allow_approval: bool = False
    timeout_seconds: float = 15.0
    sse_enabled: bool = False
    sse_reconnect_delay: float = 5.0
    notifications_enabled: bool = False
    notification_ai_behavior: str = "read"
    notification_visibility: tuple[str, ...] = ("hud",)
    max_response_size: int = 262_144
    max_instruction_chars: int = 8_000
    max_output_chars: int = 12_000
    max_concurrency: int = 3
    rate_limit_per_minute: int = 20
    max_recent_events: int = 100
    max_recent_sessions: int = 50
    auto_approve: bool = False

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "ConnectorSettings":
        if raw is not None and not isinstance(raw, Mapping):
            raise PolicyError("设置必须是对象", code="invalid_settings")
        data = dict(raw or {})
        if len(data) > 64:
            raise PolicyError("设置字段过多", code="invalid_settings")
        if any(not isinstance(key, str) or len(key) > 128 for key in data):
            raise PolicyError("设置字段名无效", code="invalid_settings")
        known = {item.name for item in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise PolicyError(
                "设置包含不支持的字段",
                code="invalid_settings",
            )
        allow_remote = _strict_bool(
            data.get("allow_remote"),
            name="allow_remote",
            default=False,
        )
        base_url = validate_base_url(
            data.get("base_url", DEFAULT_BASE_URL),
            allow_remote=allow_remote,
        )
        auth_mode = data.get("auth_mode", DEFAULT_AUTH_MODE)
        if not isinstance(auth_mode, str) or auth_mode not in SUPPORTED_AUTH_MODES:
            raise PolicyError("auth_mode 必须是 access_token 或 bearer", code="invalid_settings")

        providers_raw = data.get("allowed_providers", DEFAULT_PROVIDERS)
        if isinstance(providers_raw, str):
            if len(providers_raw) > 256:
                raise PolicyError("allowed_providers 字段过长", code="invalid_settings")
            providers_raw = [item.strip() for item in providers_raw.split(",") if item.strip()]
        if not isinstance(providers_raw, (list, tuple)):
            raise PolicyError("allowed_providers 必须是列表", code="invalid_settings")
        if len(providers_raw) > 32:
            raise PolicyError("allowed_providers 字段过多", code="invalid_settings")
        providers: list[str] = []
        for provider in providers_raw:
            if not isinstance(provider, str) or provider.lower() not in SUPPORTED_PROVIDERS:
                raise PolicyError("提供商只允许 claude、codex、opencode", code="provider_not_allowed")
            normalized = provider.lower()
            if normalized not in providers:
                providers.append(normalized)

        behavior = data.get("notification_ai_behavior", DEFAULT_NOTIFICATION_BEHAVIOR)
        if not isinstance(behavior, str) or behavior not in SUPPORTED_AI_BEHAVIORS:
            raise PolicyError("通知 AI 行为无效", code="invalid_settings")
        visibility_raw = data.get(
            "notification_visibility",
            DEFAULT_NOTIFICATION_VISIBILITY,
        )
        if isinstance(visibility_raw, str):
            visibility_raw = [visibility_raw]
        if not isinstance(visibility_raw, (list, tuple)):
            raise PolicyError("通知可见性必须是列表", code="invalid_settings")
        if len(visibility_raw) > 2:
            raise PolicyError("通知可见性无效", code="invalid_settings")
        visibility: list[str] = []
        for item in visibility_raw:
            if not isinstance(item, str) or item not in SUPPORTED_VISIBILITY:
                raise PolicyError("通知可见性只允许 chat 或 hud", code="invalid_settings")
            if item not in visibility:
                visibility.append(item)
        if len(visibility) > 2:
            raise PolicyError("通知可见性无效", code="invalid_settings")

        auto_approve = data.get("auto_approve", False)
        if auto_approve is not False:
            raise PolicyError("危险权限自动批准始终关闭", code="auto_approve_forbidden")

        return cls(
            base_url=base_url,
            auth_mode=auth_mode,
            allow_remote=allow_remote,
            allowed_workspace_roots=_normalize_roots(data.get("allowed_workspace_roots")),
            allowed_providers=tuple(providers),
            allow_create=_strict_bool(data.get("allow_create"), name="allow_create", default=False),
            allow_send=_strict_bool(data.get("allow_send"), name="allow_send", default=False),
            allow_stop=_strict_bool(data.get("allow_stop"), name="allow_stop", default=False),
            allow_approval=_strict_bool(
                data.get("allow_approval"),
                name="allow_approval",
                default=False,
            ),
            timeout_seconds=_bounded_float(
                data.get("timeout_seconds"),
                name="timeout_seconds",
                default=15.0,
                minimum=1.0,
                maximum=30.0,
            ),
            sse_enabled=_strict_bool(data.get("sse_enabled"), name="sse_enabled", default=False),
            sse_reconnect_delay=_bounded_float(
                data.get("sse_reconnect_delay"),
                name="sse_reconnect_delay",
                default=5.0,
                minimum=0.25,
                maximum=120.0,
            ),
            notifications_enabled=_strict_bool(
                data.get("notifications_enabled"),
                name="notifications_enabled",
                default=False,
            ),
            notification_ai_behavior=behavior,
            notification_visibility=tuple(visibility),
            max_response_size=_bounded_int(
                data.get("max_response_size"),
                name="max_response_size",
                default=262_144,
                minimum=16_384,
                maximum=2_097_152,
            ),
            max_instruction_chars=_bounded_int(
                data.get("max_instruction_chars"),
                name="max_instruction_chars",
                default=8_000,
                minimum=256,
                maximum=32_000,
            ),
            max_output_chars=_bounded_int(
                data.get("max_output_chars"),
                name="max_output_chars",
                default=12_000,
                minimum=1_000,
                maximum=64_000,
            ),
            max_concurrency=_bounded_int(
                data.get("max_concurrency"),
                name="max_concurrency",
                default=3,
                minimum=1,
                maximum=10,
            ),
            rate_limit_per_minute=_bounded_int(
                data.get("rate_limit_per_minute"),
                name="rate_limit_per_minute",
                default=20,
                minimum=1,
                maximum=120,
            ),
            max_recent_events=_bounded_int(
                data.get("max_recent_events"),
                name="max_recent_events",
                default=100,
                minimum=10,
                maximum=500,
            ),
            max_recent_sessions=_bounded_int(
                data.get("max_recent_sessions"),
                name="max_recent_sessions",
                default=50,
                minimum=5,
                maximum=100,
            ),
            auto_approve=False,
        )

    def to_store(self) -> dict[str, Any]:
        data = asdict(self)
        data["allowed_workspace_roots"] = list(self.allowed_workspace_roots)
        data["allowed_providers"] = list(self.allowed_providers)
        data["notification_visibility"] = list(self.notification_visibility)
        return data

    def to_public(self) -> dict[str, Any]:
        return self.to_store()


class SecurityPolicy:
    """Runtime policy gate shared by entries and the background listener."""

    def __init__(self, settings: ConnectorSettings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._calls: deque[float] = deque()
        self._active = 0

    @property
    def settings(self) -> ConnectorSettings:
        return self._settings

    def update(self, settings: ConnectorSettings) -> None:
        with self._lock:
            self._settings = settings
            while len(self._calls) > settings.rate_limit_per_minute:
                self._calls.popleft()

    def validate_provider(self, provider: Any) -> str:
        if not isinstance(provider, str):
            raise PolicyError("提供商必须是字符串", code="provider_not_allowed")
        if provider != provider.strip():
            raise PolicyError("提供商不能包含首尾空白", code="provider_not_allowed")
        normalized = provider.strip().lower()
        if (
            normalized not in SUPPORTED_PROVIDERS
            or normalized not in self._settings.allowed_providers
        ):
            raise PolicyError("该 Vibe Coding 提供商未获允许", code="provider_not_allowed")
        return normalized

    def validate_workspace(self, path: str) -> str:
        return canonical_workspace(path, self._settings.allowed_workspace_roots)

    def validate_instruction(self, instruction: Any) -> str:
        if not isinstance(instruction, str):
            raise PolicyError("开发指令必须是字符串", code="invalid_instruction")
        normalized = instruction.strip()
        if not normalized:
            raise PolicyError("开发指令不能为空", code="invalid_instruction")
        if len(normalized) > self._settings.max_instruction_chars:
            raise PolicyError(
                f"开发指令超过 {self._settings.max_instruction_chars} 个字符",
                code="instruction_too_large",
            )
        return normalized

    def require_tool(self, tool: str) -> None:
        flags = {
            "create": self._settings.allow_create,
            "send": self._settings.allow_send,
            "stop": self._settings.allow_stop,
            "approval": self._settings.allow_approval,
        }
        if tool not in flags:
            raise PolicyError("未知工具策略", code="tool_disabled")
        if not flags[tool]:
            raise PolicyError(f"{tool} 工具已在管理面板中禁用", code="tool_disabled")

    @asynccontextmanager
    async def permit(self) -> AsyncIterator[None]:
        now = time.monotonic()
        with self._lock:
            cutoff = now - 60.0
            while self._calls and self._calls[0] <= cutoff:
                self._calls.popleft()
            if len(self._calls) >= self._settings.rate_limit_per_minute:
                raise PolicyError("请求过于频繁，请稍后重试", code="rate_limited")
            if self._active >= self._settings.max_concurrency:
                raise PolicyError("并发请求已达到安全上限", code="concurrency_limited")
            self._calls.append(now)
            self._active += 1
        try:
            yield
        finally:
            with self._lock:
                self._active = max(0, self._active - 1)
