"""Secure, provider-portable image generation for N.E.K.O.

The plugin talks to an OpenAI-compatible Images API, persists its credential
and mutable settings in PluginStore, and exposes generated files through a
bounded writable copy of the plugin's static UI.  Chat delivery is deliberately
text-only Markdown: the current host renders Markdown image links in blind chat
passthroughs, while URL image parts are not rendered on that path.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, quote, urljoin, urlparse
from uuid import uuid4

import httpx

from plugin.sdk.plugin import (
    Err,
    NekoPluginBase,
    Ok,
    SdkError,
    lifecycle,
    llm_tool,
    neko_plugin,
    plugin_entry,
)

PLUGIN_VERSION = "0.1.0"
USER_AGENT = (
    f"N.E.K.O-Image-Generator/{PLUGIN_VERSION} "
    "(+https://github.com/Project-N-E-K-O/N.E.K.O)"
)

_DEFAULT_PLUGIN_SERVER_PORT = 48916
_SETTINGS_STORE_KEY = "settings"
_API_KEY_STORE_KEY = "api_key"
_HISTORY_STORE_KEY = "recent_generations"
_GENERATED_SUBDIR = "generated"

_PROMPT_MAX_CHARS = 4_000
_PROMPT_EXCERPT_MAX_CHARS = 180
_REVISED_PROMPT_MAX_CHARS = 2_000
_MODEL_MAX_CHARS = 128
_URL_MAX_CHARS = 4_096
_API_KEY_MAX_CHARS = 4_096
_MAX_REDIRECTS = 3

DEFAULT_SETTINGS: dict[str, Any] = {
    "api_base_url": "https://api.openai.com/v1",
    "model": "gpt-image-1",
    "default_size": "1024x1024",
    "default_quality": "auto",
    "default_style": "",
    "allowed_sizes": [
        "auto",
        "1024x1024",
        "1536x1024",
        "1024x1536",
        "1792x1024",
        "1024x1792",
        "512x512",
        "256x256",
    ],
    "allowed_qualities": ["auto", "standard", "hd", "low", "medium", "high"],
    "allowed_styles": ["", "auto", "vivid", "natural"],
    # Exact OpenAI image file format; "auto" lets the provider choose.
    "output_format": "auto",
    # Compatibility transport selector. "auto" accepts URL or Base64 output.
    "response_format": "auto",
    "timeout_seconds": 120.0,
    "max_download_bytes": 20 * 1024 * 1024,
    "cache_max_count": 20,
    "cache_max_bytes": 100 * 1024 * 1024,
    "history_limit": 30,
    "auto_show_in_chat": True,
}

GENERATE_IMAGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "prompt": {
            "type": "string",
            "minLength": 1,
            "maxLength": _PROMPT_MAX_CHARS,
            "description": (
                "要生成的图片描述。保留用户要求的主体、构图、氛围、文字和风格；"
                "过长内容会安全截断。"
            ),
        },
        "size": {
            "type": "string",
            "maxLength": 32,
            "description": "可选尺寸；必须属于管理面板配置的允许尺寸列表。",
        },
        "quality": {
            "type": "string",
            "maxLength": 32,
            "description": "可选质量；必须属于管理面板配置的允许质量列表。",
        },
        "style": {
            "type": "string",
            "maxLength": 32,
            "description": "可选风格；必须属于管理面板配置的允许风格列表。",
        },
    },
    "required": ["prompt"],
    "additionalProperties": False,
}

_EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

_RECENT_HISTORY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "default": 20,
        }
    },
    "additionalProperties": False,
}

_TEST_GENERATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "prompt": {
            "type": "string",
            "minLength": 1,
            "maxLength": _PROMPT_MAX_CHARS,
            "description": "用于付费测试生成的提示词。",
        }
    },
    "required": ["prompt"],
    "additionalProperties": False,
}

_SAVE_SETTINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "api_base_url": {"type": "string", "maxLength": _URL_MAX_CHARS},
        "api_key": {
            "type": "string",
            "maxLength": _API_KEY_MAX_CHARS,
            "description": "留空保留原密钥；此值只会写入 PluginStore。",
        },
        "clear_api_key": {"type": "boolean", "default": False},
        "model": {"type": "string", "maxLength": _MODEL_MAX_CHARS},
        "default_size": {"type": "string", "maxLength": 32},
        "default_quality": {"type": "string", "maxLength": 32},
        "default_style": {"type": "string", "maxLength": 32},
        "allowed_sizes": {
            "type": "array",
            "items": {"type": "string", "maxLength": 32},
            "minItems": 1,
            "maxItems": 24,
        },
        "allowed_qualities": {
            "type": "array",
            "items": {"type": "string", "maxLength": 32},
            "minItems": 1,
            "maxItems": 24,
        },
        "allowed_styles": {
            "type": "array",
            "items": {"type": "string", "maxLength": 32},
            "minItems": 1,
            "maxItems": 24,
        },
        "output_format": {
            "type": "string",
            "enum": ["auto", "png", "jpeg", "webp"],
        },
        "response_format": {
            "type": "string",
            "enum": ["auto", "url", "b64_json"],
        },
        "timeout_seconds": {"type": "number", "minimum": 5, "maximum": 240},
        "max_download_bytes": {
            "type": "integer",
            "minimum": 1024,
            "maximum": 52_428_800,
        },
        "cache_max_count": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
        },
        "cache_max_bytes": {
            "type": "integer",
            "minimum": 1024,
            "maximum": 1_073_741_824,
        },
        "history_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
        },
        "auto_show_in_chat": {"type": "boolean"},
    },
    "required": [
        "api_base_url",
        "model",
        "default_size",
        "default_quality",
        "default_style",
        "allowed_sizes",
        "allowed_qualities",
        "allowed_styles",
        "output_format",
        "response_format",
        "timeout_seconds",
        "max_download_bytes",
        "cache_max_count",
        "cache_max_bytes",
        "history_limit",
        "auto_show_in_chat",
    ],
    "additionalProperties": False,
}

_SIZE_PATTERN = re.compile(r"^(?:auto|[1-9][0-9]{1,4}x[1-9][0-9]{1,4})$")
_OPTION_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,127}$")
_GENERATED_FILE_PATTERN = re.compile(r"^[0-9a-f]{32}\.(?:png|jpg|gif|webp)$")
_GENERATED_TEMP_FILE_PATTERN = re.compile(
    r"^\.[0-9a-f]{32}\.(?:png|jpg|gif|webp)\.[0-9a-f]{32}\.tmp$"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}")
_KEY_LIKE_PATTERN = re.compile(r"(?i)\bsk-[A-Za-z0-9_\-]{8,}")
_CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class _GenerationFailure(Exception):
    """Internal exception carrying only a pre-sanitized user message."""

    def __init__(self, message: str, failure_class: str):
        super().__init__(message)
        self.message = message
        self.failure_class = failure_class


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _clean_text(
    value: Any,
    *,
    label: str,
    max_chars: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise SdkError(f"{label}必须是文本")
    cleaned = _CONTROL_PATTERN.sub(" ", value).strip()
    if not cleaned and not allow_empty:
        raise SdkError(f"{label}不能为空")
    return cleaned[:max_chars]


def _redact_text(value: Any, api_key: str = "", *, max_chars: int) -> str:
    text = str(value or "")
    if api_key:
        text = text.replace(api_key, "[REDACTED]")
    text = _BEARER_PATTERN.sub("Bearer [REDACTED]", text)
    text = _KEY_LIKE_PATTERN.sub("[REDACTED]", text)
    text = _CONTROL_PATTERN.sub(" ", text).strip()
    return text[:max_chars]


def _validate_api_key(value: Any) -> str:
    key = _clean_text(
        value,
        label="API 密钥",
        max_chars=_API_KEY_MAX_CHARS,
    )
    if len(key) < 8:
        raise SdkError("API 密钥长度过短")
    if any(ch.isspace() for ch in key):
        raise SdkError("API 密钥不能包含空白字符")
    return key


def _settings_contain_secret(
    settings: Mapping[str, Any],
    secret: str,
) -> bool:
    if not secret:
        return False
    for value in settings.values():
        if isinstance(value, str) and secret in value:
            return True
        if isinstance(value, list) and any(
            isinstance(item, str) and secret in item for item in value
        ):
            return True
    return False


def _api_key_hint(api_key: str) -> str | None:
    if not api_key:
        return None
    suffix = "".join(
        char if char.isascii() and (char.isalnum() or char in {"-", "_"}) else "•"
        for char in api_key[-4:]
    )
    return f"••••{suffix}"


def _parse_http_url(value: str) -> ParseResult | None:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    del port
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return parsed


def _normalize_api_base_url(value: Any) -> str:
    if not isinstance(value, str):
        raise SdkError("API Base URL 必须是文本")
    if len(value) > _URL_MAX_CHARS:
        raise SdkError(f"API Base URL 不能超过 {_URL_MAX_CHARS} 个字符")
    text = _clean_text(
        value,
        label="API Base URL",
        max_chars=_URL_MAX_CHARS,
    )
    parsed = _parse_http_url(text)
    if parsed is None or parsed.query or parsed.fragment or parsed.params:
        raise SdkError("API Base URL 必须是无账号、查询参数或片段的 http(s) 地址")
    path = parsed.path.rstrip("/")
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        path=path,
        params="",
        query="",
        fragment="",
    ).geturl()
    return normalized.rstrip("/")


def _validate_output_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > _URL_MAX_CHARS:
        raise _GenerationFailure(
            "图片服务返回的图片地址过长或格式无效",
            "UnsafeImageUrl",
        )
    text = _clean_text(
        value,
        label="图片 URL",
        max_chars=_URL_MAX_CHARS,
    )
    parsed = _parse_http_url(text)
    if parsed is None or parsed.fragment:
        raise _GenerationFailure(
            "图片服务返回了不安全或无效的图片地址",
            "UnsafeImageUrl",
        )
    return text


def _origin_tuple(url: str) -> tuple[str, str, int | None] | None:
    parsed = _parse_http_url(url)
    if parsed is None:
        return None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return (
        parsed.scheme.lower(),
        str(parsed.hostname or "").lower(),
        parsed.port or default_port,
    )


def _is_public_unicast_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return (
        ip.is_global
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_private
        and not ip.is_unspecified
    )


def _url_resolves_to_public_unicast(url: str) -> bool:
    parsed = _parse_http_url(url)
    if parsed is None:
        return False
    hostname = str(parsed.hostname or "").strip().lower()
    if not hostname or hostname == "localhost" or hostname.endswith(".localhost"):
        return False
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        return _is_public_unicast_ip(literal)

    try:
        records = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except Exception:
        return False
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _family, _socktype, _proto, _canonname, sockaddr in records:
        try:
            addresses.append(ipaddress.ip_address(sockaddr[0]))
        except (ValueError, TypeError):
            return False
    return bool(addresses) and all(_is_public_unicast_ip(ip) for ip in addresses)


def _normalize_option_list(
    value: Any,
    *,
    label: str,
    allow_empty: bool,
    size_values: bool = False,
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, list):
        raise SdkError(f"{label}必须是数组")
    if not 1 <= len(value) <= 24:
        raise SdkError(f"{label}必须包含 1 到 24 项")
    normalized: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise SdkError(f"{label}只能包含文本")
        item = raw.strip().lower()
        if not item and not allow_empty:
            raise SdkError(f"{label}不能包含空值")
        if item:
            if size_values:
                if not _SIZE_PATTERN.fullmatch(item):
                    raise SdkError(f"{label}包含无效尺寸：{item[:32]}")
                if item != "auto":
                    width, height = (int(part) for part in item.split("x", 1))
                    if width > 8192 or height > 8192:
                        raise SdkError("允许尺寸不能超过 8192x8192")
            elif not _OPTION_PATTERN.fullmatch(item):
                raise SdkError(f"{label}包含无效选项：{item[:32]}")
        if item not in normalized:
            normalized.append(item)
    if not normalized:
        raise SdkError(f"{label}不能为空")
    return normalized


def _bounded_int(
    value: Any,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SdkError(f"{label}必须是整数")
    if not minimum <= value <= maximum:
        raise SdkError(f"{label}必须在 {minimum} 到 {maximum} 之间")
    return value


def _bounded_float(
    value: Any,
    *,
    label: str,
    minimum: float,
    maximum: float,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise SdkError(f"{label}必须是有效数字")
    result = float(value)
    if not minimum <= result <= maximum:
        raise SdkError(f"{label}必须在 {minimum:g} 到 {maximum:g} 之间")
    return result


def _validate_settings(
    raw: Any,
    *,
    base: Mapping[str, Any],
    require_all: bool,
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise SdkError("设置必须是对象")

    known = set(DEFAULT_SETTINGS)
    unknown = sorted(str(key) for key in raw if key not in known)
    if unknown:
        raise SdkError(f"包含未知设置：{', '.join(unknown)}")
    if require_all:
        missing = sorted(known.difference(raw))
        if missing:
            raise SdkError(f"缺少设置：{', '.join(missing)}")

    result = {
        key: (list(value) if isinstance(value, list) else value)
        for key, value in base.items()
    }

    if "api_base_url" in raw:
        result["api_base_url"] = _normalize_api_base_url(raw["api_base_url"])
    if "model" in raw:
        model = _clean_text(
            raw["model"],
            label="模型",
            max_chars=_MODEL_MAX_CHARS,
        )
        if not _MODEL_PATTERN.fullmatch(model):
            raise SdkError("模型名称包含不支持的字符")
        result["model"] = model

    if "allowed_sizes" in raw:
        result["allowed_sizes"] = _normalize_option_list(
            raw["allowed_sizes"],
            label="允许尺寸",
            allow_empty=False,
            size_values=True,
        )
    if "allowed_qualities" in raw:
        result["allowed_qualities"] = _normalize_option_list(
            raw["allowed_qualities"],
            label="允许质量",
            allow_empty=False,
        )
    if "allowed_styles" in raw:
        result["allowed_styles"] = _normalize_option_list(
            raw["allowed_styles"],
            label="允许风格",
            allow_empty=True,
        )

    for field, label, allow_empty in (
        ("default_size", "默认尺寸", False),
        ("default_quality", "默认质量", False),
        ("default_style", "默认风格", True),
    ):
        if field not in raw:
            continue
        value = _clean_text(
            raw[field],
            label=label,
            max_chars=32,
            allow_empty=allow_empty,
        ).lower()
        if field == "default_size":
            if not _SIZE_PATTERN.fullmatch(value):
                raise SdkError("默认尺寸格式无效")
        elif value and not _OPTION_PATTERN.fullmatch(value):
            raise SdkError(f"{label}格式无效")
        result[field] = value

    if "output_format" in raw:
        output_format = _clean_text(
            raw["output_format"],
            label="输出格式",
            max_chars=16,
        ).lower()
        if output_format not in {"auto", "png", "jpeg", "webp"}:
            raise SdkError("图片输出格式必须是 auto、png、jpeg 或 webp")
        result["output_format"] = output_format
    if "response_format" in raw:
        response_format = _clean_text(
            raw["response_format"],
            label="响应格式",
            max_chars=16,
        ).lower()
        if response_format not in {"auto", "url", "b64_json"}:
            raise SdkError("响应格式必须是 auto、url 或 b64_json")
        result["response_format"] = response_format

    if "timeout_seconds" in raw:
        result["timeout_seconds"] = _bounded_float(
            raw["timeout_seconds"],
            label="超时秒数",
            minimum=5,
            maximum=240,
        )
    if "max_download_bytes" in raw:
        result["max_download_bytes"] = _bounded_int(
            raw["max_download_bytes"],
            label="最大下载字节数",
            minimum=1024,
            maximum=52_428_800,
        )
    if "cache_max_count" in raw:
        result["cache_max_count"] = _bounded_int(
            raw["cache_max_count"],
            label="缓存文件上限",
            minimum=1,
            maximum=100,
        )
    if "cache_max_bytes" in raw:
        result["cache_max_bytes"] = _bounded_int(
            raw["cache_max_bytes"],
            label="缓存总字节上限",
            minimum=1024,
            maximum=1_073_741_824,
        )
    if "history_limit" in raw:
        result["history_limit"] = _bounded_int(
            raw["history_limit"],
            label="历史记录上限",
            minimum=1,
            maximum=100,
        )
    if "auto_show_in_chat" in raw:
        if not isinstance(raw["auto_show_in_chat"], bool):
            raise SdkError("自动显示开关必须是布尔值")
        result["auto_show_in_chat"] = raw["auto_show_in_chat"]

    for default_field, allowed_field, label in (
        ("default_size", "allowed_sizes", "默认尺寸"),
        ("default_quality", "allowed_qualities", "默认质量"),
        ("default_style", "allowed_styles", "默认风格"),
    ):
        if result[default_field] not in result[allowed_field]:
            raise SdkError(f"{label}必须包含在对应允许列表中")
    if result["cache_max_bytes"] < result["max_download_bytes"]:
        raise SdkError("缓存总字节上限不能小于单张图片下载上限")
    return result


def _normalize_manifest_settings(raw: Any) -> dict[str, Any]:
    defaults = {
        key: (list(value) if isinstance(value, list) else value)
        for key, value in DEFAULT_SETTINGS.items()
    }
    if raw is None:
        return defaults
    # Validate the subsection as one unit so coupled changes such as a new
    # default size plus its matching allowlist are accepted together.
    return _validate_settings(
        raw,
        base=defaults,
        require_all=False,
    )


def _image_type(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "image/jpeg", "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", "gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", "webp"
    raise _GenerationFailure(
        "图片服务返回的内容不是受支持的 PNG、JPEG、GIF 或 WebP 图片",
        "InvalidImageData",
    )


def _decode_b64_image(value: Any, *, max_bytes: int) -> tuple[bytes, str, str]:
    if not isinstance(value, str) or not value.strip():
        raise _GenerationFailure(
            "图片服务返回了空的 Base64 图片",
            "MalformedResponse",
        )
    encoded = value.strip()
    max_encoded_chars = ((max_bytes + 2) // 3) * 4 + 4
    # Bound the raw string before whitespace normalization, which otherwise
    # creates a second potentially large copy. OpenAI-compatible b64_json is
    # normally unwrapped; the small allowance covers a data-URL prefix and
    # incidental surrounding whitespace.
    if len(encoded) > max_encoded_chars + 4_096:
        raise _GenerationFailure(
            "生成图片超过了配置的最大字节数",
            "ImageTooLarge",
        )
    if encoded.startswith("data:"):
        match = re.match(
            r"^data:image/(?:png|jpeg|jpg|gif|webp);base64,",
            encoded,
            flags=re.IGNORECASE,
        )
        if match is None:
            raise _GenerationFailure(
                "图片服务返回了不支持的数据 URL",
                "MalformedResponse",
            )
        encoded = encoded[match.end() :]
    encoded = "".join(encoded.split())
    if len(encoded) > max_encoded_chars:
        raise _GenerationFailure(
            "生成图片超过了配置的最大字节数",
            "ImageTooLarge",
        )
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise _GenerationFailure(
            "图片服务返回了无效的 Base64 图片",
            "InvalidBase64",
        ) from None
    if len(decoded) > max_bytes:
        raise _GenerationFailure(
            "生成图片超过了配置的最大字节数",
            "ImageTooLarge",
        )
    mime, extension = _image_type(decoded)
    return decoded, mime, extension


def _safe_history_record(
    value: Any,
    api_key: str = "",
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    status = value.get("status")
    if status not in {"succeeded", "failed"}:
        return None
    record_id = _redact_text(
        value.get("id"),
        api_key,
        max_chars=32,
    )
    timestamp = _redact_text(
        value.get("timestamp"),
        api_key,
        max_chars=40,
    )
    model = _redact_text(
        value.get("model"),
        api_key,
        max_chars=_MODEL_MAX_CHARS,
    )
    prompt_excerpt = _redact_text(
        value.get("prompt_excerpt"),
        api_key,
        max_chars=_PROMPT_EXCERPT_MAX_CHARS,
    )
    result_url = _redact_text(
        value.get("result_url"),
        api_key,
        max_chars=_URL_MAX_CHARS,
    )
    if not record_id or not timestamp or not model:
        return None
    if result_url and _parse_http_url(result_url) is None:
        result_url = ""
    return {
        "id": record_id,
        "timestamp": timestamp,
        "model": model,
        "prompt_excerpt": prompt_excerpt,
        "result_url": result_url,
        "status": status,
    }


def _new_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    )


def _atomic_write_bytes(temp_path: Path, target_path: Path, data: bytes) -> None:
    with temp_path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, target_path)


@neko_plugin
class ImageGeneratorPlugin(NekoPluginBase):
    """Generate images from normal chat or the management panel."""

    def __init__(self, ctx: Any):
        super().__init__(ctx)
        self._state_lock = threading.Lock()
        self._client_lock = threading.Lock()
        self._history_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._settings_update_lock = threading.Lock()
        self._manifest_settings = {
            key: (list(value) if isinstance(value, list) else value)
            for key, value in DEFAULT_SETTINGS.items()
        }
        self._settings = dict(self._manifest_settings)
        self._running = False
        self._api_state = "idle"
        self._configuration_warning: str | None = None
        self._last_request: dict[str, Any] = {
            "status": "not_requested",
            "time": None,
            "action": None,
            "failure_class": None,
        }
        self._client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None
        self._retired_clients: list[httpx.AsyncClient] = []
        self._writable_ui_dir: Path | None = None
        self._asset_dir: Path | None = None

    # ------------------------------------------------------------------
    # Lifecycle, Store, and loop-local HTTP client
    # ------------------------------------------------------------------

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        try:
            config = await self.config.dump(timeout=5.0)
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator config load failed: failure_class={}",
                type(exc).__name__,
            )
            config = {}

        plugin_section = config.get("plugin") if isinstance(config, Mapping) else None
        store_section = (
            plugin_section.get("store") if isinstance(plugin_section, Mapping) else None
        )
        if (
            isinstance(store_section, Mapping)
            and store_section.get("enabled") is True
            and not bool(getattr(self.store, "enabled", False))
        ):
            self.store.enabled = True
            self.logger.info("ImageGenerator store enabled from effective config")

        raw_defaults = (
            config.get("image_generator") if isinstance(config, Mapping) else None
        )
        configuration_warning: str | None = None
        try:
            manifest_settings = _normalize_manifest_settings(raw_defaults)
        except SdkError:
            manifest_settings = {
                key: (list(value) if isinstance(value, list) else value)
                for key, value in DEFAULT_SETTINGS.items()
            }
            configuration_warning = "plugin.toml 中的图片生成设置无效，已使用安全默认值"
            self.logger.warning(
                "ImageGenerator manifest settings ignored: "
                "failure_class=ValidationError"
            )
        stored_settings = await self._store_get(_SETTINGS_STORE_KEY, None)
        effective_settings = manifest_settings
        if stored_settings is not None:
            try:
                effective_settings = _validate_settings(
                    stored_settings,
                    base=manifest_settings,
                    require_all=False,
                )
            except SdkError:
                configuration_warning = "已保存的图片生成设置无效，已使用安全默认值"
                self.logger.warning(
                    "ImageGenerator stored settings ignored: "
                    "failure_class=ValidationError"
                )

        with self._state_lock:
            self._manifest_settings = manifest_settings
            self._settings = effective_settings
            self._configuration_warning = configuration_warning
            self._running = True

        ui_registered = self._register_writable_static_ui()
        asset_cache_available = self._asset_dir is not None
        if not asset_cache_available:
            configuration_warning = "生成图片缓存不可用；管理面板可能可读，但生成已降级"
            with self._state_lock:
                self._configuration_warning = configuration_warning
        try:
            await self._prune_cache()
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator cache startup sweep failed: failure_class={}",
                type(exc).__name__,
            )

        key = await self._load_api_key()
        if key and _settings_contain_secret(self._settings_snapshot(), key):
            safe_settings = (
                manifest_settings
                if not _settings_contain_secret(manifest_settings, key)
                else {
                    setting_key: (
                        list(setting_value)
                        if isinstance(setting_value, list)
                        else setting_value
                    )
                    for setting_key, setting_value in DEFAULT_SETTINGS.items()
                }
            )
            configuration_warning = "检测到设置中包含 API 密钥，已改用安全默认值"
            with self._state_lock:
                self._settings = safe_settings
                self._configuration_warning = configuration_warning
            self.logger.warning(
                "ImageGenerator secret-bearing settings ignored: "
                "failure_class=SecretInSettings"
            )
        configured = bool(key)
        lifecycle_status = (
            "running" if ui_registered and asset_cache_available else "degraded"
        )
        status_payload: dict[str, Any] = {
            "status": lifecycle_status,
            "api_key_configured": configured,
            "ui_registered": ui_registered,
            "asset_cache_available": asset_cache_available,
        }
        if configuration_warning:
            status_payload["configuration_warning"] = configuration_warning
        self.report_status(status_payload)
        self.logger.info(
            "ImageGenerator started: store_enabled={} key_configured={} "
            "ui_registered={}",
            bool(getattr(self.store, "enabled", False)),
            configured,
            ui_registered,
        )
        result_payload: dict[str, Any] = {
            "status": lifecycle_status,
            "store_enabled": bool(getattr(self.store, "enabled", False)),
            "api_key_configured": configured,
            "ui_registered": ui_registered,
            "asset_cache_available": asset_cache_available,
        }
        if configuration_warning:
            result_payload["configuration_warning"] = configuration_warning
        return Ok(result_payload)

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        with self._client_lock:
            active = self._client
            retired = list(self._retired_clients)
            self._client = None
            self._client_loop = None
            self._retired_clients = []

        clients: list[httpx.AsyncClient] = []
        if active is not None:
            clients.append(active)
        clients.extend(retired)
        close_failures = 0
        for client in clients:
            if getattr(client, "is_closed", False):
                continue
            try:
                await client.aclose()
            except Exception:
                close_failures += 1

        with self._state_lock:
            self._running = False
        self.report_status({"status": "shutdown"})
        if close_failures:
            self.logger.warning(
                "ImageGenerator client cleanup incomplete: failure_count={}",
                close_failures,
            )
        self.logger.info("ImageGenerator shutdown")
        return Ok(
            {
                "status": "shutdown",
                "clients_seen": len(clients),
                "close_failures": close_failures,
            }
        )

    def _get_client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        with self._client_lock:
            current = self._client
            if (
                current is None
                or getattr(current, "is_closed", False)
                or self._client_loop is not loop
            ):
                if current is not None and not getattr(current, "is_closed", False):
                    self._retired_clients.append(current)
                current = _new_http_client()
                self._client = current
                self._client_loop = loop
            return current

    @staticmethod
    async def _acquire_lock(lock: threading.Lock) -> None:
        while not lock.acquire(blocking=False):
            await asyncio.sleep(0.01)

    async def _store_get(self, key: str, default: Any = None) -> Any:
        if not bool(getattr(self.store, "enabled", False)):
            return default
        try:
            result = await self.store.get(key, default)
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator store read failed: key={} failure_class={}",
                key,
                type(exc).__name__,
            )
            return default
        if isinstance(result, Ok):
            return result.value
        self.logger.warning(
            "ImageGenerator store read failed: key={} failure_class=StoreError",
            key,
        )
        return default

    async def _store_set(self, key: str, value: Any) -> bool:
        if not bool(getattr(self.store, "enabled", False)):
            return False
        try:
            result = await self.store.set(key, value)
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator store write failed: key={} failure_class={}",
                key,
                type(exc).__name__,
            )
            return False
        if isinstance(result, Ok):
            return True
        self.logger.warning(
            "ImageGenerator store write failed: key={} failure_class=StoreError",
            key,
        )
        return False

    async def _store_delete(self, key: str) -> tuple[bool, bool]:
        if not bool(getattr(self.store, "enabled", False)):
            return False, False
        try:
            result = await self.store.delete(key)
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator store delete failed: key={} failure_class={}",
                key,
                type(exc).__name__,
            )
            return False, False
        if isinstance(result, Ok):
            return True, bool(result.value)
        self.logger.warning(
            "ImageGenerator store delete failed: key={} failure_class=StoreError",
            key,
        )
        return False, False

    async def _load_api_key(self) -> str:
        raw = await self._store_get(_API_KEY_STORE_KEY, "")
        if not isinstance(raw, str):
            return ""
        try:
            return _validate_api_key(raw)
        except SdkError:
            return ""

    def _settings_snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                key: (list(value) if isinstance(value, list) else value)
                for key, value in self._settings.items()
            }

    def _set_request_state(
        self,
        *,
        action: str,
        status: str,
        failure_class: str | None = None,
    ) -> None:
        with self._state_lock:
            if status == "running":
                self._api_state = "generating"
            elif status == "success":
                self._api_state = "ok"
            elif status == "error":
                self._api_state = "error"
            self._last_request = {
                "status": status,
                "time": _now_iso(),
                "action": action[:32],
                "failure_class": (str(failure_class)[:64] if failure_class else None),
            }

    # ------------------------------------------------------------------
    # Writable static UI and bounded generated-asset cache
    # ------------------------------------------------------------------

    @property
    def _source_static_dir(self) -> Path:
        return self.config_dir / "static"

    def _copy_static_ui_assets(self, target_dir: Path) -> None:
        source_dir = self._source_static_dir
        if not source_dir.is_dir():
            return
        for source_path in source_dir.rglob("*"):
            relative = source_path.relative_to(source_dir)
            if not relative.parts or relative.parts[0] == _GENERATED_SUBDIR:
                continue
            target_path = target_dir / relative
            try:
                resolved_parent = target_path.parent.resolve()
                resolved_root = target_dir.resolve()
            except OSError as exc:
                raise OSError("unable to validate static UI target") from exc
            if target_path.is_symlink() or (
                resolved_parent != resolved_root
                and resolved_root not in resolved_parent.parents
            ):
                raise OSError("unsafe static UI target path")
            if source_path.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue
            if not source_path.is_file():
                continue
            target_path.parent.mkdir(parents=True, exist_ok=True)
            copy_required = True
            if target_path.is_file():
                try:
                    copy_required = source_path.read_bytes() != target_path.read_bytes()
                except OSError:
                    copy_required = True
            if copy_required:
                shutil.copy2(source_path, target_path)

    def _register_writable_static_ui(self) -> bool:
        writable_ui = self.data_path("static_ui").resolve()
        try:
            writable_ui.mkdir(parents=True, exist_ok=True)
            self._copy_static_ui_assets(writable_ui)
            asset_dir = writable_ui / _GENERATED_SUBDIR
            if asset_dir.is_symlink():
                raise OSError("generated asset directory must not be a symlink")
            asset_dir.mkdir(parents=True, exist_ok=True)
            registered = self.register_static_ui(
                str(writable_ui),
                cache_control="no-cache",
            )
            if registered:
                self._writable_ui_dir = writable_ui
                self._asset_dir = asset_dir
                return True
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator writable UI setup failed: failure_class={}",
                type(exc).__name__,
            )

        try:
            fallback_registered = self.register_static_ui(
                "static",
                cache_control="no-cache",
            )
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator fallback UI registration failed: failure_class={}",
                type(exc).__name__,
            )
            return False
        if fallback_registered:
            # Keep the installed plugin tree immutable. The bundled UI can
            # still explain the data-directory failure, but generation must
            # fail cleanly rather than writing assets into source/package
            # files.
            self._asset_dir = None
            self._writable_ui_dir = self._source_static_dir
        return fallback_registered

    def _asset_dir_is_safe(self) -> bool:
        asset_dir = self._asset_dir
        writable_ui = self._writable_ui_dir
        if asset_dir is None or writable_ui is None:
            return False
        try:
            return (
                not asset_dir.is_symlink()
                and asset_dir.resolve() == writable_ui.resolve() / _GENERATED_SUBDIR
            )
        except OSError:
            return False

    def _cache_files(self) -> list[Path]:
        asset_dir = self._asset_dir
        if asset_dir is None or not self._asset_dir_is_safe() or not asset_dir.is_dir():
            return []
        files: list[Path] = []
        try:
            candidates = list(asset_dir.iterdir())
        except OSError:
            return []
        for path in candidates:
            if (
                path.is_file()
                and not path.is_symlink()
                and (
                    _GENERATED_FILE_PATTERN.fullmatch(path.name)
                    or _GENERATED_TEMP_FILE_PATTERN.fullmatch(path.name)
                )
            ):
                files.append(path)
        return files

    def _generated_files(self) -> list[Path]:
        return [
            path
            for path in self._cache_files()
            if _GENERATED_FILE_PATTERN.fullmatch(path.name)
        ]

    def _prune_cache_sync(self, settings: Mapping[str, Any]) -> dict[str, int]:
        files_with_stats: list[tuple[Path, int, float]] = []
        for path in self._cache_files():
            if _GENERATED_TEMP_FILE_PATTERN.fullmatch(path.name):
                try:
                    path.unlink()
                except OSError:
                    pass
                else:
                    continue
            try:
                stat = path.stat()
            except OSError:
                continue
            files_with_stats.append((path, stat.st_size, stat.st_mtime))
        files_with_stats.sort(key=lambda item: (item[2], item[0].name), reverse=True)

        kept_count = 0
        kept_bytes = 0
        max_count = int(settings["cache_max_count"])
        max_bytes = int(settings["cache_max_bytes"])
        for path, size, _mtime in files_with_stats:
            keep = kept_count < max_count and kept_bytes + size <= max_bytes
            if keep:
                kept_count += 1
                kept_bytes += size
                continue
            try:
                path.unlink()
            except OSError:
                pass
        # Report actual on-disk state, including files whose deletion failed,
        # instead of optimistic counters from the intended pruning plan.
        return self._cache_stats_sync()

    async def _prune_cache(self) -> dict[str, int]:
        await self._acquire_lock(self._cache_lock)
        try:
            return await asyncio.to_thread(
                self._prune_cache_sync,
                self._settings_snapshot(),
            )
        finally:
            self._cache_lock.release()

    def _cache_stats_sync(self) -> dict[str, int]:
        count = 0
        total_bytes = 0
        for path in self._cache_files():
            try:
                total_bytes += path.stat().st_size
                count += 1
            except OSError:
                continue
        return {"count": count, "total_bytes": total_bytes}

    async def _cache_stats(self) -> dict[str, int]:
        await self._acquire_lock(self._cache_lock)
        try:
            return await asyncio.to_thread(self._cache_stats_sync)
        finally:
            self._cache_lock.release()

    def _resolve_public_origin(self) -> str:
        for env_name in (
            "NEKO_PLUGIN_SERVER_ORIGIN",
            "NEKO_USER_PLUGIN_SERVER_ORIGIN",
            "NEKO_SERVER_ORIGIN",
        ):
            raw = str(os.getenv(env_name, "") or "").strip().rstrip("/")
            if len(raw) > _URL_MAX_CHARS:
                continue
            parsed = _parse_http_url(raw)
            if (
                parsed is not None
                and not parsed.query
                and not parsed.fragment
                and not parsed.params
            ):
                return f"{parsed.scheme.lower()}://{parsed.netloc}"
        try:
            port = int(str(os.getenv("NEKO_USER_PLUGIN_SERVER_PORT", "")).strip())
            if 1 <= port <= 65535:
                return f"http://127.0.0.1:{port}"
        except (TypeError, ValueError):
            pass
        try:
            from config import USER_PLUGIN_SERVER_PORT

            port = int(USER_PLUGIN_SERVER_PORT)
            if 1 <= port <= 65535:
                return f"http://127.0.0.1:{port}"
        except Exception:
            pass
        return f"http://127.0.0.1:{_DEFAULT_PLUGIN_SERVER_PORT}"

    def _asset_url(self, filename: str) -> str:
        safe_plugin_id = quote(self.plugin_id, safe="")
        safe_filename = quote(filename, safe="")
        path = f"/plugin/{safe_plugin_id}/ui/{_GENERATED_SUBDIR}/{safe_filename}"
        return f"{self._resolve_public_origin().rstrip('/')}{path}"

    async def _save_asset(
        self,
        data: bytes,
        *,
        extension: str,
    ) -> tuple[str, str]:
        asset_dir = self._asset_dir
        if asset_dir is None or not self._asset_dir_is_safe():
            raise _GenerationFailure(
                "本地图片缓存不可用，请检查插件数据目录权限",
                "AssetCacheUnavailable",
            )
        filename = f"{uuid4().hex}.{extension}"
        if not _GENERATED_FILE_PATTERN.fullmatch(filename):
            raise _GenerationFailure(
                "无法创建安全的图片文件名",
                "AssetCacheError",
            )
        await self._acquire_lock(self._cache_lock)
        target = asset_dir / filename
        temp_path = asset_dir / f".{filename}.{uuid4().hex}.tmp"
        try:
            asset_dir.mkdir(parents=True, exist_ok=True)
            if not self._asset_dir_is_safe():
                raise _GenerationFailure(
                    "本地图片缓存路径不安全，已拒绝写入",
                    "AssetCacheUnsafe",
                )
            await asyncio.to_thread(
                _atomic_write_bytes,
                temp_path,
                target,
                data,
            )
            settings = self._settings_snapshot()
            stats = await asyncio.to_thread(
                self._prune_cache_sync,
                settings,
            )
            if (
                not target.is_file()
                or stats["count"] > int(settings["cache_max_count"])
                or stats["total_bytes"] > int(settings["cache_max_bytes"])
            ):
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    pass
                await asyncio.to_thread(self._prune_cache_sync, settings)
                raise _GenerationFailure(
                    "无法在当前文件系统上执行图片缓存容量限制",
                    "AssetCacheLimit",
                )
        except _GenerationFailure:
            raise
        except Exception:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise _GenerationFailure(
                "保存生成图片失败，请检查插件数据目录权限",
                "AssetCacheError",
            ) from None
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._cache_lock.release()
        return self._asset_url(filename), filename

    # ------------------------------------------------------------------
    # Safe provider request and output handling
    # ------------------------------------------------------------------

    async def _ensure_download_url_allowed(
        self,
        url: str,
        *,
        api_base_url: str,
    ) -> None:
        # An operator may explicitly authorize a literal private/loopback
        # provider address. Hostnames, including same-origin provider
        # hostnames, must still resolve exclusively to public-unicast
        # addresses so a configured public name is not a blanket private-net
        # bypass. Every redirect is checked again by the caller.
        if _origin_tuple(url) == _origin_tuple(api_base_url):
            base = _parse_http_url(api_base_url)
            hostname = str(base.hostname or "") if base is not None else ""
            try:
                literal = ipaddress.ip_address(hostname)
            except ValueError:
                literal = None
            if literal is not None and not _is_public_unicast_ip(literal):
                return
        allowed = await asyncio.to_thread(
            _url_resolves_to_public_unicast,
            url,
        )
        if not allowed:
            raise _GenerationFailure(
                "图片下载地址指向了不允许的本地或私有网络",
                "UnsafeImageUrl",
            )

    async def _download_image(
        self,
        initial_url: str,
        *,
        api_base_url: str,
        timeout: float,
        max_bytes: int,
    ) -> tuple[bytes, str, str]:
        current_url = _validate_output_url(initial_url)
        client = self._get_client()
        for redirect_index in range(_MAX_REDIRECTS + 1):
            await self._ensure_download_url_allowed(
                current_url,
                api_base_url=api_base_url,
            )
            try:
                async with client.stream(
                    "GET",
                    current_url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "image/png,image/jpeg,image/gif,image/webp",
                    },
                    timeout=timeout,
                    follow_redirects=False,
                ) as response:
                    status = int(response.status_code)
                    if status in {301, 302, 303, 307, 308}:
                        if redirect_index >= _MAX_REDIRECTS:
                            raise _GenerationFailure(
                                "图片下载重定向次数过多",
                                "TooManyRedirects",
                            )
                        location = response.headers.get("location")
                        if not location:
                            raise _GenerationFailure(
                                "图片下载重定向缺少目标地址",
                                "MalformedRedirect",
                            )
                        current_url = _validate_output_url(
                            urljoin(current_url, location)
                        )
                        continue
                    if status < 200 or status >= 300:
                        raise _GenerationFailure(
                            f"下载生成图片失败（HTTP {status}）",
                            "ImageDownloadHttpError",
                        )

                    content_length = response.headers.get("content-length")
                    if content_length:
                        try:
                            declared_length = int(content_length)
                        except ValueError:
                            declared_length = -1
                        if declared_length < 0:
                            raise _GenerationFailure(
                                "图片服务返回了无效的文件长度",
                                "MalformedDownload",
                            )
                        if declared_length > max_bytes:
                            raise _GenerationFailure(
                                "生成图片超过了配置的最大下载字节数",
                                "ImageTooLarge",
                            )

                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > max_bytes:
                            raise _GenerationFailure(
                                "生成图片超过了配置的最大下载字节数",
                                "ImageTooLarge",
                            )
                        chunks.append(bytes(chunk))
                    data = b"".join(chunks)
                    mime, extension = _image_type(data)
                    return data, mime, extension
            except _GenerationFailure:
                raise
            except httpx.TimeoutException:
                raise _GenerationFailure(
                    "下载生成图片超时，请稍后重试",
                    "DownloadTimeout",
                ) from None
            except httpx.RequestError:
                raise _GenerationFailure(
                    "无法下载生成图片，请检查服务网络",
                    "DownloadNetworkError",
                ) from None
            except Exception:
                raise _GenerationFailure(
                    "下载生成图片时发生错误",
                    "DownloadError",
                ) from None
        raise _GenerationFailure(
            "图片下载重定向次数过多",
            "TooManyRedirects",
        )

    @staticmethod
    def _build_request_body(
        *,
        settings: Mapping[str, Any],
        prompt: str,
        size: str,
        quality: str,
        style: str,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": settings["model"],
            "prompt": prompt,
            "n": 1,
        }
        if size and size != "auto":
            body["size"] = size
        if quality and quality != "auto":
            body["quality"] = quality
        if style and style != "auto":
            body["style"] = style
        output_format = settings["output_format"]
        if output_format != "auto":
            body["output_format"] = output_format
        response_format = settings["response_format"]
        if response_format != "auto":
            body["response_format"] = response_format
        return body

    async def _request_generation(
        self,
        *,
        settings: Mapping[str, Any],
        api_key: str,
        prompt: str,
        size: str,
        quality: str,
        style: str,
    ) -> tuple[bytes, str, str, str]:
        endpoint = f"{str(settings['api_base_url']).rstrip('/')}/images/generations"
        body = self._build_request_body(
            settings=settings,
            prompt=prompt,
            size=size,
            quality=quality,
            style=style,
        )
        client = self._get_client()
        max_bytes = int(settings["max_download_bytes"])
        max_json_bytes = ((max_bytes + 2) // 3) * 4 + 1_048_576
        try:
            async with client.stream(
                "POST",
                endpoint,
                json=body,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=float(settings["timeout_seconds"]),
                follow_redirects=False,
            ) as response:
                status = int(getattr(response, "status_code", 0) or 0)
                if status < 200 or status >= 300:
                    if status in {401, 403}:
                        message = "图片服务拒绝了凭据，请检查 API 密钥"
                    elif status in {400, 422}:
                        message = (
                            "图片服务拒绝了生成参数，请检查模型、尺寸、质量、"
                            "风格和格式设置"
                        )
                    elif status == 404:
                        message = "图片服务端点不存在，请检查 API 地址和模型"
                    elif status == 429:
                        message = "图片服务请求过于频繁或额度不足，请稍后重试"
                    elif status >= 500:
                        message = f"图片服务暂时不可用（HTTP {status}）"
                    else:
                        message = f"图片服务请求失败（HTTP {status}）"
                    raise _GenerationFailure(
                        message,
                        f"ProviderHttp{status}",
                    )

                response_headers = getattr(response, "headers", {})
                content_length = (
                    response_headers.get("content-length")
                    if isinstance(response_headers, Mapping)
                    else None
                )
                if content_length:
                    try:
                        declared_length = int(content_length)
                    except ValueError:
                        declared_length = -1
                    if declared_length < 0:
                        raise _GenerationFailure(
                            "图片服务返回了无效的响应长度",
                            "MalformedResponse",
                        )
                    if declared_length > max_json_bytes:
                        raise _GenerationFailure(
                            "图片服务返回的数据超过了配置的最大字节数",
                            "ImageTooLarge",
                        )

                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_json_bytes:
                        raise _GenerationFailure(
                            "图片服务返回的数据超过了配置的最大字节数",
                            "ImageTooLarge",
                        )
                    chunks.append(bytes(chunk))
                raw_response = b"".join(chunks)
        except _GenerationFailure:
            raise
        except httpx.TimeoutException:
            raise _GenerationFailure(
                "生成图片超时，请稍后重试或提高超时设置",
                "ProviderTimeout",
            ) from None
        except httpx.RequestError:
            raise _GenerationFailure(
                "无法连接图片生成服务，请检查 API 地址和网络",
                "ProviderNetworkError",
            ) from None
        except Exception:
            raise _GenerationFailure(
                "请求图片生成服务时发生错误",
                "ProviderRequestError",
            ) from None

        try:
            payload = json.loads(raw_response)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            raise _GenerationFailure(
                "图片服务返回了无法解析的数据",
                "InvalidProviderJson",
            ) from None
        if not isinstance(payload, Mapping):
            raise _GenerationFailure(
                "图片服务返回的数据格式无效",
                "MalformedResponse",
            )
        data_items = payload.get("data")
        if not isinstance(data_items, list) or not data_items:
            raise _GenerationFailure(
                "图片服务没有返回图片",
                "MalformedResponse",
            )
        first = data_items[0]
        if not isinstance(first, Mapping):
            raise _GenerationFailure(
                "图片服务返回的数据格式无效",
                "MalformedResponse",
            )
        revised_prompt = _redact_text(
            first.get("revised_prompt"),
            api_key,
            max_chars=_REVISED_PROMPT_MAX_CHARS,
        )
        b64_value = first.get("b64_json")
        url_value = first.get("url")
        if isinstance(b64_value, str) and b64_value.strip():
            decoded, mime, extension = _decode_b64_image(
                b64_value,
                max_bytes=max_bytes,
            )
            return decoded, mime, extension, revised_prompt
        if isinstance(url_value, str) and url_value.strip():
            downloaded, mime, extension = await self._download_image(
                url_value,
                api_base_url=str(settings["api_base_url"]),
                timeout=float(settings["timeout_seconds"]),
                max_bytes=max_bytes,
            )
            return downloaded, mime, extension, revised_prompt
        raise _GenerationFailure(
            "图片服务未返回 url 或 b64_json",
            "MalformedResponse",
        )

    def _resolve_generation_options(
        self,
        *,
        settings: Mapping[str, Any],
        prompt: Any,
        size: Any,
        quality: Any,
        style: Any,
    ) -> tuple[str, str, str, str]:
        cleaned_prompt = _clean_text(
            prompt,
            label="图片描述",
            max_chars=_PROMPT_MAX_CHARS,
        )
        values: list[str] = []
        for supplied, default_field, allowed_field, label in (
            (size, "default_size", "allowed_sizes", "尺寸"),
            (quality, "default_quality", "allowed_qualities", "质量"),
            (style, "default_style", "allowed_styles", "风格"),
        ):
            if supplied is None:
                resolved = str(settings[default_field])
            else:
                resolved = _clean_text(
                    supplied,
                    label=label,
                    max_chars=32,
                    allow_empty=(label == "风格"),
                ).lower()
            if resolved not in settings[allowed_field]:
                raise SdkError(
                    f"{label}不在已配置的允许列表中，请使用管理面板中列出的有效选项"
                )
            values.append(resolved)
        return cleaned_prompt, values[0], values[1], values[2]

    # ------------------------------------------------------------------
    # History and user-visible Markdown delivery
    # ------------------------------------------------------------------

    def _project_history_record(
        self,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        projected = dict(record)
        result_url = str(projected.get("result_url") or "")
        if not result_url:
            return projected
        parsed = _parse_http_url(result_url)
        prefix = f"/plugin/{quote(self.plugin_id, safe='')}/ui/{_GENERATED_SUBDIR}/"
        if (
            parsed is None
            or not parsed.path.startswith(prefix)
            or _origin_tuple(result_url) != _origin_tuple(self._resolve_public_origin())
        ):
            projected["result_url"] = ""
            return projected
        filename = parsed.path[len(prefix) :]
        asset_dir = self._asset_dir
        if (
            "/" in filename
            or not _GENERATED_FILE_PATTERN.fullmatch(filename)
            or asset_dir is None
            or not (asset_dir / filename).is_file()
            or (asset_dir / filename).is_symlink()
        ):
            projected["result_url"] = ""
        return projected

    async def _load_history(
        self,
        *,
        api_key: str = "",
    ) -> list[dict[str, Any]]:
        raw = await self._store_get(_HISTORY_STORE_KEY, [])
        if not isinstance(raw, list):
            return []
        history: list[dict[str, Any]] = []
        for item in raw:
            normalized = _safe_history_record(item, api_key)
            if normalized is not None:
                history.append(self._project_history_record(normalized))
        return history

    async def _record_history(
        self,
        *,
        prompt: str,
        model: str,
        status: str,
        result_url: str,
        api_key: str,
    ) -> None:
        if not bool(getattr(self.store, "enabled", False)):
            return
        await self._acquire_lock(self._history_lock)
        try:
            history = await self._load_history(api_key=api_key)
            history.insert(
                0,
                {
                    "id": uuid4().hex,
                    "timestamp": _now_iso(),
                    "model": _redact_text(
                        model,
                        api_key,
                        max_chars=_MODEL_MAX_CHARS,
                    ),
                    "prompt_excerpt": _redact_text(
                        prompt,
                        api_key,
                        max_chars=_PROMPT_EXCERPT_MAX_CHARS,
                    ),
                    "result_url": (
                        result_url[:_URL_MAX_CHARS]
                        if _parse_http_url(result_url) is not None
                        else ""
                    ),
                    "status": status,
                },
            )
            limit = int(self._settings_snapshot()["history_limit"])
            if not await self._store_set(
                _HISTORY_STORE_KEY,
                history[:limit],
            ):
                self.logger.warning(
                    "ImageGenerator history write failed: failure_class=StoreError"
                )
        finally:
            self._history_lock.release()

    @staticmethod
    def _display_markdown(image_url: str) -> str:
        return (
            f"### 图片已生成\n\n![AI 生成图片]({image_url})\n\n[打开原图]({image_url})"
        )

    def _push_chat_markdown(self, markdown: str) -> bool:
        try:
            self.push_message(
                visibility=["chat"],
                ai_behavior="blind",
                parts=[{"type": "text", "text": markdown}],
                source="image_generator",
                priority=2,
                metadata={"event_type": "image_generated"},
            )
            return True
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator chat display failed: failure_class={}",
                type(exc).__name__,
            )
            return False

    async def _generate(
        self,
        *,
        prompt: Any,
        size: Any = None,
        quality: Any = None,
        style: Any = None,
        action: str,
        auto_show_override: bool | None,
    ):
        settings = self._settings_snapshot()
        try:
            cleaned_prompt, resolved_size, resolved_quality, resolved_style = (
                self._resolve_generation_options(
                    settings=settings,
                    prompt=prompt,
                    size=size,
                    quality=quality,
                    style=style,
                )
            )
        except SdkError as exc:
            return Err(exc)

        api_key = await self._load_api_key()
        if not api_key:
            await self._record_history(
                prompt=cleaned_prompt,
                model=str(settings["model"]),
                status="failed",
                result_url="",
                api_key="",
            )
            return Err(
                SdkError("尚未配置 API 密钥，请在 image_generator 管理面板中设置")
            )
        if _settings_contain_secret(settings, api_key):
            return Err(
                SdkError("检测到设置字段包含 API 密钥；请在管理面板重新保存安全设置")
            )

        self._set_request_state(action=action, status="running")
        self.report_status({"status": "generating"})
        self.logger.info(
            "ImageGenerator request started: action={} prompt_len={} "
            "size_configured={} quality_configured={} style_configured={}",
            action,
            len(cleaned_prompt),
            bool(resolved_size and resolved_size != "auto"),
            bool(resolved_quality and resolved_quality != "auto"),
            bool(resolved_style),
        )
        try:
            try:
                async with asyncio.timeout(float(settings["timeout_seconds"])):
                    (
                        image_bytes,
                        _mime,
                        extension,
                        revised_prompt,
                    ) = await self._request_generation(
                        settings=settings,
                        api_key=api_key,
                        prompt=cleaned_prompt,
                        size=resolved_size,
                        quality=resolved_quality,
                        style=resolved_style,
                    )
            except TimeoutError:
                raise _GenerationFailure(
                    "生成图片超过了配置的总超时时间，请稍后重试",
                    "GenerationTimeout",
                ) from None
            image_url, _filename = await self._save_asset(
                image_bytes,
                extension=extension,
            )
        except _GenerationFailure as exc:
            self._set_request_state(
                action=action,
                status="error",
                failure_class=exc.failure_class,
            )
            self.report_status(
                {
                    "status": "error",
                    "failure_class": exc.failure_class,
                }
            )
            await self._record_history(
                prompt=cleaned_prompt,
                model=str(settings["model"]),
                status="failed",
                result_url="",
                api_key=api_key,
            )
            self.logger.warning(
                "ImageGenerator request failed: action={} failure_class={}",
                action,
                exc.failure_class,
            )
            return Err(SdkError(exc.message))
        except Exception as exc:
            failure_class = type(exc).__name__
            self._set_request_state(
                action=action,
                status="error",
                failure_class=failure_class,
            )
            self.report_status({"status": "error", "failure_class": failure_class})
            await self._record_history(
                prompt=cleaned_prompt,
                model=str(settings["model"]),
                status="failed",
                result_url="",
                api_key=api_key,
            )
            self.logger.warning(
                "ImageGenerator unexpected failure: action={} failure_class={}",
                action,
                failure_class,
            )
            return Err(SdkError("生成图片时发生内部错误，请稍后重试"))

        markdown = self._display_markdown(image_url)
        should_show = (
            bool(settings["auto_show_in_chat"])
            if auto_show_override is None
            else auto_show_override
        )
        push_attempted = should_show and self._push_chat_markdown(markdown)
        if push_attempted:
            message = "图片已生成，插件已尝试直接显示"
        else:
            message = "图片已生成，可通过返回的链接查看"
        # push_message has no delivery acknowledgement. Keep a model-facing
        # Markdown fallback even after a successful enqueue attempt; a
        # duplicate image is preferable to silently losing a paid result.
        instruction = (
            "请在回复中附上 display_markdown 的原样内容，确保 "
            "{MASTER_NAME} 能直接看到并打开生成图片；再用角色口吻简短说明"
            "已经画好。"
        )

        await self._record_history(
            prompt=cleaned_prompt,
            model=str(settings["model"]),
            status="succeeded",
            result_url=image_url,
            api_key=api_key,
        )
        self._set_request_state(action=action, status="success")
        self.report_status({"status": "running"})
        self.logger.info(
            "ImageGenerator request succeeded: action={} bytes={} "
            "chat_push_attempted={}",
            action,
            len(image_bytes),
            push_attempted,
        )
        return Ok(
            {
                "message": message,
                "image_url": image_url,
                "display_markdown": markdown,
                "display_instruction": instruction,
                "revised_prompt": revised_prompt,
            }
        )

    # ------------------------------------------------------------------
    # Primary dual-registered capability
    # ------------------------------------------------------------------

    @llm_tool(
        name="generate_image",
        description=(
            "根据用户描述生成一张图片。用户说“画一张……”“生成图片”、"
            "“帮我画”“绘制插画/海报/头像”或其他明确图像创作请求时调用。"
            "prompt 必填；size、quality、style 可省略并使用管理面板默认值，"
            "提供时必须符合面板允许列表。工具会返回可直接显示的图片 Markdown。"
        ),
        parameters=GENERATE_IMAGE_SCHEMA,
        timeout=300.0,
    )
    @plugin_entry(
        id="generate_image",
        name="生成图片",
        description=(
            "根据文本描述调用 OpenAI-compatible Images API 生成图片。"
            "适用于“画一张”“生成图片”“帮我画”“绘制海报/头像/插画”等请求。"
            "prompt 必填；可选 size、quality、style 会按面板允许列表校验。"
        ),
        input_schema=GENERATE_IMAGE_SCHEMA,
        timeout=300.0,
        llm_result_fields=[
            "message",
            "image_url",
            "display_markdown",
            "display_instruction",
            "revised_prompt",
        ],
    )
    async def generate_image(
        self,
        prompt: str,
        size: str | None = None,
        quality: str | None = None,
        style: str | None = None,
        **_: Any,
    ):
        return await self._generate(
            prompt=prompt,
            size=size,
            quality=quality,
            style=style,
            action="generate_image",
            auto_show_override=None,
        )

    # ------------------------------------------------------------------
    # Management-panel entries (not exposed as LLM tools)
    # ------------------------------------------------------------------

    @plugin_entry(
        id="get_panel_state",
        name="读取图片生成器面板状态",
        description="读取安全设置、运行状态、缓存统计和最近生成记录。",
        input_schema=_EMPTY_SCHEMA,
    )
    async def get_panel_state(self, **_: Any):
        settings = self._settings_snapshot()
        api_key = await self._load_api_key()
        secret_warning: str | None = None
        if api_key and _settings_contain_secret(settings, api_key):
            settings = {
                key: (list(value) if isinstance(value, list) else value)
                for key, value in DEFAULT_SETTINGS.items()
            }
            secret_warning = "检测到设置中包含 API 密钥；面板已隐藏这些设置"
        history = await self._load_history(api_key=api_key)
        cache = await self._cache_stats()
        with self._state_lock:
            running = self._running
            api_state = self._api_state
            last_request = dict(self._last_request)
            configuration_warning = secret_warning or self._configuration_warning
            defaults = {
                key: (list(value) if isinstance(value, list) else value)
                for key, value in self._manifest_settings.items()
            }
        if api_key and _settings_contain_secret(defaults, api_key):
            defaults = {
                key: (list(value) if isinstance(value, list) else value)
                for key, value in DEFAULT_SETTINGS.items()
            }
        cache.update(
            {
                "max_count": settings["cache_max_count"],
                "max_bytes": settings["cache_max_bytes"],
            }
        )
        return Ok(
            {
                "running": running,
                "api_state": api_state,
                "configuration_warning": configuration_warning,
                "store_enabled": bool(getattr(self.store, "enabled", False)),
                "asset_cache_available": self._asset_dir is not None,
                "api_key_configured": bool(api_key),
                "api_key_hint": _api_key_hint(api_key),
                "settings": settings,
                "defaults": defaults,
                "history": history[:20],
                "cache": cache,
                "last_request": last_request,
            }
        )

    @plugin_entry(
        id="save_settings",
        name="保存图片生成器设置",
        description="校验并保存非秘密设置；API 密钥单独写入 PluginStore。",
        input_schema=_SAVE_SETTINGS_SCHEMA,
    )
    async def save_settings(
        self,
        api_base_url: str,
        model: str,
        default_size: str,
        default_quality: str,
        default_style: str,
        allowed_sizes: list[str],
        allowed_qualities: list[str],
        allowed_styles: list[str],
        output_format: str,
        response_format: str,
        timeout_seconds: float,
        max_download_bytes: int,
        cache_max_count: int,
        cache_max_bytes: int,
        history_limit: int,
        auto_show_in_chat: bool,
        api_key: str = "",
        clear_api_key: bool = False,
        **_: Any,
    ):
        if not isinstance(clear_api_key, bool):
            return Err(SdkError("清除密钥开关必须是布尔值"))
        if not isinstance(api_key, str):
            return Err(SdkError("API 密钥必须是文本"))
        try:
            validated = _validate_settings(
                {
                    "api_base_url": api_base_url,
                    "model": model,
                    "default_size": default_size,
                    "default_quality": default_quality,
                    "default_style": default_style,
                    "allowed_sizes": allowed_sizes,
                    "allowed_qualities": allowed_qualities,
                    "allowed_styles": allowed_styles,
                    "output_format": output_format,
                    "response_format": response_format,
                    "timeout_seconds": timeout_seconds,
                    "max_download_bytes": max_download_bytes,
                    "cache_max_count": cache_max_count,
                    "cache_max_bytes": cache_max_bytes,
                    "history_limit": history_limit,
                    "auto_show_in_chat": auto_show_in_chat,
                },
                base=self._manifest_settings,
                require_all=True,
            )
            new_api_key = (
                ""
                if clear_api_key
                else (_validate_api_key(api_key) if api_key.strip() else "")
            )
        except SdkError as exc:
            return Err(exc)

        if not bool(getattr(self.store, "enabled", False)):
            return Err(SdkError("插件存储已禁用，无法保存设置或 API 密钥"))
        await self._acquire_lock(self._settings_update_lock)
        key_changed = False
        try:
            old_settings = await self._store_get(_SETTINGS_STORE_KEY, None)
            old_api_key = await self._store_get(_API_KEY_STORE_KEY, None)
            effective_api_key = ""
            if not clear_api_key:
                if new_api_key:
                    effective_api_key = new_api_key
                elif isinstance(old_api_key, str):
                    try:
                        effective_api_key = _validate_api_key(old_api_key)
                    except SdkError:
                        effective_api_key = ""
            if _settings_contain_secret(validated, effective_api_key):
                return Err(SdkError("API 密钥不能出现在 API 地址、模型或允许列表中"))
            if not await self._store_set(_SETTINGS_STORE_KEY, validated):
                return Err(SdkError("保存设置失败（StoreError），请稍后重试"))

            key_error: str | None = None
            if clear_api_key:
                deleted_ok, _existed = await self._store_delete(_API_KEY_STORE_KEY)
                if not deleted_ok:
                    key_error = "清除 API 密钥失败（StoreError）"
                else:
                    key_changed = True
            elif new_api_key:
                if not await self._store_set(
                    _API_KEY_STORE_KEY,
                    new_api_key,
                ):
                    key_error = "保存 API 密钥失败（StoreError）"
                else:
                    key_changed = True

            if key_error is not None:
                if old_settings is None:
                    settings_restored, _ = await self._store_delete(_SETTINGS_STORE_KEY)
                else:
                    settings_restored = await self._store_set(
                        _SETTINGS_STORE_KEY,
                        old_settings,
                    )
                if old_api_key is None:
                    key_restored, _ = await self._store_delete(_API_KEY_STORE_KEY)
                else:
                    key_restored = await self._store_set(
                        _API_KEY_STORE_KEY,
                        old_api_key,
                    )
                if not settings_restored or not key_restored:
                    self.logger.warning(
                        "ImageGenerator settings rollback incomplete: "
                        "failure_class=StoreError"
                    )
                return Err(SdkError(key_error))

            with self._state_lock:
                self._settings = validated
                self._configuration_warning = (
                    None
                    if self._asset_dir is not None
                    else "生成图片缓存不可用；管理面板可能可读，但生成已降级"
                )
        finally:
            self._settings_update_lock.release()
        try:
            await self._prune_cache()
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator cache prune after save failed: failure_class={}",
                type(exc).__name__,
            )
        current_api_key = await self._load_api_key()
        await self._acquire_lock(self._history_lock)
        try:
            history = await self._load_history(api_key=current_api_key)
            if len(history) > int(validated["history_limit"]):
                await self._store_set(
                    _HISTORY_STORE_KEY,
                    history[: int(validated["history_limit"])],
                )
        finally:
            self._history_lock.release()
        key_configured = bool(current_api_key)
        self.logger.info(
            "ImageGenerator settings saved: output_format={} "
            "response_format={} key_changed={} key_configured={} auto_show={}",
            validated["output_format"],
            validated["response_format"],
            key_changed,
            key_configured,
            validated["auto_show_in_chat"],
        )
        return Ok(
            {
                "saved": True,
                "settings": self._settings_snapshot(),
                "api_key_configured": key_configured,
                "api_key_hint": _api_key_hint(current_api_key),
            }
        )

    @plugin_entry(
        id="reset_settings",
        name="恢复图片生成器默认设置",
        description="恢复 plugin.toml 中的非秘密默认设置；不会清除 API 密钥。",
        input_schema=_EMPTY_SCHEMA,
    )
    async def reset_settings(self, **_: Any):
        if not bool(getattr(self.store, "enabled", False)):
            return Err(SdkError("插件存储已禁用，无法恢复默认设置"))
        await self._acquire_lock(self._settings_update_lock)
        try:
            deleted_ok, _existed = await self._store_delete(_SETTINGS_STORE_KEY)
            if not deleted_ok:
                return Err(SdkError("恢复默认设置失败（StoreError）"))
            with self._state_lock:
                self._settings = {
                    key: (list(value) if isinstance(value, list) else value)
                    for key, value in self._manifest_settings.items()
                }
                self._configuration_warning = (
                    None
                    if self._asset_dir is not None
                    else "生成图片缓存不可用；管理面板可能可读，但生成已降级"
                )
        finally:
            self._settings_update_lock.release()
        try:
            await self._prune_cache()
        except Exception as exc:
            self.logger.warning(
                "ImageGenerator cache prune after reset failed: failure_class={}",
                type(exc).__name__,
            )
        return Ok(
            {
                "reset": True,
                "settings": self._settings_snapshot(),
                "api_key_configured": bool(await self._load_api_key()),
            }
        )

    @plugin_entry(
        id="clear_api_key",
        name="清除图片生成 API 密钥",
        description="显式删除 PluginStore 中保存的 API 密钥。",
        input_schema=_EMPTY_SCHEMA,
    )
    async def clear_api_key(self, **_: Any):
        if not bool(getattr(self.store, "enabled", False)):
            return Err(SdkError("插件存储已禁用，无法清除 API 密钥"))
        await self._acquire_lock(self._settings_update_lock)
        try:
            deleted_ok, existed = await self._store_delete(_API_KEY_STORE_KEY)
        finally:
            self._settings_update_lock.release()
        if not deleted_ok:
            return Err(SdkError("清除 API 密钥失败（StoreError）"))
        self.logger.info("ImageGenerator API key cleared: existed={}", existed)
        return Ok(
            {
                "cleared": existed,
                "api_key_configured": False,
                "api_key_hint": None,
            }
        )

    @plugin_entry(
        id="get_recent_history",
        name="读取最近图片生成记录",
        description="读取不含密钥和 Base64 图片的有界最近生成记录。",
        input_schema=_RECENT_HISTORY_SCHEMA,
    )
    async def get_recent_history(self, limit: int = 20, **_: Any):
        try:
            resolved_limit = _bounded_int(
                limit,
                label="历史记录数量",
                minimum=1,
                maximum=100,
            )
        except SdkError as exc:
            return Err(exc)
        api_key = await self._load_api_key()
        history = (await self._load_history(api_key=api_key))[:resolved_limit]
        return Ok({"history": history, "count": len(history)})

    @plugin_entry(
        id="clear_history",
        name="清除图片生成历史",
        description="清除最近生成记录；不会清除 API 密钥或已生成文件缓存。",
        input_schema=_EMPTY_SCHEMA,
    )
    async def clear_history(self, **_: Any):
        if not bool(getattr(self.store, "enabled", False)):
            return Err(SdkError("插件存储已禁用，无法清除历史记录"))
        await self._acquire_lock(self._history_lock)
        try:
            deleted_ok, existed = await self._store_delete(_HISTORY_STORE_KEY)
        finally:
            self._history_lock.release()
        if not deleted_ok:
            return Err(SdkError("清除历史记录失败（StoreError）"))
        return Ok({"cleared": True, "had_history": existed, "count": 0})

    @plugin_entry(
        id="test_generation",
        name="测试生成图片",
        description="使用当前配置立即生成一张测试图片；可能产生提供商费用。",
        input_schema=_TEST_GENERATION_SCHEMA,
        timeout=300.0,
    )
    async def test_generation(self, prompt: str, **_: Any):
        return await self._generate(
            prompt=prompt,
            action="test_generation",
            auto_show_override=False,
        )


__all__ = [
    "DEFAULT_SETTINGS",
    "GENERATE_IMAGE_SCHEMA",
    "ImageGeneratorPlugin",
    "PLUGIN_VERSION",
    "USER_AGENT",
    "_decode_b64_image",
    "_image_type",
    "_new_http_client",
    "_normalize_api_base_url",
    "_url_resolves_to_public_unicast",
    "_validate_settings",
]
