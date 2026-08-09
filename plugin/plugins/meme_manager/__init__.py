"""Meme Manager plugin for N.E.K.O.

The plugin presents one catalog made from the host's existing online meme
search and a persistent user-upload area. Online images remain remote and are
rendered only through the host meme proxy; uploaded assets are decoded,
validated, and stored under the plugin runtime data root.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import os
import re
import threading
import time
import warnings
from io import BytesIO
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlsplit
from uuid import uuid4
from xml.etree import ElementTree

from PIL import Image, UnidentifiedImageError

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

PLUGIN_ID = "meme_manager"
_STORE_KEY = "meme_library"
_SYSTEM_SOURCE_ID = "system:neko-online"

_ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
_CANONICAL_EXTENSION = {".jpeg": ".jpg"}
_MIME_BY_EXT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}
_MAX_IMAGE_BYTES = 2 * 1024 * 1024
# Raw uploads may exceed the stored-size limit: oversized raster images are
# normalized (resized / re-encoded) down to _MAX_IMAGE_BYTES before storage.
_MAX_UPLOAD_BYTES = 20 * 1024 * 1024
_MAX_BATCH_ITEMS = 100
# Raster images are re-encoded to at most this edge length; anything larger
# only wastes chat bandwidth when the catgirl posts the meme.
_TARGET_IMAGE_DIMENSION = 1024
_MAX_IMAGE_DIMENSION = 4096
_MAX_IMAGE_PIXELS = 16 * 1024 * 1024
_MAX_ANIMATION_FRAMES = 256
_MAX_MEMES = 500
_MAX_NAME = 48
_MAX_TAGS = 8
_MAX_TAG_LEN = 24
_MAX_SYSTEM_CANDIDATES = 3
_SYSTEM_FETCH_TIMEOUT_SECONDS = 12.0
_SYSTEM_MODERATION_TIMEOUT_SECONDS = 10.0
_SYSTEM_PROXY_PREFLIGHT_TIMEOUT_SECONDS = 6.0
_SYSTEM_SELECTION_TIMEOUT_SECONDS = 28.0

_STORED_NAME_PATTERN = re.compile(
    r"^[0-9a-f]{16}\.(?:png|jpe?g|gif|webp|svg)$",
    flags=re.IGNORECASE,
)
_SVG_NUMBER_PATTERN = re.compile(
    r"^[+]?(?:\d+(?:\.\d*)?|\.\d+)(?:px)?$",
    flags=re.IGNORECASE,
)
_SVG_UNSAFE_TEXT = re.compile(
    r"javascript:|data:|file:|https?:|//|url\s*\(|@import|expression\s*\(",
    flags=re.IGNORECASE,
)
_SVG_FORBIDDEN_TAGS = {
    "animate",
    "animatemotion",
    "animatetransform",
    "audio",
    "discard",
    "script",
    "set",
    "video",
    "foreignobject",
    "iframe",
    "object",
    "embed",
    "image",
    "style",
}

EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

MEME_SEND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "maxLength": 120,
            "description": "用户想要的表情内容，例如“摸摸头”“累瘫”“点赞”。",
        },
        "source": {
            "type": "string",
            "enum": ["auto", "user", "system"],
            "default": "auto",
            "description": "auto 优先匹配用户上传，未匹配时使用系统默认在线来源。",
        },
    },
    "additionalProperties": False,
}

ADD_MEME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": _MAX_NAME},
        "tags": {
            "type": "array",
            "items": {"type": "string", "maxLength": _MAX_TAG_LEN},
            "maxItems": _MAX_TAGS,
        },
        "filename": {"type": "string", "minLength": 1, "maxLength": 128},
        "data_base64": {"type": "string", "minLength": 8},
    },
    "required": ["name", "filename", "data_base64"],
    "additionalProperties": False,
}

ADD_MEMES_BATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "maxLength": _MAX_NAME},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string", "maxLength": _MAX_TAG_LEN},
                        "maxItems": _MAX_TAGS,
                    },
                    "filename": {"type": "string", "minLength": 1, "maxLength": 128},
                    "data_base64": {"type": "string", "minLength": 8},
                },
                "required": ["filename", "data_base64"],
                "additionalProperties": False,
            },
        },
        "tags": {
            "type": "array",
            "items": {"type": "string", "maxLength": _MAX_TAG_LEN},
            "maxItems": _MAX_TAGS,
            "description": "批量上传时未单独指定标签的图片共用这份标签。",
        },
    },
    "required": ["items"],
    "additionalProperties": False,
}

UPDATE_MEME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "meme_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "action": {
            "type": "string",
            "enum": ["enable", "disable", "delete", "rename"],
        },
        "name": {"type": "string", "maxLength": _MAX_NAME},
        "tags": {
            "type": "array",
            "items": {"type": "string", "maxLength": _MAX_TAG_LEN},
            "maxItems": _MAX_TAGS,
        },
    },
    "required": ["meme_id", "action"],
    "additionalProperties": False,
}


def _clean_text(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _clean_tags(value: Any) -> list[str]:
    cleaned: list[str] = []
    if not isinstance(value, list):
        return cleaned
    for tag in value:
        text = _clean_text(tag, _MAX_TAG_LEN)
        if text and text not in cleaned:
            cleaned.append(text)
        if len(cleaned) >= _MAX_TAGS:
            break
    return cleaned


def _canonical_extension(value: str) -> str:
    lowered = value.lower()
    return _CANONICAL_EXTENSION.get(lowered, lowered)


def _detect_extension(filename: str, data: bytes) -> str:
    provided = _canonical_extension(Path(filename).suffix)
    if provided not in {_canonical_extension(item) for item in _ALLOWED_EXTENSIONS}:
        raise SdkError("仅支持 PNG / JPEG / GIF / WebP / SVG 图片")

    stripped = data[:1024].lstrip()
    if stripped.startswith(b"<") and b"<svg" in stripped[:512].lower():
        actual = ".svg"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        actual = ".png"
    elif data.startswith(b"\xff\xd8\xff"):
        actual = ".jpg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        actual = ".gif"
    elif len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        actual = ".webp"
    else:
        raise SdkError("图片内容与支持的格式不匹配")

    if provided != actual:
        raise SdkError("文件扩展名与实际图片格式不一致")
    return actual


def _svg_number(value: Any) -> float | None:
    text = str(value or "").strip()
    if not _SVG_NUMBER_PATTERN.fullmatch(text):
        return None
    if text.lower().endswith("px"):
        text = text[:-2]
    try:
        return float(text)
    except ValueError:
        return None


def _validate_dimensions(width: float, height: float) -> tuple[int, int]:
    if width <= 0 or height <= 0:
        raise SdkError("图片尺寸必须大于 0")
    if width > _MAX_IMAGE_DIMENSION or height > _MAX_IMAGE_DIMENSION:
        raise SdkError(f"图片边长不能超过 {_MAX_IMAGE_DIMENSION}px")
    if width * height > _MAX_IMAGE_PIXELS:
        raise SdkError("图片像素总量过大")
    return int(round(width)), int(round(height))


def _validate_svg(data: bytes) -> tuple[int, int]:
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise SdkError("SVG 不允许包含 DTD 或实体声明")
    try:
        text = data.decode("utf-8", errors="strict")
        without_declaration = re.sub(
            r"^\s*<\?xml(?:\s[^?]*)?\?>",
            "",
            text,
            count=1,
            flags=re.IGNORECASE,
        )
        if "<?" in without_declaration:
            raise SdkError("SVG 不允许包含处理指令")
        root = ElementTree.fromstring(text)
    except (UnicodeDecodeError, ElementTree.ParseError) as exc:
        raise SdkError("SVG 内容无效") from exc

    root_name = str(root.tag).rsplit("}", 1)[-1].lower()
    if root_name != "svg":
        raise SdkError("SVG 内容无效")

    for element in root.iter():
        tag_name = str(element.tag).rsplit("}", 1)[-1].lower()
        if tag_name in _SVG_FORBIDDEN_TAGS:
            raise SdkError("SVG 不允许包含脚本、外部资源或活动内容")
        for raw_name, raw_value in element.attrib.items():
            attr_name = str(raw_name).rsplit("}", 1)[-1].lower()
            attr_value = str(raw_value or "").strip()
            if attr_name.startswith("on"):
                raise SdkError("SVG 不允许包含事件属性")
            if attr_name in {"base", "style"}:
                raise SdkError("SVG 不允许包含外部资源或活动样式")
            if attr_name == "href" and attr_value and not attr_value.startswith("#"):
                raise SdkError("SVG 不允许引用外部资源")
            if _SVG_UNSAFE_TEXT.search(attr_value):
                raise SdkError("SVG 不允许包含外部资源或活动内容")

    width = _svg_number(root.attrib.get("width"))
    height = _svg_number(root.attrib.get("height"))
    if width is None or height is None:
        view_box = (
            str(root.attrib.get("viewBox") or root.attrib.get("viewbox") or "")
            .replace(",", " ")
            .split()
        )
        if len(view_box) == 4:
            try:
                width = abs(float(view_box[2]))
                height = abs(float(view_box[3]))
            except ValueError:
                width = height = None
    if width is None or height is None:
        raise SdkError("SVG 必须声明可验证的 width/height 或 viewBox")
    return _validate_dimensions(width, height)


def _validate_raster(data: bytes, expected_ext: str) -> tuple[int, int]:
    format_extensions = {
        "PNG": ".png",
        "JPEG": ".jpg",
        "GIF": ".gif",
        "WEBP": ".webp",
    }
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as image:
                actual_ext = format_extensions.get(str(image.format or "").upper())
                if actual_ext != expected_ext:
                    raise SdkError("图片 MIME 与实际解码格式不一致")
                width, height = _validate_dimensions(*image.size)
                frame_count = int(getattr(image, "n_frames", 1) or 1)
                if frame_count > _MAX_ANIMATION_FRAMES:
                    raise SdkError(f"动图帧数不能超过 {_MAX_ANIMATION_FRAMES} 帧")
                image.verify()
                return width, height
    except SdkError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        ValueError,
    ) as exc:
        raise SdkError("图片无法安全解码") from exc


def _validate_image_payload(filename: str, data: bytes) -> tuple[str, int, int]:
    if not data:
        raise SdkError("图片内容为空")
    if len(data) > _MAX_UPLOAD_BYTES:
        raise SdkError(f"图片超过 {_MAX_UPLOAD_BYTES // 1024 // 1024}MB 上传上限")
    ext = _detect_extension(filename, data)
    if ext == ".svg":
        width, height = _validate_svg(data)
    else:
        width, height = _validate_raster(data, ext)
    return ext, width, height


def _encode_under_limit(
    encode: Any,
    *,
    quality_start: int = 88,
    quality_floor: int = 35,
    scale_floor: float = 0.2,
) -> bytes | None:
    """Try quality then downscale steps until the payload fits _MAX_IMAGE_BYTES."""
    for quality in range(quality_start, quality_floor - 1, -8):
        candidate = encode(1.0, quality)
        if candidate is not None and len(candidate) <= _MAX_IMAGE_BYTES:
            return candidate
    scale = 0.85
    while scale >= scale_floor:
        for quality in (quality_start, 60, quality_floor):
            candidate = encode(scale, quality)
            if candidate is not None and len(candidate) <= _MAX_IMAGE_BYTES:
                return candidate
        scale *= 0.7
    return None


def _normalize_image_payload(
    filename: str, data: bytes
) -> tuple[bytes, str, int, int, bool]:
    """Validate, then shrink/re-encode raster uploads that exceed the stored
    size limit so chat messages stay small. Returns
    ``(payload, ext, width, height, compressed)``."""
    ext, width, height = _validate_image_payload(filename, data)
    if ext == ".svg":
        if len(data) > _MAX_IMAGE_BYTES:
            raise SdkError(
                f"SVG 超过 {_MAX_IMAGE_BYTES // 1024 // 1024}MB 上限且无法自动压缩"
            )
        return data, ext, width, height, False

    oversized = len(data) > _MAX_IMAGE_BYTES
    too_large = max(width, height) > _TARGET_IMAGE_DIMENSION
    if not oversized and not too_large:
        return data, ext, width, height, False
    # Already small enough on disk and only mildly over the target edge:
    # keep the original pixels (preserves GIF animation and quality).
    if not oversized and max(width, height) <= 2 * _TARGET_IMAGE_DIMENSION:
        return data, ext, width, height, False

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as source:
                source.load()
                is_gif = ext == ".gif"
                animated = bool(getattr(source, "is_animated", False))
                if is_gif and animated:
                    # Re-encoding animated GIFs frame-by-frame is lossy and
                    # slow; only allow shrinking when it fits after a resize.
                    frames = []
                    durations = []
                    disposal = []
                    for index in range(int(getattr(source, "n_frames", 1) or 1)):
                        source.seek(index)
                        frame = source.convert("RGBA")
                        frames.append(frame)
                        durations.append(int(source.info.get("duration", 100)))
                        disposal.append(getattr(source, "disposal_method", 0))
                    base_w, base_h = frames[0].size

                    def encode_gif(scale: float, _quality: int) -> bytes | None:
                        target_w = max(1, int(base_w * scale))
                        target_h = max(1, int(base_h * scale))
                        if target_w > _TARGET_IMAGE_DIMENSION or target_h > _TARGET_IMAGE_DIMENSION:
                            ratio = _TARGET_IMAGE_DIMENSION / max(target_w, target_h)
                            target_w = max(1, int(target_w * ratio))
                            target_h = max(1, int(target_h * ratio))
                        resized = [
                            frame.resize((target_w, target_h), Image.Resampling.LANCZOS)
                            for frame in frames
                        ]
                        buffer = BytesIO()
                        resized[0].save(
                            buffer,
                            format="GIF",
                            save_all=True,
                            append_images=resized[1:],
                            duration=durations,
                            loop=int(source.info.get("loop", 0) or 0),
                            disposal=disposal,
                            optimize=True,
                        )
                        return buffer.getvalue()

                    payload = _encode_under_limit(encode_gif, quality_start=80)
                    if payload is None:
                        raise SdkError(
                            "动图 GIF 过大且自动压缩后仍超过 "
                            f"{_MAX_IMAGE_BYTES // 1024 // 1024}MB，请先自行压缩"
                        )
                    with Image.open(BytesIO(payload)) as check:
                        new_w, new_h = check.size
                    return payload, ".gif", new_w, new_h, True

                # Static raster: JPEG/WebP keep format, PNG falls back to
                # JPEG when it cannot fit (memes rarely need alpha at 2MB+).
                image = source
                if image.mode not in {"RGB", "RGBA", "P", "L", "LA"}:
                    image = image.convert("RGBA")
                has_alpha = image.mode in {"RGBA", "LA"} or (
                    image.mode == "P" and "transparency" in image.info
                )
                base = image.convert("RGBA") if has_alpha else image.convert("RGB")
                base_w, base_h = base.size

                def make_encoder(fmt: str) -> Any:
                    def encode(scale: float, quality: int) -> bytes | None:
                        target_w = max(1, int(base_w * scale))
                        target_h = max(1, int(base_h * scale))
                        if target_w > _TARGET_IMAGE_DIMENSION or target_h > _TARGET_IMAGE_DIMENSION:
                            ratio = _TARGET_IMAGE_DIMENSION / max(target_w, target_h)
                            target_w = max(1, int(target_w * ratio))
                            target_h = max(1, int(target_h * ratio))
                        working = (
                            base
                            if (target_w, target_h) == base.size
                            else base.resize((target_w, target_h), Image.Resampling.LANCZOS)
                        )
                        buffer = BytesIO()
                        if fmt == "PNG":
                            working.save(buffer, format="PNG", optimize=True)
                        elif fmt == "WEBP":
                            working.save(
                                buffer, format="WEBP", quality=quality, method=6
                            )
                        else:
                            working.convert("RGB").save(
                                buffer,
                                format="JPEG",
                                quality=quality,
                                optimize=True,
                                progressive=True,
                            )
                        return buffer.getvalue()

                    return encode

                candidates = [(".webp", make_encoder("WEBP"))]
                if ext == ".png" and has_alpha:
                    candidates.insert(0, (".png", make_encoder("PNG")))
                if ext == ".jpg":
                    candidates.insert(0, (".jpg", make_encoder("JPEG")))

                for new_ext, encoder in candidates:
                    payload = _encode_under_limit(encoder)
                    if payload is None:
                        continue
                    new_ext_actual, new_w, new_h = _validate_image_payload(
                        f"normalized{new_ext}", payload
                    )
                    return payload, new_ext_actual, new_w, new_h, True
                raise SdkError(
                    "图片自动压缩后仍超过 "
                    f"{_MAX_IMAGE_BYTES // 1024 // 1024}MB，请先自行压缩"
                )
    except SdkError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        ValueError,
    ) as exc:
        raise SdkError("图片无法安全解码") from exc


def _validate_image_bytes(filename: str, data: bytes) -> str:
    return _validate_image_payload(filename, data)[0]


def _matches(meme: Mapping[str, Any], query: str) -> bool:
    if not query:
        return True
    haystacks = [str(meme.get("name") or "")]
    haystacks.extend(str(tag) for tag in meme.get("tags") or [])
    query_lower = query.lower()
    return any(query_lower in hay.lower() for hay in haystacks)


def _plugin_server_base() -> str:
    for variable in (
        "NEKO_PLUGIN_SERVER_ORIGIN",
        "NEKO_USER_PLUGIN_SERVER_ORIGIN",
        "NEKO_SERVER_ORIGIN",
    ):
        raw_origin = os.getenv(variable, "").strip().rstrip("/")
        try:
            parsed = urlsplit(raw_origin)
            if (
                parsed.scheme in {"http", "https"}
                and parsed.hostname
                and parsed.username is None
                and parsed.password is None
                and parsed.path in {"", "/"}
                and not parsed.query
                and not parsed.fragment
            ):
                _ = parsed.port
                return raw_origin
        except ValueError:
            continue

    raw_port = os.getenv("NEKO_USER_PLUGIN_SERVER_PORT", "").strip()
    port = 48916
    valid_port = False
    if raw_port:
        try:
            candidate = int(raw_port)
            if 0 < candidate <= 65535:
                port = candidate
                valid_port = True
        except ValueError:
            pass
    if not valid_port:
        try:
            from config import USER_PLUGIN_SERVER_PORT

            candidate = int(USER_PLUGIN_SERVER_PORT)
            if 0 < candidate <= 65535:
                port = candidate
        except (ImportError, TypeError, ValueError):
            pass
    return f"http://127.0.0.1:{port}"


def _main_server_base() -> str:
    raw_origin = os.getenv("NEKO_MAIN_SERVER_ORIGIN", "").strip().rstrip("/")
    try:
        parsed = urlsplit(raw_origin)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        ):
            _ = parsed.port
            return raw_origin
    except ValueError:
        pass

    port = 48911
    for variable in ("NEKO_MAIN_SERVER_PORT", "MAIN_SERVER_PORT"):
        raw_port = os.getenv(variable, "").strip()
        if not raw_port:
            continue
        try:
            candidate = int(raw_port)
            if 0 < candidate <= 65535:
                port = candidate
                break
        except ValueError:
            continue
    else:
        try:
            from config import MAIN_SERVER_PORT

            candidate = int(MAIN_SERVER_PORT)
            if 0 < candidate <= 65535:
                port = candidate
        except (ImportError, TypeError, ValueError):
            pass
    return f"http://127.0.0.1:{port}"


def _safe_stored_name(value: Any) -> str | None:
    name = str(value or "")
    if Path(name).name != name or not _STORED_NAME_PATTERN.fullmatch(name):
        return None
    return name.lower()


def _public_path(meme: Mapping[str, Any]) -> str:
    stored_name = _safe_stored_name(meme.get("stored_name"))
    if stored_name is None:
        raise SdkError("表情包文件路径无效")
    return f"/plugin/{PLUGIN_ID}/ui/memes/{quote(stored_name, safe='')}"


def _public_url(meme: Mapping[str, Any]) -> str:
    return f"{_plugin_server_base()}{_public_path(meme)}"


def _system_proxy_url(remote_url: str) -> str:
    return f"/api/meme/proxy-image?url={quote(remote_url, safe='')}"


def _system_sources() -> list[dict[str, Any]]:
    return [
        {
            "id": _SYSTEM_SOURCE_ID,
            "name": "N.E.K.O 系统默认",
            "kind": "online_search",
            "origin": "system_default",
            "source": "utils.meme_fetcher.fetch_meme_content",
            "providers": ["斗图啦", "发表情", "Imgflip"],
            "selection": "按语言和地区自动选择，在线按需搜索",
            "description": (
                "沿用猫娘原本的在线搜索（斗图啦、发表情、Imgflip）；"
                "图片会经过系统安全检查和代理加载。"
            ),
            "read_only": True,
            "can_delete": False,
            "can_edit": False,
            "can_toggle": False,
            "enabled": True,
            "available": None,
            "availability": "on_demand",
        }
    ]


def _is_allowed_system_url(url: str) -> bool:
    try:
        from utils.meme_fetcher import MEME_ALLOWED_HOSTS

        parsed = urlsplit(url)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    hostname = (parsed.hostname or "").strip(".").lower()
    if not hostname:
        return False
    return any(
        hostname == str(allowed).lower()
        or hostname.endswith("." + str(allowed).lower())
        for allowed in MEME_ALLOWED_HOSTS
    )


def _store_enabled_setting(config: Any) -> bool | None:
    if not isinstance(config, Mapping):
        return None
    wrapped = config.get("config")
    if isinstance(wrapped, Mapping):
        nested = _store_enabled_setting(wrapped)
        if nested is not None:
            return nested
    plugin_cfg = config.get("plugin")
    if not isinstance(plugin_cfg, Mapping):
        return None
    store_cfg = plugin_cfg.get("store")
    if not isinstance(store_cfg, Mapping):
        return None
    enabled = store_cfg.get("enabled")
    return enabled if type(enabled) is bool else None


def _markdown_alt(value: Any) -> str:
    return _clean_text(value, _MAX_NAME).replace("[", "（").replace("]", "）")


@neko_plugin
class MemeManagerPlugin(NekoPluginBase):
    """Persistent user memes bridged with the host online meme catalog."""

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._library_lock = threading.RLock()
        self._meme_dir: Path | None = None
        self._runtime_ui_dir: Path | None = None
        self._effective_config: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Effective config and runtime assets
    # ------------------------------------------------------------------

    def refresh_runtime_config(
        self,
        effective_config: dict[str, object] | None = None,
    ) -> None:
        raw_config: Any = effective_config
        if not isinstance(raw_config, Mapping):
            raw_config = getattr(self.ctx, "_effective_config", None)
        if not isinstance(raw_config, Mapping):
            raw_config = getattr(
                getattr(self, "_host_ctx", None), "_effective_config", None
            )
        config = dict(raw_config) if isinstance(raw_config, Mapping) else {}
        super().refresh_runtime_config(config)
        self.store.enabled = _store_enabled_setting(config) is True
        self._effective_config = config

    async def _reconcile_store_from_effective_config(self) -> dict[str, Any]:
        candidates: list[Mapping[str, Any]] = []
        try:
            dumped = await self.config.dump(timeout=5.0)
            if isinstance(dumped, Mapping):
                candidates.append(dumped)
        except Exception as exc:
            self.logger.warning("meme_manager effective config read failed: {}", exc)

        for context in (
            self.ctx,
            getattr(self, "_host_ctx", None),
            getattr(self.ctx, "_host_ctx", None),
        ):
            effective = getattr(context, "_effective_config", None)
            if isinstance(effective, Mapping):
                candidates.append(effective)
            direct_config = getattr(context, "config", None)
            if isinstance(direct_config, Mapping):
                candidates.append(direct_config)

        selected: dict[str, Any] = {}
        store_enabled = False
        for candidate in candidates:
            if not selected:
                selected = dict(candidate)
            setting = _store_enabled_setting(candidate)
            if setting is not None:
                store_enabled = setting is True
                selected = dict(candidate)
                break
        self.store.enabled = store_enabled
        self._effective_config = selected
        return selected

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_bytes(data)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _prepare_runtime_ui(self) -> bool:
        source_index = self.config_dir / "static" / "index.html"
        if not source_index.is_file():
            raise SdkError("管理面板资源缺失")

        runtime_ui = self.data_path("ui")
        meme_dir = runtime_ui / "memes"
        runtime_ui.mkdir(parents=True, exist_ok=True)
        meme_dir.mkdir(parents=True, exist_ok=True)

        target_index = runtime_ui / "index.html"
        source_bytes = source_index.read_bytes()
        if not target_index.is_file() or target_index.read_bytes() != source_bytes:
            self._atomic_write(target_index, source_bytes)

        self._runtime_ui_dir = runtime_ui
        self._meme_dir = meme_dir
        if not self.register_static_ui(
            str(runtime_ui),
            cache_control="private, max-age=300",
        ):
            raise SdkError("管理面板注册失败")
        return True

    def _migrate_legacy_assets(self) -> None:
        if self._meme_dir is None:
            return
        legacy_dir = self.config_dir / "static" / "memes"
        if not legacy_dir.is_dir() or legacy_dir.resolve() == self._meme_dir.resolve():
            return
        with self._library_lock:
            library = self._load_library()
            for meme in library["memes"]:
                stored_name = _safe_stored_name(meme.get("stored_name"))
                if stored_name is None:
                    continue
                source = legacy_dir / stored_name
                target = self._meme_dir / stored_name
                if target.exists() or not source.is_file():
                    continue
                try:
                    data = source.read_bytes()
                    _validate_image_payload(stored_name, data)
                    self._atomic_write(target, data)
                except (OSError, SdkError) as exc:
                    self.logger.warning(
                        "meme_manager legacy asset migration skipped: {}", exc
                    )

    # ------------------------------------------------------------------
    # Store helpers
    # ------------------------------------------------------------------

    def _normalize_meme(self, raw: Any) -> dict[str, Any] | None:
        if not isinstance(raw, Mapping):
            return None
        meme_id = _clean_text(raw.get("id"), 64)
        name = _clean_text(raw.get("name"), _MAX_NAME)
        stored_name = _safe_stored_name(raw.get("stored_name"))
        if not meme_id or not name or stored_name is None:
            return None
        try:
            size_bytes = max(0, int(raw.get("size_bytes") or 0))
        except (TypeError, ValueError):
            size_bytes = 0
        try:
            created_at = float(raw.get("created_at") or 0)
        except (TypeError, ValueError):
            created_at = 0.0
        try:
            width = max(0, int(raw.get("width") or 0))
            height = max(0, int(raw.get("height") or 0))
        except (TypeError, ValueError):
            width = height = 0
        return {
            "id": meme_id,
            "name": name,
            "tags": _clean_tags(raw.get("tags")),
            "enabled": bool(raw.get("enabled", True)),
            "stored_name": stored_name,
            "mime": _MIME_BY_EXT.get(Path(stored_name).suffix.lower(), ""),
            "size_bytes": size_bytes,
            "width": width,
            "height": height,
            "created_at": created_at,
        }

    def _load_library(self) -> dict[str, Any]:
        if not self.store.enabled:
            return {"memes": []}
        raw = self.store._read_value(_STORE_KEY, {"memes": []})
        if not isinstance(raw, Mapping) or not isinstance(raw.get("memes"), list):
            return {"memes": []}
        memes: list[dict[str, Any]] = []
        for item in raw["memes"]:
            normalized = self._normalize_meme(item)
            if normalized is not None:
                memes.append(normalized)
        library: dict[str, Any] = {"memes": memes}
        # Preserve non-meme sections (e.g. the vision tagger config) verbatim.
        tagger = raw.get("tagger")
        if isinstance(tagger, Mapping):
            library["tagger"] = dict(tagger)
        return library

    def _save_library(self, library: Mapping[str, Any]) -> None:
        if not self.store.enabled:
            raise SdkError("PluginStore 不可用，无法持久化用户上传")
        raw_memes = library.get("memes")
        if not isinstance(raw_memes, list):
            raise SdkError("表情包目录数据无效")
        payload: dict[str, Any] = {"memes": raw_memes}
        tagger = library.get("tagger")
        if isinstance(tagger, Mapping):
            payload["tagger"] = dict(tagger)
        self.store._write_value(_STORE_KEY, payload)

    def _asset_path(self, stored_name: Any) -> Path:
        if self._meme_dir is None:
            raise SdkError("插件尚未启动完成")
        safe_name = _safe_stored_name(stored_name)
        if safe_name is None:
            raise SdkError("表情包文件路径无效")
        target = self._meme_dir / safe_name
        if target.parent.resolve() != self._meme_dir.resolve():
            raise SdkError("表情包文件路径无效")
        return target

    def _public_user_item(self, meme: Mapping[str, Any]) -> dict[str, Any]:
        target = self._asset_path(meme.get("stored_name"))
        return {
            "id": meme["id"],
            "name": meme["name"],
            "tags": list(meme.get("tags") or []),
            "enabled": bool(meme.get("enabled", True)),
            "url": _public_path(meme),
            "origin": "user_upload",
            "kind": "image",
            "source": "用户上传",
            "read_only": False,
            "can_delete": True,
            "can_edit": True,
            "can_toggle": True,
            "available": target.is_file(),
            "created_at": meme.get("created_at", 0),
            "size_bytes": meme.get("size_bytes", 0),
            "width": meme.get("width", 0),
            "height": meme.get("height", 0),
            "mime": meme.get("mime", ""),
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        await self._reconcile_store_from_effective_config()
        try:
            self._prepare_runtime_ui()
            self._migrate_legacy_assets()
        except (OSError, SdkError) as exc:
            self.logger.warning("meme_manager startup failed: {}", exc)
            raise SdkError(str(exc)) from exc
        return Ok(
            {
                "started": True,
                "store_ready": bool(self.store.enabled),
                "system_source_count": len(_system_sources()),
            }
        )

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        try:
            result = await self.store.close()
        except Exception as exc:
            self.logger.warning("meme_manager store close failed: {}", exc)
            return Err(SdkError("PluginStore 关闭失败"))
        if result.is_err():
            self.logger.warning("meme_manager store close failed: {}", result.error)
            return Err(SdkError("PluginStore 关闭失败"))
        return Ok({"stopped": True})

    # ------------------------------------------------------------------
    # Panel entries
    # ------------------------------------------------------------------

    @plugin_entry(
        id="get_panel_state",
        name="读取统一表情包目录",
        description="列出系统默认来源、用户上传、统计和安全上限。",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 120}},
            "additionalProperties": False,
        },
        timeout=15.0,
    )
    async def get_panel_state(self, query: Any = "", **_: Any):
        try:
            query_text = _clean_text(query, 120)
            with self._library_lock:
                library = self._load_library()
                user_memes = [
                    self._public_user_item(meme)
                    for meme in library["memes"]
                    if _matches(meme, query_text)
                ]
                user_memes.sort(key=lambda item: -float(item.get("created_at") or 0))
                enabled_count = sum(
                    1 for item in library["memes"] if item.get("enabled", True)
                )
                total = len(library["memes"])
            system_sources = _system_sources()
            tagger = self._tagger_config()
            return Ok(
                {
                    "system_sources": system_sources,
                    "user_memes": user_memes,
                    "memes": user_memes,
                    "catalog": [*system_sources, *user_memes],
                    "catalog_total": len(system_sources) + total,
                    "total": total,
                    "enabled_count": enabled_count,
                    "max_memes": _MAX_MEMES,
                    "max_image_bytes": _MAX_IMAGE_BYTES,
                    "max_image_dimension": _MAX_IMAGE_DIMENSION,
                    "store_ready": bool(self.store.enabled),
                    "tagger": {
                        "api_base": tagger["api_base"],
                        "model": tagger["model"],
                        "key_configured": bool(tagger["api_key"]),
                    },
                    "status_message": (
                        "系统默认来源已接入（在线按需搜索）；用户上传会持久保存。"
                        if self.store.enabled
                        else "系统默认来源已接入（在线按需搜索）；用户上传存储当前未启用。"
                    ),
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager panel state failed: {}", exc)
            return Err(SdkError("表情包目录暂时不可用"))

    async def _store_single_meme(
        self,
        *,
        name: Any,
        filename: Any,
        data_base64: Any,
        tags: Any,
    ) -> dict[str, Any]:
        """Validate, normalize (auto-compress), persist one upload. Raises
        SdkError on any validation/storage failure; caller handles cleanup
        expectations via the returned ``created_file`` flag."""
        if self._meme_dir is None:
            raise SdkError("插件尚未启动完成")
        clean_name = _clean_text(name, _MAX_NAME)
        if not clean_name:
            raise SdkError("名称不能为空")
        clean_filename = Path(str(filename or "")).name[:128]
        if not clean_filename:
            raise SdkError("文件名无效")
        encoded = str(data_base64 or "")
        if len(encoded) > ((_MAX_UPLOAD_BYTES * 4) // 3) + 4096:
            raise SdkError(f"图片超过 {_MAX_UPLOAD_BYTES // 1024 // 1024}MB 上传上限")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SdkError("图片数据不是有效的 base64") from exc
        data, ext, width, height, compressed = _normalize_image_payload(
            clean_filename, data
        )
        digest = hashlib.sha256(data).hexdigest()[:16]
        stored_name = f"{digest}{ext}"
        target = self._asset_path(stored_name)
        created_file = False

        with self._library_lock:
            library = self._load_library()
            if len(library["memes"]) >= _MAX_MEMES:
                raise SdkError(f"用户上传已满（{_MAX_MEMES} 张）")
            if not target.exists():
                self._atomic_write(target, data)
                created_file = True
            meme = {
                "id": f"meme-{uuid4().hex}",
                "name": clean_name,
                "tags": _clean_tags(tags),
                "enabled": True,
                "stored_name": stored_name,
                "mime": _MIME_BY_EXT[ext],
                "size_bytes": len(data),
                "width": width,
                "height": height,
                "created_at": time.time(),
            }
            library["memes"].append(meme)
            try:
                self._save_library(library)
            except Exception:
                if created_file:
                    target.unlink(missing_ok=True)
                raise
        return {
            "meme": {**self._public_user_item(meme), "stored_name": stored_name},
            "compressed": compressed,
        }

    @plugin_entry(
        id="add_meme",
        name="添加用户表情包",
        description="上传一张经过格式、解码、尺寸和路径校验的图片；过大的光栅图会自动压缩。",
        input_schema=ADD_MEME_SCHEMA,
        timeout=60.0,
    )
    async def add_meme(
        self,
        name: Any = "",
        filename: Any = "",
        data_base64: Any = "",
        tags: Any = None,
        **_: Any,
    ):
        try:
            result = await self._store_single_meme(
                name=name,
                filename=filename,
                data_base64=data_base64,
                tags=tags,
            )
            message = "已保存到用户上传，刷新或重启后仍会保留。"
            if result["compressed"]:
                message = "已自动压缩并保存到用户上传，刷新或重启后仍会保留。"
            return Ok(
                {
                    "saved": True,
                    "compressed": result["compressed"],
                    "message": message,
                    "meme": result["meme"],
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager add failed: {}", exc)
            return Err(SdkError("表情包保存失败"))

    @plugin_entry(
        id="add_memes_batch",
        name="批量添加用户表情包",
        description=(
            "一次上传多张图片（例如整个文件夹），每张独立校验并在需要时自动压缩；"
            "单张失败不影响其它图片。"
        ),
        input_schema=ADD_MEMES_BATCH_SCHEMA,
        timeout=300.0,
    )
    async def add_memes_batch(
        self,
        items: Any = None,
        tags: Any = None,
        **_: Any,
    ):
        try:
            if not isinstance(items, list) or not items:
                return Err(SdkError("批量上传需要至少一张图片"))
            if len(items) > _MAX_BATCH_ITEMS:
                return Err(SdkError(f"单次批量上传最多 {_MAX_BATCH_ITEMS} 张"))
            shared_tags = _clean_tags(tags)
            results: list[dict[str, Any]] = []
            saved = 0
            compressed_count = 0
            for position, raw_item in enumerate(items):
                if not isinstance(raw_item, Mapping):
                    results.append(
                        {
                            "index": position,
                            "ok": False,
                            "error": "条目格式无效",
                        }
                    )
                    continue
                raw_name = raw_item.get("name")
                clean_filename = Path(str(raw_item.get("filename") or "")).name
                fallback_name = Path(clean_filename).stem if clean_filename else ""
                item_name = _clean_text(raw_name, _MAX_NAME) or _clean_text(
                    fallback_name, _MAX_NAME
                )
                item_tags = (
                    _clean_tags(raw_item.get("tags"))
                    if raw_item.get("tags") is not None
                    else shared_tags
                )
                try:
                    stored = await self._store_single_meme(
                        name=item_name,
                        filename=raw_item.get("filename"),
                        data_base64=raw_item.get("data_base64"),
                        tags=item_tags,
                    )
                except SdkError as exc:
                    results.append(
                        {
                            "index": position,
                            "ok": False,
                            "name": item_name,
                            "filename": clean_filename[:128],
                            "error": str(exc),
                        }
                    )
                    continue
                except Exception as exc:
                    self.logger.warning(
                        "meme_manager batch item {} failed: {}", position, exc
                    )
                    results.append(
                        {
                            "index": position,
                            "ok": False,
                            "name": item_name,
                            "filename": clean_filename[:128],
                            "error": "表情包保存失败",
                        }
                    )
                    continue
                saved += 1
                compressed_count += 1 if stored["compressed"] else 0
                results.append(
                    {
                        "index": position,
                        "ok": True,
                        "name": stored["meme"].get("name"),
                        "compressed": stored["compressed"],
                        "meme": stored["meme"],
                    }
                )
            return Ok(
                {
                    "saved": saved,
                    "failed": len(results) - saved,
                    "compressed": compressed_count,
                    "total": len(results),
                    "results": results,
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager batch add failed: {}", exc)
            return Err(SdkError("批量保存失败"))

    @plugin_entry(
        id="update_meme",
        name="管理用户表情包",
        description="启用、禁用、删除或编辑一张用户上传表情包。",
        input_schema=UPDATE_MEME_SCHEMA,
        timeout=15.0,
    )
    async def update_meme(
        self,
        meme_id: Any = "",
        action: Any = "",
        name: Any = None,
        tags: Any = None,
        **_: Any,
    ):
        try:
            meme_id_text = _clean_text(meme_id, 64)
            action_text = _clean_text(action, 16)
            if meme_id_text.startswith("system:"):
                raise SdkError("系统默认来源为只读，不能删除、编辑或关闭")

            victim: Path | None = None
            updated_item: dict[str, Any] | None = None
            with self._library_lock:
                library = self._load_library()
                target = next(
                    (
                        item
                        for item in library["memes"]
                        if item.get("id") == meme_id_text
                    ),
                    None,
                )
                if target is None:
                    raise SdkError("没有找到这张用户上传表情包")
                if action_text == "delete":
                    library["memes"] = [
                        item
                        for item in library["memes"]
                        if item.get("id") != meme_id_text
                    ]
                    still_used = any(
                        item.get("stored_name") == target.get("stored_name")
                        for item in library["memes"]
                    )
                    if not still_used:
                        victim = self._asset_path(target.get("stored_name"))
                elif action_text in {"enable", "disable"}:
                    target["enabled"] = action_text == "enable"
                    updated_item = target
                elif action_text == "rename":
                    clean_name = _clean_text(name, _MAX_NAME)
                    if not clean_name:
                        raise SdkError("名称不能为空")
                    target["name"] = clean_name
                    if isinstance(tags, list):
                        target["tags"] = _clean_tags(tags)
                    updated_item = target
                else:
                    raise SdkError("不支持的操作")
                self._save_library(library)

            if victim is not None:
                try:
                    victim.unlink(missing_ok=True)
                except OSError as exc:
                    self.logger.warning("meme_manager orphan cleanup failed: {}", exc)
            return Ok(
                {
                    "updated": True,
                    "action": action_text,
                    "meme_id": meme_id_text,
                    "message": (
                        "用户上传已删除。"
                        if action_text == "delete"
                        else "更改已保存，刷新或重启后仍会保留。"
                    ),
                    "meme": (
                        self._public_user_item(updated_item)
                        if updated_item is not None
                        else None
                    ),
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager update failed: {}", exc)
            return Err(SdkError("表情包更新失败"))

    @plugin_entry(
        id="restore_defaults",
        name="恢复系统默认目录",
        description="删除全部用户上传，只保留不可修改的系统默认在线来源。",
        input_schema=EMPTY_SCHEMA,
        timeout=20.0,
    )
    async def restore_defaults(self, **_: Any):
        try:
            victims: set[Path] = set()
            with self._library_lock:
                library = self._load_library()
                for meme in library["memes"]:
                    victims.add(self._asset_path(meme.get("stored_name")))
                removed = len(library["memes"])
                self._save_library({"memes": []})
            cleanup_failures = 0
            for victim in victims:
                try:
                    victim.unlink(missing_ok=True)
                except OSError as exc:
                    cleanup_failures += 1
                    self.logger.warning("meme_manager reset cleanup failed: {}", exc)
            return Ok(
                {
                    "restored": True,
                    "removed": removed,
                    "cleanup_failures": cleanup_failures,
                    "message": (f"已移除 {removed} 个用户上传，系统默认来源保持不变。"),
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager restore defaults failed: {}", exc)
            return Err(SdkError("恢复系统默认目录失败"))

    # ------------------------------------------------------------------
    # Vision-model "one-click tag generation"
    #
    # Users who don't want to hand-write tags can point the plugin at any
    # OpenAI-compatible vision chat endpoint (their own API key). The plugin
    # sends the stored image inline and asks for a small JSON tag list, then
    # merges the result into that meme's tags. Secrets stay server-side and
    # are never echoed into results/logs.
    # ------------------------------------------------------------------

    _TAGGER_DEFAULT_BASE = "https://api.openai.com/v1"
    _TAGGER_DEFAULT_MODEL = "gpt-4o-mini"

    def _tagger_config(self) -> dict[str, str]:
        with self._library_lock:
            library = self._load_library()
        raw = library.get("tagger")
        cfg = raw if isinstance(raw, Mapping) else {}
        base = str(cfg.get("api_base") or "").strip() or self._TAGGER_DEFAULT_BASE
        model = str(cfg.get("model") or "").strip() or self._TAGGER_DEFAULT_MODEL
        return {
            "api_base": base.rstrip("/"),
            "api_key": str(cfg.get("api_key") or "").strip(),
            "model": model,
        }

    def _save_tagger_config(self, cfg: Mapping[str, str]) -> None:
        with self._library_lock:
            library = self._load_library()
            library["tagger"] = {
                "api_base": str(cfg.get("api_base") or "").rstrip("/"),
                "api_key": str(cfg.get("api_key") or "").strip(),
                "model": str(cfg.get("model") or "").strip(),
            }
            self._save_library(library)

    @plugin_entry(
        id="save_tagger_settings",
        name="保存标签生成模型设置",
        description="保存用于一键生成标签的视觉模型连接信息（API 地址、密钥、模型名）。",
        input_schema={
            "type": "object",
            "properties": {
                "api_base": {"type": "string", "maxLength": 200},
                "api_key": {"type": "string", "maxLength": 200},
                "model": {"type": "string", "maxLength": 100},
            },
            "additionalProperties": False,
        },
        timeout=10.0,
    )
    async def save_tagger_settings(
        self,
        api_base: Any = None,
        api_key: Any = None,
        model: Any = None,
        **_: Any,
    ):
        try:
            current = self._tagger_config()
            new_cfg = {
                "api_base": (
                    _clean_text(api_base, 200)
                    if api_base is not None
                    else current["api_base"]
                ),
                # Empty string = keep existing key; panel sends the key only
                # when the user actually typed a new one.
                "api_key": (
                    str(api_key).strip()
                    if api_key is not None and str(api_key).strip()
                    else current["api_key"]
                ),
                "model": (
                    _clean_text(model, 100)
                    if model is not None
                    else current["model"]
                ),
            }
            base = new_cfg["api_base"] or self._TAGGER_DEFAULT_BASE
            if not base.startswith(("https://", "http://127.0.0.1", "http://localhost")):
                raise SdkError("API 地址必须是 https（本机可用 http）")
            new_cfg["api_base"] = base
            if not new_cfg["model"]:
                raise SdkError("模型名不能为空")
            self._save_tagger_config(new_cfg)
            return Ok(
                {
                    "saved": True,
                    "api_base": new_cfg["api_base"],
                    "model": new_cfg["model"],
                    "key_configured": bool(new_cfg["api_key"]),
                    "message": "标签生成模型已保存。",
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager tagger settings failed: {}", exc)
            return Err(SdkError("保存标签生成设置失败"))

    async def _request_tags_for_image(
        self,
        *,
        cfg: Mapping[str, str],
        mime: str,
        data: bytes,
    ) -> list[str]:
        """Call the user's vision model and return a clean tag list.

        Raises SdkError with a human-actionable message on any failure."""
        import json as _json

        import httpx

        if not cfg.get("api_key"):
            raise SdkError("还没有配置视觉模型密钥；请先在面板里保存")
        b64 = base64.b64encode(data).decode("ascii")
        payload = {
            "model": cfg["model"],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "给这张表情包图片生成 3-8 个简短检索标签。"
                                "标签用来按关键词搜到它，覆盖：画面主体、情绪/含义、"
                                "常见使用场景、图上文字（如有）。"
                                "只返回 JSON 数组，例如 [\"猫猫\",\"疑惑\",\"挠头\"]，不要解释。"
                            ),
                        },
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{mime};base64,{b64}"},
                        },
                    ],
                }
            ],
            "max_tokens": 200,
        }
        url = f"{cfg['api_base']}/chat/completions"
        try:
            async with httpx.AsyncClient(timeout=45.0, trust_env=True) as client:
                response = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {cfg['api_key']}"},
                    json=payload,
                )
        except Exception as exc:
            raise SdkError("连不上标签生成服务；请检查网络或 API 地址") from exc
        if response.status_code in {401, 403}:
            raise SdkError("视觉模型密钥无效或没有权限；请检查后重新保存")
        if response.status_code == 404:
            raise SdkError("这个模型名不存在或不支持图片输入；请检查模型设置")
        if response.status_code >= 400:
            raise SdkError(f"标签生成服务出错（HTTP {response.status_code}）")
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
        except Exception as exc:
            raise SdkError("标签生成服务返回了无法识别的内容") from exc
        # Tolerate models that wrap the array in prose or a code fence.
        match = re.search(r"\[[^\[\]]*\]", str(content), re.DOTALL)
        if match is None:
            raise SdkError("模型没有返回标签；请重试或更换模型")
        try:
            raw_tags = _json.loads(match.group(0))
        except ValueError as exc:
            raise SdkError("模型返回的标签格式不对；请重试") from exc
        if not isinstance(raw_tags, list):
            raise SdkError("模型返回的标签格式不对；请重试")
        tags = _clean_tags([str(item) for item in raw_tags])
        if not tags:
            raise SdkError("模型没有给出可用标签；请重试")
        return tags[:8]

    @plugin_entry(
        id="generate_tags",
        name="一键生成标签",
        description=(
            "用用户配置的视觉模型为一张用户上传的表情包自动生成检索标签并合并保存。"
        ),
        input_schema={
            "type": "object",
            "properties": {"meme_id": {"type": "string", "maxLength": 64}},
            "required": ["meme_id"],
            "additionalProperties": False,
        },
        timeout=60.0,
    )
    async def generate_tags(self, meme_id: Any = "", **_: Any):
        try:
            meme_id_text = _clean_text(meme_id, 64)
            if not meme_id_text:
                raise SdkError("缺少 meme_id")
            cfg = self._tagger_config()
            if not cfg["api_key"]:
                raise SdkError("还没有配置视觉模型密钥；请先在面板里保存")

            with self._library_lock:
                library = self._load_library()
                target = next(
                    (
                        item
                        for item in library["memes"]
                        if item.get("id") == meme_id_text
                    ),
                    None,
                )
                if target is None:
                    raise SdkError("没有找到这张用户上传表情包")
                snapshot = dict(target)

            asset = self._asset_path(snapshot.get("stored_name"))
            try:
                data = asset.read_bytes()
            except OSError as exc:
                raise SdkError("读取表情包文件失败") from exc
            mime = str(snapshot.get("mime") or "image/png")

            new_tags = await self._request_tags_for_image(cfg=cfg, mime=mime, data=data)

            with self._library_lock:
                library = self._load_library()
                target = next(
                    (
                        item
                        for item in library["memes"]
                        if item.get("id") == meme_id_text
                    ),
                    None,
                )
                if target is None:
                    raise SdkError("这张表情包在生成过程中被移除了")
                merged = list(dict.fromkeys([*(target.get("tags") or []), *new_tags]))
                target["tags"] = merged[:_MAX_TAGS]
                self._save_library(library)
                updated = self._public_user_item(target)

            return Ok(
                {
                    "updated": True,
                    "meme_id": meme_id_text,
                    "added_tags": new_tags,
                    "meme": updated,
                    "message": f"已为「{snapshot.get('name')}」生成 {len(new_tags)} 个标签。",
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager generate tags failed: {}", exc)
            return Err(SdkError("生成标签失败，请稍后重试"))

    # ------------------------------------------------------------------
    # System source bridge and LLM capability
    # ------------------------------------------------------------------

    async def _fetch_system_content(self, query: str) -> Mapping[str, Any]:
        from utils.meme_fetcher import fetch_meme_content

        return await asyncio.wait_for(
            fetch_meme_content(keyword=query, limit=_MAX_SYSTEM_CANDIDATES),
            timeout=_SYSTEM_FETCH_TIMEOUT_SECONDS,
        )

    async def _moderate_system_candidate(
        self,
        candidate: Mapping[str, Any],
    ) -> bool:
        from utils.meme_moderation import moderate_meme_image_url

        url = str(candidate.get("url") or "").strip()
        if not _is_allowed_system_url(url):
            return False
        try:
            moderation = await asyncio.wait_for(
                moderate_meme_image_url(url, fail_closed=False),
                timeout=_SYSTEM_MODERATION_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            self.logger.warning(
                "meme_manager system candidate moderation failed: {}", exc
            )
            return False
        return bool(getattr(moderation, "allowed", False))

    async def _system_candidate_fetchable(self, url: str) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(
                timeout=_SYSTEM_PROXY_PREFLIGHT_TIMEOUT_SECONDS,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(
                    f"{_main_server_base()}/api/meme/proxy-image",
                    params={"url": url},
                )
        except Exception as exc:
            self.logger.warning(
                "meme_manager system candidate proxy preflight failed: {}", exc
            )
            return False
        media_type = str(response.headers.get("content-type") or "").lower()
        fetchable = (
            200 <= response.status_code < 300
            and media_type.startswith("image/")
            and bool(response.content)
        )
        if not fetchable:
            self.logger.warning(
                "meme_manager system candidate proxy rejected: status={} mime={} bytes={}",
                response.status_code,
                media_type or "missing",
                len(response.content),
            )
        return bool(fetchable)

    async def _pick_system_candidate(
        self,
        query: str,
    ) -> tuple[dict[str, Any] | None, Mapping[str, Any] | None]:
        try:
            result = await self._fetch_system_content(query)
        except Exception as exc:
            self.logger.warning("meme_manager system fetch failed: {}", exc)
            return None, None
        if not isinstance(result, Mapping) or not result.get("success"):
            return None, result if isinstance(result, Mapping) else None
        candidates = result.get("data")
        if not isinstance(candidates, list):
            return None, result
        for raw_candidate in candidates[:_MAX_SYSTEM_CANDIDATES]:
            if not isinstance(raw_candidate, Mapping):
                continue
            remote_url = str(raw_candidate.get("url") or "").strip()
            if not _is_allowed_system_url(remote_url):
                continue
            if not await self._moderate_system_candidate(raw_candidate):
                continue
            if not await self._system_candidate_fetchable(remote_url):
                continue
            candidate = {
                "title": _clean_text(
                    raw_candidate.get("title") or "系统表情包",
                    _MAX_NAME,
                ),
                "url": remote_url,
                "source": _clean_text(
                    raw_candidate.get("source") or result.get("source") or "系统默认",
                    32,
                ),
                "type": _clean_text(raw_candidate.get("type") or "meme", 12),
            }
            return candidate, result
        return None, result

    def _send_markdown(self, markdown: str) -> bool:
        try:
            self.push_message(
                visibility=["chat"],
                ai_behavior="blind",
                parts=[{"type": "text", "text": markdown}],
            )
            return True
        except Exception as exc:
            self.logger.warning("meme_manager push failed: {}", exc)
            return False

    def _send_image(
        self,
        url: str,
        *,
        alt: str,
        width: Any = None,
        height: Any = None,
        fallback_markdown: str | None = None,
    ) -> bool:
        """Push a native image part so the chat renderer can use its
        aspect-ratio path; fall back to Markdown text for hosts that reject
        image parts (older runtime)."""
        part: dict[str, Any] = {"type": "image", "url": url, "alt": alt}
        try:
            w = int(width) if width is not None else 0
            h = int(height) if height is not None else 0
        except (TypeError, ValueError):
            w, h = 0, 0
        if w > 0 and h > 0:
            part["width"], part["height"] = w, h
        try:
            self.push_message(
                visibility=["chat"],
                ai_behavior="blind",
                parts=[part],
            )
            return True
        except Exception as exc:
            self.logger.warning("meme_manager image push failed: {}", exc)
        return self._send_markdown(fallback_markdown or f"![{alt}]({url})")

    def _user_send_result(
        self,
        meme: Mapping[str, Any],
        *,
        exact_match: bool,
        fallback_reason: str = "",
    ) -> dict[str, Any]:
        url = _public_url(meme)
        markdown = f"![{_markdown_alt(meme.get('name'))}]({url})"
        sent = self._send_image(
            url,
            alt=_markdown_alt(meme.get("name")),
            width=meme.get("width"),
            height=meme.get("height"),
            fallback_markdown=markdown,
        )
        if fallback_reason:
            message = f"{fallback_reason}，改用用户上传的「{meme['name']}」。"
        elif exact_match:
            message = f"已从用户上传中找到「{meme['name']}」。"
        else:
            message = f"已从用户上传中选择「{meme['name']}」。"
        if not sent:
            message += " 图片已找到，但发送到聊天未完成。"
        return {
            "sent": sent,
            "message": message,
            "image_url": url,
            "display_markdown": markdown,
            "source_kind": "user_upload",
            "source": "用户上传",
            "meme_id": meme.get("id"),
        }

    @llm_tool(
        name="meme_send",
        description=(
            "发送一张表情包。优先匹配用户上传；没有匹配时沿用 N.E.K.O "
            "系统默认在线表情包来源，并通过系统安全检查与图片代理加载。"
        ),
        parameters=MEME_SEND_SCHEMA,
        timeout=35.0,
    )
    @plugin_entry(
        id="meme_send",
        name="发送表情包",
        description="从统一目录选择一张表情包发到聊天，并明确实际来源。",
        input_schema=MEME_SEND_SCHEMA,
        timeout=35.0,
        llm_result_fields=[
            "message",
            "image_url",
            "display_markdown",
            "source_kind",
            "source",
        ],
    )
    async def meme_send(
        self,
        query: Any = "",
        source: Any = "auto",
        **_: Any,
    ):
        try:
            query_text = _clean_text(query, 120)
            source_mode = _clean_text(source, 16).lower() or "auto"
            if source_mode not in {"auto", "user", "system"}:
                raise SdkError("来源必须是 auto、user 或 system")
            with self._library_lock:
                library = self._load_library()
                enabled = [
                    item
                    for item in library["memes"]
                    if item.get("enabled", True)
                    and self._asset_path(item.get("stored_name")).is_file()
                ]
            matches = [item for item in enabled if _matches(item, query_text)]

            if source_mode != "system" and matches:
                return Ok(self._user_send_result(matches[0], exact_match=True))
            if source_mode == "user":
                if enabled:
                    return Ok(self._user_send_result(enabled[0], exact_match=False))
                return Ok(
                    {
                        "sent": False,
                        "message": "当前没有已启用的用户上传表情包。",
                        "source_kind": "user_upload",
                        "source": "用户上传",
                    }
                )

            try:
                candidate, system_result = await asyncio.wait_for(
                    self._pick_system_candidate(query_text),
                    timeout=_SYSTEM_SELECTION_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                self.logger.warning("meme_manager system selection timed out")
                candidate, system_result = None, {"error": "selection_timeout"}
            if candidate is not None:
                proxy_url = _system_proxy_url(candidate["url"])
                markdown = f"![{_markdown_alt(candidate['title'])}]({proxy_url})"
                sent = self._send_image(
                    proxy_url,
                    alt=_markdown_alt(candidate["title"]),
                    fallback_markdown=markdown,
                )
                source_name = candidate["source"] or "系统默认"
                message = (
                    f"已从系统默认在线来源 {source_name} 找到「{candidate['title']}」。"
                )
                if not sent:
                    message += " 图片已找到，但发送到聊天未完成。"
                return Ok(
                    {
                        "sent": sent,
                        "message": message,
                        "image_url": proxy_url,
                        "display_markdown": markdown,
                        "source_kind": "system_default",
                        "source": source_name,
                        "region": (
                            system_result.get("region")
                            if isinstance(system_result, Mapping)
                            else None
                        ),
                        "keyword_used": (
                            system_result.get("keyword_used")
                            if isinstance(system_result, Mapping)
                            else query_text
                        ),
                    }
                )

            if source_mode == "auto" and enabled:
                return Ok(
                    self._user_send_result(
                        enabled[0],
                        exact_match=False,
                        fallback_reason=(
                            "没有匹配的用户上传，系统默认在线来源本次暂不可用"
                        ),
                    )
                )
            return Ok(
                {
                    "sent": False,
                    "message": (
                        "没有匹配的用户上传；系统默认在线来源本次暂不可用，请稍后再试。"
                    ),
                    "source_kind": "system_default",
                    "source": "N.E.K.O 系统默认",
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.warning("meme_manager send failed: {}", exc)
            return Err(SdkError("表情包发送失败"))
