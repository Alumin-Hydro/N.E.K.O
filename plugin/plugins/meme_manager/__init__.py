"""Meme Manager plugin for N.E.K.O.

Manages the catgirl's meme/sticker library: the panel lets users add,
disable, rename, tag and delete memes; an LLM tool lets the catgirl pick an
enabled meme and send it into the chat as Markdown pointing at the plugin's
read-only static assets.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from pathlib import Path
from typing import Any, Mapping

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

_ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
_MIME_BY_EXT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"RIFF", ".webp"),
)
_MAX_IMAGE_BYTES = 2 * 1024 * 1024
_MAX_MEMES = 500
_MAX_NAME = 48
_MAX_TAGS = 8
_MAX_TAG_LEN = 24

_SVG_FORBIDDEN = re.compile(
    rb"<\s*script|foreignObject|\son[a-z]+\s*=|javascript:", flags=re.IGNORECASE
)

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
            "description": "用户想要的表情包内容，例如“摸摸头”“累瘫”“点赞”。",
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

UPDATE_MEME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "meme_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "action": {"type": "string", "enum": ["enable", "disable", "delete", "rename"]},
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


def _detect_extension(filename: str, data: bytes) -> str:
    ext = Path(filename).suffix.lower()
    if ext == ".svg":
        head = data[:512].lstrip()
        if head.startswith(b"<") and b"<svg" in head[:256].lower():
            return ext
        raise SdkError("SVG 内容无效")
    for magic, magic_ext in _IMAGE_MAGIC:
        if data.startswith(magic):
            return ext if ext in _ALLOWED_EXTENSIONS else magic_ext
    if ext in _ALLOWED_EXTENSIONS and ext != ".svg":
        return ext
    raise SdkError("仅支持 PNG / JPEG / GIF / WebP / SVG 图片")


def _validate_image_bytes(filename: str, data: bytes) -> str:
    if not data:
        raise SdkError("图片内容为空")
    if len(data) > _MAX_IMAGE_BYTES:
        raise SdkError(f"图片超过 {_MAX_IMAGE_BYTES // 1024 // 1024}MB 上限")
    ext = _detect_extension(filename, data)
    if ext == ".svg" and _SVG_FORBIDDEN.search(data):
        raise SdkError("SVG 不允许包含脚本或事件属性")
    return ext


def _matches(meme: Mapping[str, Any], query: str) -> bool:
    if not query:
        return True
    haystacks = [str(meme.get("name") or "")]
    haystacks.extend(str(tag) for tag in meme.get("tags") or [])
    query_lower = query.lower()
    return any(query_lower in hay.lower() for hay in haystacks)


def _public_url(meme: Mapping[str, Any]) -> str:
    return f"/plugin/{PLUGIN_ID}/ui/memes/{meme['stored_name']}"


@neko_plugin
class MemeManagerPlugin(NekoPluginBase):
    """User-managed meme library with an LLM send tool."""

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._meme_dir: Path | None = None

    # ------------------------------------------------------------------
    # Store helpers
    # ------------------------------------------------------------------

    def _load_library(self) -> dict[str, Any]:
        if not self.store.enabled:
            return {"memes": []}
        raw = self.store._read_value(_STORE_KEY, {"memes": []})
        if not isinstance(raw, dict) or not isinstance(raw.get("memes"), list):
            return {"memes": []}
        return raw

    def _save_library(self, library: Mapping[str, Any]) -> None:
        if not self.store.enabled:
            raise SdkError("PluginStore 不可用，无法保存表情包库")
        self.store._write_value(_STORE_KEY, dict(library))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        try:
            meme_dir = self.config_dir / "static" / "memes"
            meme_dir.mkdir(parents=True, exist_ok=True)
            self._meme_dir = meme_dir
            self.register_static_ui("static")
        except Exception as exc:
            self.logger.warning("meme_manager startup degraded: {}", exc)
        return Ok({"started": True})

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        return Ok({"stopped": True})

    # ------------------------------------------------------------------
    # Panel entries
    # ------------------------------------------------------------------

    @plugin_entry(
        id="get_panel_state",
        name="读取表情包面板状态",
        description="列出表情包、统计和上限，供管理面板渲染。",
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
            library = self._load_library()
            memes = []
            for meme in library["memes"]:
                if not isinstance(meme, dict):
                    continue
                if not _matches(meme, query_text):
                    continue
                memes.append({
                    "id": meme["id"],
                    "name": meme["name"],
                    "tags": list(meme.get("tags") or []),
                    "enabled": bool(meme.get("enabled", True)),
                    "url": _public_url(meme),
                    "created_at": meme.get("created_at", 0),
                    "size_bytes": meme.get("size_bytes", 0),
                })
            memes.sort(key=lambda item: -float(item.get("created_at") or 0))
            enabled_count = sum(1 for item in library["memes"] if item.get("enabled", True))
            return Ok({
                "memes": memes,
                "total": len(library["memes"]),
                "enabled_count": enabled_count,
                "max_memes": _MAX_MEMES,
                "max_image_bytes": _MAX_IMAGE_BYTES,
                "store_ready": self.store.enabled,
            })
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("表情包面板状态暂时不可用"))

    @plugin_entry(
        id="add_meme",
        name="添加表情包",
        description="上传一张图片到表情包库（base64，最大 2MB）。",
        input_schema=ADD_MEME_SCHEMA,
        timeout=30.0,
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
            if self._meme_dir is None:
                raise SdkError("插件尚未启动完成")
            library = self._load_library()
            if len(library["memes"]) >= _MAX_MEMES:
                raise SdkError(f"表情包库已满（{_MAX_MEMES} 张）")
            clean_name = _clean_text(name, _MAX_NAME)
            if not clean_name:
                raise SdkError("名称不能为空")
            clean_filename = Path(str(filename or "")).name[:128]
            if not clean_filename:
                raise SdkError("文件名无效")
            try:
                data = base64.b64decode(str(data_base64), validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SdkError("图片数据不是有效的 base64") from exc
            ext = _validate_image_bytes(clean_filename, data)
            digest = hashlib.sha256(data).hexdigest()[:16]
            meme_id = f"meme-{int(time.time())}-{digest[:8]}"
            stored_name = f"{digest}{ext}"
            target = self._meme_dir / stored_name
            if not target.exists():
                target.write_bytes(data)
            clean_tags = []
            for tag in (tags if isinstance(tags, list) else []):
                text = _clean_text(tag, _MAX_TAG_LEN)
                if text and text not in clean_tags:
                    clean_tags.append(text)
                if len(clean_tags) >= _MAX_TAGS:
                    break
            meme = {
                "id": meme_id,
                "name": clean_name,
                "tags": clean_tags,
                "enabled": True,
                "stored_name": stored_name,
                "size_bytes": len(data),
                "created_at": time.time(),
            }
            library["memes"].append(meme)
            self._save_library(library)
            return Ok({"saved": True, "meme": {**meme, "url": _public_url(meme)}})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("表情包保存失败"))

    @plugin_entry(
        id="update_meme",
        name="管理表情包",
        description="启用、禁用、删除或重命名一张表情包。",
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
            meme_id = _clean_text(meme_id, 64)
            action = _clean_text(action, 16)
            library = self._load_library()
            target = next(
                (item for item in library["memes"] if item.get("id") == meme_id),
                None,
            )
            if target is None:
                raise SdkError("没有找到这张表情包")
            if action == "delete":
                library["memes"] = [
                    item for item in library["memes"] if item.get("id") != meme_id
                ]
                if self._meme_dir is not None:
                    still_used = any(
                        item.get("stored_name") == target.get("stored_name")
                        for item in library["memes"]
                    )
                    victim = self._meme_dir / str(target.get("stored_name") or "")
                    if not still_used and victim.is_file() and victim.parent == self._meme_dir:
                        victim.unlink(missing_ok=True)
            elif action in {"enable", "disable"}:
                target["enabled"] = action == "enable"
            elif action == "rename":
                clean_name = _clean_text(name, _MAX_NAME)
                if not clean_name:
                    raise SdkError("名称不能为空")
                target["name"] = clean_name
                if isinstance(tags, list):
                    clean_tags = []
                    for tag in tags:
                        text = _clean_text(tag, _MAX_TAG_LEN)
                        if text and text not in clean_tags:
                            clean_tags.append(text)
                        if len(clean_tags) >= _MAX_TAGS:
                            break
                    target["tags"] = clean_tags
            else:
                raise SdkError("不支持的操作")
            self._save_library(library)
            return Ok({"updated": True, "action": action, "meme_id": meme_id})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("表情包更新失败"))

    # ------------------------------------------------------------------
    # LLM capability
    # ------------------------------------------------------------------

    @llm_tool(
        name="meme_send",
        description=(
            "从用户的表情包库中挑一张合适的表情包发到聊天里。"
            "用户说“发个表情”“来个摸摸头”“给我个累瘫的表情”“发个点赞”等时调用。"
            "query 描述想要的表情内容；找不到完全匹配时会挑一张最相近的。"
        ),
        parameters=MEME_SEND_SCHEMA,
        timeout=20.0,
    )
    @plugin_entry(
        id="meme_send",
        name="发送表情包",
        description="从启用的表情包中选一张，以图片 Markdown 形式发到聊天。",
        input_schema=MEME_SEND_SCHEMA,
        timeout=20.0,
        llm_result_fields=["message", "image_url", "display_markdown"],
    )
    async def meme_send(self, query: Any = "", **_: Any):
        try:
            query_text = _clean_text(query, 120)
            library = self._load_library()
            enabled = [
                item for item in library["memes"]
                if isinstance(item, dict) and item.get("enabled", True)
            ]
            if not enabled:
                return Ok({
                    "sent": False,
                    "message": "表情包库是空的，主人可以先在管理面板里添加几张。",
                })
            matches = [item for item in enabled if _matches(item, query_text)]
            pick = (matches or enabled)[0]
            url = _public_url(pick)
            markdown = f"![{pick['name']}]({url})"
            try:
                self.push_message(
                    visibility=["chat"],
                    ai_behavior="blind",
                    parts=[{"type": "text", "text": markdown}],
                )
                sent = True
            except Exception:
                sent = False
            if matches:
                message = f"找到了「{pick['name']}」，已经发给主人。"
            else:
                message = f"没有完全匹配的表情，挑了一张「{pick['name']}」发给主人。"
            return Ok({
                "sent": sent,
                "message": message,
                "image_url": url,
                "display_markdown": markdown,
            })
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("表情包发送失败"))
