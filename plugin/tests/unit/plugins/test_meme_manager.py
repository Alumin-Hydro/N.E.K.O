"""Unit tests for meme_manager."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from plugin.plugins.meme_manager import (
    PLUGIN_ID,
    MemeManagerPlugin,
    _detect_extension,
    _matches,
    _normalize_image_payload,
    _plugin_server_base,
    _safe_stored_name,
    _validate_image_bytes,
    _MAX_IMAGE_BYTES,
)
from plugin.sdk.plugin import SdkError

pytestmark = pytest.mark.plugin_unit

_PNG = base64.b64encode(
    base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0l"
        "EQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
).decode("ascii")


class FakeStore:
    enabled = True

    def __init__(self) -> None:
        self.data: dict[str, Any] = {}

    def _read_value(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def _write_value(self, key: str, value: Any) -> None:
        self.data[key] = value


class FakeCtx:
    pass


async def _async_value(value: Any) -> Any:
    return value


def _make_plugin(tmp_path, monkeypatch) -> MemeManagerPlugin:
    plugin = MemeManagerPlugin(FakeCtx())
    plugin.store = FakeStore()
    monkeypatch.setattr(type(plugin), "config_dir", property(lambda self: tmp_path))
    return plugin


def test_detect_extension_png() -> None:
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    assert _detect_extension("a.png", data) == ".png"


def test_detect_extension_rejects_fake_svg() -> None:
    with pytest.raises(SdkError):
        _detect_extension("evil.svg", b"not svg at all")


def test_detect_extension_rejects_mismatched_filename() -> None:
    with pytest.raises(SdkError, match="扩展名"):
        _detect_extension("looks-like.jpg", base64.b64decode(_PNG))


def test_safe_stored_name_accepts_legacy_jpeg_without_path_escape() -> None:
    assert _safe_stored_name("0123456789abcdef.jpeg") == "0123456789abcdef.jpeg"
    assert _safe_stored_name("../0123456789abcdef.jpeg") is None


def test_plugin_server_base_honors_public_origin(monkeypatch) -> None:
    monkeypatch.setenv(
        "NEKO_USER_PLUGIN_SERVER_ORIGIN",
        "https://neko.example.test:9443/",
    )
    assert _plugin_server_base() == "https://neko.example.test:9443"


def test_validate_image_rejects_script_svg() -> None:
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    with pytest.raises(SdkError, match="脚本"):
        _validate_image_bytes("x.svg", svg)


def test_validate_image_rejects_svg_processing_instruction() -> None:
    svg = (
        b'<?xml-stylesheet href="https://example.invalid/a.css"?>'
        b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'
    )
    with pytest.raises(SdkError, match="处理指令"):
        _validate_image_bytes("x.svg", svg)


def test_validate_image_rejects_oversize() -> None:
    with pytest.raises(SdkError, match="上限"):
        _validate_image_bytes(
            "x.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * (21 * 1024 * 1024)
        )


def _make_photo_png(width: int = 2400, height: int = 1800) -> bytes:
    """A noisy true-color PNG that comfortably exceeds the 2MB store limit."""
    import random
    from io import BytesIO

    from PIL import Image

    rng = random.Random(20260808)
    image = Image.new("RGB", (width, height))
    pixels = image.load()
    for y in range(height):
        for x in range(0, width, 3):
            pixels[x, y] = (
                rng.randrange(256),
                rng.randrange(256),
                rng.randrange(256),
            )
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    payload = buffer.getvalue()
    assert len(payload) > _MAX_IMAGE_BYTES
    return payload


def test_normalize_compresses_oversize_photo() -> None:
    payload, ext, width, height, compressed = _normalize_image_payload(
        "photo.png", _make_photo_png()
    )
    assert compressed is True
    assert len(payload) <= _MAX_IMAGE_BYTES
    assert ext in {".png", ".jpg", ".webp"}
    assert max(width, height) <= 1024
    # The normalized payload must itself pass validation.
    _validate_image_bytes(f"normalized{ext}", payload)


def test_normalize_keeps_small_image_untouched() -> None:
    from io import BytesIO

    from PIL import Image

    buffer = BytesIO()
    Image.new("RGB", (64, 64), (255, 0, 0)).save(buffer, format="PNG")
    original = buffer.getvalue()
    payload, ext, width, height, compressed = _normalize_image_payload(
        "small.png", original
    )
    assert compressed is False
    assert payload == original
    assert ext == ".png"
    assert (width, height) == (64, 64)


def test_normalize_rejects_oversize_svg() -> None:
    svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
        + b" " * (_MAX_IMAGE_BYTES + 16)
        + b"</svg>"
    )
    with pytest.raises(SdkError, match="SVG"):
        _normalize_image_payload("big.svg", svg)


def test_validate_image_rejects_unknown_format() -> None:
    with pytest.raises(SdkError):
        _validate_image_bytes("x.bmp", b"BM" + b"\x00" * 32)


def test_matches_query() -> None:
    meme = {"name": "摸摸头", "tags": ["可爱", "安慰"]}
    assert _matches(meme, "摸头")
    assert _matches(meme, "安慰")
    assert _matches(meme, "")
    assert not _matches(meme, "生气")


@pytest.mark.asyncio
async def test_add_and_list_and_send(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    meme_dir = tmp_path / "static" / "memes"
    meme_dir.mkdir(parents=True)
    plugin._meme_dir = meme_dir

    result = await plugin.add_meme(
        name="摸摸头",
        filename="pat.png",
        data_base64=_PNG,
        tags=["安慰"],
    )
    assert result.is_ok(), result
    value = result.value
    assert value["saved"] is True
    meme_id = value["meme"]["id"]
    assert (meme_dir / value["meme"]["stored_name"]).is_file()

    state = await plugin.get_panel_state()
    assert state.is_ok()
    assert state.value["total"] == 1
    assert state.value["enabled_count"] == 1

    sent = await plugin.meme_send(query="摸摸")
    assert sent.is_ok()
    assert sent.value["image_url"].startswith(
        f"http://127.0.0.1:48916/plugin/{PLUGIN_ID}/ui/memes/"
    )
    assert "摸摸头" in sent.value["display_markdown"]

    disabled = await plugin.update_meme(meme_id=meme_id, action="disable")
    assert disabled.is_ok()
    state2 = await plugin.get_panel_state()
    assert state2.value["enabled_count"] == 0

    deleted = await plugin.update_meme(meme_id=meme_id, action="delete")
    assert deleted.is_ok()
    state3 = await plugin.get_panel_state()
    assert state3.value["total"] == 0


@pytest.mark.asyncio
async def test_send_empty_library_is_friendly(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    monkeypatch.setattr(
        plugin,
        "_fetch_system_content",
        lambda _query: _async_value({"success": False, "data": []}),
    )
    result = await plugin.meme_send(query="hi")
    assert result.is_ok()
    assert result.value["sent"] is False
    assert "系统默认在线来源本次暂不可用" in result.value["message"]
    assert "整个系统没有表情包" not in result.value["message"]


@pytest.mark.asyncio
async def test_add_rejects_bad_base64(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    meme_dir = tmp_path / "static" / "memes"
    meme_dir.mkdir(parents=True)
    plugin._meme_dir = meme_dir
    result = await plugin.add_meme(
        name="x", filename="x.png", data_base64="!!!not-b64!!!"
    )
    assert result.is_err()


@pytest.mark.asyncio
async def test_update_missing_meme_fails(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    result = await plugin.update_meme(meme_id="nope", action="delete")
    assert result.is_err()


def test_llm_tool_metadata() -> None:
    from plugin.sdk.plugin.llm_tool import LLM_TOOL_META_ATTR

    meta = getattr(MemeManagerPlugin.meme_send, LLM_TOOL_META_ATTR, None)
    assert meta is not None
    assert getattr(meta, "name", None) == "meme_send"
