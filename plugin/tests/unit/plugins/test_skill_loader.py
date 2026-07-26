"""Unit tests for skill_loader."""

from __future__ import annotations

from typing import Any

import pytest

from plugin.plugins.skill_loader import (
    PLUGIN_ID,
    SkillLoaderPlugin,
    _redact,
    parse_skill_markdown,
)
from plugin.sdk.plugin import SdkError


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


_SAMPLE = """---
name: ascii-art
description: 生成 ASCII 艺术
---

# ASCII Art

Use pyfiglet and cowsay.
"""


def _make_plugin(tmp_path, monkeypatch) -> SkillLoaderPlugin:
    plugin = SkillLoaderPlugin(FakeCtx())
    plugin.store = FakeStore()
    monkeypatch.setattr(type(plugin), "config_dir", property(lambda self: tmp_path))
    return plugin


def test_parse_frontmatter() -> None:
    parsed = parse_skill_markdown(_SAMPLE)
    assert parsed["name"] == "ascii-art"
    assert "ASCII" in parsed["description"]
    assert "pyfiglet" in parsed["body"]


def test_parse_without_frontmatter_falls_back_to_heading() -> None:
    parsed = parse_skill_markdown("# My Skill\n\nDo things.")
    assert parsed["name"] == "My Skill"


def test_redact_secrets() -> None:
    text = "key sk-abcdefgh1234 and password: hunter2 see .env and api_keys.json"
    redacted = _redact(text)
    assert "sk-abcdefgh1234" not in redacted
    assert "hunter2" not in redacted
    assert "api_keys.json" not in redacted


@pytest.mark.asyncio
async def test_add_pasted_skill_and_get(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    (tmp_path / "skills").mkdir()

    result = await plugin.add_skill(content=_SAMPLE)
    assert result.is_ok(), result
    skill = result.value["skill"]
    assert skill["id"] == "ascii-art"
    assert (tmp_path / "skills" / "ascii-art" / "SKILL.md").is_file()

    listed = await plugin.skill_loader_list()
    assert listed.is_ok()
    assert listed.value["skills"][0]["id"] == "ascii-art"

    got = await plugin.skill_loader_get(skill_id="ascii-art")
    assert got.is_ok()
    assert "pyfiglet" in got.value["content"]
    assert got.value["truncated"] is False


@pytest.mark.asyncio
async def test_get_redacts_sensitive_content(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    (tmp_path / "skills").mkdir()
    evil = _SAMPLE + "\n\nSetup: api_key: sk-supersecret123456\n"
    await plugin.add_skill(content=evil)
    got = await plugin.skill_loader_get(skill_id="ascii-art")
    assert got.is_ok()
    assert "sk-supersecret123456" not in got.value["content"]


@pytest.mark.asyncio
async def test_path_escape_rejected(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    (tmp_path / "skills").mkdir()
    result = await plugin.add_skill(path="/etc/passwd")
    assert result.is_err()


@pytest.mark.asyncio
async def test_register_directory_skill(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    skills_root = tmp_path / "skills"
    skill_dir = skills_root / "dirskill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(_SAMPLE, encoding="utf-8")

    result = await plugin.add_skill(path=str(skill_dir))
    assert result.is_ok(), result

    got = await plugin.skill_loader_get(skill_id="ascii-art")
    assert got.is_ok()
    assert "pyfiglet" in got.value["content"]


@pytest.mark.asyncio
async def test_disable_blocks_get(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    (tmp_path / "skills").mkdir()
    await plugin.add_skill(content=_SAMPLE)
    await plugin.update_skill(skill_id="ascii-art", action="disable")
    got = await plugin.skill_loader_get(skill_id="ascii-art")
    assert got.is_err()


@pytest.mark.asyncio
async def test_duplicate_id_rejected(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    (tmp_path / "skills").mkdir()
    first = await plugin.add_skill(content=_SAMPLE)
    assert first.is_ok()
    second = await plugin.add_skill(content=_SAMPLE)
    assert second.is_err()


@pytest.mark.asyncio
async def test_invalid_skill_id_rejected(tmp_path, monkeypatch) -> None:
    plugin = _make_plugin(tmp_path, monkeypatch)
    (tmp_path / "skills").mkdir()
    result = await plugin.add_skill(skill_id="Bad ID!!", content=_SAMPLE)
    assert result.is_err()


def test_llm_tool_metadata() -> None:
    from plugin.sdk.plugin.llm_tool import LLM_TOOL_META_ATTR

    list_meta = getattr(SkillLoaderPlugin.skill_loader_list, LLM_TOOL_META_ATTR, None)
    get_meta = getattr(SkillLoaderPlugin.skill_loader_get, LLM_TOOL_META_ATTR, None)
    assert getattr(list_meta, "name", None) == "skill_loader_list"
    assert getattr(get_meta, "name", None) == "skill_loader_get"


def test_no_code_execution_in_source() -> None:
    import inspect

    from plugin.plugins import skill_loader

    source = inspect.getsource(skill_loader)
    forbidden = ("subprocess", "os.system", "eval(", "exec(", "pty", "shlex.split")
    for token in forbidden:
        assert token not in source, token
