"""Skill Loader plugin for N.E.K.O.

Lets users register SKILL.md-style skills (directory registration or pasted
content) so the catgirl can look them up and follow their instructions in
chat. Skills are data, not code: the plugin never executes anything inside a
skill, never reads outside allow-listed roots, and redacts sensitive-looking
fragments before content reaches the LLM.
"""

from __future__ import annotations

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

PLUGIN_ID = "skill_loader"
_STORE_KEY = "skill_registry"

_MAX_SKILLS = 200
_MAX_CONTENT_BYTES = 256 * 1024
_MAX_INLINE_CHARS = 4000
_MAX_NAME = 80
_MAX_ID = 64
_MAX_DESCRIPTION = 400

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

#: Sensitive-looking fragments that must never reach the LLM.
_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)sk-[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)api[_ -]?key\s*[:=]\s*\S+"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
    re.compile(r"(?i)token\s*[:=]\s*\S{8,}"),
    re.compile(r"(?i)\.env\b"),
    re.compile(r"(?i)api_keys\.json"),
)

_REDACTED = "[已脱敏]"

EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

GET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {"type": "string", "minLength": 1, "maxLength": _MAX_ID},
    },
    "required": ["skill_id"],
    "additionalProperties": False,
}

ADD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {"type": "string", "minLength": 1, "maxLength": _MAX_ID},
        "name": {"type": "string", "minLength": 1, "maxLength": _MAX_NAME},
        "description": {"type": "string", "maxLength": _MAX_DESCRIPTION},
        "content": {"type": "string", "minLength": 1},
        "path": {"type": "string", "maxLength": 512},
    },
    "additionalProperties": False,
}

UPDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {"type": "string", "minLength": 1, "maxLength": _MAX_ID},
        "action": {"type": "string", "enum": ["enable", "disable", "delete", "rescan"]},
    },
    "required": ["skill_id", "action"],
    "additionalProperties": False,
}


def _clean_text(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _redact(text: str) -> str:
    result = text
    for pattern in _SENSITIVE_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


def parse_skill_markdown(content: str) -> dict[str, str]:
    """Parse optional YAML-ish frontmatter + body from SKILL.md content."""

    name = ""
    description = ""
    body = content
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?", content, flags=re.DOTALL)
    if match:
        frontmatter = match.group(1)
        body = content[match.end():]
        for line in frontmatter.splitlines():
            key, sep, value = line.partition(":")
            if not sep:
                continue
            key = key.strip().lower()
            value = value.strip().strip('"').strip("'")
            if key == "name" and not name:
                name = value
            elif key == "description" and not description:
                description = value
    if not name:
        heading = re.search(r"^#\s+(.+)$", body, flags=re.MULTILINE)
        if heading:
            name = heading.group(1).strip()
    return {"name": name, "description": description, "body": body.strip()}


def _normalize_skill_id(value: Any) -> str:
    text = _clean_text(value, _MAX_ID).lower().replace(" ", "-")
    if not _ID_PATTERN.fullmatch(text):
        raise SdkError("技能 ID 只能包含小写字母、数字、- 和 _")
    return text


@neko_plugin
class SkillLoaderPlugin(NekoPluginBase):
    """Registry of read-only SKILL.md skills for the catgirl."""

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._allowed_roots: list[Path] = []

    # ------------------------------------------------------------------
    # Store helpers
    # ------------------------------------------------------------------

    def _load_registry(self) -> dict[str, Any]:
        if not self.store.enabled:
            return {"skills": []}
        raw = self.store._read_value(_STORE_KEY, {"skills": []})
        if not isinstance(raw, dict) or not isinstance(raw.get("skills"), list):
            return {"skills": []}
        return raw

    def _save_registry(self, registry: Mapping[str, Any]) -> None:
        if not self.store.enabled:
            raise SdkError("PluginStore 不可用，无法保存技能库")
        self.store._write_value(_STORE_KEY, dict(registry))

    def _find_skill(self, registry: Mapping[str, Any], skill_id: str) -> dict[str, Any] | None:
        for skill in registry.get("skills", []):
            if isinstance(skill, dict) and skill.get("id") == skill_id:
                return skill
        return None

    def _allowed_roots_list(self) -> list[Path]:
        roots = [self.config_dir / "skills"]
        roots.extend(self._allowed_roots)
        resolved: list[Path] = []
        for root in roots:
            try:
                resolved.append(root.expanduser().resolve())
            except OSError:
                continue
        return resolved

    def _resolve_skill_path(self, raw_path: str) -> Path:
        if not raw_path:
            raise SdkError("路径为空")
        if len(raw_path) > 512:
            raise SdkError("路径过长")
        candidate = Path(raw_path).expanduser()
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            raise SdkError("路径无法解析") from exc
        for root in self._allowed_roots_list():
            try:
                resolved.relative_to(root)
                return resolved
            except ValueError:
                continue
        raise SdkError("路径不在允许的技能根目录内（可在高级设置中配置）")

    def _read_skill_file(self, path: Path) -> str:
        target = path if path.is_file() else path / "SKILL.md"
        if not target.is_file():
            raise SdkError("找不到 SKILL.md")
        if target.name != "SKILL.md":
            raise SdkError("只允许读取 SKILL.md")
        resolved = target.resolve()
        if resolved.name != "SKILL.md":
            raise SdkError("符号链接目标无效")
        data = target.read_bytes()[: _MAX_CONTENT_BYTES + 1]
        if len(data) > _MAX_CONTENT_BYTES:
            raise SdkError("SKILL.md 超过大小上限")
        return data.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        try:
            (self.config_dir / "skills").mkdir(parents=True, exist_ok=True)
            self.register_static_ui("static")
        except Exception as exc:
            self.logger.warning("skill_loader startup degraded: {}", exc)
        return Ok({"started": True})

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        return Ok({"stopped": True})

    # ------------------------------------------------------------------
    # Panel entries
    # ------------------------------------------------------------------

    @plugin_entry(
        id="get_panel_state",
        name="读取技能库面板状态",
        description="列出已注册技能、启停状态和上限。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
    )
    async def get_panel_state(self, **_: Any):
        try:
            registry = self._load_registry()
            skills = []
            for skill in registry["skills"]:
                if not isinstance(skill, dict):
                    continue
                skills.append({
                    "id": skill["id"],
                    "name": skill.get("name", skill["id"]),
                    "description": skill.get("description", ""),
                    "enabled": bool(skill.get("enabled", True)),
                    "source": skill.get("source", "pasted"),
                    "added_at": skill.get("added_at", 0),
                })
            skills.sort(key=lambda item: -float(item.get("added_at") or 0))
            return Ok({
                "skills": skills,
                "total": len(registry["skills"]),
                "max_skills": _MAX_SKILLS,
                "max_inline_chars": _MAX_INLINE_CHARS,
                "store_ready": self.store.enabled,
            })
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("技能库面板状态暂时不可用"))

    @plugin_entry(
        id="add_skill",
        name="添加技能",
        description="粘贴 SKILL.md 内容，或从允许的技能根目录注册一个技能目录。",
        input_schema=ADD_SCHEMA,
        timeout=20.0,
    )
    async def add_skill(
        self,
        skill_id: Any = "",
        name: Any = "",
        description: Any = "",
        content: Any = "",
        path: Any = "",
        **_: Any,
    ):
        try:
            registry = self._load_registry()
            if len(registry["skills"]) >= _MAX_SKILLS:
                raise SdkError(f"技能库已满（{_MAX_SKILLS} 个）")
            raw_path = _clean_text(path, 512)
            source = "pasted"
            stored_content = str(content or "")
            if raw_path:
                resolved = self._resolve_skill_path(raw_path)
                stored_content = self._read_skill_file(resolved)
                source = str(resolved)
            if not stored_content.strip():
                raise SdkError("技能内容为空")
            parsed = parse_skill_markdown(stored_content)
            final_id = _normalize_skill_id(skill_id or parsed["name"] or "skill")
            if self._find_skill(registry, final_id) is not None:
                raise SdkError("相同 ID 的技能已存在")
            final_name = _clean_text(name, _MAX_NAME) or parsed["name"] or final_id
            final_description = (
                _clean_text(description, _MAX_DESCRIPTION)
                or _clean_text(parsed["description"], _MAX_DESCRIPTION)
            )
            digest = hashlib.sha256(stored_content.encode("utf-8")).hexdigest()[:16]
            skill = {
                "id": final_id,
                "name": final_name,
                "description": final_description,
                "enabled": True,
                "source": source,
                "content_hash": digest,
                "added_at": time.time(),
            }
            if source == "pasted":
                user_dir = self.config_dir / "skills" / final_id
                user_dir.mkdir(parents=True, exist_ok=True)
                (user_dir / "SKILL.md").write_text(stored_content, encoding="utf-8")
            else:
                skill["content"] = None
                registry.setdefault("_external", {})
            registry["skills"].append(skill)
            if source != "pasted":
                skill["inline_content"] = stored_content
            self._save_registry(registry)
            return Ok({"saved": True, "skill": {k: v for k, v in skill.items() if k != "inline_content"}})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("技能保存失败"))

    @plugin_entry(
        id="update_skill",
        name="管理技能",
        description="启用、禁用、删除或重新扫描一个技能。",
        input_schema=UPDATE_SCHEMA,
        timeout=20.0,
    )
    async def update_skill(self, skill_id: Any = "", action: Any = "", **_: Any):
        try:
            skill_id = _normalize_skill_id(skill_id)
            action = _clean_text(action, 16)
            registry = self._load_registry()
            skill = self._find_skill(registry, skill_id)
            if skill is None:
                raise SdkError("没有找到这个技能")
            if action == "delete":
                registry["skills"] = [
                    item for item in registry["skills"] if item.get("id") != skill_id
                ]
            elif action in {"enable", "disable"}:
                skill["enabled"] = action == "enable"
            elif action == "rescan":
                source = str(skill.get("source") or "")
                if source == "pasted":
                    raise SdkError("粘贴创建的技能无需重新扫描")
                resolved = self._resolve_skill_path(source)
                content = self._read_skill_file(resolved)
                skill["inline_content"] = content
                skill["content_hash"] = hashlib.sha256(
                    content.encode("utf-8")
                ).hexdigest()[:16]
                parsed = parse_skill_markdown(content)
                if parsed["name"]:
                    skill["name"] = parsed["name"]
                if parsed["description"]:
                    skill["description"] = _clean_text(parsed["description"], _MAX_DESCRIPTION)
            else:
                raise SdkError("不支持的操作")
            self._save_registry(registry)
            return Ok({"updated": True, "action": action, "skill_id": skill_id})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("技能更新失败"))

    # ------------------------------------------------------------------
    # LLM capabilities
    # ------------------------------------------------------------------

    @llm_tool(
        name="skill_loader_list",
        description=(
            "列出用户技能库里当前可用的技能（名称、ID、简介）。"
            "用户提到“用某个技能/方法处理”“你有什么技能”时先调用它。"
        ),
        parameters=EMPTY_SCHEMA,
        timeout=15.0,
    )
    @plugin_entry(
        id="skill_loader_list",
        name="列出技能",
        description="列出启用的技能（ID、名称、简介）。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
        llm_result_fields=["skills", "message"],
    )
    async def skill_loader_list(self, **_: Any):
        try:
            registry = self._load_registry()
            skills = [
                {
                    "id": skill["id"],
                    "name": skill.get("name", skill["id"]),
                    "description": skill.get("description", ""),
                }
                for skill in registry["skills"]
                if isinstance(skill, dict) and skill.get("enabled", True)
            ]
            if not skills:
                return Ok({"skills": [], "message": "技能库是空的，主人可以在面板里添加技能。"})
            return Ok({"skills": skills, "message": f"当前有 {len(skills)} 个可用技能。"})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("技能列表暂时不可用"))

    @llm_tool(
        name="skill_loader_get",
        description=(
            "读取某个技能的精简说明文本（已脱敏、限长），然后按该说明帮助用户。"
            "不会执行技能里的任何命令或脚本。"
        ),
        parameters=GET_SCHEMA,
        timeout=20.0,
    )
    @plugin_entry(
        id="skill_loader_get",
        name="读取技能",
        description="读取指定技能的脱敏精简内容。",
        input_schema=GET_SCHEMA,
        timeout=20.0,
        llm_result_fields=["skill_id", "name", "content", "truncated"],
    )
    async def skill_loader_get(self, skill_id: Any = "", **_: Any):
        try:
            skill_id = _normalize_skill_id(skill_id)
            registry = self._load_registry()
            skill = self._find_skill(registry, skill_id)
            if skill is None or not skill.get("enabled", True):
                raise SdkError("没有找到这个技能，或它已被禁用")
            source = str(skill.get("source") or "")
            if source == "pasted":
                path = self.config_dir / "skills" / skill_id / "SKILL.md"
                content = path.read_text(encoding="utf-8") if path.is_file() else ""
            else:
                content = str(skill.get("inline_content") or "")
                if not content:
                    resolved = self._resolve_skill_path(source)
                    content = self._read_skill_file(resolved)
            if not content.strip():
                raise SdkError("技能内容为空或不可读")
            redacted = _redact(content)
            truncated = len(redacted) > _MAX_INLINE_CHARS
            if truncated:
                redacted = redacted[:_MAX_INLINE_CHARS] + "\n…[内容过长已截断]"
            return Ok({
                "skill_id": skill_id,
                "name": skill.get("name", skill_id),
                "content": redacted,
                "truncated": truncated,
            })
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return Err(SdkError("技能读取失败"))
