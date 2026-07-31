"""Complete, managed Agent Skill support for N.E.K.O.

Skill directories are copied into bounded managed generations before they are
made available to the model.  Instructions and linked files are read only
from the recorded manifest.  Python scripts require a persisted, revision-
bound user authorization and run through the bounded Python runner.
"""

from __future__ import annotations

import asyncio
import copy
import math
import os
import re
import shutil
import stat
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

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

from ._package import (
    DEFAULT_LIMITS,
    PackageError,
    SkillPackage,
    build_inline_package,
    install_package,
    normalize_relative_path,
    read_manifest_file,
    scan_skill_package,
)
from ._runner import (
    DEFAULT_RUNNER_LIMITS,
    RunnerError,
    detect_python_runtime,
    run_python_script,
    validate_argv,
)

PLUGIN_ID = "skill_loader"
_REGISTRY_KEY = "skill_registry"
_REGISTRY_SCHEMA_VERSION = 2
_MAX_SKILLS = 200
_MAX_ALLOWED_ROOTS = 16
_MAX_SKILL_ID = 64
_MAX_LLM_TEXT_CHARS = 64_000
_MAX_PANEL_TEXT_CHARS = 8_000
_DEFAULT_SCRIPT_TIMEOUT_SECONDS = 30
_MAX_SCRIPT_TIMEOUT_SECONDS = 120
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b(api[_ -]?key|password|token|secret)\s*[:=]\s*\S+"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:^|[/\\])\.env(?:$|[/\\])"),
    re.compile(r"(?i)api_keys\.json"),
)
_REDACTED = "[redacted]"
_BLOCKING_DEPENDENCY_STATUSES = frozenset(
    {
        "invalid",
        "missing",
        "syntax_error",
        "unsupported",
        "unsupported_encoding",
        "version_mismatch",
    }
)

EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

SETTINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "allowed_roots": {
            "type": "array",
            "maxItems": _MAX_ALLOWED_ROOTS,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024,
                "writeOnly": True,
                "x-sensitive": True,
            },
        },
    },
    "required": ["allowed_roots"],
    "additionalProperties": False,
}

IMPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_SKILL_ID,
        },
        "path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024,
            "writeOnly": True,
            "x-sensitive": True,
        },
        "content": {
            "type": "string",
            "minLength": 1,
            "maxLength": DEFAULT_LIMITS.max_skill_md_bytes,
            "writeOnly": True,
            "x-sensitive": True,
        },
    },
    "oneOf": [{"required": ["path"]}, {"required": ["content"]}],
    "additionalProperties": False,
}

UPDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_SKILL_ID,
        },
        "action": {
            "type": "string",
            "enum": ["enable", "disable", "delete", "refresh"],
        },
    },
    "required": ["skill_id", "action"],
    "additionalProperties": False,
}

AUTHORIZATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_SKILL_ID,
        },
        "authorized": {"type": "boolean"},
    },
    "required": ["skill_id", "authorized"],
    "additionalProperties": False,
}

READ_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_SKILL_ID,
        },
        "path": {
            "type": "string",
            "minLength": 1,
            "maxLength": DEFAULT_LIMITS.max_path_bytes,
            "default": "SKILL.md",
        },
    },
    "required": ["skill_id"],
    "additionalProperties": False,
}

RUN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "skill_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": _MAX_SKILL_ID,
        },
        "script_path": {
            "type": "string",
            "minLength": 1,
            "maxLength": DEFAULT_LIMITS.max_path_bytes,
        },
        "argv": {
            "type": "array",
            "maxItems": DEFAULT_RUNNER_LIMITS.max_argv_items,
            "items": {
                "type": "string",
                "maxLength": DEFAULT_RUNNER_LIMITS.max_arg_bytes,
                "writeOnly": True,
                "x-sensitive": True,
            },
            "default": [],
            "writeOnly": True,
            "x-sensitive": True,
        },
        "timeout_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": _MAX_SCRIPT_TIMEOUT_SECONDS,
            "default": _DEFAULT_SCRIPT_TIMEOUT_SECONDS,
        },
    },
    "required": ["skill_id", "script_path"],
    "additionalProperties": False,
}


def _new_registry() -> dict[str, Any]:
    return {
        "schema_version": _REGISTRY_SCHEMA_VERSION,
        "settings": {"allowed_roots": []},
        "skills": [],
    }


def _clean_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value).strip()[:limit]


def _redact(text: str) -> str:
    redacted = text
    for pattern in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    return redacted


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return f"{text[:limit]}\n...[truncated by skill_loader]", True


def parse_skill_markdown(content: str) -> dict[str, Any]:
    """Parse SKILL.md through the same strict package parser used by imports."""

    package = build_inline_package(content)
    manifest = package.manifest
    body = content.removeprefix("\ufeff")
    lines = body.splitlines(keepends=True)
    if lines and lines[0].rstrip("\r\n") == "---":
        for index, line in enumerate(lines[1:], start=1):
            if line.rstrip("\r\n") == "---":
                body = "".join(lines[index + 1 :])
                break
    return {
        "name": str(manifest.get("name") or ""),
        "description": str(manifest.get("description") or ""),
        "frontmatter": copy.deepcopy(manifest.get("frontmatter") or {}),
        "body": body.strip(),
    }


def _reject_unexpected(extra: Mapping[str, Any]) -> None:
    unexpected = sorted(key for key in extra if key != "_ctx")
    if unexpected:
        raise SdkError(
            f"不支持的参数：{', '.join(unexpected)}",
            code="unexpected_arguments",
        )


def _normalize_skill_id(value: Any, *, inferred_name: str = "") -> str:
    if value not in ("", None) and not isinstance(value, str):
        raise SdkError("技能 ID 必须是字符串", code="invalid_skill_id")
    raw = str(value or "").strip().lower()
    if not raw:
        raw = re.sub(r"[^a-z0-9_-]+", "-", inferred_name.strip().lower())
        raw = re.sub(r"-{2,}", "-", raw).strip("-_")
    if not _ID_PATTERN.fullmatch(raw):
        raise SdkError(
            "技能 ID 只能包含小写字母、数字、- 和 _，且最多 64 个字符",
            code="invalid_skill_id",
        )
    return raw


def _require_skill_id(value: Any) -> str:
    return _normalize_skill_id(value)


def _friendly_package_error(error: PackageError) -> SdkError:
    messages = {
        "absolute_path": "不允许使用绝对的包内路径。",
        "file_not_in_manifest": "这个文件不在已导入的技能清单中。",
        "file_too_large": "技能中的单个文件超过了安全上限。",
        "frontmatter_too_large": "SKILL.md 的 frontmatter 太大。",
        "hardlink_rejected": "技能目录包含硬链接，无法安全导入。",
        "invalid_frontmatter": "SKILL.md frontmatter 不是受支持的安全 YAML。",
        "invalid_utf8": "SKILL.md 必须使用严格 UTF-8 编码。",
        "missing_skill_md": "技能根目录中找不到 SKILL.md。",
        "package_too_large": "技能目录总大小超过了安全上限。",
        "path_traversal": "路径包含 ..，已拒绝越界访问。",
        "read_limit_exceeded": "文件太大，不能直接放入对话上下文。",
        "sensitive_entry_rejected": "技能目录含隐藏或疑似凭据文件，已拒绝导入。",
        "special_file_rejected": "技能目录包含管道、设备或套接字等特殊文件。",
        "symlink_rejected": "技能目录包含符号链接或重解析点，已拒绝导入。",
        "too_many_directories": "技能目录层级或目录数量超过安全上限。",
        "too_many_files": "技能文件数量超过安全上限。",
        "unsafe_link": "SKILL.md 中有越界或不安全的本地链接。",
    }
    return SdkError(
        messages.get(error.code, str(error)),
        code=error.code,
        details=error.as_dict(),
    )


def _friendly_runner_error(error: RunnerError) -> SdkError:
    messages = {
        "invalid_argv": "脚本参数必须是逐项填写的字符串列表。",
        "invalid_script": "只能运行清单中 scripts/ 目录下的 Python 文件。",
        "invalid_timeout": "脚本超时必须是 1 到 120 秒的整数。",
        "python_unavailable": "当前 N.E.K.O Python 解释器不可用。",
        "unsupported_script": "目前只支持运行 UTF-8 Python .py 脚本。",
        "unsafe_output_root": "脚本输出目录不在当前技能的 managed root 内。",
        "unsafe_script": "脚本路径越出了当前技能的 managed root。",
    }
    return SdkError(
        messages.get(error.code, error.message),
        code=error.code,
        details=error.to_dict(),
    )


@neko_plugin
class SkillLoaderPlugin(NekoPluginBase):
    """Managed Agent Skill registry and permission-gated Python runner."""

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._registry_lock = threading.RLock()
        self._active_skills: set[str] = set()
        self._managed_root = self.data_path("skills")

    # ------------------------------------------------------------------
    # Runtime and persistence
    # ------------------------------------------------------------------

    async def _align_store_from_effective_config(self) -> None:
        try:
            effective = await self.config.dump(timeout=5.0)
        except Exception as exc:
            self.logger.warning(
                "skill_loader could not read effective config: {}",
                type(exc).__name__,
            )
            return
        plugin_cfg = effective.get("plugin")
        store_cfg = plugin_cfg.get("store") if isinstance(plugin_cfg, Mapping) else None
        if isinstance(store_cfg, Mapping) and store_cfg.get("enabled") is True:
            self.store.enabled = True

    @staticmethod
    def _legacy_entry_is_linklike(info: os.stat_result) -> bool:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(info, "st_file_attributes", 0)
        return stat.S_ISLNK(info.st_mode) or bool(
            reparse_flag and attributes & reparse_flag
        )

    def _read_legacy_pasted_skill(self, skill_id: str) -> bytes:
        """Read only the old plugin-owned ``skills/<id>/SKILL.md`` location.

        Legacy external source paths are deliberately never consulted during
        migration.  Every lexical component below the old plugin directory is
        checked before the file is opened with ``O_NOFOLLOW`` where available.
        """

        legacy_root = self.config_dir / "skills"
        legacy_directory = legacy_root / skill_id
        target = legacy_directory / "SKILL.md"
        try:
            root_info = legacy_root.lstat()
            directory_info = legacy_directory.lstat()
            target_info = target.lstat()
            resolved_root = legacy_root.resolve(strict=True)
            resolved_target = target.resolve(strict=True)
            resolved_target.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise PackageError(
                "legacy pasted SKILL.md is unavailable",
                code="legacy_content_unavailable",
                path="SKILL.md",
            ) from exc
        if (
            self._legacy_entry_is_linklike(root_info)
            or not stat.S_ISDIR(root_info.st_mode)
            or self._legacy_entry_is_linklike(directory_info)
            or not stat.S_ISDIR(directory_info.st_mode)
            or self._legacy_entry_is_linklike(target_info)
            or not stat.S_ISREG(target_info.st_mode)
            or getattr(target_info, "st_nlink", 1) != 1
        ):
            raise PackageError(
                "legacy pasted SKILL.md is not an ordinary unlinked file",
                code="legacy_content_unsafe",
                path="SKILL.md",
            )
        if target_info.st_size > DEFAULT_LIMITS.max_skill_md_bytes:
            raise PackageError(
                "legacy pasted SKILL.md exceeds the configured limit",
                code="file_too_large",
                path="SKILL.md",
            )

        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags)
        except OSError as exc:
            raise PackageError(
                "legacy pasted SKILL.md cannot be opened safely",
                code="legacy_content_unsafe",
                path="SKILL.md",
            ) from exc
        try:
            opened_info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened_info.st_mode)
                or getattr(opened_info, "st_nlink", 1) != 1
                or opened_info.st_dev != target_info.st_dev
                or opened_info.st_ino != target_info.st_ino
            ):
                raise PackageError(
                    "legacy pasted SKILL.md changed during migration",
                    code="legacy_content_unsafe",
                    path="SKILL.md",
                )
            chunks: list[bytes] = []
            remaining = DEFAULT_LIMITS.max_skill_md_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            final_info = os.fstat(descriptor)
            if len(data) > DEFAULT_LIMITS.max_skill_md_bytes:
                raise PackageError(
                    "legacy pasted SKILL.md exceeds the configured limit",
                    code="file_too_large",
                    path="SKILL.md",
                )
            if (
                final_info.st_size != len(data)
                or final_info.st_mtime_ns != opened_info.st_mtime_ns
                or final_info.st_ctime_ns != opened_info.st_ctime_ns
            ):
                raise PackageError(
                    "legacy pasted SKILL.md changed during migration",
                    code="legacy_content_unsafe",
                    path="SKILL.md",
                )
            return data
        finally:
            os.close(descriptor)

    def _migrate_legacy_registry_locked(
        self,
        legacy: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Migrate v0.1 records using only persisted or plugin-owned content."""

        legacy_skills = legacy.get("skills")
        if not isinstance(legacy_skills, list):
            raise SdkError("技能库持久化数据格式损坏。", code="registry_corrupt")

        migrated = _new_registry()
        installed: list[Path] = []
        issues: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for index, legacy_skill in enumerate(legacy_skills[:_MAX_SKILLS]):
            label = f"legacy-{index + 1}"
            current_generation: Path | None = None
            if not isinstance(legacy_skill, Mapping):
                issues.append(
                    {
                        "entry": label,
                        "code": "legacy_record_invalid",
                        "message": "旧技能记录不是对象，已跳过。",
                    }
                )
                continue
            try:
                skill_id = _require_skill_id(legacy_skill.get("id"))
                label = skill_id
                if skill_id in seen_ids:
                    raise SdkError("旧技能 ID 重复。", code="legacy_duplicate_id")
                source_value = legacy_skill.get("source")
                if source_value == "pasted":
                    content: str | bytes = self._read_legacy_pasted_skill(skill_id)
                    source = {
                        "kind": "legacy-pasted",
                        "label": "migrated pasted SKILL.md",
                        "path": "",
                    }
                else:
                    inline_content = legacy_skill.get("inline_content")
                    if (
                        not isinstance(inline_content, str)
                        or not inline_content.strip()
                    ):
                        raise SdkError(
                            "旧外部技能没有已保存的内容快照；为安全起见不会回读旧来源路径。",
                            code="legacy_snapshot_missing",
                        )
                    content = inline_content
                    source = {
                        "kind": "legacy-snapshot",
                        "label": "migrated external snapshot",
                        "path": "",
                    }
                package = build_inline_package(
                    content,
                    name=_clean_text(legacy_skill.get("name"), 160) or None,
                    description=_clean_text(
                        legacy_skill.get("description"),
                        1_000,
                    )
                    or None,
                )
                generation, manifest = install_package(
                    package,
                    self._managed_root,
                    skill_id,
                )
                current_generation = generation
                installed.append(generation)
                raw_added_at = legacy_skill.get("added_at")
                try:
                    added_at = float(raw_added_at)
                except (TypeError, ValueError):
                    added_at = time.time()
                if not math.isfinite(added_at) or added_at <= 0:
                    added_at = time.time()
                migrated["skills"].append(
                    self._skill_record(
                        skill_id=skill_id,
                        source=source,
                        generation=generation,
                        manifest=manifest,
                        enabled=legacy_skill.get("enabled", True) is not False,
                        added_at=added_at,
                    )
                )
                seen_ids.add(skill_id)
            except (PackageError, SdkError) as exc:
                if current_generation is not None:
                    self._safe_remove_managed(current_generation)
                    installed.remove(current_generation)
                issues.append(
                    {
                        "entry": label,
                        "code": getattr(exc, "code", "legacy_migration_failed"),
                        "message": str(exc),
                    }
                )

        if len(legacy_skills) > _MAX_SKILLS:
            issues.append(
                {
                    "entry": "registry",
                    "code": "skill_limit",
                    "message": f"旧技能超过 {_MAX_SKILLS} 个上限，多余记录已跳过。",
                }
            )
        migrated["migration"] = {
            "from": "0.1",
            "completed_at": time.time(),
            "imported": len(migrated["skills"]),
            "skipped": issues,
            "external_paths_reread": False,
        }
        try:
            self._save_registry_locked(migrated)
        except Exception:
            for generation in installed:
                self._safe_remove_managed(generation)
            raise
        return migrated

    def _load_registry_locked(self) -> dict[str, Any]:
        if not self.store.enabled:
            raise SdkError(
                "持久化存储未启用，技能库当前只能显示故障状态。",
                code="store_disabled",
            )
        raw = self.store._read_value(_REGISTRY_KEY, None)
        if raw is None:
            return _new_registry()
        if not isinstance(raw, dict):
            raise SdkError("技能库持久化数据格式损坏。", code="registry_corrupt")
        if "schema_version" not in raw:
            raw = self._migrate_legacy_registry_locked(raw)
        if raw.get("schema_version") != _REGISTRY_SCHEMA_VERSION:
            raise SdkError(
                "检测到旧版技能库数据；请重新导入技能以建立完整 managed copy。",
                code="registry_upgrade_required",
            )
        settings = raw.get("settings")
        skills = raw.get("skills")
        if not isinstance(settings, dict) or not isinstance(skills, list):
            raise SdkError("技能库持久化数据格式损坏。", code="registry_corrupt")
        roots = settings.get("allowed_roots")
        if not isinstance(roots, list) or not all(
            isinstance(item, str) for item in roots
        ):
            raise SdkError("技能库允许目录设置损坏。", code="registry_corrupt")
        if not all(isinstance(skill, dict) for skill in skills):
            raise SdkError("技能库条目格式损坏。", code="registry_corrupt")
        return copy.deepcopy(raw)

    def _save_registry_locked(self, registry: Mapping[str, Any]) -> None:
        if not self.store.enabled:
            raise SdkError("持久化存储未启用，无法保存技能库。", code="store_disabled")
        self.store._write_value(_REGISTRY_KEY, copy.deepcopy(dict(registry)))

    @staticmethod
    def _find_skill(
        registry: Mapping[str, Any], skill_id: str
    ) -> dict[str, Any] | None:
        skills = registry.get("skills")
        if not isinstance(skills, Sequence):
            return None
        for skill in skills:
            if isinstance(skill, dict) and skill.get("id") == skill_id:
                return skill
        return None

    def _managed_generation(self, skill: Mapping[str, Any]) -> Path:
        raw = skill.get("managed_rel")
        if not isinstance(raw, str):
            raise SdkError("技能 managed copy 记录损坏。", code="managed_copy_invalid")
        try:
            normalized = normalize_relative_path(raw)
        except PackageError as exc:
            raise _friendly_package_error(exc) from exc
        candidate = self._managed_root.joinpath(*PurePosixPath(normalized).parts)
        try:
            resolved_root = self._managed_root.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
            value = resolved.lstat()
        except (OSError, ValueError) as exc:
            raise SdkError(
                "技能 managed copy 已丢失或越界。",
                code="managed_copy_invalid",
            ) from exc
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
            raise SdkError(
                "技能 managed copy 不是普通目录。", code="managed_copy_invalid"
            )
        return resolved

    def _safe_remove_managed(self, target: Path) -> None:
        try:
            root = self._managed_root.resolve(strict=True)
            resolved = target.resolve(strict=False)
            relative = resolved.relative_to(root)
        except (OSError, ValueError):
            return
        if not relative.parts or target.is_symlink():
            return
        shutil.rmtree(target, ignore_errors=True)

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        try:
            _reject_unexpected(_)
            await self._align_store_from_effective_config()
            await asyncio.to_thread(
                self._managed_root.mkdir, parents=True, exist_ok=True
            )
            self.register_static_ui("static")
            return Ok(
                {
                    "started": True,
                    "store_ready": self.store.enabled,
                    "managed_root": str(self._managed_root),
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception("skill_loader startup failed: {}", type(exc).__name__)
            return Err(SdkError("技能库启动失败。", code="startup_failed"))

    @lifecycle(id="config_change")
    async def config_change(self, **_: Any):
        try:
            _reject_unexpected(_)
            await self._align_store_from_effective_config()
            return Ok({"store_ready": self.store.enabled})
        except SdkError as exc:
            return Err(exc)

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        try:
            _reject_unexpected(_)
            close = getattr(self.store, "close", None)
            if callable(close):
                await close()
        except Exception as exc:
            self.logger.warning(
                "skill_loader store close failed: {}", type(exc).__name__
            )
        return Ok({"stopped": True})

    # ------------------------------------------------------------------
    # Panel projections and settings
    # ------------------------------------------------------------------

    def _limits_payload(self) -> dict[str, Any]:
        return {
            "max_skills": _MAX_SKILLS,
            "max_files": DEFAULT_LIMITS.max_files,
            "max_directories": DEFAULT_LIMITS.max_directories,
            "max_file_bytes": DEFAULT_LIMITS.max_file_bytes,
            "max_total_bytes": DEFAULT_LIMITS.max_total_bytes,
            "max_read_bytes": DEFAULT_LIMITS.max_read_bytes,
            "max_stdout_bytes": DEFAULT_RUNNER_LIMITS.max_stdout_bytes,
            "max_stderr_bytes": DEFAULT_RUNNER_LIMITS.max_stderr_bytes,
            "max_timeout_seconds": _MAX_SCRIPT_TIMEOUT_SECONDS,
        }

    @staticmethod
    def _friendly_dependency(item: Mapping[str, Any]) -> dict[str, Any]:
        name = _clean_text(item.get("name"), 200) or "unknown"
        status = _clean_text(item.get("status"), 80) or "unknown"
        kind = _clean_text(item.get("kind"), 80) or "dependency"
        if status in {"available", "bundled", "not_applicable"}:
            message = f"{name} 可用。"
        elif status == "missing":
            message = (
                f"缺少 {name}。请为 N.E.K.O 使用的独立 Python 环境准备它；"
                "技能库不会自动安装，也不会修改系统 Python。"
            )
        elif status == "version_mismatch":
            message = (
                f"{name} 的版本不符合技能要求。请在独立环境中调整；插件不会自动升级。"
            )
        elif status == "unsupported":
            message = f"{name} 当前不受支持，插件不会交给 shell 尝试运行。"
        else:
            message = f"{name} 需要检查（{status}）。插件不会盲目安装或修改系统环境。"
        required_by = item.get("required_by")
        return {
            "kind": kind,
            "name": name,
            "status": status,
            "message": message,
            "required_by": (
                [str(value) for value in required_by if isinstance(value, str)]
                if isinstance(required_by, list)
                else []
            ),
            **(
                {"installed_version": str(item["installed_version"])}
                if item.get("installed_version") is not None
                else {}
            ),
            **(
                {"specifier": str(item["specifier"])}
                if item.get("specifier") is not None
                else {}
            ),
        }

    @staticmethod
    def _file_kind_for_panel(kind: str) -> str:
        return {
            "reference": "references",
            "template": "templates",
            "asset": "assets",
            "script": "scripts",
            "script_resource": "scripts",
            "support": "references",
        }.get(kind, "references")

    def _panel_skill(self, skill: Mapping[str, Any]) -> dict[str, Any]:
        manifest = skill.get("manifest")
        if not isinstance(manifest, Mapping):
            raise SdkError("技能 manifest 损坏。", code="registry_corrupt")
        files = manifest.get("files")
        scripts = manifest.get("scripts")
        dependencies = manifest.get("dependencies")
        if not isinstance(files, list) or not isinstance(scripts, list):
            raise SdkError("技能 manifest 文件清单损坏。", code="registry_corrupt")
        runtime = detect_python_runtime()
        linked_paths = {
            item.get("path")
            for item in manifest.get("linked_paths", [])
            if isinstance(item, Mapping) and item.get("exists") is True
        }
        linked_files: list[dict[str, Any]] = []
        for item in files:
            if not isinstance(item, Mapping) or item.get("path") == "SKILL.md":
                continue
            path = str(item.get("path") or "")
            linked_files.append(
                {
                    "path": path,
                    "kind": self._file_kind_for_panel(str(item.get("kind") or "")),
                    "source_kind": str(item.get("kind") or "support"),
                    "size_bytes": int(item.get("size") or 0),
                    "sha256": str(item.get("sha256") or ""),
                    "readable": item.get("readable") is True,
                    "linked_from_markdown": path in linked_paths,
                }
            )
        panel_scripts: list[dict[str, Any]] = []
        for item in scripts:
            if not isinstance(item, Mapping):
                continue
            supported = item.get("supported") is True
            script_size = int(item.get("size") or 0)
            size_supported = 0 <= script_size <= DEFAULT_RUNNER_LIMITS.max_script_bytes
            available = (
                supported and size_supported and runtime.get("available") is True
            )
            diagnostic = (
                "可在受限 Python runner 中运行；仍需用户显式授权。"
                if available
                else (
                    ("脚本超过 runner 的单文件大小上限，已保留但不能执行。")
                    if supported and not size_supported
                    else "当前 Python 解释器不可用。"
                    if supported
                    else "此扩展会完整保留，但不会交给 shell 或不受支持的解释器。"
                )
            )
            panel_scripts.append(
                {
                    "path": str(item.get("path") or ""),
                    "sha256": str(item.get("sha256") or ""),
                    "size_bytes": script_size,
                    "interpreter": item.get("interpreter"),
                    "supported": supported,
                    "available": available,
                    "diagnostic": diagnostic,
                    "blocking_dependencies": [
                        str(value)
                        for value in item.get("blocking_dependencies", [])
                        if isinstance(value, str)
                    ],
                }
            )
        manifest_hash = str(manifest.get("manifest_sha256") or "")
        authorization = skill.get("authorization")
        authorization = authorization if isinstance(authorization, Mapping) else {}
        authorized = (
            authorization.get("script_execution") is True
            and authorization.get("manifest_hash") == manifest_hash
        )
        source = skill.get("source")
        source = source if isinstance(source, Mapping) else {}
        return {
            "id": str(skill.get("id") or ""),
            "name": str(skill.get("name") or skill.get("id") or ""),
            "description": str(skill.get("description") or ""),
            "enabled": skill.get("enabled") is True,
            "source": {
                "kind": str(source.get("kind") or "unknown"),
                "label": str(source.get("label") or source.get("kind") or "unknown"),
                "path": str(source.get("path") or ""),
            },
            "manifest_hash": manifest_hash,
            "frontmatter": copy.deepcopy(manifest.get("frontmatter") or {}),
            "linked_files": linked_files,
            "scripts": panel_scripts,
            "authorization": {
                "script_execution": authorized,
                "manifest_hash": authorization.get("manifest_hash"),
                "authorized_at": authorization.get("authorized_at"),
            },
            "dependencies": [
                self._friendly_dependency(item)
                for item in (dependencies if isinstance(dependencies, list) else [])
                if isinstance(item, Mapping)
            ],
            "capabilities": copy.deepcopy(manifest.get("capabilities") or {}),
            "linked_paths": copy.deepcopy(manifest.get("linked_paths") or []),
            "last_run": copy.deepcopy(skill.get("last_run")),
            "added_at": skill.get("added_at"),
            "updated_at": skill.get("updated_at"),
        }

    def _panel_state_sync(self) -> dict[str, Any]:
        if not self.store.enabled:
            return {
                "store_ready": False,
                "store_error": "持久化存储未启用，导入和权限修改已停用。",
                "managed_root": str(self._managed_root),
                "limits": self._limits_payload(),
                "settings": {"allowed_roots": []},
                "skills": [],
                "total": 0,
            }
        with self._registry_lock:
            registry = self._load_registry_locked()
            panel_skills = [
                self._panel_skill(skill)
                for skill in registry["skills"]
                if isinstance(skill, Mapping)
            ]
            panel_skills.sort(
                key=lambda item: float(item.get("added_at") or 0), reverse=True
            )
            return {
                "store_ready": True,
                "store_error": "",
                "managed_root": str(self._managed_root),
                "limits": self._limits_payload(),
                "settings": copy.deepcopy(registry["settings"]),
                "skills": panel_skills,
                "total": len(panel_skills),
                "migration": copy.deepcopy(registry.get("migration")),
            }

    @plugin_entry(
        id="get_panel_state",
        name="读取技能库状态",
        description="读取 managed skills、依赖、权限和最近运行结果。",
        input_schema=EMPTY_SCHEMA,
        timeout=20.0,
    )
    async def get_panel_state(self, **_: Any):
        try:
            _reject_unexpected(_)
            return Ok(await asyncio.to_thread(self._panel_state_sync))
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception(
                "skill_loader panel state failed: {}", type(exc).__name__
            )
            return Err(SdkError("技能库状态读取失败。", code="panel_state_failed"))

    def _normalize_allowed_roots(self, roots: Any) -> list[str]:
        if not isinstance(roots, list) or len(roots) > _MAX_ALLOWED_ROOTS:
            raise SdkError(
                f"允许目录必须是最多 {_MAX_ALLOWED_ROOTS} 项的列表。",
                code="invalid_allowed_roots",
            )
        normalized: list[str] = []
        for value in roots:
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise SdkError("允许目录必须是非空路径。", code="invalid_allowed_root")
            if any(part == ".." for part in Path(value).parts):
                raise SdkError("允许目录不能包含 ..。", code="path_traversal")
            path = Path(value).expanduser()
            if not path.is_absolute():
                raise SdkError("允许目录必须是绝对路径。", code="invalid_allowed_root")
            try:
                value_stat = path.lstat()
                resolved = path.resolve(strict=True)
            except OSError as exc:
                raise SdkError(
                    "允许目录不存在或不可读取。",
                    code="invalid_allowed_root",
                ) from exc
            if stat.S_ISLNK(value_stat.st_mode) or not stat.S_ISDIR(value_stat.st_mode):
                raise SdkError(
                    "允许目录必须是普通目录，不能是符号链接。",
                    code="invalid_allowed_root",
                )
            rendered = str(resolved)
            self._validate_saved_allowed_root(rendered)
            if rendered not in normalized:
                normalized.append(rendered)
        return normalized

    def _validate_saved_allowed_root(self, raw_root: str) -> Path:
        """Revalidate a persisted canonical root without following new links."""

        root = Path(raw_root)
        if not root.is_absolute():
            raise SdkError("允许目录记录不是绝对路径。", code="invalid_allowed_root")
        current = Path(root.anchor)
        parts = (
            root.parts[1:]
            if root.parts and root.parts[0] == root.anchor
            else root.parts
        )
        try:
            for part in parts:
                current = current / part
                info = current.lstat()
                if self._legacy_entry_is_linklike(info) or not stat.S_ISDIR(
                    info.st_mode
                ):
                    raise SdkError(
                        "已保存的允许目录已被链接或特殊路径替换，请重新确认设置。",
                        code="allowed_root_changed",
                    )
            resolved = root.resolve(strict=True)
        except SdkError:
            raise
        except OSError as exc:
            raise SdkError(
                "已保存的允许目录不存在或不可读取，请重新确认设置。",
                code="allowed_root_changed",
            ) from exc
        if resolved != root:
            raise SdkError(
                "已保存的允许目录不再指向原来的规范路径，请重新确认设置。",
                code="allowed_root_changed",
            )
        return resolved

    def _save_settings_sync(self, roots: Any) -> dict[str, Any]:
        normalized = self._normalize_allowed_roots(roots)
        with self._registry_lock:
            registry = self._load_registry_locked()
            registry["settings"] = {"allowed_roots": normalized}
            self._save_registry_locked(registry)
        return {"saved": True, "allowed_roots": normalized}

    @plugin_entry(
        id="save_settings",
        name="保存技能库设置",
        description="保存用户明确授权的技能来源根目录。",
        input_schema=SETTINGS_SCHEMA,
        timeout=20.0,
    )
    async def save_settings(self, allowed_roots: Any = None, **_: Any):
        try:
            _reject_unexpected(_)
            return Ok(
                await asyncio.to_thread(
                    self._save_settings_sync,
                    allowed_roots,
                )
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception(
                "skill_loader settings save failed: {}", type(exc).__name__
            )
            return Err(SdkError("允许目录保存失败。", code="settings_save_failed"))

    # ------------------------------------------------------------------
    # Import and registry mutation
    # ------------------------------------------------------------------

    def _resolve_source_root(
        self,
        raw_path: str,
        allowed_roots: Sequence[str],
    ) -> Path:
        if "\x00" in raw_path or not raw_path.strip():
            raise SdkError("技能目录路径为空。", code="invalid_source_path")
        lexical = Path(raw_path).expanduser()
        if any(part == ".." for part in lexical.parts):
            raise SdkError("技能目录路径不能包含 ..。", code="path_traversal")
        if not lexical.is_absolute():
            raise SdkError("技能目录路径必须是绝对路径。", code="invalid_source_path")
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as exc:
            raise SdkError(
                "技能目录不存在或不可读取。", code="source_unavailable"
            ) from exc
        source_root = (
            resolved.parent
            if resolved.is_file() and resolved.name == "SKILL.md"
            else resolved
        )
        trusted = False
        for raw_root in allowed_roots:
            try:
                trusted_root = self._validate_saved_allowed_root(raw_root)
                source_root.relative_to(trusted_root)
                trusted = True
                break
            except (SdkError, ValueError):
                continue
        if not trusted:
            raise SdkError(
                "这个路径不在允许导入目录中；请先在高级设置中添加它的可信根目录。",
                code="source_not_allowed",
            )
        return source_root

    def _skill_record(
        self,
        *,
        skill_id: str,
        source: Mapping[str, Any],
        generation: Path,
        manifest: Mapping[str, Any],
        enabled: bool = True,
        added_at: float | None = None,
    ) -> dict[str, Any]:
        try:
            managed_rel = generation.relative_to(self._managed_root).as_posix()
        except ValueError as exc:
            raise SdkError(
                "managed generation 越界。", code="managed_copy_invalid"
            ) from exc
        now = time.time()
        return {
            "id": skill_id,
            "name": _clean_text(manifest.get("name"), 160) or skill_id,
            "description": _clean_text(manifest.get("description"), 1_000),
            "enabled": enabled,
            "source": copy.deepcopy(dict(source)),
            "managed_rel": managed_rel,
            "manifest": copy.deepcopy(dict(manifest)),
            "authorization": {
                "script_execution": False,
                "manifest_hash": None,
                "authorized_at": None,
            },
            "last_run": None,
            "added_at": added_at if added_at is not None else now,
            "updated_at": now,
        }

    def _import_skill_sync(
        self,
        *,
        skill_id: Any,
        path: Any,
        content: Any,
    ) -> dict[str, Any]:
        if path not in ("", None) and not isinstance(path, str):
            raise SdkError("path 必须是字符串。", code="invalid_source_path")
        if content not in ("", None) and not isinstance(content, str):
            raise SdkError("content 必须是字符串。", code="invalid_content")
        has_path = isinstance(path, str) and bool(path.strip())
        has_content = isinstance(content, str) and bool(content.strip())
        if has_path == has_content:
            raise SdkError(
                "必须且只能提供技能目录 path 或粘贴的 SKILL.md content。",
                code="invalid_import_source",
            )
        with self._registry_lock:
            registry = self._load_registry_locked()
            if len(registry["skills"]) >= _MAX_SKILLS:
                raise SdkError(
                    f"技能库已达到 {_MAX_SKILLS} 个上限。", code="skill_limit"
                )
            package: SkillPackage
            source: dict[str, Any]
            if has_path:
                source_root = self._resolve_source_root(
                    str(path),
                    registry["settings"]["allowed_roots"],
                )
                try:
                    package = scan_skill_package(source_root)
                except PackageError as exc:
                    raise _friendly_package_error(exc) from exc
                source = {
                    "kind": "directory",
                    "label": source_root.name,
                    "path": str(source_root),
                    "refresh_path": str(source_root),
                }
            else:
                try:
                    package = build_inline_package(str(content))
                except PackageError as exc:
                    raise _friendly_package_error(exc) from exc
                source = {
                    "kind": "pasted",
                    "label": "pasted SKILL.md",
                    "path": "",
                }
            normalized_id = _normalize_skill_id(
                skill_id,
                inferred_name=str(package.manifest.get("name") or ""),
            )
            if self._find_skill(registry, normalized_id) is not None:
                raise SdkError("相同 ID 的技能已经存在。", code="skill_exists")
            try:
                generation, manifest = install_package(
                    package,
                    self._managed_root,
                    normalized_id,
                )
            except PackageError as exc:
                raise _friendly_package_error(exc) from exc
            record = self._skill_record(
                skill_id=normalized_id,
                source=source,
                generation=generation,
                manifest=manifest,
            )
            registry["skills"].append(record)
            try:
                self._save_registry_locked(registry)
            except Exception:
                self._safe_remove_managed(generation)
                raise
            return {
                "saved": True,
                "skill": self._panel_skill(record),
            }

    @plugin_entry(
        id="import_skill",
        name="导入完整 Agent Skill",
        description="安全复制完整技能目录，解析 frontmatter、linked files、脚本和依赖。",
        input_schema=IMPORT_SCHEMA,
        timeout=60.0,
    )
    async def import_skill(
        self,
        skill_id: Any = "",
        path: Any = "",
        content: Any = "",
        **_: Any,
    ):
        try:
            _reject_unexpected(_)
            return Ok(
                await asyncio.to_thread(
                    self._import_skill_sync,
                    skill_id=skill_id,
                    path=path,
                    content=content,
                )
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception("skill_loader import failed: {}", type(exc).__name__)
            return Err(SdkError("技能导入失败。", code="skill_import_failed"))

    async def add_skill(
        self,
        skill_id: Any = "",
        name: Any = "",
        description: Any = "",
        content: Any = "",
        path: Any = "",
        **_: Any,
    ):
        """Compatibility wrapper for the original panel entry method."""

        del name, description
        return await self.import_skill(
            skill_id=skill_id,
            path=path,
            content=content,
            **_,
        )

    def _refresh_skill_locked(
        self,
        registry: dict[str, Any],
        skill: dict[str, Any],
    ) -> dict[str, Any]:
        source = skill.get("source")
        if not isinstance(source, Mapping) or source.get("kind") != "directory":
            raise SdkError(
                "粘贴创建的技能没有外部来源，不能刷新；请重新导入。",
                code="skill_not_refreshable",
            )
        source_root = self._resolve_source_root(
            str(source.get("refresh_path") or ""),
            registry["settings"]["allowed_roots"],
        )
        try:
            package = scan_skill_package(source_root)
            generation, manifest = install_package(
                package,
                self._managed_root,
                str(skill["id"]),
            )
        except PackageError as exc:
            raise _friendly_package_error(exc) from exc
        old_generation = self._managed_generation(skill)
        old_hash = str(
            skill.get("manifest", {}).get("manifest_sha256")
            if isinstance(skill.get("manifest"), Mapping)
            else ""
        )
        new_hash = str(manifest.get("manifest_sha256") or "")
        authorization = skill.get("authorization")
        authorization = authorization if isinstance(authorization, Mapping) else {}
        was_authorized = (
            authorization.get("script_execution") is True
            and authorization.get("manifest_hash") == old_hash
        )
        replacement = self._skill_record(
            skill_id=str(skill["id"]),
            source={
                "kind": "directory",
                "label": source_root.name,
                "path": str(source_root),
                "refresh_path": str(source_root),
            },
            generation=generation,
            manifest=manifest,
            enabled=skill.get("enabled") is True,
            added_at=float(skill.get("added_at") or time.time()),
        )
        changed = old_hash != new_hash
        if not changed and was_authorized:
            replacement["authorization"] = copy.deepcopy(dict(authorization))
        replacement["last_run"] = copy.deepcopy(skill.get("last_run"))
        index = registry["skills"].index(skill)
        registry["skills"][index] = replacement
        try:
            self._save_registry_locked(registry)
        except Exception:
            self._safe_remove_managed(generation)
            raise
        if old_generation != generation:
            self._safe_remove_managed(old_generation)
        return {
            "updated": True,
            "action": "refresh",
            "skill_id": skill["id"],
            "changed": changed,
            "authorization_revoked": changed and was_authorized,
            "skill": self._panel_skill(replacement),
        }

    def _update_skill_sync(self, skill_id: Any, action: Any) -> dict[str, Any]:
        normalized_id = _require_skill_id(skill_id)
        if not isinstance(action, str) or action not in {
            "enable",
            "disable",
            "delete",
            "refresh",
        }:
            raise SdkError("不支持的技能操作。", code="invalid_action")
        with self._registry_lock:
            if normalized_id in self._active_skills and action in {"delete", "refresh"}:
                raise SdkError("技能脚本正在运行，请稍后再操作。", code="skill_busy")
            registry = self._load_registry_locked()
            skill = self._find_skill(registry, normalized_id)
            if skill is None:
                raise SdkError("没有找到这个技能。", code="skill_not_found")
            if action == "refresh":
                return self._refresh_skill_locked(registry, skill)
            generation = self._managed_generation(skill)
            if action == "delete":
                registry["skills"] = [
                    item
                    for item in registry["skills"]
                    if not isinstance(item, Mapping) or item.get("id") != normalized_id
                ]
            else:
                skill["enabled"] = action == "enable"
                skill["updated_at"] = time.time()
            self._save_registry_locked(registry)
            if action == "delete":
                self._safe_remove_managed(generation.parent)
            return {
                "updated": True,
                "action": action,
                "skill_id": normalized_id,
            }

    @plugin_entry(
        id="update_skill",
        name="管理技能",
        description="启用、禁用、删除或从已授权来源刷新 managed skill。",
        input_schema=UPDATE_SCHEMA,
        timeout=60.0,
    )
    async def update_skill(self, skill_id: Any = "", action: Any = "", **_: Any):
        try:
            _reject_unexpected(_)
            return Ok(
                await asyncio.to_thread(
                    self._update_skill_sync,
                    skill_id,
                    action,
                )
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception("skill_loader update failed: {}", type(exc).__name__)
            return Err(SdkError("技能更新失败。", code="skill_update_failed"))

    def _set_authorization_sync(
        self,
        skill_id: Any,
        authorized: Any,
    ) -> dict[str, Any]:
        normalized_id = _require_skill_id(skill_id)
        if not isinstance(authorized, bool):
            raise SdkError("authorized 必须是布尔值。", code="invalid_authorization")
        with self._registry_lock:
            registry = self._load_registry_locked()
            skill = self._find_skill(registry, normalized_id)
            if skill is None:
                raise SdkError("没有找到这个技能。", code="skill_not_found")
            manifest = skill.get("manifest")
            if not isinstance(manifest, Mapping):
                raise SdkError("技能 manifest 损坏。", code="registry_corrupt")
            scripts = manifest.get("scripts")
            if authorized and not isinstance(scripts, list):
                raise SdkError("技能脚本清单损坏。", code="registry_corrupt")
            if authorized and not scripts:
                raise SdkError("这个技能没有可授权的脚本。", code="no_scripts")
            manifest_hash = str(manifest.get("manifest_sha256") or "")
            skill["authorization"] = {
                "script_execution": authorized,
                "manifest_hash": manifest_hash if authorized else None,
                "authorized_at": time.time() if authorized else None,
            }
            skill["updated_at"] = time.time()
            self._save_registry_locked(registry)
            return {
                "updated": True,
                "skill_id": normalized_id,
                "authorized": authorized,
                "manifest_hash": manifest_hash if authorized else None,
            }

    @plugin_entry(
        id="set_script_authorization",
        name="设置技能脚本权限",
        description="由用户显式授权或撤销当前 manifest revision 的脚本执行权限。",
        input_schema=AUTHORIZATION_SCHEMA,
        timeout=20.0,
    )
    async def set_script_authorization(
        self,
        skill_id: Any = "",
        authorized: Any = False,
        **_: Any,
    ):
        try:
            _reject_unexpected(_)
            return Ok(
                await asyncio.to_thread(
                    self._set_authorization_sync,
                    skill_id,
                    authorized,
                )
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception(
                "skill_loader authorization update failed: {}",
                type(exc).__name__,
            )
            return Err(SdkError("脚本权限保存失败。", code="authorization_save_failed"))

    # ------------------------------------------------------------------
    # Model-visible capabilities
    # ------------------------------------------------------------------

    @llm_tool(
        name="skill_loader_list",
        description=(
            "List enabled managed Agent Skills, their capabilities, linked-file "
            "counts, dependency status, and whether the user authorized scripts. "
            "Use this before choosing a skill. This tool cannot grant permission."
        ),
        parameters=EMPTY_SCHEMA,
        timeout=20.0,
    )
    @plugin_entry(
        id="skill_loader_list",
        name="列出技能",
        description="列出启用技能、能力、文件类别和脚本权限。",
        input_schema=EMPTY_SCHEMA,
        timeout=20.0,
        llm_result_fields=["skills", "message"],
    )
    async def skill_loader_list(self, **_: Any):
        try:
            _reject_unexpected(_)
            skills = await asyncio.to_thread(self._list_skills_sync)
            return Ok(
                {
                    "skills": skills,
                    "message": (
                        f"当前有 {len(skills)} 个可用的 managed Agent Skills。"
                        if skills
                        else "技能库为空，或所有技能都已禁用。"
                    ),
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception("skill_loader list failed: {}", type(exc).__name__)
            return Err(SdkError("技能列表读取失败。", code="skill_list_failed"))

    def _list_skills_sync(self) -> list[dict[str, Any]]:
        with self._registry_lock:
            registry = self._load_registry_locked()
            result: list[dict[str, Any]] = []
            for skill in registry["skills"]:
                if not isinstance(skill, Mapping) or skill.get("enabled") is not True:
                    continue
                panel = self._panel_skill(skill)
                counts: dict[str, int] = {}
                for item in panel["linked_files"]:
                    kind = str(item["kind"])
                    counts[kind] = counts.get(kind, 0) + 1
                dependency_issues = [
                    item
                    for item in panel["dependencies"]
                    if item["status"] in _BLOCKING_DEPENDENCY_STATUSES
                ]
                result.append(
                    {
                        "id": panel["id"],
                        "name": panel["name"],
                        "description": panel["description"],
                        "capabilities": panel["capabilities"],
                        "file_counts": counts,
                        "linked_files": [
                            {
                                "path": item["path"],
                                "kind": item["kind"],
                                "readable": item["readable"],
                                "size_bytes": item["size_bytes"],
                            }
                            for item in panel["linked_files"]
                        ],
                        "linked_paths": panel["linked_paths"],
                        "scripts": [
                            {
                                "path": item["path"],
                                "supported": item["supported"],
                                "available": item["available"],
                            }
                            for item in panel["scripts"]
                        ],
                        "script_authorized": panel["authorization"]["script_execution"],
                        "dependency_issues": dependency_issues,
                    }
                )
            return result

    def _read_skill_sync(self, skill_id: Any, raw_path: Any) -> dict[str, Any]:
        normalized_id = _require_skill_id(skill_id)
        if raw_path in ("", None):
            relative_path = "SKILL.md"
        elif isinstance(raw_path, str):
            try:
                relative_path = normalize_relative_path(raw_path)
            except PackageError as exc:
                raise _friendly_package_error(exc) from exc
        else:
            raise SdkError("path 必须是字符串。", code="invalid_path")
        with self._registry_lock:
            registry = self._load_registry_locked()
            skill = self._find_skill(registry, normalized_id)
            if skill is None or skill.get("enabled") is not True:
                raise SdkError(
                    "没有找到这个技能，或它已被禁用。", code="skill_unavailable"
                )
            manifest = skill.get("manifest")
            if not isinstance(manifest, Mapping):
                raise SdkError("技能 manifest 损坏。", code="registry_corrupt")
            generation = self._managed_generation(skill)
            try:
                result = read_manifest_file(
                    generation,
                    manifest,
                    relative_path,
                    max_bytes=DEFAULT_LIMITS.max_read_bytes,
                )
            except PackageError as exc:
                raise _friendly_package_error(exc) from exc
        content = result.get("content")
        if isinstance(content, str):
            safe_content, truncated = _truncate(
                _redact(content),
                _MAX_LLM_TEXT_CHARS,
            )
            message = "已读取 UTF-8 文本。"
        else:
            safe_content = ""
            truncated = False
            message = (
                "这是二进制素材或模板：已保留在 managed skill 中，可由已授权脚本"
                "按相对路径使用，但不会把原始二进制塞进对话上下文。"
            )
        return {
            "skill_id": normalized_id,
            "name": str(skill.get("name") or normalized_id),
            "path": relative_path,
            "kind": result.get("kind"),
            "readable": isinstance(content, str),
            "content": safe_content,
            "truncated": truncated,
            "size_bytes": result.get("size"),
            "sha256": result.get("sha256"),
            "message": message,
        }

    @llm_tool(
        name="skill_loader_read",
        description=(
            "Read SKILL.md or one exact manifest-listed linked file from an "
            "enabled managed skill. Paths must be package-relative; binary "
            "assets return metadata only. Never accepts arbitrary host paths."
        ),
        parameters=READ_SCHEMA,
        timeout=30.0,
    )
    @plugin_entry(
        id="skill_loader_read",
        name="读取技能文件",
        description="读取 SKILL.md 或 manifest 中指定的 linked file。",
        input_schema=READ_SCHEMA,
        timeout=30.0,
        llm_result_fields=[
            "skill_id",
            "name",
            "path",
            "content",
            "truncated",
            "message",
        ],
    )
    async def skill_loader_read(
        self,
        skill_id: Any = "",
        path: Any = "SKILL.md",
        **_: Any,
    ):
        try:
            _reject_unexpected(_)
            return Ok(
                await asyncio.to_thread(
                    self._read_skill_sync,
                    skill_id,
                    path,
                )
            )
        except SdkError as exc:
            return Err(exc)
        except Exception as exc:
            self.logger.exception("skill_loader read failed: {}", type(exc).__name__)
            return Err(SdkError("技能文件读取失败。", code="skill_read_failed"))

    async def skill_loader_get(self, skill_id: Any = "", **_: Any):
        """Compatibility wrapper that reads the skill's SKILL.md."""

        return await self.skill_loader_read(skill_id=skill_id, path="SKILL.md", **_)

    def _prepare_run_sync(
        self,
        skill_id: Any,
        script_path: Any,
        argv: Any,
        timeout_seconds: Any,
    ) -> tuple[str, Path, str, list[str], int]:
        normalized_id = _require_skill_id(skill_id)
        if not isinstance(script_path, str):
            raise SdkError("script_path 必须是字符串。", code="invalid_script")
        try:
            normalized_script = normalize_relative_path(script_path)
        except PackageError as exc:
            raise _friendly_package_error(exc) from exc
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds < 1
            or timeout_seconds > _MAX_SCRIPT_TIMEOUT_SECONDS
        ):
            raise SdkError(
                "timeout_seconds 必须是 1 到 120 的整数。",
                code="invalid_timeout",
            )
        try:
            normalized_argv = validate_argv(argv)
        except RunnerError as exc:
            raise _friendly_runner_error(exc) from exc
        with self._registry_lock:
            if normalized_id in self._active_skills:
                raise SdkError("这个技能已有脚本正在运行。", code="skill_busy")
            registry = self._load_registry_locked()
            skill = self._find_skill(registry, normalized_id)
            if skill is None or skill.get("enabled") is not True:
                raise SdkError(
                    "没有找到这个技能，或它已被禁用。", code="skill_unavailable"
                )
            manifest = skill.get("manifest")
            if not isinstance(manifest, Mapping):
                raise SdkError("技能 manifest 损坏。", code="registry_corrupt")
            manifest_hash = str(manifest.get("manifest_sha256") or "")
            authorization = skill.get("authorization")
            if not isinstance(authorization, Mapping) or not (
                authorization.get("script_execution") is True
                and authorization.get("manifest_hash") == manifest_hash
            ):
                raise SdkError(
                    "用户尚未授权这个技能当前版本的脚本执行；LLM 不能自行授权。",
                    code="script_not_authorized",
                )
            scripts = manifest.get("scripts")
            script = (
                next(
                    (
                        item
                        for item in scripts
                        if isinstance(item, Mapping)
                        and item.get("path") == normalized_script
                    ),
                    None,
                )
                if isinstance(scripts, list)
                else None
            )
            if script is None:
                raise SdkError(
                    "脚本不在导入时保存的 scripts manifest 中。",
                    code="script_not_in_manifest",
                )
            if script.get("supported") is not True:
                raise SdkError(
                    "这个脚本已保留，但当前只支持 UTF-8 Python .py。",
                    code="unsupported_script",
                )
            script_size = script.get("size")
            if (
                isinstance(script_size, bool)
                or not isinstance(script_size, int)
                or script_size < 0
                or script_size > DEFAULT_RUNNER_LIMITS.max_script_bytes
            ):
                raise SdkError(
                    "脚本超过 runner 的单文件大小上限，已保留但不能执行。",
                    code="script_too_large",
                )
            blockers = [
                str(value)
                for value in script.get("blocking_dependencies", [])
                if isinstance(value, str)
            ]
            if blockers:
                raise SdkError(
                    "脚本依赖尚未满足："
                    + "、".join(blockers)
                    + "。请在 N.E.K.O 的独立环境中准备依赖；插件不会自动安装。",
                    code="missing_dependency",
                    details={"dependencies": blockers},
                )
            generation = self._managed_generation(skill)
            try:
                read_manifest_file(
                    generation,
                    manifest,
                    normalized_script,
                    max_bytes=DEFAULT_RUNNER_LIMITS.max_script_bytes,
                )
            except PackageError as exc:
                raise _friendly_package_error(exc) from exc
            self._active_skills.add(normalized_id)
            return (
                normalized_id,
                generation,
                normalized_script,
                normalized_argv,
                timeout_seconds,
            )

    def _record_last_run_sync(self, skill_id: str, result: Mapping[str, Any]) -> None:
        with self._registry_lock:
            registry = self._load_registry_locked()
            skill = self._find_skill(registry, skill_id)
            if skill is None:
                return
            compact = copy.deepcopy(dict(result))
            stdout = compact.get("stdout")
            stderr = compact.get("stderr")
            if isinstance(stdout, str):
                compact["stdout"] = _truncate(_redact(stdout), _MAX_PANEL_TEXT_CHARS)[0]
            if isinstance(stderr, str):
                compact["stderr"] = _truncate(_redact(stderr), _MAX_PANEL_TEXT_CHARS)[0]
            compact["finished_at"] = time.time()
            skill["last_run"] = compact
            skill["updated_at"] = time.time()
            self._save_registry_locked(registry)

    def _release_active_skill(self, skill_id: str) -> None:
        with self._registry_lock:
            self._active_skills.discard(skill_id)

    @llm_tool(
        name="skill_loader_run_script",
        description=(
            "Run one imported scripts/*.py file only after the user explicitly "
            "authorized this exact skill manifest revision. Arguments are an "
            "array, never a shell command. The tool cannot grant permission or "
            "install dependencies."
        ),
        parameters=RUN_SCHEMA,
        timeout=130.0,
    )
    @plugin_entry(
        id="skill_loader_run_script",
        name="运行已授权技能脚本",
        description="以 argv-only、固定 cwd、受限环境运行 manifest 中的 Python 脚本。",
        input_schema=RUN_SCHEMA,
        timeout=130.0,
        llm_result_fields=[
            "summary",
            "status",
            "stdout",
            "stderr",
            "artifacts",
            "diagnostic",
        ],
    )
    async def skill_loader_run_script(
        self,
        skill_id: Any = "",
        script_path: Any = "",
        argv: Any = None,
        timeout_seconds: Any = _DEFAULT_SCRIPT_TIMEOUT_SECONDS,
        **_: Any,
    ):
        active_id = ""
        try:
            _reject_unexpected(_)
            if argv is None:
                argv = []
            (
                active_id,
                generation,
                normalized_script,
                normalized_argv,
                normalized_timeout,
            ) = await asyncio.to_thread(
                self._prepare_run_sync,
                skill_id,
                script_path,
                argv,
                timeout_seconds,
            )
            result = await run_python_script(
                generation,
                normalized_script,
                normalized_argv,
                generation / ".neko-runs",
                normalized_timeout,
            )
            result["skill_id"] = active_id
            if isinstance(result.get("stdout"), str):
                result["stdout"] = _redact(str(result["stdout"]))
            if isinstance(result.get("stderr"), str):
                result["stderr"] = _redact(str(result["stderr"]))
            await asyncio.to_thread(self._record_last_run_sync, active_id, result)
            if result.get("ok") is True:
                return Ok(result)
            diagnostic = result.get("diagnostic")
            diagnostic_message = (
                str(diagnostic.get("message") or "")
                if isinstance(diagnostic, Mapping)
                else ""
            )
            summary = str(result.get("summary") or "脚本运行失败。")
            return Err(
                SdkError(
                    diagnostic_message or summary,
                    code=str(
                        diagnostic.get("code")
                        if isinstance(diagnostic, Mapping)
                        else result.get("status") or "script_failed"
                    ),
                    details=result,
                )
            )
        except SdkError as exc:
            return Err(exc)
        except RunnerError as exc:
            return Err(_friendly_runner_error(exc))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.exception(
                "skill_loader script run failed: {}", type(exc).__name__
            )
            return Err(SdkError("技能脚本运行失败。", code="script_run_failed"))
        finally:
            if active_id:
                await asyncio.to_thread(self._release_active_skill, active_id)


__all__ = [
    "AUTHORIZATION_SCHEMA",
    "EMPTY_SCHEMA",
    "IMPORT_SCHEMA",
    "PLUGIN_ID",
    "READ_SCHEMA",
    "RUN_SCHEMA",
    "SETTINGS_SCHEMA",
    "SkillLoaderPlugin",
    "UPDATE_SCHEMA",
    "_redact",
    "parse_skill_markdown",
]
