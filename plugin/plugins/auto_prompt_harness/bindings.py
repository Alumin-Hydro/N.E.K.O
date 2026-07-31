"""Character-card binding and managed-overlay primitives.

The host character file is the recovery source of truth.  PluginStore keeps
the user-facing workflow state, while immutable provenance embedded in each
managed overlay makes interrupted writes and restarts reconcilable.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
import re
import time
import unicodedata
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from config import APP_NAME
from config.prompts.prompts_chara import get_lanlan_prompt, is_default_prompt
from utils.persona_presets import PERSONA_OVERRIDE_FIELDS
from utils.character_name import (
    PROFILE_NAME_MAX_UNITS,
    count_character_name_units,
    trim_character_name_to_max_units,
    validate_character_name,
)
from utils.config_manager import get_config_manager, get_reserved, set_reserved
from utils.config_manager.persona_payload import (
    _append_persona_guidance_to_prompt,
    _resolve_effective_character_prompt,
)


PLUGIN_ID = "auto_prompt_harness"
STATE_SCHEMA_VERSION = 2
STATE_KEY = "auto_prompt_harness.state.v2"
LEGACY_STATE_KEY = "auto_prompt_harness.state.v1"
PROVENANCE_KEY = "auto_prompt_harness"
PROVENANCE_KIND = "adaptive_overlay"
PROMPT_STORAGE_SYSTEM = "system_prompt"
PROMPT_STORAGE_DYNAMIC_DEFAULT = "dynamic_default_guidance"
DYNAMIC_PERSONA_SOURCE = "auto_prompt_harness.managed_prompt"
ADAPTATION_START = "<NEKO_AUTO_PROMPT_HARNESS_ADAPTATION>"
ADAPTATION_END = "</NEKO_AUTO_PROMPT_HARNESS_ADAPTATION>"
MAX_BASE_PROMPT_CHARS = 120_000
MAX_ADAPTATION_CHARS = 400
MAX_ACTIVE_ADAPTATIONS = 8
MAX_COMPOSED_PROMPT_CHARS = 128_000
MAX_PROPOSALS = 24
MAX_HISTORY = 80
MAX_VERSIONS = 32
MAX_EVIDENCE_MESSAGES = 12
MAX_EVIDENCE_CHARS = 240

_FINGERPRINT_RE = re.compile(r"^[a-f0-9]{64}$")
_ID_RE = re.compile(r"^[a-f0-9]{16,32}$")
_SPACE_RE = re.compile(r"\s+")
_FORBIDDEN_ADAPTATION_PATTERNS = (
    re.compile(r"(?i)\b(?:system|developer|assistant|tool)\s*(?:message|prompt|role)\b"),
    re.compile(r"(?i)\bignore\b.{0,40}\b(?:previous|above|higher[- ]priority)\b"),
    re.compile(r"(?i)\b(?:reveal|print|repeat|leak|show)\b.{0,40}\b(?:prompt|instruction|secret)\b"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|private[_ -]?key)\b"),
    re.compile(r"(?i)\b(?:curl|wget|powershell|cmd|bash|sh)\b.{0,80}(?:\||&&|;|/c)\b"),
    re.compile(r"(?i)<\s*/?\s*(?:system|developer|assistant|tool|prompt|instruction)\b"),
    re.compile(r"(?i)\b(?:never\s+refuse|bypass\s+safety|disable\s+safety|jailbreak)\b"),
    re.compile(
        r"(?:忽略|无视|覆盖|绕过|废除|取消).{0,30}"
        r"(?:之前|先前|原来|原有|系统|角色|人设|设定|指令|规则|安全)"
    ),
    re.compile(
        r"(?:你现在是|改成|变成|冒充|伪装成).{0,24}"
        r"(?:管理员|开发者|系统|其他角色|另一个角色)"
    ),
    re.compile(
        r"(?:泄露|显示|输出|打印|复述|公开).{0,30}"
        r"(?:系统提示|提示词|隐藏指令|密钥|密码|令牌|私钥)"
    ),
    re.compile(
        r"(?:关闭|禁用|绕过|突破|解除).{0,24}"
        r"(?:安全|审查|限制|防护|权限检查)"
    ),
    re.compile(
        r"(?i)(?:以前の|システム|役割).{0,24}(?:無視|上書き|解除)"
        r"|(?:시스템|이전|역할).{0,24}(?:무시|덮어|해제)"
    ),
)

DEFAULT_SETTINGS: dict[str, Any] = {
    "learning_enabled": True,
    "automatic_reflection": False,
    "auto_apply_low_risk": False,
    "reflection_threshold": 4,
    "minimum_confidence": 0.75,
    "evidence_window": 12,
    "show_evidence_excerpts": True,
}

_ALLOWED_BINDING_STATUSES = {
    "active",
    "inactive",
    "restored",
    "suspended_for_shutdown",
    "conflict",
    "deletion_pending",
    "overlay_deleted",
}
_ALLOWED_PROPOSAL_STATUSES = {
    "pending",
    "approved",
    "rejected",
    "superseded",
}


class CharacterOperationError(RuntimeError):
    """Raised when a host character operation cannot be completed safely."""

    def __init__(self, message: str, *, code: str = "character_operation_failed"):
        super().__init__(message)
        self.code = code


def now_ts(value: object | None = None) -> float:
    """Return a finite non-negative timestamp."""

    try:
        result = float(time.time() if value is None else value)
    except (TypeError, ValueError, OverflowError):
        return time.time()
    return max(0.0, result) if math.isfinite(result) else time.time()


def canonical_json(value: object) -> str:
    """Serialize a value deterministically for integrity fingerprints."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def text_fingerprint(value: str) -> str:
    """Return a full SHA-256 fingerprint for prompt text."""

    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def card_fingerprint(card: Mapping[str, Any]) -> str:
    """Return a deep-content fingerprint for one raw character payload."""

    return hashlib.sha256(canonical_json(card).encode("utf-8")).hexdigest()


def prompt_storage_mode(card: Mapping[str, Any]) -> str:
    """Return the immutable managed-prompt storage mode for an overlay."""

    reserved = card.get("_reserved")
    provenance = (
        reserved.get(PROVENANCE_KEY)
        if isinstance(reserved, Mapping)
        else None
    )
    mode = (
        provenance.get("prompt_storage_mode")
        if isinstance(provenance, Mapping)
        else None
    )
    return (
        mode
        if mode in {
            PROMPT_STORAGE_SYSTEM,
            PROMPT_STORAGE_DYNAMIC_DEFAULT,
        }
        else PROMPT_STORAGE_SYSTEM
    )


def _overlay_integrity_view(card: Mapping[str, Any]) -> dict[str, Any]:
    view = copy.deepcopy(dict(card))
    reserved = view.get("_reserved")
    if isinstance(reserved, dict):
        mode = prompt_storage_mode(card)
        reserved.pop(PROVENANCE_KEY, None)
        if mode == PROMPT_STORAGE_DYNAMIC_DEFAULT:
            override = reserved.get("persona_override")
            if isinstance(override, dict):
                override.pop("prompt_guidance", None)
        else:
            reserved.pop("system_prompt", None)
        if not reserved:
            view.pop("_reserved", None)
    return view


def overlay_integrity_fingerprint(card: Mapping[str, Any]) -> str:
    """Fingerprint every overlay field except the two managed fields."""

    return card_fingerprint(_overlay_integrity_view(card))


def effective_prompt(card: Mapping[str, Any]) -> str:
    """Resolve the exact prompt the host would use for a raw character card."""

    payload = copy.deepcopy(dict(card))
    prompt = _resolve_effective_character_prompt(payload)
    prompt = _append_persona_guidance_to_prompt(str(prompt), payload)
    prompt = str(prompt or get_lanlan_prompt())
    if len(prompt) > MAX_BASE_PROMPT_CHARS:
        raise CharacterOperationError(
            "角色卡的基础提示词过长，无法安全创建适配副本。",
            code="base_prompt_too_large",
        )
    return prompt


def stored_prompt(card: Mapping[str, Any]) -> str:
    """Read the stable logical prompt managed by the plugin.

    Dynamic-default overlays keep the host's raw default prompt untouched so
    the legacy resolver can localize it at runtime.  Their approved block is
    stored in a neutral ``persona_override.prompt_guidance`` field, while this
    helper reconstructs the same immutable version shape used by history and
    rollback.
    """

    if prompt_storage_mode(card) == PROMPT_STORAGE_DYNAMIC_DEFAULT:
        provenance = provenance_for(card) or {}
        base_prompt = provenance.get("base_prompt_snapshot")
        if not isinstance(base_prompt, str) or not base_prompt:
            return ""
        reserved = card.get("_reserved")
        override = (
            reserved.get("persona_override")
            if isinstance(reserved, Mapping)
            else None
        )
        if not isinstance(override, Mapping):
            return ""
        guidance = override.get("prompt_guidance")
        if not isinstance(guidance, str):
            return ""
        if not guidance:
            return base_prompt
        return f"{base_prompt}\n\n{guidance}"

    value = get_reserved(
        dict(card),
        "system_prompt",
        default=None,
        legacy_keys=("system_prompt",),
    )
    return effective_prompt(card) if value is None else str(value)


def set_stored_prompt(card: dict[str, Any], prompt: str) -> None:
    """Write the host-authoritative managed prompt field."""

    if prompt_storage_mode(card) == PROMPT_STORAGE_DYNAMIC_DEFAULT:
        provenance = provenance_for(card) or {}
        base_prompt = provenance.get("base_prompt_snapshot")
        if not isinstance(base_prompt, str) or not base_prompt:
            raise CharacterOperationError(
                "自适应副本缺少动态默认提示词快照。",
                code="dynamic_base_missing",
            )
        prompt = str(prompt)
        if prompt == base_prompt:
            guidance = ""
        else:
            adaptations = extract_managed_adaptations(prompt)
            if (
                not adaptations
                or compose_prompt(base_prompt, adaptations) != prompt
            ):
                raise CharacterOperationError(
                    "动态默认提示词版本结构无效。",
                    code="dynamic_prompt_invalid",
                )
            guidance = prompt[len(base_prompt) + 2 :]
        reserved = card.get("_reserved")
        override = (
            reserved.get("persona_override")
            if isinstance(reserved, dict)
            else None
        )
        if (
            not isinstance(override, dict)
            or override.get("source") != DYNAMIC_PERSONA_SOURCE
            or str(override.get("preset_id") or "")
            or override.get("profile") != {}
        ):
            raise CharacterOperationError(
                "动态默认提示词的受控字段已变化。",
                code="dynamic_prompt_container_changed",
            )
        override["prompt_guidance"] = guidance
        return

    set_reserved(card, "system_prompt", str(prompt))


def requires_managed_prompt_composition(card: Mapping[str, Any]) -> bool:
    """Return whether a source card must be materialized before adaptation."""

    raw_prompt = get_reserved(
        dict(card),
        "system_prompt",
        default=None,
        legacy_keys=("system_prompt",),
    )
    reserved = card.get("_reserved")
    resolved_prompt = _resolve_effective_character_prompt(
        copy.deepcopy(dict(card))
    )
    effective = _append_persona_guidance_to_prompt(
        str(resolved_prompt),
        copy.deepcopy(dict(card)),
    )
    return (
        raw_prompt is not None
        and not is_default_prompt(str(raw_prompt))
    ) or effective != resolved_prompt


def _flatten_persona_profile(overlay: dict[str, Any]) -> None:
    """Materialize the legacy runtime's persona field overrides in a copy."""

    reserved = overlay.get("_reserved")
    override = (
        reserved.get("persona_override")
        if isinstance(reserved, dict)
        else None
    )
    profile = override.get("profile") if isinstance(override, Mapping) else None
    if isinstance(profile, Mapping):
        for field in PERSONA_OVERRIDE_FIELDS:
            value = str(profile.get(field) or "").strip()
            if value:
                overlay[field] = value
    if isinstance(reserved, dict):
        reserved.pop("persona_override", None)


def _install_dynamic_prompt_container(overlay: dict[str, Any]) -> None:
    reserved = overlay.setdefault("_reserved", {})
    if not isinstance(reserved, dict):
        raise CharacterOperationError(
            "角色卡保留字段结构异常。",
            code="characters_invalid",
        )
    reserved["persona_override"] = {
        "preset_id": "",
        "selected_at": "",
        "source": DYNAMIC_PERSONA_SOURCE,
        "prompt_guidance": "",
        "profile": {},
    }


def provenance_for(card: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return validated-looking plugin provenance without mutating the card."""

    reserved = card.get("_reserved")
    if not isinstance(reserved, Mapping):
        return None
    raw = reserved.get(PROVENANCE_KEY)
    if not isinstance(raw, Mapping):
        return None
    return copy.deepcopy(dict(raw))


def has_managed_provenance_marker(card: object) -> bool:
    """Return whether a card contains this plugin's reserved namespace.

    This intentionally does not imply valid ownership.  Malformed provenance
    must remain recognizable and must never be offered as a fresh original
    card.
    """

    if not isinstance(card, Mapping):
        return False
    reserved = card.get("_reserved")
    return isinstance(reserved, Mapping) and PROVENANCE_KEY in reserved


def provenance_fingerprint(card: Mapping[str, Any]) -> str:
    """Fingerprint the complete immutable ownership marker."""

    provenance = provenance_for(card)
    return card_fingerprint(provenance) if provenance is not None else ""


def is_managed_overlay(card: object) -> bool:
    """Return whether a raw card is recognizably owned by this plugin."""

    if not isinstance(card, Mapping):
        return False
    provenance = provenance_for(card)
    return bool(
        provenance
        and provenance.get("plugin_id") == PLUGIN_ID
        and provenance.get("kind") == PROVENANCE_KIND
        and type(provenance.get("schema_version")) is int
        and provenance.get("schema_version") == STATE_SCHEMA_VERSION
        and isinstance(provenance.get("binding_id"), str)
        and _ID_RE.fullmatch(provenance["binding_id"])
        and provenance.get(
            "prompt_storage_mode",
            PROMPT_STORAGE_SYSTEM,
        )
        in {
            PROMPT_STORAGE_SYSTEM,
            PROMPT_STORAGE_DYNAMIC_DEFAULT,
        }
    )


def _name_identity(value: str) -> str:
    return unicodedata.normalize("NFC", str(value)).casefold()


def unique_overlay_name(original_name: str, existing_names: Sequence[str]) -> str:
    """Build a valid, recognizable, case-insensitively unique overlay name."""

    identities = {_name_identity(name) for name in existing_names}
    for index in range(1, 10_000):
        suffix = "（自适应）" if index == 1 else f"（自适应 {index}）"
        base_units = max(
            2,
            PROFILE_NAME_MAX_UNITS - count_character_name_units(suffix),
        )
        base = trim_character_name_to_max_units(str(original_name).strip(), base_units)
        candidate = f"{base or '角色'}{suffix}"
        validation = validate_character_name(
            candidate,
            max_units=PROFILE_NAME_MAX_UNITS,
        )
        if not validation.ok:
            candidate = f"角色{suffix}"
            validation = validate_character_name(
                candidate,
                max_units=PROFILE_NAME_MAX_UNITS,
            )
        if validation.ok and _name_identity(validation.normalized) not in identities:
            return validation.normalized
    raise CharacterOperationError(
        "无法生成唯一的自适应副本名称。",
        code="overlay_name_exhausted",
    )


def normalize_adaptation_text(value: object) -> tuple[bool, str]:
    """Validate one approved communication-style adaptation."""

    if not isinstance(value, str):
        return False, "建议内容必须是普通文本。"
    if any(marker in value for marker in ("\n", "\r", "```")):
        return False, "建议内容必须是单行文本。"
    cleaned = unicodedata.normalize("NFKC", value)
    cleaned = "".join(
        character
        for character in cleaned
        if unicodedata.category(character) not in {"Cc", "Cf"}
    )
    cleaned = _SPACE_RE.sub(" ", cleaned).strip()
    if not cleaned:
        return False, "建议内容不能为空。"
    if len(cleaned) > MAX_ADAPTATION_CHARS:
        return False, f"建议内容最多 {MAX_ADAPTATION_CHARS} 个字符。"
    lowered = cleaned.lower()
    if ADAPTATION_START.lower() in lowered or ADAPTATION_END.lower() in lowered:
        return False, "建议内容包含保留的适配边界。"
    if any(pattern.search(cleaned) for pattern in _FORBIDDEN_ADAPTATION_PATTERNS):
        return False, "建议内容包含角色覆盖、提示泄露、密钥或危险指令。"
    return True, cleaned


def compose_prompt(base_prompt: str, adaptations: Sequence[str]) -> str:
    """Compose the immutable base prompt with a bounded managed block."""

    base = str(base_prompt)
    if len(base) > MAX_BASE_PROMPT_CHARS:
        raise CharacterOperationError(
            "角色卡的基础提示词过长。",
            code="base_prompt_too_large",
        )
    clean: list[str] = []
    seen: set[str] = set()
    for raw in list(adaptations)[-MAX_ACTIVE_ADAPTATIONS:]:
        ok, normalized = normalize_adaptation_text(raw)
        if not ok or normalized in seen:
            continue
        clean.append(normalized)
        seen.add(normalized)
    if not clean:
        return base
    block = (
        f"{ADAPTATION_START}\n"
        "Approved communication-style adaptations for this character copy only. "
        "Keep the original identity, safety rules, factual standards, and task goals unchanged.\n"
        + "\n".join(f"- {item}" for item in clean)
        + f"\n{ADAPTATION_END}"
    )
    combined = f"{base}\n\n{block}"
    if len(combined) > MAX_COMPOSED_PROMPT_CHARS:
        raise CharacterOperationError(
            "组合后的提示词超过安全上限。",
            code="composed_prompt_too_large",
        )
    return combined


def strip_managed_adaptation(prompt: str) -> str:
    """Recover the base prefix from a prompt containing our terminal block."""

    text = str(prompt)
    start = text.rfind(ADAPTATION_START)
    end = text.rfind(ADAPTATION_END)
    if start < 0 or end < start or text[end + len(ADAPTATION_END) :].strip():
        return text
    prefix = text[:start]
    return prefix[:-2] if prefix.endswith("\n\n") else text


def extract_managed_adaptations(prompt: str) -> list[str]:
    """Recover validated bullet items from our terminal managed block."""

    text = str(prompt)
    start = text.rfind(ADAPTATION_START)
    end = text.rfind(ADAPTATION_END)
    if start < 0 or end < start or text[end + len(ADAPTATION_END) :].strip():
        return []
    block = text[start + len(ADAPTATION_START) : end]
    result: list[str] = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("- "):
            continue
        ok, cleaned = normalize_adaptation_text(line[2:])
        if ok and cleaned not in result:
            result.append(cleaned)
    return result[-MAX_ACTIVE_ADAPTATIONS:]


def fresh_state() -> dict[str, Any]:
    """Return a new bounded v2 state."""

    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "settings": copy.deepcopy(DEFAULT_SETTINGS),
        "binding": None,
        "proposals": [],
        "evidence": [],
        "bus_cursor": {"timestamp": 0.0, "fingerprints": []},
        "last_reflection_evidence_fingerprint": "",
        "legacy_migration": {
            "detected": False,
            "migrated_at": 0.0,
            "profiles_not_bound": 0,
        },
        "stats": {
            "messages_seen": 0,
            "reflections": 0,
            "approved": 0,
            "rejected": 0,
            "rollbacks": 0,
            "errors": 0,
        },
    }


def normalize_settings(raw: object) -> dict[str, Any]:
    """Normalize the small advanced-settings surface."""

    settings = copy.deepcopy(DEFAULT_SETTINGS)
    if not isinstance(raw, Mapping):
        return settings
    for key in (
        "learning_enabled",
        "automatic_reflection",
        "auto_apply_low_risk",
        "show_evidence_excerpts",
    ):
        if isinstance(raw.get(key), bool):
            settings[key] = raw[key]
    for key, minimum, maximum in (
        ("reflection_threshold", 1, 12),
        ("evidence_window", 2, MAX_EVIDENCE_MESSAGES),
    ):
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            settings[key] = max(minimum, min(maximum, value))
    confidence = raw.get("minimum_confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        confidence = float(confidence)
        if math.isfinite(confidence):
            settings["minimum_confidence"] = round(
                max(0.5, min(0.95, confidence)),
                3,
            )
    if settings["reflection_threshold"] > settings["evidence_window"]:
        settings["reflection_threshold"] = settings["evidence_window"]
    return settings


def _clean_string(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value[: max(0, limit)]


def _clean_timestamp(value: object) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return max(0.0, result) if math.isfinite(result) else 0.0


def _clean_fingerprint(value: object) -> str:
    return value if isinstance(value, str) and _FINGERPRINT_RE.fullmatch(value) else ""


def _normalize_version(raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    prompt = _clean_string(raw.get("prompt"), MAX_COMPOSED_PROMPT_CHARS)
    fingerprint = _clean_fingerprint(raw.get("prompt_fingerprint"))
    if not prompt or fingerprint != text_fingerprint(prompt):
        return None
    adaptations: list[str] = []
    if isinstance(raw.get("adaptations"), list):
        for item in raw["adaptations"][-MAX_ACTIVE_ADAPTATIONS:]:
            ok, clean = normalize_adaptation_text(item)
            if ok and clean not in adaptations:
                adaptations.append(clean)
    number = raw.get("version")
    if not isinstance(number, int) or isinstance(number, bool) or number < 0:
        return None
    return {
        "version": min(number, 1_000_000),
        "prompt": prompt,
        "prompt_fingerprint": fingerprint,
        "adaptations": adaptations,
        "created_at": _clean_timestamp(raw.get("created_at")),
        "proposal_id": _clean_string(raw.get("proposal_id"), 64),
    }


def _normalize_history(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for item in raw[-MAX_HISTORY:]:
        if not isinstance(item, Mapping):
            continue
        action = _clean_string(item.get("action"), 32)
        if action not in {
            "bound",
            "activated",
            "approved",
            "rejected",
            "rolled_back",
            "restored",
            "shutdown_restored",
            "recovered",
            "overlay_renamed",
            "overlay_deleted",
            "conflict",
        }:
            continue
        result.append(
            {
                "action": action,
                "at": _clean_timestamp(item.get("at")),
                "summary": _clean_string(item.get("summary"), 400),
                "proposal_id": _clean_string(item.get("proposal_id"), 64),
                "before": _clean_string(item.get("before"), 1_600),
                "after": _clean_string(item.get("after"), 1_600),
                "before_fingerprint": _clean_fingerprint(
                    item.get("before_fingerprint")
                ),
                "after_fingerprint": _clean_fingerprint(
                    item.get("after_fingerprint")
                ),
                "version": (
                    item.get("version")
                    if isinstance(item.get("version"), int)
                    and not isinstance(item.get("version"), bool)
                    else 0
                ),
            }
        )
    return result


def normalize_binding(raw: object) -> dict[str, Any] | None:
    """Normalize one persisted binding without guessing missing identity."""

    if not isinstance(raw, Mapping):
        return None
    binding_id = _clean_string(raw.get("binding_id"), 32)
    original_name = _clean_string(raw.get("original_name"), 120)
    overlay_name = _clean_string(raw.get("overlay_name"), 120)
    if not _ID_RE.fullmatch(binding_id) or not original_name or not overlay_name:
        return None
    base_prompt = _clean_string(
        raw.get("base_prompt"),
        MAX_BASE_PROMPT_CHARS,
    )
    base_prompt_fingerprint = _clean_fingerprint(
        raw.get("base_prompt_fingerprint")
    )
    if (
        not base_prompt
        or base_prompt_fingerprint != text_fingerprint(base_prompt)
    ):
        return None
    versions: list[dict[str, Any]] = []
    if isinstance(raw.get("versions"), list):
        for item in raw["versions"][-MAX_VERSIONS:]:
            version = _normalize_version(item)
            if version is None:
                return None
            try:
                expected_prompt = compose_prompt(
                    base_prompt,
                    version["adaptations"],
                )
            except CharacterOperationError:
                return None
            if version["prompt"] != expected_prompt:
                return None
            versions.append(version)
    if not versions:
        return None
    version_numbers = [item["version"] for item in versions]
    if any(
        current <= previous
        for previous, current in zip(version_numbers, version_numbers[1:])
    ):
        return None
    active_version = raw.get("active_version")
    if (
        not isinstance(active_version, int)
        or isinstance(active_version, bool)
        or active_version not in version_numbers
    ):
        return None
    status = _clean_string(raw.get("status"), 48)
    if status not in _ALLOWED_BINDING_STATUSES:
        status = "conflict"
    storage_mode = raw.get("prompt_storage_mode")
    if storage_mode not in {
        PROMPT_STORAGE_SYSTEM,
        PROMPT_STORAGE_DYNAMIC_DEFAULT,
    }:
        storage_mode = PROMPT_STORAGE_SYSTEM
    return {
        "binding_id": binding_id,
        "original_name": original_name,
        "overlay_name": overlay_name,
        "original_card_fingerprint": _clean_fingerprint(
            raw.get("original_card_fingerprint")
        ),
        "base_prompt": base_prompt,
        "base_prompt_fingerprint": base_prompt_fingerprint,
        "overlay_integrity_fingerprint": _clean_fingerprint(
            raw.get("overlay_integrity_fingerprint")
        ),
        "provenance_fingerprint": _clean_fingerprint(
            raw.get("provenance_fingerprint")
        ),
        "created_at": _clean_timestamp(raw.get("created_at")),
        "updated_at": _clean_timestamp(raw.get("updated_at")),
        "desired_enabled": bool(raw.get("desired_enabled", False)),
        "status": status,
        "conflict_code": _clean_string(raw.get("conflict_code"), 64),
        "last_error": _clean_string(raw.get("last_error"), 500),
        "active_version": active_version,
        "versions": versions,
        "history": _normalize_history(raw.get("history")),
        "runtime_refresh_mode": _clean_string(
            raw.get("runtime_refresh_mode"),
            48,
        ),
        "managed_prompt_composition_required": (
            raw.get("managed_prompt_composition_required") is not False
        ),
        "prompt_storage_mode": storage_mode,
    }


def _normalize_proposal(raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    proposal_id = _clean_string(raw.get("id"), 64)
    status = _clean_string(raw.get("status"), 24)
    proposed = _clean_string(raw.get("proposed_prompt"), MAX_ADAPTATION_CHARS)
    if not proposal_id or status not in _ALLOWED_PROPOSAL_STATUSES:
        return None
    if proposed:
        ok, proposed = normalize_adaptation_text(proposed)
        if not ok:
            return None
    confidence = raw.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        return None
    confidence = float(confidence)
    if not math.isfinite(confidence):
        return None
    risk = _clean_string(raw.get("risk"), 16)
    if risk not in {"low", "medium", "high"}:
        return None
    excerpts = []
    if isinstance(raw.get("evidence_excerpt"), list):
        excerpts = [
            _clean_string(item, MAX_EVIDENCE_CHARS)
            for item in raw["evidence_excerpt"][-4:]
            if isinstance(item, str) and item
        ]
    return {
        "id": proposal_id,
        "status": status,
        "trigger": _clean_string(raw.get("trigger"), 200),
        "evidence_summary": _clean_string(raw.get("evidence_summary"), 400),
        "preference": _clean_string(raw.get("preference"), 400),
        "proposed_prompt": proposed,
        "applied_prompt": _clean_string(
            raw.get("applied_prompt"),
            MAX_ADAPTATION_CHARS,
        ),
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
        "risk": risk,
        "created_at": _clean_timestamp(raw.get("created_at")),
        "resolved_at": _clean_timestamp(raw.get("resolved_at")),
        "evidence_excerpt": excerpts,
        "version": 1,
    }


def normalize_state(raw: object) -> dict[str, Any]:
    """Normalize persisted v2 state and drop unknown/unbounded data."""

    state = fresh_state()
    if not isinstance(raw, Mapping) or raw.get("schema_version") != STATE_SCHEMA_VERSION:
        return state
    state["settings"] = normalize_settings(raw.get("settings"))
    state["binding"] = normalize_binding(raw.get("binding"))
    if isinstance(raw.get("proposals"), list):
        state["proposals"] = [
            proposal
            for item in raw["proposals"][-MAX_PROPOSALS:]
            if (proposal := _normalize_proposal(item)) is not None
        ]
    if isinstance(raw.get("evidence"), list):
        evidence: list[dict[str, Any]] = []
        for item in raw["evidence"][-MAX_EVIDENCE_MESSAGES:]:
            if not isinstance(item, Mapping):
                continue
            role = item.get("role")
            text = _clean_string(item.get("text"), MAX_EVIDENCE_CHARS)
            fingerprint = _clean_string(item.get("fingerprint"), 64)
            if role not in {"user", "assistant"} or not text or not fingerprint:
                continue
            evidence.append(
                {
                    "role": role,
                    "text": text,
                    "at": _clean_timestamp(item.get("at")),
                    "fingerprint": fingerprint,
                }
            )
        state["evidence"] = evidence
    cursor = raw.get("bus_cursor")
    if isinstance(cursor, Mapping):
        fingerprints = cursor.get("fingerprints")
        state["bus_cursor"] = {
            "timestamp": _clean_timestamp(cursor.get("timestamp")),
            "fingerprints": (
                [
                    item
                    for item in fingerprints[-512:]
                    if isinstance(item, str) and re.fullmatch(r"[a-f0-9]{16}", item)
                ]
                if isinstance(fingerprints, list)
                else []
            ),
        }
    state["last_reflection_evidence_fingerprint"] = _clean_fingerprint(
        raw.get("last_reflection_evidence_fingerprint")
    )
    migration = raw.get("legacy_migration")
    if isinstance(migration, Mapping):
        state["legacy_migration"] = {
            "detected": bool(migration.get("detected", False)),
            "migrated_at": _clean_timestamp(migration.get("migrated_at")),
            "profiles_not_bound": (
                max(0, min(1_000, int(migration.get("profiles_not_bound", 0))))
                if isinstance(migration.get("profiles_not_bound", 0), int)
                and not isinstance(migration.get("profiles_not_bound", 0), bool)
                else 0
            ),
        }
    stats = raw.get("stats")
    if isinstance(stats, Mapping):
        for key in state["stats"]:
            value = stats.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                state["stats"][key] = max(0, min(1_000_000, value))
    return state


def append_history(
    binding: dict[str, Any],
    *,
    action: str,
    summary: str,
    proposal_id: str = "",
    before: str = "",
    after: str = "",
    before_fingerprint: str = "",
    after_fingerprint: str = "",
    version: int = 0,
    at: float | None = None,
) -> None:
    """Append one bounded user-auditable binding event."""

    history = binding.setdefault("history", [])
    history.append(
        {
            "action": action,
            "at": now_ts(at),
            "summary": str(summary)[:400],
            "proposal_id": str(proposal_id)[:64],
            "before": str(before)[:1_600],
            "after": str(after)[:1_600],
            "before_fingerprint": (
                before_fingerprint if _FINGERPRINT_RE.fullmatch(before_fingerprint) else ""
            ),
            "after_fingerprint": (
                after_fingerprint if _FINGERPRINT_RE.fullmatch(after_fingerprint) else ""
            ),
            "version": max(0, int(version)),
        }
    )
    del history[:-MAX_HISTORY]
    binding["updated_at"] = now_ts(at)


def active_version(binding: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return the active immutable prompt version."""

    number = binding.get("active_version")
    versions = binding.get("versions")
    if not isinstance(versions, list):
        return None
    for item in versions:
        if isinstance(item, Mapping) and item.get("version") == number:
            return dict(item)
    return None


def create_binding(
    *,
    original_name: str,
    overlay_name: str,
    original_card: Mapping[str, Any],
    overlay_card: Mapping[str, Any],
    base_prompt: str,
    binding_id: str | None = None,
    at: float | None = None,
) -> dict[str, Any]:
    """Create the persisted binding after both cards exist."""

    timestamp = now_ts(at)
    binding_id = binding_id or uuid.uuid4().hex[:24]
    integrity_fingerprint = overlay_integrity_fingerprint(overlay_card)
    provenance = provenance_for(overlay_card) or {}
    if (
        provenance.get("overlay_integrity_fingerprint")
        != integrity_fingerprint
    ):
        raise CharacterOperationError(
            "自适应副本的创建完整性校验失败。",
            code="overlay_integrity_invalid",
        )
    version = {
        "version": 0,
        "prompt": base_prompt,
        "prompt_fingerprint": text_fingerprint(base_prompt),
        "adaptations": [],
        "created_at": timestamp,
        "proposal_id": "",
    }
    binding = {
        "binding_id": binding_id,
        "original_name": original_name,
        "overlay_name": overlay_name,
        "original_card_fingerprint": card_fingerprint(original_card),
        "base_prompt": base_prompt,
        "base_prompt_fingerprint": text_fingerprint(base_prompt),
        "overlay_integrity_fingerprint": integrity_fingerprint,
        "provenance_fingerprint": provenance_fingerprint(overlay_card),
        "created_at": timestamp,
        "updated_at": timestamp,
        "desired_enabled": True,
        "status": "active",
        "conflict_code": "",
        "last_error": "",
        "active_version": 0,
        "versions": [version],
        "history": [],
        "runtime_refresh_mode": "",
        "managed_prompt_composition_required": False,
        "prompt_storage_mode": prompt_storage_mode(overlay_card),
    }
    if binding["prompt_storage_mode"] == PROMPT_STORAGE_DYNAMIC_DEFAULT:
        provenance = provenance_for(overlay_card) or {}
        if provenance.get("base_prompt_snapshot") != base_prompt:
            raise CharacterOperationError(
                "动态默认提示词快照与绑定不一致。",
                code="dynamic_base_mismatch",
            )
    append_history(
        binding,
        action="bound",
        summary=f"已从「{original_name}」创建受控副本「{overlay_name}」。",
        after_fingerprint=version["prompt_fingerprint"],
        version=0,
        at=timestamp,
    )
    return binding


def build_overlay(
    *,
    original_name: str,
    overlay_name: str,
    original_card: Mapping[str, Any],
    binding_id: str,
    at: float | None = None,
) -> tuple[dict[str, Any], str]:
    """Deep-copy an original card and add immutable ownership provenance."""

    timestamp = now_ts(at)
    original_copy = copy.deepcopy(dict(original_card))
    overlay = copy.deepcopy(original_copy)
    raw_prompt = get_reserved(
        original_copy,
        "system_prompt",
        default=None,
        legacy_keys=("system_prompt",),
    )
    resolved_prompt = str(
        _resolve_effective_character_prompt(copy.deepcopy(original_copy))
        or get_lanlan_prompt()
    )
    base_prompt = effective_prompt(original_copy)
    dynamic_default = (
        (raw_prompt is None or is_default_prompt(str(raw_prompt)))
        and base_prompt == resolved_prompt
    )
    _flatten_persona_profile(overlay)
    if dynamic_default:
        storage_mode = PROMPT_STORAGE_DYNAMIC_DEFAULT
        _install_dynamic_prompt_container(overlay)
    else:
        storage_mode = PROMPT_STORAGE_SYSTEM
        set_reserved(overlay, "system_prompt", base_prompt)
    original_fp = card_fingerprint(original_copy)
    base_fp = text_fingerprint(base_prompt)
    provenance = {
        "schema_version": STATE_SCHEMA_VERSION,
        "plugin_id": PLUGIN_ID,
        "kind": PROVENANCE_KIND,
        "binding_id": binding_id,
        "original_name": original_name,
        "overlay_name_created": overlay_name,
        "original_card_fingerprint": original_fp,
        "base_prompt_fingerprint": base_fp,
        "managed_prompt_composition_required": False,
        "prompt_storage_mode": storage_mode,
        "persona_materialized": True,
        "created_at": timestamp,
    }
    if dynamic_default:
        provenance["base_prompt_snapshot"] = base_prompt
    set_reserved(
        overlay,
        PROVENANCE_KEY,
        provenance,
    )
    provenance["overlay_integrity_fingerprint"] = (
        overlay_integrity_fingerprint(overlay)
    )
    set_reserved(
        overlay,
        PROVENANCE_KEY,
        provenance,
    )
    return overlay, base_prompt


def inspect_binding(
    characters: Mapping[str, Any],
    binding: dict[str, Any],
) -> dict[str, Any]:
    """Reconcile names and return a fail-closed binding health snapshot."""

    cards = characters.get("猫娘")
    if not isinstance(cards, Mapping):
        return {
            "healthy": False,
            "code": "characters_invalid",
            "message": "角色配置结构异常。",
            "effective": False,
            "current_name": "",
        }
    binding_id = binding.get("binding_id")
    matching_overlays = [
        name
        for name, card in cards.items()
        if isinstance(card, Mapping)
        and (provenance := provenance_for(card))
        and provenance.get("plugin_id") == PLUGIN_ID
        and provenance.get("kind") == PROVENANCE_KIND
        and provenance.get("binding_id") == binding_id
    ]
    current_name = str(characters.get("当前猫娘") or "")
    if len(matching_overlays) > 1:
        return {
            "healthy": False,
            "code": "duplicate_overlays",
            "message": "发现多个同源自适应副本，已停止写入。",
            "effective": current_name in matching_overlays,
            "current_name": current_name,
        }
    if not matching_overlays:
        return {
            "healthy": False,
            "code": "overlay_missing",
            "message": "自适应副本已被删除或失去来源标记。",
            "effective": False,
            "current_name": current_name,
        }
    overlay_name = matching_overlays[0]
    renamed = overlay_name != binding.get("overlay_name")
    binding["overlay_name"] = overlay_name
    original_name = str(binding.get("original_name") or "")
    original = cards.get(original_name)
    if not isinstance(original, Mapping):
        return {
            "healthy": False,
            "code": "original_missing_or_renamed",
            "message": "原角色卡已删除或改名；插件不会猜测新的对应关系。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    original_fp = card_fingerprint(original)
    if original_fp != binding.get("original_card_fingerprint"):
        return {
            "healthy": False,
            "code": "original_changed",
            "message": "原角色卡已被修改；请恢复后重新绑定，插件不会覆盖原卡。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    overlay = cards.get(overlay_name)
    if not isinstance(overlay, Mapping) or not is_managed_overlay(overlay):
        return {
            "healthy": False,
            "code": "overlay_unmanaged",
            "message": "自适应副本的来源标记无效，已停止写入。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    provenance = provenance_for(overlay) or {}
    if (
        provenance_fingerprint(overlay)
        != binding.get("provenance_fingerprint")
        or provenance.get("original_name") != original_name
        or provenance.get("original_card_fingerprint")
        != binding.get("original_card_fingerprint")
        or provenance.get("base_prompt_fingerprint")
        != binding.get("base_prompt_fingerprint")
        or (
            provenance.get("overlay_integrity_fingerprint") is not None
            and provenance.get("overlay_integrity_fingerprint")
            != binding.get("overlay_integrity_fingerprint")
        )
        or provenance.get("managed_prompt_composition_required") is not False
        or bool(binding.get("managed_prompt_composition_required", True))
        or provenance.get("persona_materialized") is not True
        or provenance.get("prompt_storage_mode")
        != binding.get("prompt_storage_mode")
        or (
            provenance.get("prompt_storage_mode")
            == PROMPT_STORAGE_DYNAMIC_DEFAULT
            and (
                provenance.get("base_prompt_snapshot")
                != binding.get("base_prompt")
                or text_fingerprint(
                    str(provenance.get("base_prompt_snapshot") or "")
                )
                != binding.get("base_prompt_fingerprint")
            )
        )
    ):
        return {
            "healthy": False,
            "code": "overlay_provenance_changed",
            "message": "自适应副本的来源标记已变化，已停止自动覆盖。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    integrity_fp = overlay_integrity_fingerprint(overlay)
    if integrity_fp != binding.get("overlay_integrity_fingerprint"):
        return {
            "healthy": False,
            "code": "overlay_changed",
            "message": "自适应副本的非提示字段已被修改，已停止自动覆盖。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    version = active_version(binding)
    if version is None:
        return {
            "healthy": False,
            "code": "version_missing",
            "message": "适配版本记录损坏，已停止写入。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    prompt_fp = text_fingerprint(stored_prompt(overlay))
    if prompt_fp != version.get("prompt_fingerprint"):
        return {
            "healthy": False,
            "code": "overlay_prompt_changed",
            "message": "自适应副本的提示词被外部修改，已停止自动覆盖。",
            "effective": current_name == overlay_name,
            "current_name": current_name,
            "overlay_name": overlay_name,
            "overlay_renamed": renamed,
        }
    return {
        "healthy": True,
        "code": "",
        "message": "",
        "effective": current_name == overlay_name,
        "current_name": current_name,
        "overlay_name": overlay_name,
        "overlay_renamed": renamed,
        "current_prompt_fingerprint": prompt_fp,
    }


def recover_binding(
    characters: Mapping[str, Any],
    *,
    preferred_overlay: str = "",
) -> tuple[dict[str, Any] | None, list[str]]:
    """Recover one deterministic binding from provenance after a crash."""

    cards = characters.get("猫娘")
    if not isinstance(cards, Mapping):
        return None, []
    overlays = [
        str(name)
        for name, card in cards.items()
        if isinstance(card, Mapping) and is_managed_overlay(card)
    ]
    if not overlays:
        return None, []
    if len(overlays) != 1:
        return None, overlays
    selected = overlays[0]
    if preferred_overlay and preferred_overlay != selected:
        return None, overlays
    current = str(characters.get("当前猫娘") or "")
    overlay = cards[selected]
    provenance = provenance_for(overlay) or {}
    integrity_fingerprint = overlay_integrity_fingerprint(overlay)
    if (
        _clean_fingerprint(
            provenance.get("overlay_integrity_fingerprint")
        )
        != integrity_fingerprint
    ):
        return None, overlays
    storage_mode = provenance.get(
        "prompt_storage_mode",
        PROMPT_STORAGE_SYSTEM,
    )
    if storage_mode not in {
        PROMPT_STORAGE_SYSTEM,
        PROMPT_STORAGE_DYNAMIC_DEFAULT,
    }:
        storage_mode = PROMPT_STORAGE_SYSTEM
    original_name = str(provenance.get("original_name") or "")
    original = cards.get(original_name)
    if not isinstance(original, Mapping):
        original = {}
    prompt = stored_prompt(overlay)
    base_prompt = strip_managed_adaptation(prompt)
    timestamp = _clean_timestamp(provenance.get("created_at")) or now_ts()
    version = {
        "version": 0,
        "prompt": prompt,
        "prompt_fingerprint": text_fingerprint(prompt),
        "adaptations": extract_managed_adaptations(prompt),
        "created_at": timestamp,
        "proposal_id": "",
    }
    binding = {
        "binding_id": str(provenance.get("binding_id") or ""),
        "original_name": original_name,
        "overlay_name": selected,
        "original_card_fingerprint": str(
            provenance.get("original_card_fingerprint") or ""
        ),
        "base_prompt": base_prompt,
        "base_prompt_fingerprint": str(
            provenance.get("base_prompt_fingerprint") or text_fingerprint(base_prompt)
        ),
        "overlay_integrity_fingerprint": integrity_fingerprint,
        "provenance_fingerprint": provenance_fingerprint(overlay),
        "created_at": timestamp,
        "updated_at": now_ts(),
        "desired_enabled": current == selected,
        "status": "active" if current == selected else "inactive",
        "conflict_code": "",
        "last_error": "",
        "active_version": 0,
        "versions": [version],
        "history": [],
        "runtime_refresh_mode": "",
        "managed_prompt_composition_required": (
            provenance.get("managed_prompt_composition_required") is not False
        ),
        "prompt_storage_mode": storage_mode,
    }
    append_history(
        binding,
        action="recovered",
        summary="根据自适应副本的来源标记恢复了绑定。",
        after_fingerprint=version["prompt_fingerprint"],
        at=now_ts(),
    )
    normalized = normalize_binding(binding)
    if normalized is None:
        return None, overlays
    return normalized, [name for name in overlays if name != selected]


class CharacterConfigBridge:
    """Use ConfigManager for raw writes and host APIs for runtime side effects."""

    def __init__(
        self,
        config_manager: object | None = None,
        *,
        main_server_base: str | None = None,
        request_handler: object | None = None,
    ) -> None:
        self._config_manager = config_manager
        self._request_handler = request_handler
        self._fallback_mutation_lock = asyncio.Lock()
        if main_server_base:
            self._main_server_base = main_server_base.rstrip("/")
        else:
            try:
                from config import MAIN_SERVER_PORT

                port = int(MAIN_SERVER_PORT)
            except Exception:
                port = 48911
            self._main_server_base = f"http://127.0.0.1:{port}"

    def _manager(self):
        if self._config_manager is None:
            self._config_manager = get_config_manager(APP_NAME, migrate=False)
        return self._config_manager

    async def load(self) -> dict[str, Any]:
        """Load a deep raw characters snapshot through ConfigManager."""

        data = await self._manager().aload_characters()
        if not isinstance(data, dict) or not isinstance(data.get("猫娘"), dict):
            raise CharacterOperationError(
                "角色配置结构异常。",
                code="characters_invalid",
            )
        return copy.deepcopy(data)

    async def save(self, characters: Mapping[str, Any]) -> None:
        """Save one atomic raw characters snapshot through ConfigManager."""

        await self._manager().asave_characters(copy.deepcopy(dict(characters)))

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        timeout: float = 12.0,
    ) -> tuple[int, dict[str, Any]]:
        if callable(self._request_handler):
            result = self._request_handler(method, path, copy.deepcopy(payload))
            if hasattr(result, "__await__"):
                result = await result
            if (
                isinstance(result, tuple)
                and len(result) == 2
                and isinstance(result[0], int)
                and isinstance(result[1], Mapping)
            ):
                return result[0], copy.deepcopy(dict(result[1]))
            raise CharacterOperationError(
                "测试宿主返回了无效响应。",
                code="host_response_invalid",
            )
        async with httpx.AsyncClient(
            timeout=timeout,
            proxy=None,
            trust_env=False,
        ) as client:
            response = await client.request(
                method,
                f"{self._main_server_base}{path}",
                json=dict(payload) if payload is not None else None,
            )
        try:
            body = response.json()
        except Exception:
            body = {}
        return response.status_code, body if isinstance(body, dict) else {}

    @staticmethod
    def _response_error(
        body: Mapping[str, Any],
        fallback: str,
    ) -> str:
        error = body.get("error")
        if isinstance(error, Mapping):
            message = error.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()
        if isinstance(error, str) and error.strip():
            return error.strip()
        message = body.get("message")
        return message.strip() if isinstance(message, str) and message.strip() else fallback

    @staticmethod
    def _is_missing_managed_endpoint(
        status: int,
        body: Mapping[str, Any],
    ) -> bool:
        """Distinguish a legacy-host 404 from a managed business rejection."""

        return status == 404 and not body.get("code")

    @staticmethod
    def _validated_binding_snapshot(
        characters: Mapping[str, Any],
        binding: Mapping[str, Any],
        *,
        require_materialized_prompt: bool = True,
    ) -> tuple[dict[str, Any], str, str]:
        """Validate every immutable binding guard on one fresh snapshot."""

        overlay = str(binding.get("overlay_name") or "")
        original = str(binding.get("original_name") or "")
        cards = characters.get("猫娘")
        if not isinstance(cards, dict):
            raise CharacterOperationError(
                "角色配置结构异常。",
                code="characters_invalid",
            )
        matching_names = [
            str(name)
            for name, card in cards.items()
            if isinstance(card, Mapping)
            and (provenance_for(card) or {}).get("binding_id")
            == binding.get("binding_id")
            and (provenance_for(card) or {}).get("plugin_id") == PLUGIN_ID
            and (provenance_for(card) or {}).get("kind") == PROVENANCE_KIND
        ]
        if matching_names != [overlay]:
            raise CharacterOperationError(
                "绑定对应的自适应副本不唯一或已改名。",
                code="duplicate_or_renamed_overlay",
            )
        original_card = cards.get(original)
        if (
            not isinstance(original_card, Mapping)
            or card_fingerprint(original_card)
            != binding.get("original_card_fingerprint")
        ):
            raise CharacterOperationError(
                "原角色卡不存在、已改名或已被修改。",
                code="original_changed",
            )
        overlay_card = cards.get(overlay)
        provenance = (
            provenance_for(overlay_card)
            if isinstance(overlay_card, Mapping)
            else None
        )
        if (
            not isinstance(overlay_card, Mapping)
            or not is_managed_overlay(overlay_card)
            or not provenance
            or provenance.get("binding_id") != binding.get("binding_id")
            or provenance.get("original_name") != original
            or provenance.get("original_card_fingerprint")
            != binding.get("original_card_fingerprint")
            or provenance_fingerprint(overlay_card)
            != binding.get("provenance_fingerprint")
            or (
                provenance.get("overlay_integrity_fingerprint") is not None
                and provenance.get("overlay_integrity_fingerprint")
                != binding.get("overlay_integrity_fingerprint")
            )
        ):
            raise CharacterOperationError(
                "自适应副本的来源标记已变化。",
                code="overlay_provenance_changed",
            )
        if (
            overlay_integrity_fingerprint(overlay_card)
            != binding.get("overlay_integrity_fingerprint")
        ):
            raise CharacterOperationError(
                "自适应副本的非提示字段已变化。",
                code="overlay_changed",
            )
        version = active_version(binding)
        if (
            version is None
            or text_fingerprint(stored_prompt(overlay_card))
            != version.get("prompt_fingerprint")
        ):
            raise CharacterOperationError(
                "自适应副本的提示词版本已变化。",
                code="overlay_prompt_changed",
            )
        if require_materialized_prompt and (
            provenance.get("managed_prompt_composition_required") is not False
            or provenance.get("persona_materialized") is not True
            or provenance.get("prompt_storage_mode")
            != binding.get("prompt_storage_mode")
        ):
            raise CharacterOperationError(
                "自适应副本尚未完成 package-only prompt 物化。",
                code="overlay_prompt_materialization_required",
            )
        return cards, original, overlay

    async def _save_and_verify_exact(
        self,
        expected: Mapping[str, Any],
        *,
        error_message: str,
        error_code: str,
    ) -> dict[str, Any]:
        """Save then fresh-load the exact expected character snapshot."""

        await self.save(expected)
        verified = await self.load()
        if verified != expected:
            raise CharacterOperationError(
                error_message,
                code=error_code,
            )
        return verified

    async def reload_runtime(self) -> str:
        """Reload character runtime state on hosts without the managed endpoint."""

        status, body = await self._request("POST", "/api/characters/reload")
        if status != 200 or body.get("success") is not True:
            raise CharacterOperationError(
                self._response_error(body, "角色运行态刷新失败。"),
                code="runtime_refresh_failed",
            )
        return "compat_reload"

    async def refresh_managed_prompt(
        self,
        *,
        overlay_name: str,
        binding_id: str,
        prompt_fingerprint: str,
        prefer_managed_route: bool,
    ) -> str:
        """Refresh a verified prompt, with a package-contained legacy path."""

        if not prefer_managed_route:
            return await self.reload_runtime()

        payload = {
            "character_name": overlay_name,
            "plugin_id": PLUGIN_ID,
            "binding_id": binding_id,
            "prompt_fingerprint": prompt_fingerprint,
        }
        try:
            status, body = await self._request(
                "POST",
                "/api/characters/managed-overlay/refresh-prompt",
                payload=payload,
            )
        except (httpx.HTTPError, OSError):
            return await self.reload_runtime()
        if self._is_missing_managed_endpoint(status, body):
            return await self.reload_runtime()
        if status != 200 or body.get("success") is not True:
            raise CharacterOperationError(
                self._response_error(body, "角色提示词运行态刷新失败。"),
                code=str(body.get("code") or "runtime_refresh_failed"),
            )
        return "managed_session_refresh"

    async def switch_current(self, name: str) -> None:
        """Use the host switch route so runtime globals and clients agree."""

        status, body = await self._request(
            "POST",
            "/api/characters/current_catgirl",
            payload={"catgirl_name": name},
        )
        if status != 200 or body.get("success") is not True:
            raise CharacterOperationError(
                self._response_error(body, "角色切换失败。"),
                code=str(body.get("code") or "character_switch_failed"),
            )
        verified = await self.load()
        if (
            str(verified.get("当前猫娘") or "") != name
            or name not in verified["猫娘"]
        ):
            raise CharacterOperationError(
                "角色切换后的配置验证失败。",
                code="character_switch_verification_failed",
            )

    async def switch_current_direct_if(
        self,
        *,
        expected_current: str,
        target: str,
    ) -> bool:
        """Best-effort local compensation for an already-failed activation.

        This is deliberately not used for disable/shutdown restoration: an
        older host has no shared conditional-switch lock, so using this as a
        compatibility restore could overwrite a concurrent user selection.
        """

        async with self._fallback_mutation_lock:
            characters = await self.load()
            cards = characters["猫娘"]
            if str(characters.get("当前猫娘") or "") != expected_current:
                return False
            if target not in cards:
                raise CharacterOperationError(
                    "原角色卡不存在，无法自动恢复。",
                    code="original_missing_or_renamed",
                )
            characters["当前猫娘"] = target
            await self._save_and_verify_exact(
                characters,
                error_message="角色切换后的配置验证失败。",
                error_code="character_switch_verification_failed",
            )
            await self.reload_runtime()
            return True

    async def restore_original_if_overlay(
        self,
        *,
        binding: Mapping[str, Any],
        allow_runtime_unavailable: bool = False,
    ) -> dict[str, bool]:
        """Restore only the exact currently-active managed overlay.

        A managed route is an optional fast path.  Legacy hosts use the same
        fresh-load, full-binding guard, ConfigManager atomic save, fresh-load
        verification, and generic runtime reload entirely from this package.
        """

        overlay = str(binding.get("overlay_name") or "")
        original = str(binding.get("original_name") or "")
        characters = await self.load()
        current = str(characters.get("当前猫娘") or "")
        if current != overlay:
            return {
                "switched": False,
                "preserved_user_choice": bool(
                    current and current != original
                ),
            }
        self._validated_binding_snapshot(
            characters,
            binding,
            require_materialized_prompt=False,
        )
        payload = {
            "plugin_id": PLUGIN_ID,
            "binding_id": str(binding.get("binding_id") or ""),
            "overlay_name": overlay,
            "original_name": original,
        }
        try:
            status, body = await self._request(
                "POST",
                "/api/characters/managed-overlay/restore-original",
                payload=payload,
            )
            missing_endpoint = self._is_missing_managed_endpoint(
                status,
                body,
            )
        except (httpx.HTTPError, OSError):
            missing_endpoint = True
            status, body = 0, {}
        if not missing_endpoint and (
            status != 200 or body.get("success") is not True
        ):
            raise CharacterOperationError(
                self._response_error(body, "原角色恢复失败。"),
                code=str(body.get("code") or "character_restore_failed"),
            )
        if not missing_endpoint:
            verified = await self.load()
            switched = body.get("switched") is True
            if switched:
                self._validated_binding_snapshot(
                    verified,
                    binding,
                    require_materialized_prompt=False,
                )
                if str(verified.get("当前猫娘") or "") != original:
                    raise CharacterOperationError(
                        "宿主恢复后的配置验证失败。",
                        code="character_restore_verification_failed",
                    )
            return {
                "switched": switched,
                "preserved_user_choice": (
                    body.get("preserved_user_choice") is True
                ),
            }

        async with self._fallback_mutation_lock:
            fresh = await self.load()
            fresh_current = str(fresh.get("当前猫娘") or "")
            if fresh_current != overlay:
                return {
                    "switched": False,
                    "preserved_user_choice": bool(
                        fresh_current and fresh_current != original
                    ),
                }
            self._validated_binding_snapshot(
                fresh,
                binding,
                require_materialized_prompt=False,
            )
            expected = copy.deepcopy(fresh)
            expected["当前猫娘"] = original
            await self._save_and_verify_exact(
                expected,
                error_message="原角色恢复后的配置验证失败。",
                error_code="character_restore_verification_failed",
            )
            try:
                await self.reload_runtime()
                runtime_refreshed = True
            except (
                CharacterOperationError,
                httpx.HTTPError,
                OSError,
            ) as exc:
                # During host shutdown the HTTP runtime may already be gone.
                # The exact ConfigManager snapshot is durably restored and was
                # fresh-load verified, which is the shutdown safety contract.
                if not allow_runtime_unavailable:
                    raise CharacterOperationError(
                        "原角色配置已恢复，但运行态刷新失败；"
                        "请重新加载宿主后确认当前角色。",
                        code="runtime_refresh_failed_after_restore",
                    ) from exc
                runtime_refreshed = False
            return {
                "switched": True,
                "preserved_user_choice": False,
                "runtime_refreshed": runtime_refreshed,
            }

    async def delete_character(
        self,
        *,
        name: str,
        binding_id: str,
        expected_provenance_fingerprint: str,
        expected_card_fingerprint: str,
    ) -> None:
        """Delete one exact non-current managed card.

        Legacy hosts use a package-contained full-card conditional mutation;
        the old name-only character delete route is never called.
        """

        payload = {
            "plugin_id": PLUGIN_ID,
            "binding_id": binding_id,
            "overlay_name": name,
            "expected_card_fingerprint": expected_card_fingerprint,
        }
        try:
            status, body = await self._request(
                "POST",
                "/api/characters/managed-overlay/delete",
                payload=payload,
            )
            missing_endpoint = self._is_missing_managed_endpoint(
                status,
                body,
            )
        except (httpx.HTTPError, OSError):
            missing_endpoint = True
            status, body = 0, {}
        if not missing_endpoint and (
            status != 200 or body.get("success") is not True
        ):
            raise CharacterOperationError(
                self._response_error(body, "自适应副本删除失败。"),
                code=str(body.get("code") or "overlay_delete_failed"),
            )
        if not missing_endpoint:
            verified = await self.load()
            if name in verified["猫娘"]:
                raise CharacterOperationError(
                    "宿主删除后的配置验证失败。",
                    code="overlay_delete_verification_failed",
                )
            return

        async with self._fallback_mutation_lock:
            fresh = await self.load()
            cards = fresh["猫娘"]
            if str(fresh.get("当前猫娘") or "") == name:
                raise CharacterOperationError(
                    "自适应副本仍是当前角色，未删除。",
                    code="managed_overlay_is_current",
                )
            candidate = cards.get(name)
            provenance = (
                provenance_for(candidate)
                if isinstance(candidate, Mapping)
                else None
            )
            if (
                not isinstance(candidate, Mapping)
                or not is_managed_overlay(candidate)
                or not provenance
                or provenance.get("binding_id") != binding_id
                or provenance_fingerprint(candidate)
                != expected_provenance_fingerprint
            ):
                raise CharacterOperationError(
                    "自适应副本的来源标记不匹配，未删除。",
                    code="overlay_provenance_changed",
                )
            if card_fingerprint(candidate) != expected_card_fingerprint:
                raise CharacterOperationError(
                    "自适应副本在删除前发生变化，未删除。",
                    code="overlay_card_changed",
                )
            expected = copy.deepcopy(fresh)
            del expected["猫娘"][name]
            await self._save_and_verify_exact(
                expected,
                error_message="自适应副本删除后的配置验证失败。",
                error_code="overlay_delete_verification_failed",
            )
            try:
                await self.reload_runtime()
            except (CharacterOperationError, httpx.HTTPError, OSError):
                # The deleted overlay was required to be non-current, so the
                # durable exact-card deletion remains valid even if a closing
                # host can no longer refresh its in-memory character list.
                pass


__all__ = [
    "ADAPTATION_END",
    "ADAPTATION_START",
    "CharacterConfigBridge",
    "CharacterOperationError",
    "DEFAULT_SETTINGS",
    "LEGACY_STATE_KEY",
    "MAX_EVIDENCE_CHARS",
    "MAX_EVIDENCE_MESSAGES",
    "PLUGIN_ID",
    "PROMPT_STORAGE_DYNAMIC_DEFAULT",
    "PROMPT_STORAGE_SYSTEM",
    "PROVENANCE_KEY",
    "STATE_KEY",
    "active_version",
    "append_history",
    "build_overlay",
    "canonical_json",
    "card_fingerprint",
    "compose_prompt",
    "create_binding",
    "extract_managed_adaptations",
    "fresh_state",
    "has_managed_provenance_marker",
    "inspect_binding",
    "is_managed_overlay",
    "normalize_adaptation_text",
    "normalize_settings",
    "normalize_state",
    "now_ts",
    "overlay_integrity_fingerprint",
    "prompt_storage_mode",
    "provenance_fingerprint",
    "provenance_for",
    "recover_binding",
    "requires_managed_prompt_composition",
    "set_stored_prompt",
    "stored_prompt",
    "strip_managed_adaptation",
    "text_fingerprint",
    "unique_overlay_name",
]
