"""Defensive normalization for current and forward-compatible chat payloads."""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from itertools import islice
from typing import Any, Iterable, Mapping

from .engine import GUIDANCE_END, GUIDANCE_START, sanitize_text


_TEXT_KEYS = ("text", "content", "message", "data", "body")
_NESTED_KEYS = ("payload", "event", "message", "data", "record")
_IDENTITY_KEYS = ("user_id", "sender_id", "account_id", "member_id", "uid")
_CONVERSATION_KEYS = (
    "conversation_id",
    "session_id",
    "chat_id",
    "thread_id",
    "channel_id",
)
_META_KEYS = ("metadata", "meta", "_ctx", "context")
_BLOCKED_ROLES = {"assistant", "system", "developer", "tool", "plugin", "bot", "ai"}
_USER_ROLES = {"user", "human", "master", "owner"}
_BLOCKED_SOURCES = {
    "auto_prompt_harness",
    "plugin.auto_prompt_harness",
    "system",
    "developer",
    "assistant",
    "plugin",
    "tool",
}


@dataclass(frozen=True, slots=True)
class ChatEvent:
    text: str
    user_id: str
    conversation_id: str
    lanlan: str
    source: str
    timestamp: float
    is_voice: bool = False
    conversation_id_source: str = "payload"


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _string(value: object, *, limit: int = 256) -> str:
    if isinstance(value, str):
        return sanitize_text(value, limit=limit)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            return ""
        return str(value)[:limit]
    return ""


def sanitize_identity(value: object, *, limit: int = 256) -> str:
    """Validate an opaque host identity without changing its code points.

    User, conversation, and character identifiers are routing/security keys,
    not natural-language content. Compatibility normalization or truncation can
    collapse two host-distinct identifiers, so invalid values fail closed.
    """

    if isinstance(value, str):
        raw = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            return ""
        raw = str(value)
    else:
        return ""
    if not raw or not raw.strip() or len(raw) > max(0, int(limit)):
        return ""
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in raw):
        return ""
    return raw


def _content_text(value: object) -> str:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, Mapping):
        # Role/source markers can appear on a content part or below a wrapper
        # that is not itself included in ``_candidate_mappings``.  Refuse that
        # subtree before recursively extracting text; otherwise an assistant or
        # plugin payload can be mistaken for an unlabelled user utterance.
        if _blocked([value]):
            return ""
        typ = _string(value.get("type"), limit=32).lower()
        if typ and typ not in {"text", "input_text", "message", "user_message"}:
            return ""
        for key in ("text", "content", "value"):
            found = _content_text(value.get(key))
            if found:
                return found
        return ""
    if isinstance(value, Iterable) and not isinstance(
        value, (bytes, bytearray, str, Mapping)
    ):
        parts: list[str] = []
        remaining = 4000
        for item in islice(value, 64):
            part = _content_text(item)
            if not part:
                continue
            parts.append(part[:remaining])
            remaining -= len(parts[-1])
            if remaining <= 0:
                break
        return "\n".join(parts)[:4000]
    return ""


def _last_user_message(messages: object) -> Mapping[str, Any] | None:
    if not isinstance(messages, list):
        return None
    for item in reversed(messages[-128:]):
        if not isinstance(item, Mapping):
            continue
        role = _string(item.get("role"), limit=32).lower()
        if role in _BLOCKED_ROLES:
            continue
        if role in _USER_ROLES or not role:
            return item
    return None


def _candidate_mappings(root: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    candidates: list[Mapping[str, Any]] = [root]
    messages = _last_user_message(root.get("messages"))
    if messages is not None:
        candidates.insert(0, messages)
    for key in _NESTED_KEYS:
        nested = _mapping(root.get(key))
        if nested is not None and nested not in candidates:
            nested_messages = _last_user_message(nested.get("messages"))
            if nested_messages is not None:
                candidates.insert(0, nested_messages)
            candidates.insert(0, nested)
    # SDK memory records put the original utterance under ``raw``.
    raw = _mapping(root.get("raw"))
    if raw is not None:
        candidates.insert(0, raw)
    return candidates


def _read_across(candidates: list[Mapping[str, Any]], keys: tuple[str, ...]) -> object:
    for candidate in candidates:
        for key in keys:
            value = candidate.get(key)
            if _has_value(value, allow_mapping=key in {"sender", "user", "author"}):
                return value
        for meta_key in _META_KEYS:
            meta = _mapping(candidate.get(meta_key))
            if meta is None:
                continue
            for key in keys:
                value = meta.get(key)
                if _has_value(value, allow_mapping=key in {"sender", "user", "author"}):
                    return value
    return None


def _has_value(value: object, *, allow_mapping: bool) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(_string(value))
    if isinstance(value, Mapping):
        return allow_mapping and bool(_sender_identity(value))
    if isinstance(value, float):
        return math.isfinite(value)
    return True


def _sender_identity(value: object) -> str:
    mapping = _mapping(value)
    if mapping is not None:
        for key in (*_IDENTITY_KEYS, "id", "name", "username"):
            found = sanitize_identity(mapping.get(key))
            if found:
                return found
        return ""
    return sanitize_identity(value)


def _blocked(candidates: list[Mapping[str, Any]]) -> bool:
    for candidate in candidates:
        inspected = [candidate]
        inspected.extend(
            meta
            for meta_key in _META_KEYS
            if (meta := _mapping(candidate.get(meta_key))) is not None
        )
        for item in inspected:
            role = _string(item.get("role"), limit=32).lower()
            if role in _BLOCKED_ROLES:
                return True
            source = _string(item.get("source"), limit=96).lower()
            plugin_id = _string(item.get("plugin_id"), limit=96).lower()
            generated_by = _string(item.get("generated_by"), limit=96).lower()
            if source in _BLOCKED_SOURCES or source.startswith("plugin."):
                return True
            if plugin_id or generated_by in {
                "plugin",
                "assistant",
                "system",
                "auto_prompt_harness",
            }:
                return True
            if any(
                item.get(flag) is True
                for flag in ("self_generated", "is_self", "from_plugin", "generated")
            ):
                return True
            typ = _string(item.get("type"), limit=64).lower()
            if typ in {
                "assistant_message",
                "system_message",
                "plugin_message",
                "tool_message",
            }:
                return True
            event_type = _string(item.get("event_type"), limit=96).lower()
            if event_type.startswith("auto_prompt_harness"):
                return True
    return False


def extract_chat_event(*args: Any, **kwargs: Any) -> ChatEvent | None:
    """Extract text and isolation hints from all known host payload families.

    Accepted inputs include ``(text, sender)``, one mapping payload, keyword
    payloads, OpenAI-style content parts, history arrays, frontend ``data``
    records, message-plane records, and SDK memory records.
    """

    root: dict[str, Any] = dict(kwargs)
    if args:
        first = args[0]
        if isinstance(first, Mapping):
            root = {**dict(first), **root}
        elif isinstance(first, str):
            root.setdefault("text", first)
        if len(args) > 1:
            root.setdefault("sender", args[1])
    if not root:
        return None
    candidates = _candidate_mappings(root)
    if _blocked(candidates):
        return None
    text = ""
    for candidate in candidates:
        role = _string(candidate.get("role"), limit=32).lower()
        if role in _BLOCKED_ROLES:
            continue
        input_type = _string(candidate.get("input_type"), limit=32).lower()
        for key in _TEXT_KEYS:
            if (
                key == "data"
                and input_type
                and input_type not in {"text", "transcript", "voice"}
            ):
                continue
            found = _content_text(candidate.get(key))
            if found:
                text = found
                break
        if text:
            break
    if not text or GUIDANCE_START in text or GUIDANCE_END in text:
        return None
    role_value = _string(_read_across(candidates, ("role",)), limit=32).lower()
    if role_value and role_value not in _USER_ROLES:
        return None
    lanlan = sanitize_identity(
        _read_across(candidates, ("lanlan", "lanlan_name", "character", "role_name")),
        limit=80,
    )
    user_raw = _read_across(candidates, _IDENTITY_KEYS)
    if user_raw is None:
        user_raw = _read_across(candidates, ("sender", "user", "author"))
    user_id = _sender_identity(user_raw)
    if not user_id:
        # The verified user-context bus does not carry a human identity.  Use
        # its character name as the narrowest available local partition so
        # the default user scope does not mix every character into one profile.
        user_id = f"local-character:{lanlan}" if lanlan else "local-user"
    conversation_id = sanitize_identity(
        _read_across(candidates, _CONVERSATION_KEYS),
    )
    conversation_id_source = "payload" if conversation_id else "local_fallback"
    if not conversation_id:
        conversation_id = f"lanlan:{lanlan}" if lanlan else "local-conversation"
    source = _string(_read_across(candidates, ("source",)), limit=96) or "chat"
    timestamp_raw = _read_across(candidates, ("_ts", "timestamp", "time", "created_at"))
    try:
        parsed_timestamp = float(timestamp_raw)
        timestamp = (
            max(0.0, parsed_timestamp) if math.isfinite(parsed_timestamp) else 0.0
        )
    except (TypeError, ValueError, OverflowError):
        timestamp = 0.0
    is_voice = bool(_read_across(candidates, ("is_voice",))) or (
        _string(_read_across(candidates, ("input_type",)), limit=32).lower()
        == "transcript"
    )
    return ChatEvent(
        text=text,
        user_id=user_id,
        conversation_id=conversation_id,
        lanlan=lanlan,
        source=source,
        timestamp=timestamp,
        is_voice=is_voice,
        conversation_id_source=conversation_id_source,
    )


def unwrap_memory_record(item: object) -> Mapping[str, Any] | None:
    """Return the original memory event from either SDK or legacy records."""

    seen: set[int] = set()

    def _unwrap(value: object, depth: int) -> Mapping[str, Any] | None:
        if depth > 6 or id(value) in seen:
            return None
        seen.add(id(value))
        payload = getattr(value, "payload", None)
        if isinstance(payload, Mapping):
            outer: Mapping[str, Any] | None = payload
        elif isinstance(value, Mapping):
            outer = value
        else:
            dumper = getattr(value, "dump", None)
            try:
                dumped = dumper() if callable(dumper) else None
            except Exception:
                dumped = None
            outer = dumped if isinstance(dumped, Mapping) else None
        if outer is None:
            return None
        raw = outer.get("raw")
        if isinstance(raw, Mapping):
            event = dict(raw)
            event.setdefault("_ts", outer.get("timestamp"))
            return event
        if any(key in outer for key in ("type", "content", "source", "_ts")):
            return outer
        for key in ("value", "event", "record", "payload"):
            nested = outer.get(key)
            if nested is None or nested is value or nested is outer:
                continue
            unwrapped = _unwrap(nested, depth + 1)
            if unwrapped is not None:
                return unwrapped
        return outer

    return _unwrap(item, 0)


__all__ = [
    "ChatEvent",
    "extract_chat_event",
    "sanitize_identity",
    "unwrap_memory_record",
]
