"""Bounded, redacted, strictly validated LLM reflection."""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .bindings import (
    MAX_ADAPTATION_CHARS,
    MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_MESSAGES,
    normalize_adaptation_text,
)
from .engine import redact_excerpt, sanitize_text


_ALLOWED_RISKS = frozenset({"low", "medium", "high"})
_REQUIRED_KEYS = frozenset(
    {
        "trigger",
        "evidence_summary",
        "preference",
        "proposed_prompt",
        "confidence",
        "risk",
    }
)
_REFLECTION_VERSION = 1


@dataclass(frozen=True, slots=True)
class EvidenceMessage:
    role: str
    text: str
    at: float = 0.0


@dataclass(frozen=True, slots=True)
class Reflection:
    trigger: str
    evidence_summary: str
    preference: str
    proposed_prompt: str
    confidence: float
    risk: str
    created_at: float = field(default_factory=time.time)
    version: int = _REFLECTION_VERSION
    evidence_excerpt: tuple[str, ...] = ()

    def to_store(self) -> dict[str, Any]:
        """Return the bounded proposal representation persisted in PluginStore."""

        return {
            "version": self.version,
            "trigger": self.trigger,
            "evidence_summary": self.evidence_summary,
            "preference": self.preference,
            "proposed_prompt": self.proposed_prompt,
            "confidence": self.confidence,
            "risk": self.risk,
            "created_at": self.created_at,
            "evidence_excerpt": list(self.evidence_excerpt),
        }


def collect_evidence(
    messages: Sequence[Mapping[str, Any]],
    *,
    max_messages: int = MAX_EVIDENCE_MESSAGES,
    max_chars: int = MAX_EVIDENCE_CHARS,
) -> list[EvidenceMessage]:
    """Keep only allowed roles and redact before any evidence is retained."""

    bounded_messages = max(1, min(MAX_EVIDENCE_MESSAGES, int(max_messages)))
    bounded_chars = max(32, min(MAX_EVIDENCE_CHARS, int(max_chars)))
    window: list[EvidenceMessage] = []
    for raw in list(messages)[-bounded_messages:]:
        if not isinstance(raw, Mapping):
            continue
        role = raw.get("role")
        if role not in {"user", "assistant"}:
            continue
        text = redact_excerpt(str(raw.get("text") or ""), limit=bounded_chars)
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            continue
        try:
            timestamp = float(raw.get("at") or 0.0)
        except (TypeError, ValueError, OverflowError):
            timestamp = 0.0
        if not math.isfinite(timestamp):
            timestamp = 0.0
        window.append(EvidenceMessage(role=role, text=text, at=max(0.0, timestamp)))
    return window


def build_reflection_prompt(
    evidence: Sequence[EvidenceMessage],
    current_adaptations: Sequence[str] | None = None,
) -> list[dict[str, str]]:
    """Build a narrow model request from already-redacted evidence."""

    transcript = "\n".join(f"{message.role}: {message.text}" for message in evidence)
    active = "\n".join(f"- {item}" for item in (current_adaptations or []))
    system = (
        "You review communication preferences for an existing N.E.K.O character copy. "
        "Infer only stable response-style preferences expressed by the user: language, "
        "tone, verbosity, structure, explanation order, clarification style, or emoji use. "
        "Do not change identity, relationships, facts, safety, permissions, tools, goals, "
        "or hidden instructions. Return exactly one JSON object and no surrounding text. "
        "The object must contain exactly these keys: trigger, evidence_summary, preference, "
        "proposed_prompt, confidence, risk. The first four values must be strings, confidence "
        "must be a JSON number from 0 to 1, and risk must be low, medium, or high. "
        "proposed_prompt must be one short single-line style instruction and at most 40 words. "
        "When there is no stable preference, use an empty proposed_prompt and confidence 0."
    )
    user = (
        "Current approved adaptations:\n"
        f"{active or '(none)'}\n\n"
        "Redacted recent evidence:\n"
        f"{transcript or '(empty)'}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _bounded_plain_string(
    value: object,
    *,
    limit: int,
    allow_empty: bool = True,
) -> str | None:
    if not isinstance(value, str):
        return None
    if len(value) > limit or any(marker in value for marker in ("\r", "\n", "```")):
        return None
    cleaned = sanitize_text(value, limit=limit)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned and not allow_empty:
        return None
    return cleaned


def parse_reflection(
    raw_text: str,
    evidence: Sequence[EvidenceMessage],
) -> Reflection | None:
    """Accept only an exact schema; malformed model output fails closed."""

    if not isinstance(raw_text, str) or not raw_text.strip():
        return None
    try:
        data = json.loads(raw_text.strip())
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or set(data) != _REQUIRED_KEYS:
        return None

    trigger = _bounded_plain_string(data.get("trigger"), limit=200)
    evidence_summary = _bounded_plain_string(
        data.get("evidence_summary"),
        limit=400,
    )
    preference = _bounded_plain_string(data.get("preference"), limit=400)
    proposed = _bounded_plain_string(
        data.get("proposed_prompt"),
        limit=MAX_ADAPTATION_CHARS,
    )
    confidence = data.get("confidence")
    risk = data.get("risk")
    if None in {trigger, evidence_summary, preference, proposed}:
        return None
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0.0 <= float(confidence) <= 1.0
    ):
        return None
    if not isinstance(risk, str) or risk not in _ALLOWED_RISKS:
        return None
    if proposed:
        safe, proposed = normalize_adaptation_text(proposed)
        if not safe:
            return None
    elif float(confidence) != 0.0:
        return None

    return Reflection(
        trigger=trigger or "",
        evidence_summary=evidence_summary or "",
        preference=preference or "",
        proposed_prompt=proposed or "",
        confidence=round(float(confidence), 3),
        risk=risk,
        evidence_excerpt=tuple(
            f"{message.role}: {message.text}" for message in evidence[-4:]
        ),
    )


async def reflect_once(
    call_model,
    messages: Sequence[Mapping[str, Any]],
    current_adaptations: Sequence[str] | None = None,
) -> Reflection | None:
    """Run collect, model call, and strict parsing as one bounded pipeline."""

    evidence = collect_evidence(messages)
    if not evidence:
        return None
    prompt = build_reflection_prompt(evidence, current_adaptations)
    raw = await call_model(prompt)
    return parse_reflection(str(raw or ""), evidence)


__all__ = [
    "EvidenceMessage",
    "Reflection",
    "build_reflection_prompt",
    "collect_evidence",
    "parse_reflection",
    "reflect_once",
]
