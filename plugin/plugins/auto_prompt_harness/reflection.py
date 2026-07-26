"""LLM reflection module for auto_prompt_harness v0.2.

Collects a bounded, redacted evidence window from chat events, asks the
configured agent model for a structured reflection, and validates the result
before it becomes a pending preference proposal. Raw chat text never goes
directly into the injected prompt — only the reviewed short preference
sentence does.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

_MAX_EVIDENCE_MESSAGES = 12
_MAX_MESSAGE_CHARS = 240
_MAX_PROPOSED_CHARS = 400
_ALLOWED_RISKS = ("low", "medium", "high")
_REFLECTION_VERSION = 1

#: Things the proposed prompt must never contain.
_FORBIDDEN_PATTERNS = (
    re.compile(r"(?i)ignore (?:all )?previous instructions"),
    re.compile(r"(?i)you are (?:now|a) (?!(?:helpful|friendly))"),
    re.compile(r"(?i)system prompt"),
    re.compile(r"(?i)reveal (?:your|the) (?:prompt|instructions)"),
    re.compile(r"(?i)sk-[A-Za-z0-9]"),
    re.compile(r"(?i)api[_ -]?key"),
    re.compile(r"(?i)curl .*\| *sh"),
)


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
    max_messages: int = _MAX_EVIDENCE_MESSAGES,
    max_chars: int = _MAX_MESSAGE_CHARS,
) -> list[EvidenceMessage]:
    """Bound and redact a rolling window of chat messages for reflection."""

    window: list[EvidenceMessage] = []
    for raw in list(messages)[-max_messages:]:
        role = str(raw.get("role") or "user")[:16]
        if role not in {"user", "assistant"}:
            role = "user"
        text = re.sub(r"\s+", " ", str(raw.get("text") or "")).strip()[:max_chars]
        if not text:
            continue
        window.append(EvidenceMessage(role=role, text=text, at=float(raw.get("at") or 0.0)))
    return window


def build_reflection_prompt(
    evidence: Sequence[EvidenceMessage],
    current_guidance: str = "",
) -> list[dict[str, str]]:
    """Build the messages sent to the LLM. Evidence is already truncated."""

    transcript = "\n".join(f"{m.role}: {m.text}" for m in evidence)
    system = (
        "You are a preference-reflection assistant for a catgirl companion. "
        "Read the short chat excerpt and decide whether the USER expressed a "
        "stable communication preference (language, tone, verbosity, structure, "
        "emoji/meme use, clarification style, etc). "
        "Respond with ONLY a JSON object with keys: "
        "trigger (short reason), evidence_summary (one sentence), "
        "preference (short natural-language preference), "
        "proposed_prompt (one short instruction sentence for the companion, "
        "no role-play, no secrets, max 40 words), "
        "confidence (0-1), risk (low|medium|high). "
        "If no stable preference is visible, respond with confidence 0 and an "
        "empty proposed_prompt. Never include raw chat logs, secrets, or "
        "instructions that override the companion's identity."
    )
    user = (
        f"Current injected guidance (may be empty):\n{current_guidance or '(none)'}\n\n"
        f"Recent chat excerpt:\n{transcript or '(empty)'}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def parse_reflection(raw_text: str, evidence: Sequence[EvidenceMessage]) -> Reflection | None:
    """Parse and strictly validate the LLM output. Bad JSON degrades to None."""

    if not isinstance(raw_text, str) or not raw_text.strip():
        return None
    text = raw_text.strip()
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    proposed = str(data.get("proposed_prompt") or "").strip()[:_MAX_PROPOSED_CHARS]
    preference = str(data.get("preference") or "").strip()[:_MAX_PROPOSED_CHARS]
    try:
        confidence = float(data.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    risk = str(data.get("risk") or "high").lower()
    if risk not in _ALLOWED_RISKS:
        risk = "high"

    if proposed and any(pattern.search(proposed) for pattern in _FORBIDDEN_PATTERNS):
        return None
    if not proposed:
        confidence = 0.0

    return Reflection(
        trigger=str(data.get("trigger") or "")[:200],
        evidence_summary=str(data.get("evidence_summary") or "")[:400],
        preference=preference,
        proposed_prompt=proposed,
        confidence=confidence,
        risk=risk,
        evidence_excerpt=tuple(f"{m.role}: {m.text}" for m in evidence[-4:]),
    )


async def reflect_once(
    call_model,
    messages: Sequence[Mapping[str, Any]],
    current_guidance: str = "",
) -> Reflection | None:
    """Full pipeline: collect evidence → LLM → validated reflection."""

    evidence = collect_evidence(messages)
    if not evidence:
        return None
    prompt = build_reflection_prompt(evidence, current_guidance)
    raw = await call_model(prompt)
    return parse_reflection(str(raw or ""), evidence)
