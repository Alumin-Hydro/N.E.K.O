"""Runtime settings persistence for the Discord adapter plugin.

Settings live in the plugin data directory (outside the tracked manifest) so
that panel writes never dirty the git tree. The shape mirrors the
bilibili_dm config store: defaults + normalization + atomic JSON writes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Mapping

from utils.file_utils import atomic_write_json_async, read_json_async

VALID_TRIGGER_MODES = {"mention", "all", "dm_only"}
VALID_PERMISSION_MODES = {"allow_list", "deny_list", "open"}


class DiscordConfigStore:
    """Runtime settings stored outside the tracked plugin manifest."""

    FILE_NAME = "business_config.json"

    def __init__(self, base_dir: Path, *, logger: Any | None = None):
        self._path = Path(base_dir) / self.FILE_NAME
        self._lock = asyncio.Lock()
        self._logger = logger

    @property
    def path(self) -> Path:
        return self._path

    def default_config(self) -> dict[str, Any]:
        return {
            "bot_token": "",
            "trigger_mode": "mention",
            "admin_user_ids": "",
            "channel_whitelist": "",
            "guild_whitelist": "",
            "permission_mode": "allow_list",
            "max_concurrent_messages": 3,
            "ai_connect_timeout_seconds": 10.0,
            "ai_turn_timeout_seconds": 60.0,
            "max_attachment_bytes": 10 * 1024 * 1024,
            "max_total_attachment_bytes": 20 * 1024 * 1024,
            "max_attachments_per_message": 3,
            "reconnect_backoff_seconds": 3.0,
            "max_reconnect_attempts": 5,
            "proxy_url": "",
            # 主动对话：频道空闲超过 N 秒后让 LLM 主动发一条。0 = 关闭。
            "proactive_idle_seconds": 0,
            # 每个频道触发过一次后，至少再过 N 秒才再次触发（防刷屏）。
            "proactive_cooldown_seconds": 3600,
        }

    async def exists(self) -> bool:
        return self._path.is_file()

    @staticmethod
    def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(maximum, parsed))

    @staticmethod
    def _bounded_float(
        value: Any, default: float, minimum: float, maximum: float
    ) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(maximum, parsed))

    def normalize(self, config: Mapping[str, Any] | None) -> dict[str, Any]:
        raw = dict(config or {})
        normalized = self.default_config()
        normalized["bot_token"] = str(raw.get("bot_token") or "").strip()
        normalized["admin_user_ids"] = str(raw.get("admin_user_ids") or "").strip()
        normalized["channel_whitelist"] = str(
            raw.get("channel_whitelist") or ""
        ).strip()
        normalized["guild_whitelist"] = str(
            raw.get("guild_whitelist") or ""
        ).strip()
        normalized["proxy_url"] = str(raw.get("proxy_url") or "").strip()
        trigger_mode = str(raw.get("trigger_mode") or "").strip().lower()
        normalized["trigger_mode"] = (
            trigger_mode if trigger_mode in VALID_TRIGGER_MODES else "mention"
        )
        permission_mode = str(raw.get("permission_mode") or "").strip().lower()
        normalized["permission_mode"] = (
            permission_mode if permission_mode in VALID_PERMISSION_MODES
            else "allow_list"
        )
        normalized["max_concurrent_messages"] = self._bounded_int(
            raw.get("max_concurrent_messages"), 3, 1, 20
        )
        normalized["ai_connect_timeout_seconds"] = self._bounded_float(
            raw.get("ai_connect_timeout_seconds"), 10.0, 1.0, 120.0
        )
        normalized["ai_turn_timeout_seconds"] = self._bounded_float(
            raw.get("ai_turn_timeout_seconds"), 60.0, 5.0, 600.0
        )
        normalized["max_attachment_bytes"] = self._bounded_int(
            raw.get("max_attachment_bytes"), 10 * 1024 * 1024, 1024, 25 * 1024 * 1024
        )
        normalized["max_total_attachment_bytes"] = self._bounded_int(
            raw.get("max_total_attachment_bytes"),
            20 * 1024 * 1024,
            1024,
            50 * 1024 * 1024,
        )
        normalized["max_attachments_per_message"] = self._bounded_int(
            raw.get("max_attachments_per_message"), 3, 0, 10
        )
        normalized["reconnect_backoff_seconds"] = self._bounded_float(
            raw.get("reconnect_backoff_seconds"), 3.0, 1.0, 60.0
        )
        normalized["max_reconnect_attempts"] = self._bounded_int(
            raw.get("max_reconnect_attempts"), 5, 1, 50
        )
        normalized["proactive_idle_seconds"] = self._bounded_int(
            raw.get("proactive_idle_seconds"), 0, 0, 86400
        )
        normalized["proactive_cooldown_seconds"] = self._bounded_int(
            raw.get("proactive_cooldown_seconds"), 3600, 60, 86400
        )
        return normalized

    async def load(self) -> dict[str, Any]:
        async with self._lock:
            if not self._path.is_file():
                return self.default_config()
            try:
                payload = await read_json_async(self._path)
            except (OSError, UnicodeError, TypeError, ValueError) as exc:
                if self._logger is not None:
                    self._logger.warning(
                        "Failed to read Discord adapter config, falling back to "
                        f"defaults: {type(exc).__name__}"
                    )
                return self.default_config()
            if not isinstance(payload, dict):
                if self._logger is not None:
                    self._logger.warning(
                        "Discord adapter config has an invalid shape, falling "
                        "back to defaults"
                    )
                return self.default_config()
            return self.normalize(payload)

    async def create(self, initial: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self.save(dict(initial or {}))

    async def save(self, config: Mapping[str, Any]) -> dict[str, Any]:
        async with self._lock:
            normalized = self.normalize(config)
            await atomic_write_json_async(self._path, normalized)
            return normalized
