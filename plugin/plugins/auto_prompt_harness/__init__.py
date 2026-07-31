"""Bind adaptive suggestions to managed copies of real N.E.K.O character cards."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import inspect
import math
import threading
import time
import uuid
from collections.abc import Callable, Coroutine, Mapping
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
from typing import Any, TypeVar

from plugin.sdk.plugin import (
    Err,
    NekoPluginBase,
    Ok,
    PluginStore,
    SdkError,
    lifecycle,
    llm_tool,
    message,
    neko_plugin,
    plugin_entry,
    timer_interval,
)

from .bindings import (
    DEFAULT_SETTINGS,
    LEGACY_STATE_KEY,
    MAX_ACTIVE_ADAPTATIONS,
    MAX_EVIDENCE_MESSAGES,
    MAX_HISTORY,
    MAX_PROPOSALS,
    MAX_VERSIONS,
    PLUGIN_ID,
    PROMPT_STORAGE_DYNAMIC_DEFAULT,
    STATE_KEY,
    CharacterConfigBridge,
    CharacterOperationError,
    active_version,
    append_history,
    build_overlay,
    card_fingerprint,
    compose_prompt,
    create_binding,
    fresh_state,
    has_managed_provenance_marker,
    inspect_binding,
    is_managed_overlay,
    normalize_adaptation_text,
    normalize_settings,
    normalize_state,
    now_ts,
    overlay_integrity_fingerprint,
    provenance_for,
    provenance_fingerprint,
    recover_binding,
    set_stored_prompt,
    stored_prompt,
    text_fingerprint,
    unique_overlay_name,
)
from .engine import cursor_accepts, infer_observations
from .events import extract_chat_event, unwrap_memory_record
from .reflection import collect_evidence, reflect_once


POLL_LIMIT = 256
POLL_TIMEOUT = 1.5
_StoreResult = TypeVar("_StoreResult")

EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}
START_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "original_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 120,
            "description": "从角色列表返回的真实角色卡名称。",
        }
    },
    "required": ["original_name"],
    "additionalProperties": False,
}
RESOLVE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "proposal_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "action": {"type": "string", "enum": ["approve", "reject"]},
        "edited_prompt": {"type": "string", "maxLength": 400},
    },
    "required": ["proposal_id", "action"],
    "additionalProperties": False,
}
DELETE_OVERLAY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "confirmation": {
            "type": "string",
            "enum": ["DELETE"],
        }
    },
    "required": ["confirmation"],
    "additionalProperties": False,
}
DELETE_ORPHAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "overlay_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 120,
        },
        "confirmation": {
            "type": "string",
            "enum": ["DELETE"],
        },
    },
    "required": ["overlay_name", "confirmation"],
    "additionalProperties": False,
}
SETTINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "settings": {
            "type": "object",
            "properties": {
                "learning_enabled": {"type": "boolean"},
                "automatic_reflection": {"type": "boolean"},
                "auto_apply_low_risk": {"type": "boolean"},
                "reflection_threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 12,
                },
                "minimum_confidence": {
                    "type": "number",
                    "minimum": 0.5,
                    "maximum": 0.95,
                },
                "evidence_window": {
                    "type": "integer",
                    "minimum": 2,
                    "maximum": 12,
                },
                "show_evidence_excerpts": {"type": "boolean"},
            },
            "additionalProperties": False,
        }
    },
    "required": ["settings"],
    "additionalProperties": False,
}
ANALYZE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "text": {
            "type": "string",
            "minLength": 1,
            "maxLength": 4000,
            "writeOnly": True,
            "x-sensitive": True,
        }
    },
    "required": ["text"],
    "additionalProperties": False,
}
CHAT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
}


def _friendly_error(
    message_text: str,
    code: str,
    *,
    details: object | None = None,
) -> Err[SdkError]:
    return Err(SdkError(message_text, code=code, details=details))


class _PluginStoreWorker:
    """Keep public PluginStore calls on one event loop and one executor."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._operation_lock: asyncio.Lock | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    def reopen(self) -> None:
        with self._guard:
            if self._thread is None:
                self._closed = False

    def _ensure_loop_locked(self) -> asyncio.AbstractEventLoop:
        loop = self._loop
        thread = self._thread
        if self._closed:
            raise RuntimeError("PluginStore worker is closed")
        if (
            loop is not None
            and thread is not None
            and thread.is_alive()
            and loop.is_running()
            and not loop.is_closed()
        ):
            return loop

        ready = threading.Event()
        holder: dict[str, Any] = {}

        def run_worker_loop() -> None:
            worker_loop: asyncio.AbstractEventLoop | None = None
            executor: ThreadPoolExecutor | None = None
            try:
                worker_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(worker_loop)
                executor = ThreadPoolExecutor(
                    max_workers=1,
                    thread_name_prefix="auto-prompt-store",
                )
                worker_loop.set_default_executor(executor)
                holder["loop"] = worker_loop
                holder["operation_lock"] = asyncio.Lock()
            except BaseException as exc:
                holder["error"] = exc
                ready.set()
                if executor is not None:
                    executor.shutdown(wait=True, cancel_futures=True)
                if worker_loop is not None:
                    worker_loop.close()
                return
            worker_loop.call_soon(ready.set)
            try:
                worker_loop.run_forever()
            finally:
                pending = [
                    task for task in asyncio.all_tasks(worker_loop) if not task.done()
                ]
                for task in pending:
                    task.cancel()
                if pending:
                    worker_loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                worker_loop.run_until_complete(worker_loop.shutdown_asyncgens())
                worker_loop.run_until_complete(worker_loop.shutdown_default_executor())
                asyncio.set_event_loop(None)
                worker_loop.close()

        thread = threading.Thread(
            target=run_worker_loop,
            name="auto-prompt-store-loop",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        ready.wait()
        error = holder.get("error")
        if isinstance(error, BaseException):
            self._thread = None
            raise RuntimeError("PluginStore worker failed to start") from error
        loop = holder.get("loop")
        operation_lock = holder.get("operation_lock")
        if not isinstance(loop, asyncio.AbstractEventLoop) or not isinstance(
            operation_lock,
            asyncio.Lock,
        ):
            self._thread = None
            raise RuntimeError("PluginStore worker did not initialize")
        self._loop = loop
        self._operation_lock = operation_lock
        return loop

    async def _invoke(
        self,
        operation: Callable[..., Coroutine[Any, Any, _StoreResult]],
        args: tuple[Any, ...],
    ) -> _StoreResult:
        lock = self._operation_lock
        if lock is None:
            raise RuntimeError("PluginStore worker is unavailable")
        async with lock:
            return await operation(*args)

    async def _drain(self) -> None:
        lock = self._operation_lock
        if lock is not None:
            async with lock:
                return

    async def call(
        self,
        operation: Callable[..., Coroutine[Any, Any, _StoreResult]],
        *args: Any,
    ) -> _StoreResult:
        with self._guard:
            loop = self._ensure_loop_locked()
            invocation = self._invoke(operation, args)
            try:
                future = asyncio.run_coroutine_threadsafe(invocation, loop)
            except BaseException:
                invocation.close()
                raise
        wrapped = asyncio.wrap_future(future)
        cancelled = False
        while not wrapped.done():
            try:
                await asyncio.shield(wrapped)
            except asyncio.CancelledError:
                cancelled = True
            except BaseException:
                break
        if cancelled:
            try:
                wrapped.result()
            except BaseException:
                pass
            raise asyncio.CancelledError
        return wrapped.result()

    async def shutdown(self) -> None:
        with self._guard:
            loop = self._loop
            thread = self._thread
            self._closed = True
        if loop is None or thread is None:
            return
        cancelled = False
        drain = self._drain()
        try:
            future = asyncio.run_coroutine_threadsafe(drain, loop)
        except BaseException:
            drain.close()
        else:
            wrapped = asyncio.wrap_future(future)
            while not wrapped.done():
                try:
                    await asyncio.shield(wrapped)
                except asyncio.CancelledError:
                    cancelled = True
                except BaseException:
                    break
        if not loop.is_closed():
            try:
                loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
        while thread.is_alive():
            try:
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                cancelled = True
        thread.join()
        with self._guard:
            if self._thread is thread:
                self._loop = None
                self._operation_lock = None
                self._thread = None
        if cancelled:
            raise asyncio.CancelledError


@neko_plugin
class AutoPromptHarnessPlugin(NekoPluginBase):
    """Manage a reversible adaptive overlay for one real character card."""

    def __init__(self, ctx: Any):
        super().__init__(ctx)
        self._state_lock = threading.RLock()
        self._persist_lock = threading.Lock()
        self._mutation_lock = threading.Lock()
        self._poll_guard = threading.Lock()
        self._lifecycle_guard = threading.Lock()
        self._reflection_guard = threading.Lock()
        self._stopping = threading.Event()
        self._runtime_started = False
        self._store_ready = False
        self._state: dict[str, Any] = fresh_state()
        self._store_worker = _PluginStoreWorker()
        self._character_bridge: CharacterConfigBridge | None = None
        self._shutdown_result: dict[str, Any] | None = None
        self._last_orphan_overlays: list[str] = []
        self._last_invalid_managed_overlays: list[str] = []

    @staticmethod
    async def _acquire_thread_lock(lock: threading.Lock | threading.RLock) -> None:
        while not lock.acquire(blocking=False):
            await asyncio.sleep(0.01)

    def _bridge(self) -> CharacterConfigBridge:
        if self._character_bridge is None:
            self._character_bridge = CharacterConfigBridge()
        return self._character_bridge

    async def _call_store(
        self,
        operation: Callable[..., Coroutine[Any, Any, _StoreResult]],
        *args: Any,
    ) -> _StoreResult:
        if isinstance(self.store, PluginStore):
            return await self._store_worker.call(operation, *args)
        return await operation(*args)

    def _checkpoint(self) -> dict[str, Any]:
        with self._state_lock:
            return copy.deepcopy(self._state)

    def _restore_checkpoint(self, checkpoint: Mapping[str, Any]) -> None:
        with self._state_lock:
            current_errors = int(self._state.get("stats", {}).get("errors", 0))
            self._state = normalize_state(copy.deepcopy(checkpoint))
            self._state["stats"]["errors"] = max(
                current_errors,
                int(self._state["stats"].get("errors", 0)),
            )

    async def _persist_state(self) -> bool:
        if not bool(getattr(self.store, "enabled", False)) or not self._store_ready:
            return False
        acquired = False
        try:
            await self._acquire_thread_lock(self._persist_lock)
            acquired = True
            with self._state_lock:
                snapshot = copy.deepcopy(self._state)
            task = asyncio.create_task(
                self._call_store(self.store.set, STATE_KEY, snapshot)
            )
            cancelled = False
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    cancelled = True
                except BaseException:
                    break
            result = task.result()
            if cancelled:
                raise asyncio.CancelledError
            if isinstance(result, Ok):
                return True
            raise RuntimeError("PluginStore returned Err")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            with self._state_lock:
                self._state["stats"]["errors"] = min(
                    1_000_000,
                    int(self._state["stats"].get("errors", 0)) + 1,
                )
            self.logger.warning(
                "Auto Prompt Harness state save failed: failure_class={}",
                type(exc).__name__,
            )
            return False
        finally:
            if acquired:
                self._persist_lock.release()

    async def _persist_or_restore(self, checkpoint: Mapping[str, Any]) -> bool:
        try:
            persisted = await self._persist_state()
        except BaseException:
            self._restore_checkpoint(checkpoint)
            raise
        if not persisted:
            self._restore_checkpoint(checkpoint)
        return persisted

    @staticmethod
    def _unwrap_effective_config(raw: object) -> dict[str, Any] | None:
        if not isinstance(raw, Mapping):
            return None
        value: Mapping[str, Any] = raw
        if isinstance(value.get("data"), Mapping):
            value = value["data"]
        if "config" in value:
            config = value.get("config")
            return (
                copy.deepcopy(dict(config))
                if isinstance(config, Mapping)
                else None
            )
        return copy.deepcopy(dict(value))

    async def _load_store_state(self) -> tuple[dict[str, Any], bool]:
        if not bool(getattr(self.store, "enabled", False)):
            return fresh_state(), False
        try:
            result = await self._call_store(self.store.get, STATE_KEY, None)
        except Exception as exc:
            self.logger.warning(
                "Auto Prompt Harness state load failed: failure_class={}",
                type(exc).__name__,
            )
            return fresh_state(), False
        if not isinstance(result, Ok):
            return fresh_state(), False
        raw = result.value
        state = normalize_state(raw)
        if raw is None:
            try:
                legacy_result = await self._call_store(
                    self.store.get,
                    LEGACY_STATE_KEY,
                    None,
                )
            except Exception:
                legacy_result = None
            if isinstance(legacy_result, Ok) and isinstance(
                legacy_result.value,
                Mapping,
            ):
                profiles = legacy_result.value.get("profiles")
                state["legacy_migration"] = {
                    "detected": True,
                    "migrated_at": now_ts(),
                    "profiles_not_bound": (
                        min(1_000, len(profiles))
                        if isinstance(profiles, Mapping)
                        else 0
                    ),
                }
        return state, True

    async def _reconcile_locked(
        self,
        *,
        allow_resume: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        characters = await self._bridge().load()
        self._last_invalid_managed_overlays = sorted(
            [
                str(name)
                for name, card in characters["猫娘"].items()
                if has_managed_provenance_marker(card)
                and not is_managed_overlay(card)
            ],
            key=str.casefold,
        )
        with self._state_lock:
            binding = self._state.get("binding")
            if not isinstance(binding, dict):
                recovered, orphans = recover_binding(characters)
                self._last_orphan_overlays = orphans
                if recovered is not None:
                    self._state["binding"] = recovered
                    binding = recovered

        if isinstance(binding, dict):
            binding_id = str(binding.get("binding_id") or "")
            self._last_orphan_overlays = [
                str(name)
                for name, card in characters["猫娘"].items()
                if is_managed_overlay(card)
                and (provenance_for(card) or {}).get("binding_id")
                != binding_id
            ]
            self._last_orphan_overlays.sort(key=str.casefold)

        if not isinstance(binding, dict):
            return characters, {
                "healthy": True,
                "code": "",
                "message": "",
                "effective": False,
                "current_name": str(characters.get("当前猫娘") or ""),
            }

        if binding.get("status") in {"deletion_pending", "overlay_deleted"}:
            cards = characters["猫娘"]
            matching = [
                str(name)
                for name, card in cards.items()
                if is_managed_overlay(card)
                and (provenance_for(card) or {}).get("binding_id")
                == binding.get("binding_id")
            ]
            current_name = str(characters.get("当前猫娘") or "")
            if not matching:
                if binding.get("status") == "deletion_pending":
                    binding["status"] = "overlay_deleted"
                    append_history(
                        binding,
                        action="overlay_deleted",
                        summary="重启核对后确认自适应副本已删除。",
                    )
                return characters, {
                    "healthy": True,
                    "code": "",
                    "message": "自适应副本已删除。",
                    "effective": False,
                    "current_name": current_name,
                    "overlay_name": str(binding.get("overlay_name") or ""),
                }
            if binding.get("status") == "overlay_deleted":
                binding["status"] = "conflict"
                binding["conflict_code"] = "deleted_overlay_reappeared"
                binding["last_error"] = "已删除的自适应副本再次出现，已停止写入。"
                return characters, {
                    "healthy": False,
                    "code": "deleted_overlay_reappeared",
                    "message": binding["last_error"],
                    "effective": current_name in matching,
                    "current_name": current_name,
                    "overlay_name": matching[0],
                }

        previous_overlay = str(binding.get("overlay_name") or "")
        health = inspect_binding(characters, binding)
        if health.get("overlay_renamed"):
            append_history(
                binding,
                action="overlay_renamed",
                summary=(
                    f"检测到自适应副本已从「{previous_overlay}」改名为"
                    f"「{binding['overlay_name']}」。"
                ),
            )

        if not health["healthy"]:
            code = str(health.get("code") or "binding_conflict")
            if binding.get("conflict_code") != code:
                append_history(
                    binding,
                    action="conflict",
                    summary=str(health.get("message") or "绑定需要处理。"),
                )
            binding["status"] = "conflict"
            binding["conflict_code"] = code
            binding["last_error"] = str(health.get("message") or "")
            return characters, health

        binding["conflict_code"] = ""
        binding["last_error"] = ""
        if binding.get("status") == "deletion_pending":
            return characters, health
        if (
            allow_resume
            and binding.get("status") == "suspended_for_shutdown"
            and binding.get("desired_enabled") is True
        ):
            # A clean shutdown deliberately restored the original.  Do not
            # infer permission to switch again during startup: the user may
            # have selected another card while this plugin was offline.
            binding["status"] = "inactive"

        if health.get("healthy") and health.get("effective"):
            binding["status"] = "active"
        elif binding.get("desired_enabled") is False:
            binding["status"] = "restored"
        elif binding.get("status") != "suspended_for_shutdown":
            binding["status"] = "inactive"
        return characters, health

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        await self._acquire_thread_lock(self._lifecycle_guard)
        try:
            self._shutdown_result = None
            self._stopping.clear()
            effective: dict[str, Any] | None = None
            try:
                effective = self._unwrap_effective_config(
                    await self.config.dump(timeout=5.0)
                )
            except Exception as exc:
                self.logger.warning(
                    "Auto Prompt Harness effective config load failed: failure_class={}",
                    type(exc).__name__,
                )
            if effective is not None:
                self.refresh_runtime_config(effective)
            if isinstance(self.store, PluginStore):
                self._store_worker.reopen()
            loaded, ready = await self._load_store_state()
            with self._state_lock:
                self._state = loaded
                self._store_ready = ready
                self._runtime_started = True
            reconciliation_error = ""
            await self._acquire_thread_lock(self._mutation_lock)
            try:
                try:
                    await self._reconcile_locked(allow_resume=True)
                except Exception as exc:
                    reconciliation_error = str(exc)
                    with self._state_lock:
                        self._state["stats"]["errors"] = min(
                            1_000_000,
                            int(self._state["stats"].get("errors", 0)) + 1,
                        )
                if ready and not await self._persist_state():
                    with self._state_lock:
                        self._store_ready = False
                    ready = False
            finally:
                self._mutation_lock.release()
            ui_registered = self.register_static_ui(
                "static",
                cache_control="no-cache",
            )
            return Ok(
                {
                    "status": "running" if ready else "degraded",
                    "store_enabled": bool(getattr(self.store, "enabled", False)),
                    "persistence_ready": ready,
                    "ui_registered": ui_registered,
                    "reconciliation_error": reconciliation_error,
                }
            )
        finally:
            self._lifecycle_guard.release()

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        await self._acquire_thread_lock(self._lifecycle_guard)
        try:
            if self._shutdown_result is not None:
                return Ok(copy.deepcopy(self._shutdown_result))
            self._stopping.set()
            restored = False
            skipped_user_choice = False
            restore_error = ""
            store_closed = False
            await self._acquire_thread_lock(self._mutation_lock)
            try:
                try:
                    characters, health = await self._reconcile_locked()
                    with self._state_lock:
                        binding = self._state.get("binding")
                    if isinstance(binding, dict):
                        current = str(characters.get("当前猫娘") or "")
                        overlay = str(
                            health.get("overlay_name")
                            or binding.get("overlay_name")
                            or ""
                        )
                        original = str(binding.get("original_name") or "")
                        if current == overlay:
                            restore_result = (
                                await self._bridge().restore_original_if_overlay(
                                    binding=binding,
                                    allow_runtime_unavailable=True,
                                )
                            )
                            restored = restore_result["switched"]
                            skipped_user_choice = restore_result[
                                "preserved_user_choice"
                            ]
                            if restored:
                                binding["status"] = "suspended_for_shutdown"
                                append_history(
                                    binding,
                                    action="shutdown_restored",
                                    summary=f"关闭前已按条件切回「{original}」。",
                                )
                        elif current and current != original:
                            skipped_user_choice = True
                            binding["status"] = "inactive"
                    if self._store_ready:
                        await self._persist_state()
                except Exception as exc:
                    restore_error = str(exc)
                with self._state_lock:
                    self._runtime_started = False
                try:
                    close_result = await self._call_store(self.store.close)
                    store_closed = isinstance(close_result, Ok)
                except Exception:
                    store_closed = False
            finally:
                self._mutation_lock.release()
            try:
                await self._store_worker.shutdown()
            except Exception:
                store_closed = False
            result = {
                "status": "shutdown",
                "restored_original": restored,
                "preserved_user_choice": skipped_user_choice,
                "restore_error": restore_error,
                "store_closed": store_closed,
            }
            self._shutdown_result = copy.deepcopy(result)
            return Ok(result)
        finally:
            self._lifecycle_guard.release()

    @message(
        id="observe_chat_message",
        name="拒绝未验证聊天载荷",
        description="真实证据只从宿主只读上下文轮询读取。",
        source="chat",
        input_schema=CHAT_SCHEMA,
    )
    async def observe_chat_message(self, *args: Any, **kwargs: Any):
        del args, kwargs
        return Ok({"accepted": False, "reason": "unverified_message_route"})

    @timer_interval(
        id="poll_user_context",
        name="读取脱敏证据",
        description="从宿主只读上下文读取当前适配副本的真实用户消息。",
        seconds=2,
        auto_start=True,
    )
    async def poll_user_context(self, **_: Any):
        if not self._poll_guard.acquire(blocking=False):
            return Ok({"accepted": 0, "reason": "poll_in_flight"})
        should_reflect = False
        try:
            if self._stopping.is_set() or not self._runtime_started:
                return Ok({"accepted": 0, "reason": "not_running"})
            if not self._store_ready:
                return Ok({"accepted": 0, "reason": "store_unavailable"})
            with self._state_lock:
                binding = copy.deepcopy(self._state.get("binding"))
                settings = copy.deepcopy(self._state["settings"])
            if (
                not isinstance(binding, dict)
                or binding.get("status") != "active"
                or settings.get("learning_enabled") is not True
            ):
                return Ok({"accepted": 0, "reason": "binding_inactive"})
            raw_result = await asyncio.to_thread(
                self.bus.memory.get,
                bucket_id="default",
                limit=POLL_LIMIT,
                timeout=POLL_TIMEOUT,
            )
            if inspect.isawaitable(raw_result):
                raw_result = await raw_result
            if isinstance(raw_result, Err):
                return Ok({"accepted": 0, "reason": "bus_unavailable"})
            if isinstance(raw_result, Ok):
                raw_result = raw_result.value
            try:
                records = list(islice(raw_result, POLL_LIMIT))
            except TypeError:
                records = []

            await self._acquire_thread_lock(self._mutation_lock)
            try:
                checkpoint = self._checkpoint()
                accepted = 0
                cursor_changed = False
                for record in records:
                    raw = unwrap_memory_record(record)
                    if not isinstance(raw, Mapping):
                        continue
                    if (
                        raw.get("type") != "user_message"
                        or raw.get("source") != "main_logic.core"
                        or raw.get("plugin_id")
                    ):
                        continue
                    with self._state_lock:
                        if not cursor_accepts(self._state, raw):
                            continue
                    cursor_changed = True
                    event = extract_chat_event(raw)
                    if (
                        event is None
                        or event.lanlan != binding.get("overlay_name")
                    ):
                        continue
                    evidence = collect_evidence(
                        [
                            {
                                "role": "user",
                                "text": event.text,
                                "at": event.timestamp,
                            }
                        ]
                    )
                    if not evidence:
                        continue
                    item = evidence[0]
                    fingerprint = hashlib.sha256(
                        (
                            f"{binding['binding_id']}\0{item.at:.6f}\0"
                            f"{item.role}\0{item.text}"
                        ).encode("utf-8")
                    ).hexdigest()
                    with self._state_lock:
                        if any(
                            entry.get("fingerprint") == fingerprint
                            for entry in self._state["evidence"]
                        ):
                            continue
                        self._state["evidence"].append(
                            {
                                "role": item.role,
                                "text": item.text,
                                "at": item.at,
                                "fingerprint": fingerprint,
                            }
                        )
                        window = int(self._state["settings"]["evidence_window"])
                        del self._state["evidence"][:-window]
                        self._state["stats"]["messages_seen"] = min(
                            1_000_000,
                            int(self._state["stats"].get("messages_seen", 0)) + 1,
                        )
                    accepted += 1
                if (accepted or cursor_changed) and not await self._persist_or_restore(
                    checkpoint
                ):
                    return Ok({"accepted": 0, "reason": "store_failed"})
                with self._state_lock:
                    should_reflect = bool(
                        accepted
                        and self._state["settings"]["automatic_reflection"]
                        and len(self._state["evidence"])
                        >= int(self._state["settings"]["reflection_threshold"])
                    )
            finally:
                self._mutation_lock.release()
            if should_reflect:
                await self._reflect_now_internal(automatic=True)
            return Ok({"accepted": accepted})
        except Exception as exc:
            self.logger.warning(
                "Auto Prompt Harness evidence poll failed: failure_class={}",
                type(exc).__name__,
            )
            return Ok({"accepted": 0, "reason": "poll_failed"})
        finally:
            self._poll_guard.release()

    async def _call_reflection_model(self, messages: list[dict[str, str]]) -> str:
        try:
            import utils.config_manager as config_manager_module
            import utils.llm_client as llm_client_module
        except Exception as exc:
            raise CharacterOperationError(
                "反思模型运行时不可用。",
                code="reflection_runtime_unavailable",
            ) from exc
        get_manager = getattr(config_manager_module, "get_config_manager", None)
        create_llm = getattr(llm_client_module, "create_chat_llm_async", None)
        if not callable(get_manager) or not callable(create_llm):
            raise CharacterOperationError(
                "反思模型运行时不可用。",
                code="reflection_runtime_unavailable",
            )
        manager = get_manager()
        api_config = manager.get_model_api_config("correction")
        if not str(api_config.get("base_url") or "").strip():
            api_config = manager.get_model_api_config("agent")
        base_url = str(api_config.get("base_url") or "").strip()
        model = str(api_config.get("model") or "").strip()
        api_key = str(api_config.get("api_key") or "").strip()
        if not base_url or not model:
            raise CharacterOperationError(
                "未配置反思模型；请先在主设置里配置 agent/correction 模型。",
                code="reflection_model_unconfigured",
            )
        llm = await create_llm(
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=0.2,
            timeout=30.0,
        )
        reply = await llm.ainvoke(messages)
        content = getattr(reply, "content", reply)
        if isinstance(content, list):
            content = " ".join(
                str(part.get("text", "")) if isinstance(part, dict) else str(part)
                for part in content
            )
        return str(content or "")

    def _evidence_fingerprint_locked(self) -> str:
        payload = "\n".join(
            str(item.get("fingerprint") or "") for item in self._state["evidence"]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def _reflect_now_internal(self, *, automatic: bool) -> dict[str, Any]:
        if not self._reflection_guard.acquire(blocking=False):
            return {"reflected": False, "reason": "reflection_in_flight"}
        try:
            with self._state_lock:
                binding = copy.deepcopy(self._state.get("binding"))
                evidence = copy.deepcopy(self._state["evidence"])
                evidence_fp = self._evidence_fingerprint_locked()
                last_evidence_fp = str(
                    self._state.get("last_reflection_evidence_fingerprint") or ""
                )
                settings = copy.deepcopy(self._state["settings"])
            if not isinstance(binding, dict):
                raise CharacterOperationError(
                    "请先选择角色卡并开始自适应。",
                    code="binding_required",
                )
            version = active_version(binding)
            if version is None:
                raise CharacterOperationError(
                    "适配版本记录不可用。",
                    code="version_missing",
                )
            if not evidence:
                return {"reflected": False, "reason": "evidence_empty"}
            if (
                automatic
                and evidence_fp
                == last_evidence_fp
            ):
                return {"reflected": False, "reason": "evidence_unchanged"}
            reflection = await reflect_once(
                self._call_reflection_model,
                evidence,
                version.get("adaptations", []),
            )
            await self._acquire_thread_lock(self._mutation_lock)
            try:
                checkpoint = self._checkpoint()
                with self._state_lock:
                    self._state["last_reflection_evidence_fingerprint"] = evidence_fp
                    self._state["stats"]["reflections"] = min(
                        1_000_000,
                        int(self._state["stats"].get("reflections", 0)) + 1,
                    )
                    no_proposal = (
                        reflection is None or not reflection.proposed_prompt
                    )
                    if no_proposal:
                        proposal = None
                    else:
                        proposal = reflection.to_store()
                        proposal.update(
                            {
                                "id": f"proposal-{uuid.uuid4().hex[:20]}",
                                "status": "pending",
                                "resolved_at": 0.0,
                                "applied_prompt": "",
                            }
                        )
                        self._state["proposals"].append(proposal)
                        del self._state["proposals"][:-MAX_PROPOSALS]
                if not await self._persist_or_restore(checkpoint):
                    raise CharacterOperationError(
                        (
                            "反思状态暂时无法保存。"
                            if no_proposal
                            else "建议暂时无法保存。"
                        ),
                        code="store_failed",
                    )
                if no_proposal:
                    return {
                        "reflected": False,
                        "reason": "no_stable_preference_or_invalid_output",
                    }
            finally:
                self._mutation_lock.release()

            auto_apply = bool(
                automatic
                and settings["auto_apply_low_risk"]
                and reflection.risk == "low"
                and reflection.confidence >= settings["minimum_confidence"]
            )
            result: dict[str, Any] = {
                "reflected": True,
                "proposal": copy.deepcopy(proposal),
                "auto_applied": False,
            }
            if auto_apply:
                applied = await self._resolve_proposal_internal(
                    proposal_id=proposal["id"],
                    action="approve",
                    edited_prompt=None,
                )
                result["auto_applied"] = bool(applied.get("applied"))
                result["proposal"] = applied.get("proposal", proposal)
            return result
        finally:
            self._reflection_guard.release()

    @plugin_entry(
        id="reflect_now",
        name="立即反思一次",
        description="从最近的脱敏证据生成一条待确认建议。",
        input_schema=EMPTY_SCHEMA,
        timeout=60.0,
    )
    async def reflect_now(self, **_: Any):
        try:
            return Ok(await self._reflect_now_internal(automatic=False))
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("反思暂时失败，请稍后重试。", "reflection_failed")

    async def _compensate_prompt(
        self,
        *,
        binding: Mapping[str, Any],
        expected_prompt: str,
        restore_prompt: str,
    ) -> bool:
        try:
            characters = await self._bridge().load()
            overlay = self._guard_overlay_write(
                characters,
                binding,
                expected_prompt=expected_prompt,
            )
            if overlay is None:
                return False
            set_stored_prompt(overlay, restore_prompt)
            await self._bridge().save(characters)
            verified = await self._bridge().load()
            if self._guard_overlay_write(
                verified,
                binding,
                expected_prompt=restore_prompt,
            ) is None:
                return False
            overlay_name = str(binding.get("overlay_name") or "")
            await self._bridge().refresh_managed_prompt(
                overlay_name=overlay_name,
                binding_id=str(binding["binding_id"]),
                prompt_fingerprint=text_fingerprint(restore_prompt),
                prefer_managed_route=(
                    binding.get("prompt_storage_mode")
                    != PROMPT_STORAGE_DYNAMIC_DEFAULT
                ),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def _guard_overlay_write(
        characters: Mapping[str, Any],
        binding: Mapping[str, Any],
        *,
        expected_prompt: str,
    ) -> dict[str, Any] | None:
        cards = characters.get("猫娘")
        if not isinstance(cards, Mapping):
            return None
        original = cards.get(str(binding.get("original_name") or ""))
        overlay = cards.get(str(binding.get("overlay_name") or ""))
        if (
            not isinstance(original, Mapping)
            or card_fingerprint(original)
            != binding.get("original_card_fingerprint")
            or not isinstance(overlay, dict)
            or not is_managed_overlay(overlay)
            or provenance_fingerprint(overlay)
            != binding.get("provenance_fingerprint")
            or overlay_integrity_fingerprint(overlay)
            != binding.get("overlay_integrity_fingerprint")
            or stored_prompt(overlay) != expected_prompt
        ):
            return None
        return overlay

    async def _write_overlay_prompt(
        self,
        binding: dict[str, Any],
        *,
        expected_prompt: str,
        new_prompt: str,
    ) -> str:
        characters = await self._bridge().load()
        health = inspect_binding(characters, binding)
        if not health["healthy"]:
            raise CharacterOperationError(
                str(health["message"]),
                code=str(health["code"]),
            )
        overlay_name = str(binding["overlay_name"])
        overlay = characters["猫娘"][overlay_name]
        if stored_prompt(overlay) != expected_prompt:
            raise CharacterOperationError(
                "自适应副本已在本次操作前变化，未覆盖。",
                code="overlay_prompt_changed",
            )
        set_stored_prompt(overlay, new_prompt)
        await self._bridge().save(characters)
        verified = await self._bridge().load()
        if self._guard_overlay_write(
            verified,
            binding,
            expected_prompt=new_prompt,
        ) is None:
            await self._compensate_prompt(
                binding=binding,
                expected_prompt=new_prompt,
                restore_prompt=expected_prompt,
            )
            raise CharacterOperationError(
                "角色配置在写入期间发生变化，未报告为已应用。",
                code="character_write_conflict",
            )
        try:
            return await self._bridge().refresh_managed_prompt(
                overlay_name=overlay_name,
                binding_id=str(binding["binding_id"]),
                prompt_fingerprint=text_fingerprint(new_prompt),
                prefer_managed_route=(
                    binding.get("prompt_storage_mode")
                    != PROMPT_STORAGE_DYNAMIC_DEFAULT
                ),
            )
        except Exception as exc:
            compensated = await self._compensate_prompt(
                binding=binding,
                expected_prompt=new_prompt,
                restore_prompt=expected_prompt,
            )
            if not compensated:
                raise CharacterOperationError(
                    "角色运行态刷新失败，且无法确认副本已恢复到上一版本；"
                    "请在角色管理中检查。",
                    code=str(
                        getattr(exc, "code", None)
                        or "runtime_refresh_failed"
                    ),
                ) from exc
            raise

    def _find_proposal_locked(self, proposal_id: str) -> dict[str, Any] | None:
        return next(
            (
                proposal
                for proposal in self._state["proposals"]
                if proposal.get("id") == proposal_id
            ),
            None,
        )

    async def _resolve_proposal_internal(
        self,
        *,
        proposal_id: str,
        action: str,
        edited_prompt: object,
    ) -> dict[str, Any]:
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            checkpoint = self._checkpoint()
            with self._state_lock:
                proposal = self._find_proposal_locked(proposal_id)
                binding = self._state.get("binding")
                if not isinstance(proposal, dict) or proposal.get("status") != "pending":
                    raise CharacterOperationError(
                        "建议不存在或已经处理。",
                        code="proposal_not_pending",
                    )
                if not isinstance(binding, dict):
                    raise CharacterOperationError(
                        "当前没有角色卡绑定。",
                        code="binding_required",
                    )
                binding_work = copy.deepcopy(binding)
            if action == "reject":
                with self._state_lock:
                    target = self._find_proposal_locked(proposal_id)
                    if target is None or target.get("status") != "pending":
                        raise CharacterOperationError(
                            "建议状态已变化。",
                            code="proposal_not_pending",
                        )
                    target["status"] = "rejected"
                    target["resolved_at"] = now_ts()
                    current_binding = self._state["binding"]
                    append_history(
                        current_binding,
                        action="rejected",
                        summary="已拒绝建议，角色卡未发生变化。",
                        proposal_id=proposal_id,
                    )
                    self._state["stats"]["rejected"] = min(
                        1_000_000,
                        int(self._state["stats"].get("rejected", 0)) + 1,
                    )
                if not await self._persist_or_restore(checkpoint):
                    raise CharacterOperationError(
                        "拒绝结果暂时无法保存。",
                        code="store_failed",
                    )
                return {
                    "resolved": True,
                    "action": "reject",
                    "applied": False,
                    "proposal": copy.deepcopy(target),
                }
            if action != "approve":
                raise CharacterOperationError(
                    "不支持的建议操作。",
                    code="invalid_action",
                )

            candidate = (
                edited_prompt
                if isinstance(edited_prompt, str) and edited_prompt.strip()
                else proposal.get("proposed_prompt")
            )
            valid, candidate = normalize_adaptation_text(candidate)
            if not valid:
                raise CharacterOperationError(
                    candidate,
                    code="unsafe_adaptation",
                )
            current_version = active_version(binding_work)
            if current_version is None:
                raise CharacterOperationError(
                    "适配版本记录不可用。",
                    code="version_missing",
                )
            adaptations = list(current_version.get("adaptations") or [])
            if candidate in adaptations:
                raise CharacterOperationError(
                    "这条建议已经在当前适配中生效。",
                    code="adaptation_unchanged",
                )
            adaptations.append(candidate)
            adaptations = adaptations[-MAX_ACTIVE_ADAPTATIONS:]
            new_prompt = compose_prompt(binding_work["base_prompt"], adaptations)
            old_prompt = str(current_version["prompt"])
            if new_prompt == old_prompt:
                raise CharacterOperationError(
                    "这条建议不会改变当前提示词。",
                    code="adaptation_unchanged",
                )
            refresh_mode = await self._write_overlay_prompt(
                binding_work,
                expected_prompt=old_prompt,
                new_prompt=new_prompt,
            )
            proposal_race = False
            with self._state_lock:
                target = self._find_proposal_locked(proposal_id)
                live_binding = self._state.get("binding")
                if (
                    target is None
                    or target.get("status") != "pending"
                    or not isinstance(live_binding, dict)
                    or live_binding.get("binding_id")
                    != binding_work.get("binding_id")
                ):
                    proposal_race = True
                else:
                    live_versions = [
                        item
                        for item in live_binding["versions"]
                        if isinstance(item, Mapping)
                    ]
                    next_number = max(
                        [
                            int(item.get("version", 0))
                            for item in live_versions
                        ]
                        or [0]
                    ) + 1
                    active_number = live_binding.get("active_version")
                    active_index = next(
                        (
                            index
                            for index, item in enumerate(live_versions)
                            if item.get("version") == active_number
                        ),
                        -1,
                    )
                    if active_index < 0:
                        proposal_race = True
                        live_versions = []
                    else:
                        # A rollback creates a branch. Discard inaccessible
                        # future versions before appending the new child so
                        # the next rollback returns to the actual parent.
                        live_binding["versions"] = [
                            dict(item)
                            for item in live_versions[: active_index + 1]
                        ]
                    version = {
                        "version": next_number,
                        "prompt": new_prompt,
                        "prompt_fingerprint": text_fingerprint(new_prompt),
                        "adaptations": adaptations,
                        "created_at": now_ts(),
                        "proposal_id": proposal_id,
                    }
                    if not proposal_race:
                        live_binding["versions"].append(version)
                        del live_binding["versions"][:-MAX_VERSIONS]
                        live_binding["active_version"] = next_number
                        live_binding["status"] = (
                            "active"
                            if binding_work.get("status") == "active"
                            else "inactive"
                        )
                        live_binding["runtime_refresh_mode"] = refresh_mode
                        append_history(
                            live_binding,
                            action="approved",
                            summary=str(
                                target.get("evidence_summary")
                                or "已批准一条沟通偏好。"
                            ),
                            proposal_id=proposal_id,
                            before="\n".join(
                                current_version.get("adaptations") or []
                            )
                            or "无",
                            after="\n".join(adaptations) or "无",
                            before_fingerprint=str(
                                current_version["prompt_fingerprint"]
                            ),
                            after_fingerprint=version["prompt_fingerprint"],
                            version=next_number,
                        )
                        target["status"] = "approved"
                        target["resolved_at"] = now_ts()
                        target["applied_prompt"] = candidate
                        self._state["stats"]["approved"] = min(
                            1_000_000,
                            int(self._state["stats"].get("approved", 0)) + 1,
                        )
            if proposal_race:
                await self._compensate_prompt(
                    binding=binding_work,
                    expected_prompt=new_prompt,
                    restore_prompt=old_prompt,
                )
                raise CharacterOperationError(
                    "建议状态在写入期间发生变化，已撤销。",
                    code="proposal_race",
                )
            if not await self._persist_or_restore(checkpoint):
                compensated = await self._compensate_prompt(
                    binding=binding_work,
                    expected_prompt=new_prompt,
                    restore_prompt=old_prompt,
                )
                raise CharacterOperationError(
                    (
                        "建议记录保存失败，角色副本已恢复到上一版本。"
                        if compensated
                        else "建议记录保存失败；副本状态需要人工检查。"
                    ),
                    code="store_failed",
                )
            return {
                "resolved": True,
                "action": "approve",
                "applied": True,
                "overlay_name": binding_work["overlay_name"],
                "runtime_refresh_mode": refresh_mode,
                "version": next_number,
                "proposal": copy.deepcopy(target),
            }
        finally:
            self._mutation_lock.release()

    @plugin_entry(
        id="resolve_proposal",
        name="确认或拒绝建议",
        description="批准后只修改受控角色副本的 system prompt；拒绝不会写角色卡。",
        input_schema=RESOLVE_SCHEMA,
        timeout=30.0,
    )
    async def resolve_proposal(
        self,
        proposal_id: str,
        action: str,
        edited_prompt: str | None = None,
        **_: Any,
    ):
        try:
            return Ok(
                await self._resolve_proposal_internal(
                    proposal_id=str(proposal_id),
                    action=str(action),
                    edited_prompt=edited_prompt,
                )
            )
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("建议处理失败。", "proposal_resolution_failed")

    @plugin_entry(
        id="rollback_last_change",
        name="回滚上一次修改",
        description="把受控副本恢复到前一个已保存的 prompt 版本。",
        input_schema=EMPTY_SCHEMA,
        timeout=30.0,
    )
    async def rollback_last_change(self, **_: Any):
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            checkpoint = self._checkpoint()
            with self._state_lock:
                binding = copy.deepcopy(self._state.get("binding"))
            if not isinstance(binding, dict):
                return _friendly_error("当前没有角色卡绑定。", "binding_required")
            versions = [
                item
                for item in binding.get("versions", [])
                if isinstance(item, Mapping)
            ]
            current_number = binding.get("active_version")
            current_index = next(
                (
                    index
                    for index, item in enumerate(versions)
                    if item.get("version") == current_number
                ),
                -1,
            )
            if current_index <= 0:
                return _friendly_error("没有更早的修改版本可回滚。", "rollback_unavailable")
            current_version = dict(versions[current_index])
            previous_version = dict(versions[current_index - 1])
            refresh_mode = await self._write_overlay_prompt(
                binding,
                expected_prompt=str(current_version["prompt"]),
                new_prompt=str(previous_version["prompt"]),
            )
            binding_race = False
            with self._state_lock:
                live = self._state.get("binding")
                if not isinstance(live, dict) or live.get("binding_id") != binding.get(
                    "binding_id"
                ):
                    binding_race = True
                else:
                    live["active_version"] = int(previous_version["version"])
                    live["runtime_refresh_mode"] = refresh_mode
                    append_history(
                        live,
                        action="rolled_back",
                        summary="已恢复受控副本的前一个提示词版本。",
                        proposal_id=str(
                            current_version.get("proposal_id") or ""
                        ),
                        before="\n".join(
                            current_version.get("adaptations") or []
                        )
                        or "无",
                        after="\n".join(
                            previous_version.get("adaptations") or []
                        )
                        or "无",
                        before_fingerprint=str(
                            current_version["prompt_fingerprint"]
                        ),
                        after_fingerprint=str(
                            previous_version["prompt_fingerprint"]
                        ),
                        version=int(previous_version["version"]),
                    )
                    proposal_id = str(
                        current_version.get("proposal_id") or ""
                    )
                    proposal = self._find_proposal_locked(proposal_id)
                    if (
                        proposal is not None
                        and proposal.get("status") == "approved"
                    ):
                        proposal["status"] = "superseded"
                        proposal["resolved_at"] = now_ts()
                    self._state["stats"]["rollbacks"] = min(
                        1_000_000,
                        int(self._state["stats"].get("rollbacks", 0)) + 1,
                    )
            if binding_race:
                await self._compensate_prompt(
                    binding=binding,
                    expected_prompt=str(previous_version["prompt"]),
                    restore_prompt=str(current_version["prompt"]),
                )
                raise CharacterOperationError(
                    "绑定在回滚期间发生变化，已撤销。",
                    code="binding_race",
                )
            if not await self._persist_or_restore(checkpoint):
                compensated = await self._compensate_prompt(
                    binding=binding,
                    expected_prompt=str(previous_version["prompt"]),
                    restore_prompt=str(current_version["prompt"]),
                )
                raise CharacterOperationError(
                    (
                        "回滚记录保存失败，副本已恢复到回滚前版本。"
                        if compensated
                        else "回滚记录保存失败；副本状态需要人工检查。"
                    ),
                    code="store_failed",
                )
            return Ok(
                {
                    "rolled_back": True,
                    "version": previous_version["version"],
                    "overlay_name": binding["overlay_name"],
                    "runtime_refresh_mode": refresh_mode,
                }
            )
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("暂时无法回滚。", "rollback_failed")
        finally:
            self._mutation_lock.release()

    async def _activate_existing_binding(
        self,
        binding: dict[str, Any],
        *,
        previous_current: str,
    ) -> dict[str, Any]:
        checkpoint = self._checkpoint()
        await self._bridge().switch_current(str(binding["overlay_name"]))
        binding_race = False
        with self._state_lock:
            live = self._state.get("binding")
            if not isinstance(live, dict) or live.get("binding_id") != binding.get(
                "binding_id"
            ):
                binding_race = True
            else:
                live["desired_enabled"] = True
                live["status"] = "active"
                live["conflict_code"] = ""
                live["last_error"] = ""
                append_history(
                    live,
                    action="activated",
                    summary=f"已切换到自适应副本「{live['overlay_name']}」。",
                )
        if binding_race:
            if previous_current:
                await self._bridge().switch_current_direct_if(
                    expected_current=str(binding["overlay_name"]),
                    target=previous_current,
                )
            raise CharacterOperationError(
                "绑定在切换期间发生变化。",
                code="binding_race",
            )
        if not await self._persist_or_restore(checkpoint):
            if previous_current:
                try:
                    await self._bridge().switch_current_direct_if(
                        expected_current=str(binding["overlay_name"]),
                        target=previous_current,
                    )
                except Exception:
                    pass
            raise CharacterOperationError(
                "启用状态无法保存，已尝试恢复原先角色。",
                code="store_failed",
            )
        return {
            "started": True,
            "reused_overlay": True,
            "original_name": binding["original_name"],
            "overlay_name": binding["overlay_name"],
            "effective": True,
        }

    async def _cleanup_failed_overlay(
        self,
        *,
        overlay_name: str,
        binding_id: str,
        expected_card_fingerprint: str,
    ) -> bool:
        """Delete a just-created overlay through the host, or leave it marked."""

        try:
            latest = await self._bridge().load()
            candidate = latest["猫娘"].get(overlay_name)
            provenance = (
                provenance_for(candidate)
                if isinstance(candidate, Mapping)
                else None
            )
            if (
                not is_managed_overlay(candidate)
                or not provenance
                or provenance.get("binding_id") != binding_id
                or card_fingerprint(candidate) != expected_card_fingerprint
            ):
                return False
            await self._bridge().delete_character(
                name=overlay_name,
                binding_id=binding_id,
                expected_provenance_fingerprint=provenance_fingerprint(
                    candidate
                ),
                expected_card_fingerprint=expected_card_fingerprint,
            )
            return True
        except Exception:
            # Keeping a provenance-marked copy is recoverable and visible in
            # reconciliation; directly popping it would skip host cleanup.
            return False

    @plugin_entry(
        id="start_adaptation",
        name="开始自适应",
        description="从所选真实角色卡创建明确标记的深拷贝，并切换到副本。",
        input_schema=START_SCHEMA,
        timeout=30.0,
    )
    async def start_adaptation(self, original_name: str, **_: Any):
        original_name = str(original_name or "").strip()
        if not original_name:
            return _friendly_error("请选择一张角色卡。", "character_required")
        if not self._store_ready:
            return _friendly_error(
                "本地存储尚未就绪，不能安全创建绑定。",
                "store_unavailable",
            )
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            characters, health = await self._reconcile_locked()
            cards = characters["猫娘"]
            previous_current = str(characters.get("当前猫娘") or "")
            existing_binding = self._state.get("binding")
            if isinstance(existing_binding, dict) and existing_binding.get(
                "status"
            ) != "overlay_deleted":
                if (
                    existing_binding.get("original_name") == original_name
                    and health.get("healthy")
                ):
                    return Ok(
                        await self._activate_existing_binding(
                            copy.deepcopy(existing_binding),
                            previous_current=str(characters.get("当前猫娘") or ""),
                        )
                    )
                return _friendly_error(
                    "当前已有角色卡绑定；请先恢复原角色并按需删除旧副本。",
                    "binding_exists",
                )
            if self._last_orphan_overlays:
                return _friendly_error(
                    "发现未绑定的受控副本；请先在面板中逐一确认删除，插件不会继续创建。",
                    "ambiguous_managed_overlays",
                    details={
                        "overlay_names": copy.deepcopy(
                            self._last_orphan_overlays
                        )
                    },
                )
            if self._last_invalid_managed_overlays:
                return _friendly_error(
                    "发现来源标记损坏的自适应副本；请先在角色管理中检查，"
                    "插件不会把它当作原角色继续复制。",
                    "invalid_managed_overlays",
                    details={
                        "overlay_names": copy.deepcopy(
                            self._last_invalid_managed_overlays
                        )
                    },
                )
            original = cards.get(original_name)
            if (
                not isinstance(original, dict)
                or has_managed_provenance_marker(original)
            ):
                return _friendly_error(
                    "所选原角色卡不存在或不是可绑定的原卡。",
                    "original_not_found",
                )
            original_snapshot = copy.deepcopy(original)
            overlay_name = unique_overlay_name(original_name, list(cards))
            binding_id = uuid.uuid4().hex[:24]
            created_at = now_ts()
            overlay, base_prompt = build_overlay(
                original_name=original_name,
                overlay_name=overlay_name,
                original_card=original_snapshot,
                binding_id=binding_id,
                at=created_at,
            )
            cards[overlay_name] = overlay
            if cards[original_name] != original_snapshot:
                raise CharacterOperationError(
                    "原角色卡在创建副本时发生变化，已中止。",
                    code="original_changed",
                )
            await self._bridge().save(characters)
            persisted_characters = await self._bridge().load()
            persisted_original = persisted_characters["猫娘"].get(original_name)
            persisted_overlay = persisted_characters["猫娘"].get(overlay_name)
            if (
                not isinstance(persisted_original, Mapping)
                or card_fingerprint(persisted_original)
                != card_fingerprint(original_snapshot)
                or not isinstance(persisted_overlay, Mapping)
                or card_fingerprint(persisted_overlay)
                != card_fingerprint(overlay)
            ):
                await self._cleanup_failed_overlay(
                    overlay_name=overlay_name,
                    binding_id=binding_id,
                    expected_card_fingerprint=card_fingerprint(overlay),
                )
                raise CharacterOperationError(
                    "角色配置在创建副本期间发生变化，已停止绑定。",
                    code="character_write_conflict",
                )
            try:
                await self._bridge().reload_runtime()
            except Exception:
                await self._cleanup_failed_overlay(
                    overlay_name=overlay_name,
                    binding_id=binding_id,
                    expected_card_fingerprint=card_fingerprint(overlay),
                )
                raise

            binding = create_binding(
                original_name=original_name,
                overlay_name=overlay_name,
                original_card=original_snapshot,
                overlay_card=overlay,
                base_prompt=base_prompt,
                binding_id=binding_id,
                at=created_at,
            )
            binding["status"] = "inactive"
            checkpoint = self._checkpoint()
            with self._state_lock:
                self._state["binding"] = binding
                self._state["proposals"] = []
                self._state["evidence"] = []
                self._state["last_reflection_evidence_fingerprint"] = ""
            if not await self._persist_or_restore(checkpoint):
                cleaned = await self._cleanup_failed_overlay(
                    overlay_name=overlay_name,
                    binding_id=binding_id,
                    expected_card_fingerprint=card_fingerprint(overlay),
                )
                raise CharacterOperationError(
                    (
                        "绑定记录无法保存，未保留新副本。"
                        if cleaned
                        else "绑定记录无法保存；带来源标记的副本已保留，重启后可识别。"
                    ),
                    code="store_failed",
                )
            try:
                await self._bridge().switch_current(overlay_name)
            except CharacterOperationError as exc:
                with self._state_lock:
                    live = self._state.get("binding")
                    if isinstance(live, dict):
                        live["last_error"] = str(exc)
                await self._persist_state()
                raise
            checkpoint = self._checkpoint()
            with self._state_lock:
                live = self._state["binding"]
                live["status"] = "active"
                live["desired_enabled"] = True
                append_history(
                    live,
                    action="activated",
                    summary=f"已切换到自适应副本「{overlay_name}」。",
                )
            if not await self._persist_or_restore(checkpoint):
                try:
                    if previous_current:
                        await self._bridge().switch_current_direct_if(
                            expected_current=overlay_name,
                            target=previous_current,
                        )
                except Exception:
                    pass
                raise CharacterOperationError(
                    "启用状态无法保存，已尝试切回原角色。",
                    code="store_failed",
                )
            return Ok(
                {
                    "started": True,
                    "reused_overlay": False,
                    "original_name": original_name,
                    "overlay_name": overlay_name,
                    "effective": True,
                    "base_prompt_fingerprint": binding[
                        "base_prompt_fingerprint"
                    ],
                }
            )
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception as exc:
            code = getattr(exc, "code", None) or "start_failed"
            return _friendly_error(
                "暂时无法开始自适应，请检查角色卡状态后重试。",
                str(code),
            )
        finally:
            self._mutation_lock.release()

    async def _restore_original_locked(
        self,
        *,
        reason: str,
    ) -> dict[str, Any]:
        checkpoint = self._checkpoint()
        characters, health = await self._reconcile_locked()
        with self._state_lock:
            binding = self._state.get("binding")
        if not isinstance(binding, dict):
            raise CharacterOperationError(
                "当前没有角色卡绑定。",
                code="binding_required",
            )
        cards = characters["猫娘"]
        original = str(binding.get("original_name") or "")
        overlay = str(
            health.get("overlay_name") or binding.get("overlay_name") or ""
        )
        current = str(characters.get("当前猫娘") or "")
        switched = False
        preserved_user_choice = False
        if current == overlay:
            if original not in cards:
                raise CharacterOperationError(
                    "原角色卡已删除或改名，无法自动恢复。",
                    code="original_missing_or_renamed",
                )
            restore_result = await self._bridge().restore_original_if_overlay(
                binding=binding,
            )
            switched = restore_result["switched"]
            preserved_user_choice = restore_result[
                "preserved_user_choice"
            ]
        elif current and current != original:
            preserved_user_choice = True
        with self._state_lock:
            live = self._state.get("binding")
            if not isinstance(live, dict):
                raise CharacterOperationError(
                    "绑定在恢复期间发生变化。",
                    code="binding_race",
                )
            live["desired_enabled"] = False
            if live.get("status") != "conflict":
                live["status"] = "restored"
            append_history(
                live,
                action="restored",
                summary=(
                    f"已切回原角色「{original}」。"
                    if switched
                    else (
                        "检测到用户已切换其他角色，未抢切。"
                        if preserved_user_choice
                        else f"当前已经是原角色「{original}」。"
                    )
                ),
            )
        if not await self._persist_or_restore(checkpoint):
            raise CharacterOperationError(
                "恢复结果已执行，但本地记录保存失败。",
                code="store_failed",
            )
        return {
            "restored": switched or current == original,
            "switched": switched,
            "preserved_user_choice": preserved_user_choice,
            "original_name": original,
            "overlay_name": overlay,
            "reason": reason,
        }

    @plugin_entry(
        id="restore_original",
        name="恢复原角色",
        description="仅当当前角色仍是本插件副本时切回原卡；不会抢切其他角色。",
        input_schema=EMPTY_SCHEMA,
        timeout=30.0,
    )
    async def restore_original(self, **_: Any):
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            return Ok(await self._restore_original_locked(reason="manual"))
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("暂时无法恢复原角色。", "restore_failed")
        finally:
            self._mutation_lock.release()

    @plugin_entry(
        id="delete_overlay",
        name="删除自适应副本",
        description="先安全恢复，再按来源标记与完整卡片指纹精确删除副本。",
        input_schema=DELETE_OVERLAY_SCHEMA,
        timeout=30.0,
    )
    async def delete_overlay(self, confirmation: str, **_: Any):
        if confirmation != "DELETE":
            return _friendly_error(
                "请输入 DELETE 确认删除自适应副本。",
                "confirmation_required",
            )
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            characters, health = await self._reconcile_locked()
            with self._state_lock:
                binding = copy.deepcopy(self._state.get("binding"))
            if not isinstance(binding, dict):
                return _friendly_error("当前没有角色卡绑定。", "binding_required")
            overlay = str(
                health.get("overlay_name") or binding.get("overlay_name") or ""
            )
            current = str(characters.get("当前猫娘") or "")
            if current == overlay:
                original = str(binding.get("original_name") or "")
                if original not in characters["猫娘"]:
                    return _friendly_error(
                        "原角色卡不存在；请先在角色管理中切换到其他角色。",
                        "original_missing_or_renamed",
                    )
                await self._bridge().restore_original_if_overlay(
                    binding=binding,
                )
            latest = await self._bridge().load()
            candidate = latest["猫娘"].get(overlay)
            if (
                not is_managed_overlay(candidate)
                or provenance_fingerprint(candidate)
                != binding.get("provenance_fingerprint")
            ):
                return _friendly_error(
                    "副本来源标记不匹配，未删除。",
                    "overlay_unmanaged",
                )
            checkpoint = self._checkpoint()
            with self._state_lock:
                live = self._state.get("binding")
                if isinstance(live, dict):
                    live["desired_enabled"] = False
                    live["status"] = "deletion_pending"
            if not await self._persist_or_restore(checkpoint):
                raise CharacterOperationError(
                    "删除准备状态无法保存。",
                    code="store_failed",
                )
            await self._bridge().delete_character(
                name=overlay,
                binding_id=str(binding["binding_id"]),
                expected_provenance_fingerprint=str(
                    binding.get("provenance_fingerprint") or ""
                ),
                expected_card_fingerprint=card_fingerprint(candidate),
            )
            checkpoint = self._checkpoint()
            with self._state_lock:
                live = self._state.get("binding")
                if isinstance(live, dict):
                    live["status"] = "overlay_deleted"
                    live["desired_enabled"] = False
                    append_history(
                        live,
                        action="overlay_deleted",
                        summary=f"已删除自适应副本「{overlay}」。",
                    )
            if not await self._persist_or_restore(checkpoint):
                raise CharacterOperationError(
                    "副本已删除，但删除记录保存失败。",
                    code="store_failed",
                )
            return Ok({"deleted": True, "overlay_name": overlay})
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("暂时无法删除自适应副本。", "overlay_delete_failed")
        finally:
            self._mutation_lock.release()

    @plugin_entry(
        id="delete_orphan_overlay",
        name="删除未绑定的受控副本",
        description="按明确名称删除带本插件来源标记、但不属于当前绑定的副本。",
        input_schema=DELETE_ORPHAN_SCHEMA,
        timeout=30.0,
    )
    async def delete_orphan_overlay(
        self,
        overlay_name: str,
        confirmation: str,
        **_: Any,
    ):
        overlay_name = str(overlay_name or "").strip()
        if confirmation != "DELETE":
            return _friendly_error(
                "请输入 DELETE 确认删除未绑定副本。",
                "confirmation_required",
            )
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            characters, _health = await self._reconcile_locked()
            if overlay_name not in self._last_orphan_overlays:
                return _friendly_error(
                    "所选名称不是当前可确认删除的未绑定副本。",
                    "orphan_overlay_not_found",
                )
            if str(characters.get("当前猫娘") or "") == overlay_name:
                return _friendly_error(
                    "该未绑定副本当前正在使用；请先在角色管理中切换到其他角色。",
                    "orphan_overlay_is_current",
                )
            candidate = characters["猫娘"].get(overlay_name)
            if not is_managed_overlay(candidate):
                return _friendly_error(
                    "副本来源标记无效，未删除。",
                    "overlay_unmanaged",
                )
            provenance = provenance_for(candidate) or {}
            await self._bridge().delete_character(
                name=overlay_name,
                binding_id=str(provenance.get("binding_id") or ""),
                expected_provenance_fingerprint=provenance_fingerprint(
                    candidate
                ),
                expected_card_fingerprint=card_fingerprint(candidate),
            )
            await self._reconcile_locked()
            state_persisted = (
                await self._persist_state()
                if self._store_ready
                else False
            )
            return Ok(
                {
                    "deleted": True,
                    "overlay_name": overlay_name,
                    "state_persisted": state_persisted,
                }
            )
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error(
                "暂时无法删除未绑定副本。",
                "orphan_overlay_delete_failed",
            )
        finally:
            self._mutation_lock.release()

    @staticmethod
    def _validate_settings(raw: object) -> tuple[bool, str, dict[str, Any]]:
        if not isinstance(raw, Mapping):
            return False, "设置必须是对象。", {}
        unknown = set(raw) - set(DEFAULT_SETTINGS)
        if unknown:
            return False, "设置包含不支持的字段。", {}
        merged = {**DEFAULT_SETTINGS, **dict(raw)}
        normalized = normalize_settings(merged)
        for key in (
            "learning_enabled",
            "automatic_reflection",
            "auto_apply_low_risk",
            "show_evidence_excerpts",
        ):
            if key in raw and not isinstance(raw[key], bool):
                return False, f"{key} 必须是布尔值。", {}
        for key, minimum, maximum in (
            ("reflection_threshold", 1, 12),
            ("evidence_window", 2, 12),
        ):
            if key in raw and (
                not isinstance(raw[key], int)
                or isinstance(raw[key], bool)
                or not minimum <= raw[key] <= maximum
            ):
                return False, f"{key} 超出允许范围。", {}
        if "minimum_confidence" in raw:
            value = raw["minimum_confidence"]
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or not 0.5 <= float(value) <= 0.95
            ):
                return False, "minimum_confidence 超出允许范围。", {}
        if normalized["reflection_threshold"] > normalized["evidence_window"]:
            return False, "触发条数不能大于证据窗口。", {}
        return True, "", normalized

    @plugin_entry(
        id="save_settings",
        name="保存高级设置",
        description="验证并保存证据窗口、反思阈值和自动批准设置。",
        input_schema=SETTINGS_SCHEMA,
        timeout=15.0,
    )
    async def save_settings(self, settings: Mapping[str, Any], **_: Any):
        valid, message_text, normalized = self._validate_settings(settings)
        if not valid:
            return _friendly_error(message_text, "invalid_settings")
        if not self._store_ready:
            return _friendly_error("本地存储不可用。", "store_unavailable")
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            checkpoint = self._checkpoint()
            with self._state_lock:
                self._state["settings"] = normalized
                if len(self._state["evidence"]) > int(
                    normalized["evidence_window"]
                ):
                    self._state["evidence"] = self._state["evidence"][
                        -int(normalized["evidence_window"]) :
                    ]
            if not await self._persist_or_restore(checkpoint):
                return _friendly_error("设置暂时无法保存。", "store_failed")
            return Ok({"saved": True, "settings": copy.deepcopy(normalized)})
        finally:
            self._mutation_lock.release()

    @plugin_entry(
        id="reset_settings",
        name="恢复默认设置",
        description="恢复内置的安全默认值，不删除角色副本或历史。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
    )
    async def reset_settings(self, **_: Any):
        return await self.save_settings(copy.deepcopy(DEFAULT_SETTINGS))

    @llm_tool(
        name="auto_prompt_harness.analyze_text",
        description="只在内存中判断一段文字是否包含明确的表达风格偏好，不保存。",
        parameters=ANALYZE_SCHEMA,
        timeout=15.0,
    )
    @plugin_entry(
        id="analyze_text",
        name="模拟偏好识别",
        description="只返回固定枚举观察，不读取或修改角色卡。",
        input_schema=ANALYZE_SCHEMA,
        llm_result_fields=["persisted", "observations"],
        timeout=15.0,
    )
    async def analyze_text(self, text: str, **_: Any):
        observations = [
            observation.dump() for observation in infer_observations(str(text or ""))
        ]
        return Ok({"persisted": False, "observations": observations})

    def _public_binding(
        self,
        binding: Mapping[str, Any] | None,
        health: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if not isinstance(binding, Mapping):
            return None
        version = active_version(binding)
        return {
            "binding_id": str(binding.get("binding_id") or ""),
            "original_name": str(binding.get("original_name") or ""),
            "overlay_name": str(binding.get("overlay_name") or ""),
            "base_prompt_fingerprint": str(
                binding.get("base_prompt_fingerprint") or ""
            ),
            "status": str(binding.get("status") or ""),
            "desired_enabled": bool(binding.get("desired_enabled", False)),
            "effective": bool(health.get("effective", False)),
            "healthy": bool(health.get("healthy", False)),
            "conflict_code": str(binding.get("conflict_code") or ""),
            "message": str(
                health.get("message") or binding.get("last_error") or ""
            ),
            "current_character": str(health.get("current_name") or ""),
            "current_version": (
                int(version.get("version", 0)) if isinstance(version, Mapping) else 0
            ),
            "active_adaptations": (
                copy.deepcopy(version.get("adaptations", []))
                if isinstance(version, Mapping)
                else []
            ),
            "prompt_fingerprint": (
                str(version.get("prompt_fingerprint") or "")
                if isinstance(version, Mapping)
                else ""
            ),
            "runtime_refresh_mode": str(
                binding.get("runtime_refresh_mode") or ""
            ),
            "history": copy.deepcopy(binding.get("history", []))[-MAX_HISTORY:],
            "created_at": float(binding.get("created_at") or 0.0),
            "updated_at": float(binding.get("updated_at") or 0.0),
            "overlay_retention": "preserve_until_manual_delete",
        }

    async def _panel_state_locked(self) -> dict[str, Any]:
        characters, health = await self._reconcile_locked()
        with self._state_lock:
            state = copy.deepcopy(self._state)
        cards = characters["猫娘"]
        binding = state.get("binding")
        card_items = [
            {
                "name": str(name),
                "current": str(characters.get("当前猫娘") or "") == str(name),
                "bound": bool(
                    isinstance(binding, Mapping)
                    and binding.get("original_name") == name
                ),
            }
            for name, card in cards.items()
            if (
                isinstance(card, Mapping)
                and not has_managed_provenance_marker(card)
            )
        ]
        card_items.sort(key=lambda item: item["name"].casefold())
        evidence = (
            copy.deepcopy(state["evidence"])
            if state["settings"]["show_evidence_excerpts"]
            else []
        )
        return {
            "status": (
                "running"
                if self._runtime_started and self._store_ready
                else "degraded"
            ),
            "persistence_ready": self._store_ready,
            "characters": card_items,
            "current_character": str(characters.get("当前猫娘") or ""),
            "binding": self._public_binding(binding, health),
            "proposals": copy.deepcopy(state["proposals"])[-MAX_PROPOSALS:],
            "settings": copy.deepcopy(state["settings"]),
            "evidence": evidence[-MAX_EVIDENCE_MESSAGES:],
            "evidence_count": len(state["evidence"]),
            "stats": copy.deepcopy(state["stats"]),
            "legacy_migration": copy.deepcopy(state["legacy_migration"]),
            "unbound_managed_overlays": copy.deepcopy(self._last_orphan_overlays),
            "invalid_managed_overlays": copy.deepcopy(
                self._last_invalid_managed_overlays
            ),
            "policy": {
                "original_never_modified": True,
                "overlay_deleted_only_manually": True,
                "hidden_prompt_injection_used": False,
            },
        }

    @plugin_entry(
        id="list_characters",
        name="列出真实角色卡",
        description="列出可绑定的 N.E.K.O 原角色卡，不返回插件副本。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
    )
    async def list_characters(self, **_: Any):
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            payload = await self._panel_state_locked()
            return Ok(
                {
                    "characters": payload["characters"],
                    "current_character": payload["current_character"],
                }
            )
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("暂时无法读取角色卡。", "characters_load_failed")
        finally:
            self._mutation_lock.release()

    @plugin_entry(
        id="get_panel_state",
        name="读取角色卡自适应状态",
        description="返回真实角色列表、绑定、生效状态、建议和修改记录。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
    )
    async def get_panel_state(self, **_: Any):
        await self._acquire_thread_lock(self._mutation_lock)
        try:
            checkpoint = self._checkpoint()
            payload = await self._panel_state_locked()
            if self._store_ready and self._state != checkpoint:
                await self._persist_state()
            return Ok(payload)
        except CharacterOperationError as exc:
            return _friendly_error(str(exc), exc.code)
        except Exception:
            return _friendly_error("管理面板状态暂时不可用。", "panel_state_failed")
        finally:
            self._mutation_lock.release()


__all__ = ["AutoPromptHarnessPlugin", "PLUGIN_ID"]
