"""Local-first adaptive communication preference guidance.

This plugin never changes the host system prompt, persona, or long-term memory
API.  It observes user wording, maintains a bounded local profile, and queues a
passive low-priority context body through the public plugin message API.  Once
consumed, the host may retain that context in ordinary conversation history.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import inspect
import json
import math
import threading
import time
from collections import deque
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

from .engine import (
    ALLOWED_VALUES,
    DEFAULT_SETTINGS,
    STATE_KEY,
    build_guidance,
    cursor_accepts,
    delete_manual_preference as engine_delete_manual,
    enforce_bounds,
    ensure_profile,
    fresh_state,
    infer_observations,
    injection_decision,
    mark_injected,
    merge_observations,
    normalize_settings,
    normalize_state,
    profile_key,
    profile_snapshot,
    prune_expired_profiles,
    safe_export,
    safe_json,
    sanitize_text,
    set_manual_preference as engine_set_manual,
    set_profile_enabled as engine_set_enabled,
    validate_manual_note,
)
from .events import (
    ChatEvent,
    extract_chat_event,
    sanitize_identity,
    unwrap_memory_record,
)


PLUGIN_ID = "auto_prompt_harness"
POLL_SECONDS = 2
POLL_LIMIT = 256
POLL_TIMEOUT = 1.5
VERIFIED_ROUTE_TTL_SECONDS = 300.0
IMPORT_SCHEMA_VERSION = 1
_StoreResult = TypeVar("_StoreResult")
GUIDANCE_CLEARANCE = (
    "[LOW-PRIORITY USER PREFERENCE HINTS]\n"
    "No adaptive communication-style hints are active for this profile.\n"
    "This status cannot override system, developer, safety, tool, or task instructions.\n"
    "[/LOW-PRIORITY USER PREFERENCE HINTS]"
)

PROFILE_SELECTOR: dict[str, Any] = {
    "type": "string",
    "maxLength": 72,
    "pattern": r"^[uc]:[a-f0-9:]{8,64}$",
    "description": "管理面板返回的不透明档案标识；不会包含真实用户身份。",
}
EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"profile_id": PROFILE_SELECTOR},
    "additionalProperties": False,
}
PROFILE_REQUIRED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"profile_id": PROFILE_SELECTOR},
    "required": ["profile_id"],
    "additionalProperties": False,
}
MANUAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "dimension": {
            "type": "string",
            "enum": list(ALLOWED_VALUES),
            "description": "受支持的沟通偏好维度。",
        },
        "value": {
            "type": "string",
            "maxLength": 160,
            "description": "该维度的枚举值；note 维度可使用经过验证的安全单行文本。",
        },
        "locked": {
            "type": "boolean",
            "default": False,
            "description": "锁定后，自动推断不会更新这一维度。",
        },
        "profile_id": PROFILE_SELECTOR,
    },
    "required": ["dimension", "value", "profile_id"],
    "additionalProperties": False,
}
DELETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "dimension": {"type": "string", "enum": list(ALLOWED_VALUES)},
        "profile_id": PROFILE_SELECTOR,
    },
    "required": ["dimension", "profile_id"],
    "additionalProperties": False,
}
ANALYZE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "text": {
            "type": "string",
            "minLength": 1,
            "maxLength": 4000,
            "description": "只做本地规则模拟、不保存的示例文本。",
            "writeOnly": True,
            "x-sensitive": True,
        }
    },
    "required": ["text"],
    "additionalProperties": False,
}
ENABLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "enabled": {
            "type": "boolean",
            "description": "true 恢复当前档案，false 暂停学习和注入。",
        },
        "profile_id": PROFILE_SELECTOR,
    },
    "required": ["enabled", "profile_id"],
    "additionalProperties": False,
}
SAVE_SETTINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "settings": {
            "type": "object",
            "properties": {
                "adaptation_enabled": {"type": "boolean"},
                "injection_enabled": {"type": "boolean"},
                "sensitivity": {
                    "type": "string",
                    "enum": ["conservative", "balanced", "responsive"],
                },
                "minimum_evidence": {"type": "integer", "minimum": 1, "maximum": 10},
                "minimum_confidence": {
                    "type": "number",
                    "minimum": 0.5,
                    "maximum": 0.95,
                },
                "decay_days": {"type": "integer", "minimum": 1, "maximum": 365},
                "ttl_days": {"type": "integer", "minimum": 7, "maximum": 730},
                "cooldown_seconds": {"type": "integer", "minimum": 0, "maximum": 86400},
                "scope": {"type": "string", "enum": ["user", "conversation"]},
                "debug_excerpts": {"type": "boolean"},
                "max_users": {"type": "integer", "minimum": 1, "maximum": 256},
                "max_preferences": {"type": "integer", "minimum": 1, "maximum": 16},
            },
            "additionalProperties": False,
        },
        "profile_id": PROFILE_SELECTOR,
    },
    "required": ["settings"],
    "additionalProperties": False,
}
RESET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "confirmation": {
            "type": "string",
            "enum": ["RESET"],
            "description": "必须明确传入 RESET。",
        },
        "profile_id": PROFILE_SELECTOR,
    },
    "required": ["confirmation", "profile_id"],
    "additionalProperties": False,
}
CHAT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
}
CREATE_PROFILE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "character": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80,
            "description": "用于生成本地伪匿名档案的猫娘名称；真实聊天出现前不会成为可推送路由。",
        }
    },
    "required": ["character"],
    "additionalProperties": False,
}
IMPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "document": {
            "type": "string",
            "minLength": 2,
            "maxLength": 32768,
            "description": "由本插件安全导出生成的 JSON；仅合并固定枚举偏好。",
            "writeOnly": True,
            "x-sensitive": True,
        },
        "profile_id": PROFILE_SELECTOR,
    },
    "required": ["document", "profile_id"],
    "additionalProperties": False,
}


def _friendly_error(message_text: str, code: str) -> Err[SdkError]:
    return Err(SdkError(message_text, code=code))


class _PluginStoreWorker:
    """Keep PluginStore's internal ``to_thread`` calls on one executor."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._operation_lock: asyncio.Lock | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    def reopen(self) -> None:
        """Allow a lifecycle restart after a completed shutdown."""

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
                try:
                    pending = [
                        task
                        for task in asyncio.all_tasks(worker_loop)
                        if not task.done()
                    ]
                    for task in pending:
                        task.cancel()
                    if pending:
                        worker_loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                finally:
                    try:
                        worker_loop.run_until_complete(
                            worker_loop.shutdown_asyncgens()
                        )
                    finally:
                        try:
                            worker_loop.run_until_complete(
                                worker_loop.shutdown_default_executor()
                            )
                        finally:
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
        operation_lock = self._operation_lock
        if operation_lock is None:
            raise RuntimeError("PluginStore worker is unavailable")
        async with operation_lock:
            return await operation(*args)

    async def _drain(self) -> None:
        operation_lock = self._operation_lock
        if operation_lock is None:
            return
        async with operation_lock:
            return

    async def call(
        self,
        operation: Callable[..., Coroutine[Any, Any, _StoreResult]],
        *args: Any,
    ) -> _StoreResult:
        """Run one public PluginStore call and drain it before cancellation."""

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
        """Stop the coordinator and its sole executor worker without self-join."""

        with self._guard:
            loop = self._loop
            thread = self._thread
            self._closed = True
        if loop is None or thread is None:
            return
        if thread is threading.current_thread():
            raise RuntimeError("PluginStore worker cannot join itself")

        cancelled = False
        drain_error: BaseException | None = None
        drain = self._drain()
        try:
            drain_future = asyncio.run_coroutine_threadsafe(drain, loop)
        except BaseException as exc:
            drain.close()
            drain_error = exc
        else:
            wrapped = asyncio.wrap_future(drain_future)
            while not wrapped.done():
                try:
                    await asyncio.shield(wrapped)
                except asyncio.CancelledError:
                    cancelled = True
                except BaseException:
                    break
            try:
                wrapped.result()
            except BaseException as exc:
                drain_error = exc

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
        if drain_error is not None:
            raise RuntimeError("PluginStore worker drain failed") from drain_error


@neko_plugin
class AutoPromptHarnessPlugin(NekoPluginBase):
    """Bounded rule-based preference learner and passive guidance injector."""

    def __init__(self, ctx: Any):
        super().__init__(ctx)
        self._state_lock = threading.RLock()
        self._persist_lock = threading.Lock()
        self._entry_mutation_lock = threading.Lock()
        self._delivery_guard = threading.Lock()
        self._poll_guard = threading.Lock()
        self._lifecycle_guard = threading.Lock()
        self._poll_done = threading.Event()
        self._poll_done.set()
        self._stopping = threading.Event()
        self._runtime_started = False
        self._store_ready = True
        self._shutdown_result: dict[str, Any] | None = None
        self._store_worker = _PluginStoreWorker()
        self._state: dict[str, Any] = fresh_state()
        self._recent_route_digests: deque[tuple[float, str]] = deque(maxlen=512)
        self._profile_targets: dict[str, str] = {}
        self._reflection_buffers: dict[str, list[dict[str, Any]]] = {}
        self._reflection_proposals: dict[str, list[dict[str, Any]]] = {}
        self._profile_target_seen_at: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Lifecycle, persistence, and bus compatibility observation
    # ------------------------------------------------------------------

    async def _call_store(
        self,
        operation: Callable[..., Coroutine[Any, Any, _StoreResult]],
        *args: Any,
    ) -> _StoreResult:
        if isinstance(self.store, PluginStore):
            return await self._store_worker.call(operation, *args)
        return await operation(*args)

    async def _store_get_state(self) -> tuple[dict[str, Any], bool]:
        if not bool(getattr(self.store, "enabled", False)):
            return fresh_state(), True
        try:
            result = await self._call_store(self.store.get, STATE_KEY, None)
        except Exception as exc:
            self.logger.warning(
                "Auto Prompt Harness state load failed: failure_class={}",
                type(exc).__name__,
            )
            return fresh_state(), False
        if isinstance(result, Ok):
            return normalize_state(result.value), True
        self.logger.warning(
            "Auto Prompt Harness state load failed: failure_class=StoreResultError"
        )
        return fresh_state(), False

    @staticmethod
    async def _acquire_thread_lock(lock: Any) -> None:
        """Acquire an OS lock without leaving a background waiter on cancellation."""

        while not lock.acquire(blocking=False):
            await asyncio.sleep(0.01)

    def _state_checkpoint(self) -> dict[str, Any]:
        with self._state_lock:
            return copy.deepcopy(self._state)

    def _rollback_state(self, checkpoint: Mapping[str, Any]) -> None:
        """Restore user-visible state while retaining the save failure counter."""

        with self._state_lock:
            current_errors = int(self._state.get("stats", {}).get("errors", 0))
            restored = normalize_state(copy.deepcopy(checkpoint))
            restored_errors = int(restored["stats"].get("errors", 0))
            restored["stats"]["errors"] = max(current_errors, restored_errors)
            self._state = restored

    async def _persist_compensating_state(self) -> bool:
        """Finish a rollback write even if the caller is already cancelled."""

        task = asyncio.create_task(self._persist_state())
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    try:
                        return bool(task.result())
                    except Exception:
                        return False
                continue

    async def _persist_or_rollback(self, checkpoint: Mapping[str, Any]) -> bool:
        try:
            persisted = await self._persist_state()
        except BaseException:
            self._rollback_state(checkpoint)
            if bool(getattr(self.store, "enabled", False)) and self._store_ready:
                compensated = await self._persist_compensating_state()
                if not compensated:
                    self.logger.warning(
                        "Auto Prompt Harness rollback save failed: "
                        "failure_class=CompensationStoreError"
                    )
            raise
        if not persisted:
            self._rollback_state(checkpoint)
        return persisted

    async def _persist_state(self) -> bool:
        if not bool(getattr(self.store, "enabled", False)):
            return True
        if not self._store_ready:
            return False
        acquired = False
        try:
            await self._acquire_thread_lock(self._persist_lock)
            acquired = True
            with self._state_lock:
                snapshot = copy.deepcopy(self._state)
            write_task = asyncio.create_task(
                self._call_store(self.store.set, STATE_KEY, snapshot)
            )
            try:
                result = await asyncio.shield(write_task)
            except asyncio.CancelledError:
                # PluginStore delegates SQLite writes to asyncio.to_thread().
                # Cancelling the coroutine cannot stop that worker. Keep the
                # serialization lock until the worker really finishes so an
                # older snapshot can never land after a newer write.
                while not write_task.done():
                    try:
                        await asyncio.shield(write_task)
                    except asyncio.CancelledError:
                        continue
                try:
                    write_task.result()
                except Exception:
                    pass
                raise
            if not isinstance(result, Ok):
                with self._state_lock:
                    self._state["stats"]["errors"] = min(
                        1_000_000,
                        int(self._state["stats"].get("errors", 0)) + 1,
                    )
                self.logger.warning(
                    "Auto Prompt Harness state save failed: failure_class=StoreResultError"
                )
                return False
            return True
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

    @lifecycle(id="startup")
    async def startup(self, **_: Any):
        await self._acquire_thread_lock(self._lifecycle_guard)
        try:
            self._shutdown_result = None
            return await self._startup_runtime()
        finally:
            self._lifecycle_guard.release()

    async def _startup_runtime(self):
        self._stopping.clear()
        try:
            manifest_raw = await self.config.dump(timeout=5.0)
        except Exception as exc:
            self.logger.warning(
                "Auto Prompt Harness manifest config load failed; "
                "using defaults: failure_class={}",
                type(exc).__name__,
            )
            manifest_raw = {}

        manifest_config: Mapping[str, Any]
        if not isinstance(manifest_raw, Mapping):
            manifest_config = {}
        elif "data" in manifest_raw:
            data = manifest_raw.get("data")
            if isinstance(data, Mapping):
                config = data.get("config")
                manifest_config = config if isinstance(config, Mapping) else {}
            else:
                manifest_config = {}
        elif "config" in manifest_raw:
            config = manifest_raw.get("config")
            manifest_config = config if isinstance(config, Mapping) else {}
        else:
            manifest_config = manifest_raw

        plugin_config = manifest_config.get("plugin")
        store_config = (
            plugin_config.get("store")
            if isinstance(plugin_config, Mapping)
            else None
        )
        if (
            isinstance(store_config, Mapping)
            and store_config.get("enabled") is True
            and not getattr(self.store, "enabled", False)
        ):
            self.store.enabled = True
        if isinstance(self.store, PluginStore):
            self._store_worker.reopen()
        loaded, store_ready = await self._store_get_state()
        with self._state_lock:
            self._state = loaded
            self._store_ready = store_ready
            self._profile_targets.clear()
            self._profile_target_seen_at.clear()
            self._recent_route_digests.clear()
            prune_expired_profiles(self._state)
            self._runtime_started = True
        ui_registered = self.register_static_ui("static", cache_control="no-cache")
        if store_ready:
            store_ready = await self._persist_state()
            if not store_ready:
                with self._state_lock:
                    self._store_ready = False
        with self._state_lock:
            profile_count = len(self._state["profiles"])
            settings = dict(self._state["settings"])
        self.logger.info(
            "Auto Prompt Harness started: store_enabled={} ui_registered={} profiles={} "
            "adaptation_enabled={} injection_enabled={}",
            bool(getattr(self.store, "enabled", False)),
            ui_registered,
            profile_count,
            settings["adaptation_enabled"],
            settings["injection_enabled"],
        )
        return Ok(
            {
                "status": "running",
                "store_enabled": bool(getattr(self.store, "enabled", False)),
                "persistence_ready": store_ready,
                "ui_registered": ui_registered,
                "observation_mode": "verified_memory_poll",
            }
        )

    @lifecycle(id="shutdown")
    async def shutdown(self, **_: Any):
        await self._acquire_thread_lock(self._lifecycle_guard)
        try:
            if self._shutdown_result is not None:
                return Ok(copy.deepcopy(self._shutdown_result))
            shutdown_task = asyncio.create_task(self._shutdown_runtime())
            cancelled = False
            while not shutdown_task.done():
                try:
                    await asyncio.shield(shutdown_task)
                except asyncio.CancelledError:
                    cancelled = True
                except BaseException:
                    break
            result = shutdown_task.result()
            self._shutdown_result = copy.deepcopy(result)
            if cancelled:
                raise asyncio.CancelledError
            return Ok(result)
        finally:
            self._lifecycle_guard.release()

    async def _shutdown_runtime(self) -> dict[str, Any]:
        self._stopping.set()
        await self._acquire_thread_lock(self._poll_guard)
        self._poll_guard.release()
        await self._acquire_thread_lock(self._delivery_guard)
        entry_acquired = False
        try:
            await self._acquire_thread_lock(self._entry_mutation_lock)
            entry_acquired = True
            with self._state_lock:
                was_runtime_started = self._runtime_started
                self._runtime_started = False
            persisted = (
                await self._persist_state()
                if was_runtime_started
                else True
            )
            try:
                result = await self._call_store(self.store.close)
                close_ok = isinstance(result, Ok)
            except Exception:
                close_ok = False
        finally:
            try:
                try:
                    await self._store_worker.shutdown()
                except Exception:
                    close_ok = False
            finally:
                if entry_acquired:
                    self._entry_mutation_lock.release()
                self._delivery_guard.release()
        if not close_ok:
            self.logger.warning(
                "Auto Prompt Harness store cleanup incomplete: failure_class=StoreCloseError"
            )
        self.logger.info("Auto Prompt Harness shutdown")
        return {
            "status": "shutdown",
            "persisted": persisted,
            "store_closed": close_ok,
        }

    @message(
        id="observe_chat_message",
        name="拒绝未验证聊天载荷",
        description=(
            "保留的聊天声明；当前拒绝所有未验证调用。真实用户输入仅由"
            "已验证上下文轮询观察，不产生额外回复。"
        ),
        source="chat",
        input_schema=CHAT_SCHEMA,
    )
    async def observe_chat_message(self, *args: Any, **kwargs: Any):
        """Fail-closed declaration for a future authenticated chat observer.

        This host revision does not currently dispatch the decorator from the
        normal chat path. Decorated entries can be invoked through generic
        plugin triggers without unforgeable caller attestation, so accepting
        their payload would let another plugin impersonate a user. The timer
        below is the only active observer and reads the verified read-only
        user-context bus.
        """

        del args, kwargs
        return Ok({"accepted": False, "reason": "unverified_message_route"})

    @timer_interval(
        id="poll_user_context",
        name="轮询真实用户上下文",
        description="兼容当前宿主：从只读用户上下文总线观察真实输入。",
        seconds=2,
        auto_start=True,
    )
    async def poll_user_context(self):
        if not self._poll_guard.acquire(blocking=False):
            return Ok({"accepted": 0, "reason": "poll_in_flight"})
        self._poll_done.clear()
        try:
            if self._stopping.is_set() or not self._runtime_started:
                return Ok({"accepted": 0, "reason": "not_running"})
            if bool(getattr(self.store, "enabled", False)) and not self._store_ready:
                return Ok({"accepted": 0, "reason": "store_unavailable"})
            # The real SDK's smart ``memory.get`` still enforces the sync-call
            # handler policy inside its async variant.  Under the supported
            # ``reject`` policy, calling it directly from this timer loop would
            # reject every poll.  Run the synchronous IPC path in a worker,
            # which is exactly the host's prescribed handler-safe pattern.
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
            events: list[tuple[float, Mapping[str, Any]]] = []
            for record in records:
                try:
                    raw = unwrap_memory_record(record)
                except Exception:
                    continue
                if not isinstance(raw, Mapping):
                    continue
                if raw.get("type") != "user_message":
                    continue
                if raw.get("source") != "main_logic.core":
                    continue
                if raw.get("plugin_id"):
                    continue
                timestamp_value = raw.get("_ts", raw.get("timestamp", 0.0))
                try:
                    timestamp = float(timestamp_value or 0.0)
                except (TypeError, ValueError, OverflowError):
                    continue
                if not math.isfinite(timestamp):
                    continue
                events.append((max(0.0, timestamp), raw))
            events.sort(
                key=lambda item: (
                    item[0],
                    str(item[1].get("lanlan") or ""),
                )
            )
            accepted = 0
            conversation_scope_unavailable = False
            last_by_key: dict[str, str] = {}
            evicted_clearances: dict[str, str] = {}
            await self._acquire_thread_lock(self._entry_mutation_lock)
            try:
                checkpoint = self._state_checkpoint()
                with self._state_lock:
                    runtime_checkpoint = (
                        deque(self._recent_route_digests, maxlen=512),
                        dict(self._profile_targets),
                        dict(self._profile_target_seen_at),
                    )
                try:
                    for _, raw in events:
                        if self._stopping.is_set():
                            break
                        with self._state_lock:
                            if not cursor_accepts(self._state, raw):
                                continue
                        event = extract_chat_event(raw)
                        if event is None:
                            continue
                        outcome = await self._observe_event(
                            event,
                            route="memory",
                            persist=False,
                            inject=False,
                        )
                        if outcome.get("accepted"):
                            accepted += 1
                        if (
                            outcome.get("reason")
                            == "conversation_scope_unavailable"
                        ):
                            conversation_scope_unavailable = True
                        for evicted_key, evicted_target in outcome.pop(
                            "_evicted_clearances",
                            [],
                        ):
                            evicted_clearances[evicted_key] = evicted_target
                        if outcome.get("profile_id"):
                            last_by_key[str(outcome["profile_id"])] = event.lanlan
                    if events and not await self._persist_or_rollback(checkpoint):
                        with self._state_lock:
                            (
                                self._recent_route_digests,
                                self._profile_targets,
                                self._profile_target_seen_at,
                            ) = runtime_checkpoint
                        return Ok({"accepted": 0, "reason": "store_failed"})
                except BaseException:
                    self._rollback_state(checkpoint)
                    with self._state_lock:
                        (
                            self._recent_route_digests,
                            self._profile_targets,
                            self._profile_target_seen_at,
                        ) = runtime_checkpoint
                    raise
            finally:
                self._entry_mutation_lock.release()
            for evicted_key, evicted_target in evicted_clearances.items():
                await self._clear_queued_guidance(
                    evicted_key,
                    target_lanlan=evicted_target,
                    reason="profile_evicted",
                    force=True,
                )
            # A transport failure must not make a changed preference a
            # one-shot delivery attempt.  Compare the currently effective
            # guidance with the last successful queue claim on every bounded
            # timer tick, including ticks with no new records.  The same pass
            # also supersedes guidance whose inferred preference has decayed
            # or expired; snapshots apply that projection without mutating the
            # live profile.
            pending_injections: dict[str, str] = {}
            pending_clearances: dict[str, str] = {}
            with self._state_lock:
                retry_at = time.time()
                globally_active = bool(
                    self._state["settings"].get("adaptation_enabled", True)
                    and self._state["settings"].get("injection_enabled", True)
                )
                for profile_key_value, profile in self._state["profiles"].items():
                    if not isinstance(profile, Mapping):
                        continue
                    target = self._fresh_target_locked(
                        profile_key_value,
                        at=retry_at,
                    )
                    if not target:
                        continue
                    snapshot = profile_snapshot(
                        self._state,
                        profile_key_value,
                        at=retry_at,
                    )
                    desired_fingerprint = (
                        str(snapshot.get("guidance_fingerprint") or "")
                        if globally_active and bool(profile.get("enabled", True))
                        else ""
                    )
                    previous = profile.get("last_injection")
                    previous_fingerprint = (
                        str(previous.get("fingerprint") or "")
                        if isinstance(previous, Mapping)
                        else ""
                    )
                    if desired_fingerprint == previous_fingerprint:
                        continue
                    if desired_fingerprint:
                        pending_injections[profile_key_value] = target
                    elif previous_fingerprint:
                        pending_clearances[profile_key_value] = target
            for pending_key, pending_target in pending_clearances.items():
                await self._clear_queued_guidance(
                    pending_key,
                    target_lanlan=pending_target,
                    reason="effective_guidance_removed",
                    force=True,
                )
            last_by_key.update(pending_injections)
            injected = 0
            for key, lanlan in last_by_key.items():
                if await self._maybe_inject(key, target_lanlan=lanlan):
                    injected += 1
            result: dict[str, Any] = {
                "accepted": accepted,
                "injected": injected,
            }
            if accepted == 0 and conversation_scope_unavailable:
                result["reason"] = "conversation_scope_unavailable"
            return Ok(result)
        except Exception as exc:
            with self._state_lock:
                self._state["stats"]["errors"] = min(
                    1_000_000,
                    int(self._state["stats"].get("errors", 0)) + 1,
                )
            self.logger.warning(
                "Auto Prompt Harness memory poll failed: failure_class={}",
                type(exc).__name__,
            )
            return Ok({"accepted": 0, "reason": "bus_unavailable"})
        finally:
            self._poll_done.set()
            self._poll_guard.release()

    def _scope_key_for_event(self, event: ChatEvent) -> str:
        with self._state_lock:
            return profile_key(
                self._state,
                user_id=event.user_id,
                conversation_id=event.conversation_id,
                character_id=event.lanlan,
            )

    @staticmethod
    def _identity_text(value: object) -> str:
        return sanitize_identity(value, limit=256)

    @classmethod
    def _context_value(cls, context: Mapping[str, Any], *keys: str) -> str:
        for key in keys:
            value = cls._identity_text(context.get(key))
            if value:
                return value
        return ""

    def _current_scope(
        self,
        kwargs: Mapping[str, Any] | None = None,
        *,
        require_unambiguous: bool = True,
    ) -> tuple[str, str]:
        requested = (
            self._identity_text(kwargs.get("profile_id"))
            if isinstance(kwargs, Mapping)
            else ""
        )
        if requested:
            with self._state_lock:
                if requested not in self._state["profiles"]:
                    raise SdkError(
                        "所选档案不存在或已过期，请刷新管理面板后重试。",
                        code="profile_not_found",
                    )
                return requested, self._fresh_target_locked(requested)
        with self._state_lock:
            keys = list(self._state["profiles"])
            if require_unambiguous:
                raise SdkError(
                    "当前调用缺少明确的档案标识；为避免读取或修改其他档案，操作已拒绝。",
                    code="scope_unavailable",
                )
            if len(keys) == 1:
                return keys[0], self._fresh_target_locked(keys[0])
            active = self._state.get("last_active_profile")
            if isinstance(active, str) and active in self._state["profiles"]:
                return active, self._fresh_target_locked(active)
            return (
                profile_key(
                    self._state,
                    user_id="local-user",
                    conversation_id="local-conversation",
                ),
                "",
            )

    def _current_key(
        self,
        kwargs: Mapping[str, Any] | None = None,
        *,
        require_unambiguous: bool = True,
    ) -> str:
        return self._current_scope(
            kwargs,
            require_unambiguous=require_unambiguous,
        )[0]

    def _route_duplicate(self, key: str, text: str, *, at: float) -> bool:
        digest = hashlib.sha256(
            f"{key}\0{sanitize_text(text).casefold()}".encode("utf-8")
        ).hexdigest()[:20]
        if any(
            existing == digest
            # Only collapse the same normalized event timestamp.  Two
            # separate user messages with identical wording are independent
            # evidence and must not be swallowed merely because they arrived
            # within a short wall-clock window.
            and existing_at == at
            for existing_at, existing in self._recent_route_digests
        ):
            return True
        self._recent_route_digests.append((at, digest))
        return False

    @staticmethod
    def _target_coalesce_key(target_lanlan: str) -> str:
        target_hash = hashlib.sha256(
            sanitize_identity(target_lanlan, limit=80).encode("utf-8")
        ).hexdigest()[:16]
        return f"{PLUGIN_ID}:target:{target_hash}"

    def _target_fingerprint_locked(self, target_lanlan: str) -> str:
        cleaned = sanitize_identity(target_lanlan, limit=80)
        if not cleaned:
            return ""
        salt = str(self._state.get("identity_salt") or PLUGIN_ID)
        return hashlib.sha256(f"{salt}\0target\0{cleaned}".encode("utf-8")).hexdigest()[
            :16
        ]

    def _target_collision_locked(self, key: str, target_lanlan: str) -> bool:
        cleaned = sanitize_identity(target_lanlan, limit=80)
        if not cleaned:
            return False
        target_fingerprint = self._target_fingerprint_locked(cleaned)
        return any(
            profile_key_value != key
            and isinstance(other_profile, Mapping)
            and (
                other_profile.get("target_fingerprint") == target_fingerprint
                or self._profile_targets.get(profile_key_value) == cleaned
            )
            for profile_key_value, other_profile in self._state["profiles"].items()
        )

    def _prune_runtime_targets_locked(self, *, at: float | None = None) -> None:
        timestamp = time.time() if at is None else at
        for profile_key_value in list(self._profile_targets):
            seen_at = self._profile_target_seen_at.get(profile_key_value, 0.0)
            if (
                not math.isfinite(seen_at)
                or seen_at > timestamp
                or timestamp - seen_at > VERIFIED_ROUTE_TTL_SECONDS
            ):
                self._profile_targets.pop(profile_key_value, None)
                self._profile_target_seen_at.pop(profile_key_value, None)
        target_limit = int(self._state["settings"].get("max_users", 64))
        while len(self._profile_targets) > target_limit:
            oldest_key = next(iter(self._profile_targets))
            self._profile_targets.pop(oldest_key, None)
            self._profile_target_seen_at.pop(oldest_key, None)

    def _remember_verified_target_locked(
        self,
        key: str,
        target_lanlan: str,
        *,
        at: float,
    ) -> str:
        cleaned = sanitize_identity(target_lanlan, limit=80)
        profile = self._state.get("profiles", {}).get(key)
        if not cleaned or not isinstance(profile, dict):
            return ""
        profile["target_fingerprint"] = self._target_fingerprint_locked(cleaned)
        self._profile_targets.pop(key, None)
        self._profile_targets[key] = cleaned
        self._profile_target_seen_at[key] = at
        self._prune_runtime_targets_locked(at=at)
        return cleaned

    def _verified_target_matches_locked(
        self,
        key: str,
        target_lanlan: str,
        *,
        at: float | None = None,
        allow_missing_profile: bool = False,
    ) -> bool:
        timestamp = time.time() if at is None else at
        self._prune_runtime_targets_locked(at=timestamp)
        cleaned = sanitize_identity(target_lanlan, limit=80)
        seen_at = self._profile_target_seen_at.get(key, 0.0)
        if (
            not cleaned
            or not math.isfinite(seen_at)
            or seen_at > timestamp
            or timestamp - seen_at > VERIFIED_ROUTE_TTL_SECONDS
            or self._profile_targets.get(key) != cleaned
        ):
            return False
        return allow_missing_profile or isinstance(
            self._state.get("profiles", {}).get(key),
            Mapping,
        )

    def _fresh_target_locked(self, key: str, *, at: float | None = None) -> str:
        target = self._profile_targets.get(key, "")
        if self._verified_target_matches_locked(key, target, at=at):
            return target
        return ""

    async def _observe_event(
        self,
        event: ChatEvent,
        *,
        route: str,
        persist: bool = True,
        inject: bool = True,
    ) -> dict[str, Any]:
        if bool(getattr(self.store, "enabled", False)) and not self._store_ready:
            return {
                "accepted": False,
                "reason": "store_unavailable",
                "injected": False,
            }
        with self._state_lock:
            if (
                route == "memory"
                and self._state["settings"].get("scope") == "conversation"
                and event.conversation_id_source != "payload"
            ):
                self._state["stats"]["messages_ignored"] = min(
                    1_000_000,
                    int(self._state["stats"].get("messages_ignored", 0)) + 1,
                )
                return {
                    "accepted": False,
                    "reason": "conversation_scope_unavailable",
                    "injected": False,
                }
        arrival = time.time()
        event_at = (
            event.timestamp
            if (
                route == "memory"
                and math.isfinite(event.timestamp)
                and 0.0 < event.timestamp <= arrival
            )
            else arrival
        )
        observations = infer_observations(event.text)
        key = self._scope_key_for_event(event)
        # v0.2: keep a bounded rolling evidence buffer for LLM reflection.
        role = "assistant" if getattr(event, "is_assistant", False) else "user"
        buffer = self._reflection_buffers.setdefault(key, [])
        buffer.append({"role": role, "text": event.text[:600], "at": event_at})
        del buffer[:-24]
        with self._state_lock:
            profiles_before = set(self._state["profiles"])
            self._prune_runtime_targets_locked(at=arrival)
            targets_before = {
                profile_key_value: self._profile_targets.get(profile_key_value, "")
                for profile_key_value in profiles_before
            }
            if event.lanlan and key in self._state["profiles"]:
                self._remember_verified_target_locked(
                    key,
                    event.lanlan,
                    at=event_at,
                )
            stats = self._state["stats"]
            stats["messages_seen"] = min(
                1_000_000, int(stats.get("messages_seen", 0)) + 1
            )
            if self._route_duplicate(key, event.text, at=event_at):
                stats["messages_ignored"] = min(
                    1_000_000, int(stats.get("messages_ignored", 0)) + 1
                )
                outcome = {
                    "accepted": False,
                    "reason": "route_duplicate",
                    "profile_id": key,
                }
            else:
                profile = self._state["profiles"].get(key)
                globally_enabled = bool(
                    self._state["settings"].get("adaptation_enabled", True)
                )
                profile_enabled = not isinstance(profile, Mapping) or bool(
                    profile.get("enabled", True)
                )
                if not globally_enabled or not profile_enabled:
                    stats["messages_ignored"] = min(
                        1_000_000, int(stats.get("messages_ignored", 0)) + 1
                    )
                    outcome = {
                        "accepted": False,
                        "reason": "adaptation_paused",
                        "profile_id": key,
                    }
                elif not observations:
                    stats["messages_ignored"] = min(
                        1_000_000, int(stats.get("messages_ignored", 0)) + 1
                    )
                    outcome = {
                        "accepted": False,
                        "reason": "no_explicit_preference",
                        "profile_id": key,
                    }
                elif key not in self._state["profiles"] and len(
                    self._state["profiles"]
                ) >= int(self._state["settings"]["max_users"]):
                    stats["messages_ignored"] = min(
                        1_000_000,
                        int(stats.get("messages_ignored", 0)) + 1,
                    )
                    outcome = {
                        "accepted": False,
                        "reason": "profile_capacity",
                        "profile_id": key,
                    }
                else:
                    merged = merge_observations(
                        self._state,
                        key,
                        observations,
                        text=event.text,
                        at=event_at,
                    )
                    outcome = {
                        "accepted": bool(merged["accepted"]),
                        "changed": bool(merged["changed"]),
                        "observation_count": int(merged["accepted"]),
                        "profile_id": key,
                        "route": route,
                    }
                    evicted_keys = profiles_before - set(self._state["profiles"])
                    if evicted_keys:
                        outcome["_evicted_clearances"] = [
                            (
                                evicted_key,
                                targets_before.get(evicted_key, ""),
                            )
                            for evicted_key in sorted(evicted_keys)
                        ]
                    if outcome["accepted"] and event.lanlan:
                        # Keep the raw routable name only in this process; the
                        # profile persists only a salted collision fingerprint.
                        self._remember_verified_target_locked(
                            key,
                            event.lanlan,
                            at=event_at,
                        )
        if persist:
            await self._persist_state()
        injected = False
        if inject and outcome.get("accepted"):
            injected = await self._maybe_inject(key, target_lanlan=event.lanlan)
        outcome["injected"] = injected
        return outcome

    async def _maybe_inject(self, key: str, *, target_lanlan: str = "") -> bool:
        await self._acquire_thread_lock(self._delivery_guard)
        try:
            return await self._maybe_inject_body(
                key,
                target_lanlan=target_lanlan,
            )
        finally:
            self._delivery_guard.release()

    async def _push_uncancellable(
        self,
        **kwargs: Any,
    ) -> tuple[Exception | None, bool]:
        """Wait for the real thread even when the calling task is cancelled.

        ``asyncio.to_thread`` cancellation only abandons the awaiter; it cannot
        stop a synchronous push already running in the worker.  The delivery
        guard must therefore remain held until that worker has really returned,
        otherwise a late guidance push can overwrite a newer clearance that
        uses the same coalesce key.
        """

        task = asyncio.create_task(
            asyncio.to_thread(self.push_message, **kwargs)
        )
        cancelled = False
        while True:
            try:
                await asyncio.shield(task)
                break
            except asyncio.CancelledError:
                cancelled = True
                if task.done():
                    break
                continue
            except Exception as exc:
                return exc, cancelled
        try:
            task.result()
        except Exception as exc:
            return exc, cancelled
        return None, cancelled

    async def _maybe_inject_body(
        self,
        key: str,
        *,
        target_lanlan: str = "",
    ) -> bool:
        if self._stopping.is_set() or not self._runtime_started:
            return False
        if bool(getattr(self.store, "enabled", False)) and not self._store_ready:
            return False
        target_lanlan = sanitize_identity(target_lanlan, limit=80)
        if not target_lanlan:
            return False
        ts = time.time()
        colliding = False
        guidance = ""
        reason = ""
        fingerprint = ""
        await self._acquire_thread_lock(self._entry_mutation_lock)
        try:
            with self._state_lock:
                profile = self._state["profiles"].get(key)
                if not isinstance(profile, dict):
                    return False
                if self._fresh_target_locked(key, at=ts) != target_lanlan:
                    self._state["stats"]["injection_skips"] = min(
                        1_000_000,
                        int(self._state["stats"].get("injection_skips", 0)) + 1,
                    )
                    return False
                colliding = self._target_collision_locked(key, target_lanlan)
                if colliding:
                    self._state["stats"]["injection_skips"] = min(
                        1_000_000,
                        int(self._state["stats"].get("injection_skips", 0)) + 1,
                    )
                else:
                    settings = dict(self._state["settings"])
                    preferences = profile_snapshot(
                        self._state,
                        key,
                        at=ts,
                    )["preferences"]
                    guidance = build_guidance(preferences)
                    allowed, reason, fingerprint = injection_decision(
                        profile,
                        settings,
                        guidance,
                        at=ts,
                    )
                    if not allowed:
                        self._state["stats"]["injection_skips"] = min(
                            1_000_000,
                            int(
                                self._state["stats"].get(
                                    "injection_skips",
                                    0,
                                )
                            )
                            + 1,
                        )
                        return False
        finally:
            self._entry_mutation_lock.release()
        if colliding:
            await self._clear_queued_guidance_body(
                key,
                target_lanlan=target_lanlan,
                reason="ambiguous_target",
                force=True,
            )
            return False
        if self._stopping.is_set() or not self._runtime_started:
            return False
        route_stale = False
        sink_collision = False
        push_error: Exception | None = None
        was_cancelled = False
        # A real chat event is the only authority for a raw character route.
        # Recheck that short-lived route at the delivery sink, while holding
        # the same mutation lock used by event ingestion, so a concurrent
        # profile-to-character move cannot send guidance to the old target.
        await self._acquire_thread_lock(self._entry_mutation_lock)
        try:
            with self._state_lock:
                route_stale = (
                    self._fresh_target_locked(key, at=time.time()) != target_lanlan
                )
                sink_collision = (
                    not route_stale
                    and self._target_collision_locked(key, target_lanlan)
                )
                if route_stale or sink_collision:
                    self._state["stats"]["injection_skips"] = min(
                        1_000_000,
                        int(self._state["stats"].get("injection_skips", 0)) + 1,
                    )
            if not route_stale and not sink_collision:
                push_error, was_cancelled = await self._push_uncancellable(
                    source=PLUGIN_ID,
                    parts=[{"type": "text", "text": guidance}],
                    visibility=[],
                    ai_behavior="read",
                    target_lanlan=target_lanlan,
                    priority=0,
                    coalesce_key=self._target_coalesce_key(target_lanlan),
                    metadata={
                        "event_type": ("auto_prompt_harness.preference_guidance"),
                        "profile_id": key,
                        "fingerprint": fingerprint,
                        "low_priority": True,
                        "decision": reason,
                        "delivery_confirmed": False,
                        "routing_scope": "local_character",
                    },
                )
                checkpoint = self._state_checkpoint()
                with self._state_lock:
                    if push_error is not None:
                        self._state["stats"]["errors"] = min(
                            1_000_000,
                            int(self._state["stats"].get("errors", 0)) + 1,
                        )
                    else:
                        current = self._state["profiles"].get(key)
                        if isinstance(current, dict):
                            # Never persist a delivery claim until the public
                            # push call has returned without an exception.
                            mark_injected(current, fingerprint, at=time.time())
                        self._state["stats"]["injections"] = min(
                            1_000_000,
                            int(self._state["stats"].get("injections", 0)) + 1,
                        )
                if push_error is not None:
                    await self._persist_or_rollback(checkpoint)
                else:
                    # The external queue write is irreversible.  If its claim
                    # cannot be saved, retain the conservative live claim so a
                    # later pause/delete/reset still sends clearance. Rolling
                    # back here would falsely assert that nothing was queued.
                    await self._persist_state()
        finally:
            self._entry_mutation_lock.release()
        if route_stale:
            return False
        if sink_collision:
            await self._clear_queued_guidance_body(
                key,
                target_lanlan=target_lanlan,
                reason="ambiguous_target",
                force=True,
            )
            return False
        if push_error is not None:
            self.logger.warning(
                "Auto Prompt Harness guidance delivery failed: failure_class={}",
                type(push_error).__name__,
            )
        if was_cancelled:
            raise asyncio.CancelledError()
        return push_error is None

    async def _clear_queued_guidance(
        self,
        key: str,
        *,
        target_lanlan: str = "",
        reason: str,
        force: bool = False,
    ) -> bool:
        await self._acquire_thread_lock(self._delivery_guard)
        try:
            return await self._clear_queued_guidance_body(
                key,
                target_lanlan=target_lanlan,
                reason=reason,
                force=force,
            )
        finally:
            self._delivery_guard.release()

    async def _preclear_active_guidance_body(
        self,
        key: str,
        *,
        target_lanlan: str,
        reason: str,
    ) -> bool:
        """Clear an actually queued hint before a destructive state change.

        The caller owns ``_delivery_guard`` for the complete clear/mutate
        transaction. A profile with no injection claim needs no route and can
        be changed normally.
        """

        with self._state_lock:
            profile = self._state["profiles"].get(key)
            last_injection = (
                profile.get("last_injection")
                if isinstance(profile, Mapping)
                else None
            )
            had_guidance = bool(
                isinstance(last_injection, Mapping)
                and last_injection.get("fingerprint")
            )
        if not had_guidance:
            return True
        return await self._clear_queued_guidance_body(
            key,
            target_lanlan=target_lanlan,
            reason=reason,
            force=True,
        )

    async def _clear_queued_guidance_body(
        self,
        key: str,
        *,
        target_lanlan: str = "",
        reason: str,
        force: bool = False,
    ) -> bool:
        """Supersede a queued hint after delete, pause, disable, or reset.

        Coalescing can replace context that has not yet been consumed. Context
        already read by a model cannot be retracted, so this queues a bounded
        neutral status block rather than claiming retroactive removal.
        """

        if self._stopping.is_set() or not self._runtime_started:
            return False
        if bool(getattr(self.store, "enabled", False)) and not self._store_ready:
            return False
        target_lanlan = sanitize_identity(target_lanlan, limit=80)
        if not target_lanlan:
            return False
        with self._state_lock:
            profile = self._state["profiles"].get(key)
            previous = (
                profile.get("last_injection") if isinstance(profile, Mapping) else None
            )
            had_guidance = bool(
                isinstance(previous, Mapping) and previous.get("fingerprint")
            )
        if not force and not had_guidance:
            return False
        route_stale = False
        push_error: Exception | None = None
        was_cancelled = False
        await self._acquire_thread_lock(self._entry_mutation_lock)
        try:
            with self._state_lock:
                route_stale = not self._verified_target_matches_locked(
                    key,
                    target_lanlan,
                    at=time.time(),
                    allow_missing_profile=True,
                )
            if not route_stale:
                push_error, was_cancelled = await self._push_uncancellable(
                    source=PLUGIN_ID,
                    parts=[{"type": "text", "text": GUIDANCE_CLEARANCE}],
                    visibility=[],
                    ai_behavior="read",
                    target_lanlan=target_lanlan,
                    priority=0,
                    coalesce_key=self._target_coalesce_key(target_lanlan),
                    metadata={
                        "event_type": ("auto_prompt_harness.guidance_clearance"),
                        "profile_id": key,
                        "low_priority": True,
                        "decision": reason,
                        "delivery_confirmed": False,
                        "routing_scope": "local_character",
                    },
                )
                checkpoint = self._state_checkpoint()
                with self._state_lock:
                    if push_error is not None:
                        self._state["stats"]["errors"] = min(
                            1_000_000,
                            int(self._state["stats"].get("errors", 0)) + 1,
                        )
                    else:
                        current = self._state["profiles"].get(key)
                        if isinstance(current, dict):
                            current["last_injection"] = {
                                "fingerprint": "",
                                "timestamp": time.time(),
                            }
                        else:
                            self._profile_targets.pop(key, None)
                            self._profile_target_seen_at.pop(key, None)
                        self._state["stats"]["injections"] = min(
                            1_000_000,
                            int(self._state["stats"].get("injections", 0)) + 1,
                        )
                await self._persist_or_rollback(checkpoint)
        finally:
            self._entry_mutation_lock.release()
        if route_stale:
            with self._state_lock:
                if key not in self._state["profiles"]:
                    self._profile_targets.pop(key, None)
                    self._profile_target_seen_at.pop(key, None)
            return False
        if push_error is not None:
            self.logger.warning(
                "Auto Prompt Harness guidance clearance failed: failure_class={}",
                type(push_error).__name__,
            )
        if was_cancelled:
            raise asyncio.CancelledError()
        return push_error is None

    # ------------------------------------------------------------------
    # Shared safe views and validation
    # ------------------------------------------------------------------

    @staticmethod
    def _effective_preference_values(
        state: dict[str, Any],
        key: str,
        *,
        at: float,
    ) -> dict[str, str]:
        settings = normalize_settings(state.get("settings"))
        profile = state.get("profiles", {}).get(key)
        if (
            not isinstance(profile, Mapping)
            or not bool(profile.get("enabled", True))
            or not settings["adaptation_enabled"]
            or not settings["injection_enabled"]
        ):
            return {}
        snapshot = profile_snapshot(state, key, at=at)
        return {
            str(item["dimension"]): str(item["value"])
            for item in snapshot["preferences"]
            if isinstance(item, Mapping)
            and item.get("dimension") in ALLOWED_VALUES
            and isinstance(item.get("value"), str)
        }

    @classmethod
    def _queued_guidance_would_be_invalidated(
        cls,
        before: dict[str, Any],
        after: dict[str, Any],
        key: str,
        *,
        at: float,
    ) -> bool:
        old_values = cls._effective_preference_values(before, key, at=at)
        if not old_values:
            return False
        new_values = cls._effective_preference_values(after, key, at=at)
        return any(new_values.get(name) != value for name, value in old_values.items())

    @staticmethod
    def _import_items_retained(
        state: Mapping[str, Any],
        key: str,
        imported_items: list[tuple[str, str, bool]],
    ) -> bool:
        profiles = state.get("profiles")
        profile = profiles.get(key) if isinstance(profiles, Mapping) else None
        manual = profile.get("manual") if isinstance(profile, Mapping) else None
        if not isinstance(manual, Mapping):
            return not imported_items
        return all(
            isinstance(manual.get(dimension), Mapping)
            and manual[dimension].get("value") == value
            and bool(manual[dimension].get("locked", False)) is locked
            for dimension, value, locked in imported_items
        )

    def _snapshot_for_key(self, key: str) -> dict[str, Any]:
        with self._state_lock:
            return profile_snapshot(self._state, key)

    def _panel_payload(self, key: str) -> dict[str, Any]:
        with self._state_lock:
            route_target = self._fresh_target_locked(key)
            route_verified = bool(route_target)
            route_collision = route_verified and self._target_collision_locked(
                key, route_target
            )
            snapshot = profile_snapshot(
                self._state,
                key,
                include_debug=True,
            )
            profile_options = []
            for profile_key_value, profile in self._state["profiles"].items():
                if not isinstance(profile, Mapping):
                    continue
                option_snapshot = profile_snapshot(
                    self._state,
                    profile_key_value,
                )
                profile_options.append(
                    {
                        "profile_id": profile_key_value,
                        "enabled": option_snapshot["enabled"],
                        "preference_count": option_snapshot["preference_count"],
                        "updated_at": option_snapshot["updated_at"],
                        "last_seen_at": option_snapshot["last_seen_at"],
                    }
                )
            profile_options.sort(
                key=lambda item: (
                    -float(item["last_seen_at"]),
                    str(item["profile_id"]),
                )
            )
            return {
                "status": (
                    "degraded"
                    if self._runtime_started and not self._store_ready
                    else ("running" if self._runtime_started else "stopped")
                ),
                "profile": snapshot,
                "selected_profile_id": (key if key in self._state["profiles"] else ""),
                "profiles": profile_options,
                "settings": copy.deepcopy(self._state["settings"]),
                "defaults": copy.deepcopy(DEFAULT_SETTINGS),
                "dimensions": {
                    dimension: list(values)
                    for dimension, values in ALLOWED_VALUES.items()
                },
                "recent_changes": copy.deepcopy(snapshot["recent_changes"]),
                "reflection_proposals": copy.deepcopy(
                    self._reflection_proposals.get(key, [])
                ),
                "aggregate_stats": copy.deepcopy(self._state["stats"]),
                "profile_count": len(self._state["profiles"]),
                "persistence_ready": self._store_ready,
                "route_verified": route_verified,
                "route_collision": route_collision,
                "observation": {
                    "message_handler_declared": True,
                    "message_handler_active": False,
                    "verified_memory_poll_active": bool(
                        self._runtime_started
                        and not self._stopping.is_set()
                        and (
                            not bool(getattr(self.store, "enabled", False))
                            or self._store_ready
                        )
                    ),
                    "memory_poll_fallback": True,
                    "poll_seconds": POLL_SECONDS,
                    "fallback_identity_scope": "local_character_only",
                    "conversation_scope_requires_payload_identity": True,
                },
                "privacy": {
                    "external_services": False,
                    "raw_messages_stored_by_default": False,
                    "debug_excerpts_enabled": bool(
                        self._state["settings"]["debug_excerpts"]
                    ),
                    "system_prompt_mutation": False,
                    "long_term_memory_api_mutation": False,
                    "host_conversation_history_may_retain_consumed_guidance": True,
                    "preview_is_guidance_body": True,
                },
            }

    @staticmethod
    def _validate_settings_input(raw: object) -> tuple[bool, str, dict[str, Any]]:
        if not isinstance(raw, Mapping):
            return False, "设置必须是对象。", {}
        unknown = set(raw) - set(DEFAULT_SETTINGS)
        if unknown:
            return False, "设置中包含未知字段。", {}
        for key in ("adaptation_enabled", "injection_enabled", "debug_excerpts"):
            if key in raw and not isinstance(raw[key], bool):
                return False, f"{key} 必须是布尔值。", {}
        if "sensitivity" in raw and raw["sensitivity"] not in {
            "conservative",
            "balanced",
            "responsive",
        }:
            return False, "推断灵敏度无效。", {}
        if "scope" in raw and raw["scope"] not in {"user", "conversation"}:
            return False, "档案范围无效。", {}
        numeric_limits = {
            "minimum_evidence": (1, 10),
            "minimum_confidence": (0.5, 0.95),
            "decay_days": (1, 365),
            "ttl_days": (7, 730),
            "cooldown_seconds": (0, 86400),
            "max_users": (1, 256),
            "max_preferences": (1, 16),
        }
        for key, (minimum, maximum) in numeric_limits.items():
            if key not in raw:
                continue
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False, f"{key} 必须是数字。", {}
            if (
                key
                in {
                    "minimum_evidence",
                    "decay_days",
                    "ttl_days",
                    "cooldown_seconds",
                    "max_users",
                    "max_preferences",
                }
                and not isinstance(value, int)
            ):
                return False, f"{key} 必须是整数。", {}
            try:
                numeric = float(value)
            except OverflowError:
                return False, f"{key} 超出允许范围。", {}
            if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
                return False, f"{key} 超出允许范围。", {}
        return True, "", dict(raw)

    @staticmethod
    def _parse_import_document(
        document: object,
    ) -> tuple[bool, str, list[tuple[str, str, bool]]]:
        if not isinstance(document, str) or len(document) < 2:
            return False, "导入文档大小无效。", []
        try:
            if len(document.encode("utf-8")) > 32768:
                return False, "导入文档大小无效。", []
        except UnicodeEncodeError:
            return False, "导入文档编码无效。", []
        try:
            payload = json.loads(document)
        except (ValueError, RecursionError):
            return False, "导入文档不是有效 JSON。", []
        if not isinstance(payload, Mapping):
            return False, "导入文档必须是 JSON 对象。", []
        allowed_top = {
            "schema_version",
            "exported_at",
            "profile",
            "settings",
            "aggregate_stats",
            "recent_changes",
            "privacy",
        }
        if set(payload) - allowed_top:
            return False, "导入文档包含不受支持的字段。", []
        version = payload.get("schema_version")
        if type(version) is not int or version != IMPORT_SCHEMA_VERSION:
            return False, "导入文档版本不受支持。", []
        profile = payload.get("profile")
        if not isinstance(profile, Mapping):
            return False, "导入文档缺少安全档案。", []
        allowed_profile = {
            "profile_id",
            "enabled",
            "adaptation_enabled",
            "injection_enabled",
            "preferences",
            "preference_count",
            "guidance",
            "guidance_fingerprint",
            "updated_at",
            "last_seen_at",
            "recent_changes",
        }
        if set(profile) - allowed_profile:
            return False, "导入档案包含不受支持的状态。", []
        preferences = profile.get("preferences")
        if not isinstance(preferences, list) or len(preferences) > 16:
            return False, "导入偏好列表无效或超过上限。", []
        allowed_preference = {
            "dimension",
            "value",
            "confidence",
            "evidence_count",
            "source_type",
            "locked",
            "updated_at",
        }
        imported: list[tuple[str, str, bool]] = []
        seen_dimensions: set[str] = set()
        for item in preferences:
            if not isinstance(item, Mapping) or set(item) - allowed_preference:
                return False, "导入偏好包含未知字段。", []
            dimension = item.get("dimension")
            value = item.get("value")
            locked = item.get("locked", False)
            if (
                not isinstance(dimension, str)
                or dimension not in ALLOWED_VALUES
                or dimension in seen_dimensions
                or not isinstance(value, str)
                or not isinstance(locked, bool)
            ):
                return False, "导入偏好的维度、值或锁定状态无效。", []
            if dimension == "note":
                note_ok, safe_note = validate_manual_note(value)
                if not note_ok:
                    return False, "导入的自定义备注不安全。", []
                value = safe_note
            elif value not in ALLOWED_VALUES[dimension]:
                return False, "导入偏好值不在固定枚举中。", []
            source_type = item.get("source_type")
            if source_type is not None and source_type not in {
                "manual",
                "inferred",
            }:
                return False, "导入偏好来源无效。", []
            seen_dimensions.add(dimension)
            imported.append((dimension, value, locked))
        return True, "", imported

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # LLM reflection (v0.2)
    # ------------------------------------------------------------------

    async def _call_reflection_model(self, messages: list[dict[str, str]]) -> str:
        """Call the host-configured agent model, mirroring study_companion."""

        try:
            import utils.config_manager as config_manager_module
            import utils.llm_client as llm_client_module
        except Exception as exc:
            raise SdkError("反思模型运行时不可用") from exc
        get_config_manager = getattr(config_manager_module, "get_config_manager", None)
        create_chat_llm_async = getattr(llm_client_module, "create_chat_llm_async", None)
        if not callable(get_config_manager) or not callable(create_chat_llm_async):
            raise SdkError("反思模型运行时不可用")
        api_config = get_config_manager().get_model_api_config("correction")
        if not str(api_config.get("base_url") or "").strip():
            api_config = get_config_manager().get_model_api_config("agent")
        base_url = str(api_config.get("base_url") or "").strip()
        model = str(api_config.get("model") or "").strip()
        api_key = str(api_config.get("api_key") or "").strip()
        if not base_url or not model:
            raise SdkError("未配置反思模型；请先在主设置里配置 agent/correction 模型")
        llm = await create_chat_llm_async(
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=0.2,
            timeout=30.0,
        )
        reply = await llm.ainvoke(messages)
        content = getattr(reply, "content", reply)
        if isinstance(content, list):
            content = " ".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content)
        return str(content or "")

    @plugin_entry(
        id="reflect_now",
        name="立即反思一次",
        description="用 LLM 对最近对话做一次结构化反思，生成可批准的 prompt 提案。",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        timeout=60.0,
    )
    async def reflect_now(self, **kwargs: Any):
        try:
            key = self._current_key(kwargs)
            with self._state_lock:
                buffer = list(self._reflection_buffers.get(key, []))
                profile = self._state["profiles"].get(key)
                preferences = profile_snapshot(self._state, key)["preferences"] if profile else []
                guidance = build_guidance(preferences)
            from . import reflection

            result = await reflection.reflect_once(
                self._call_reflection_model,
                buffer,
                guidance,
            )
            if result is None:
                return Ok({"reflected": False, "reason": "no_stable_preference_or_invalid_output"})
            proposal = result.to_store()
            proposal["id"] = f"ref-{int(result.created_at)}-{abs(hash(proposal['proposed_prompt'])) % 10_000:04d}"
            proposal["status"] = "pending"
            with self._state_lock:
                pending = self._reflection_proposals.setdefault(key, [])
                pending.append(proposal)
                del pending[:-20]
            await self._persist_state()
            return Ok({"reflected": True, "proposal": proposal})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("反思暂时失败，请稍后重试。", "reflect_failed")

    @plugin_entry(
        id="resolve_proposal",
        name="处理反思提案",
        description="批准、拒绝或回滚一条 LLM 反思生成的 prompt 提案。",
        input_schema={
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "action": {"type": "string", "enum": ["approve", "reject", "rollback"]},
                "edited_prompt": {"type": "string", "maxLength": 400},
            },
            "required": ["proposal_id", "action"],
            "additionalProperties": False,
        },
        timeout=15.0,
    )
    async def resolve_proposal(self, proposal_id: Any = None, action: Any = None, edited_prompt: Any = None, **kwargs: Any):
        try:
            key = self._current_key(kwargs)
            proposal_id = self._identity_text(proposal_id)
            action = self._identity_text(action)
            if not proposal_id or action not in {"approve", "reject", "rollback"}:
                raise SdkError("提案参数无效")
            with self._state_lock:
                pending = self._reflection_proposals.get(key, [])
                target = next((item for item in pending if item.get("id") == proposal_id), None)
                if target is None:
                    raise SdkError("提案不存在或已处理")
                if action == "reject":
                    target["status"] = "rejected"
                elif action == "rollback":
                    target["status"] = "rolled_back"
                    engine_delete_manual(self._state, key, dimension="note")
                else:
                    prompt = self._identity_text(edited_prompt)[:400] or target.get("proposed_prompt", "")
                    if not prompt:
                        raise SdkError("提案 prompt 为空")
                    from . import reflection as _reflection_mod

                    if any(pattern.search(prompt) for pattern in _reflection_mod._FORBIDDEN_PATTERNS):
                        raise SdkError("提案 prompt 包含不允许的内容")
                    engine_set_manual(self._state, key, dimension="note", value=prompt)
                    target["status"] = "active"
                    target["applied_prompt"] = prompt
            await self._persist_state()
            return Ok({"resolved": True, "proposal_id": proposal_id, "action": action})
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("提案处理失败。", "resolve_failed")

    # Scoped management entries and context-free model capability
    # ------------------------------------------------------------------

    @plugin_entry(
        id="inspect_profile",
        name="查看自适应偏好",
        description="查看当前范围内的偏好、置信度、证据计数和提示正文。",
        input_schema=PROFILE_REQUIRED_SCHEMA,
        llm_result_fields=[
            "enabled",
            "preferences",
            "preference_count",
            "guidance",
        ],
        timeout=15.0,
    )
    async def inspect_profile(self, **kwargs: Any):
        try:
            key = self._current_key(kwargs)
            snapshot = self._snapshot_for_key(key)
            return Ok(
                {
                    "enabled": snapshot["enabled"],
                    "preferences": snapshot["preferences"],
                    "preference_count": snapshot["preference_count"],
                    "guidance": snapshot["guidance"],
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("暂时无法读取自适应偏好。", "inspect_failed")

    @plugin_entry(
        id="set_manual_preference",
        name="保存手动偏好",
        description="添加、编辑或锁定当前范围的手动偏好。",
        input_schema=MANUAL_SCHEMA,
        llm_result_fields=["saved", "preference", "guidance"],
        timeout=15.0,
    )
    async def set_manual_preference(
        self,
        dimension: str,
        value: str,
        locked: bool = False,
        **kwargs: Any,
    ):
        try:
            if not isinstance(locked, bool):
                return _friendly_error(
                    "locked 必须是布尔值。",
                    "invalid_preference",
                )
            key, target_lanlan = self._current_scope(kwargs)
            comparison_at = time.time()
            with self._state_lock:
                before_state = copy.deepcopy(self._state)
                validation_state = copy.deepcopy(self._state)
            valid, message_text, _ = engine_set_manual(
                validation_state,
                key,
                dimension=dimension,
                value=value,
                locked=locked,
                at=comparison_at,
            )
            if not valid:
                return _friendly_error(message_text, "invalid_preference")
            requires_clearance = self._queued_guidance_would_be_invalidated(
                before_state,
                validation_state,
                key,
                at=comparison_at,
            )
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                with self._state_lock:
                    if key not in self._state["profiles"]:
                        return _friendly_error(
                            "所选档案不存在或已过期，请刷新管理面板后重试。",
                            "profile_not_found",
                        )
                    before_state = copy.deepcopy(self._state)
                    validation_state = copy.deepcopy(self._state)
                valid, message_text, _ = engine_set_manual(
                    validation_state,
                    key,
                    dimension=dimension,
                    value=value,
                    locked=locked,
                    at=comparison_at,
                )
                if not valid:
                    return _friendly_error(message_text, "invalid_preference")
                requires_clearance = self._queued_guidance_would_be_invalidated(
                    before_state,
                    validation_state,
                    key,
                    at=comparison_at,
                )
                if (
                    requires_clearance
                    and not await self._preclear_active_guidance_body(
                        key,
                        target_lanlan=target_lanlan,
                        reason="manual_preference_changed",
                    )
                ):
                    return _friendly_error(
                        "旧提示暂时无法安全清除；偏好未更改，请在真实聊天后重试。",
                        "clearance_failed",
                    )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        if key not in self._state["profiles"]:
                            return _friendly_error(
                                "所选档案不存在或已过期，请刷新管理面板后重试。",
                                "profile_not_found",
                            )
                        ok, message_text, preference = engine_set_manual(
                            self._state,
                            key,
                            dimension=dimension,
                            value=value,
                            locked=locked,
                        )
                        snapshot = profile_snapshot(self._state, key)
                    if not ok:
                        return _friendly_error(
                            message_text,
                            "invalid_preference",
                        )
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "偏好暂时无法保存，请稍后重试。",
                            "store_failed",
                        )
                finally:
                    self._entry_mutation_lock.release()
                await self._maybe_inject_body(
                    key,
                    target_lanlan=target_lanlan,
                )
                return Ok(
                    {
                        "saved": True,
                        "preference": preference,
                        "guidance": snapshot["guidance"],
                    }
                )
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("偏好暂时无法保存，请稍后重试。", "save_failed")

    @plugin_entry(
        id="delete_manual_preference",
        name="删除手动偏好",
        description="删除当前范围的一条手动偏好。",
        input_schema=DELETE_SCHEMA,
        llm_result_fields=["deleted", "dimension", "guidance"],
        timeout=15.0,
    )
    async def delete_manual_preference(self, dimension: str, **kwargs: Any):
        try:
            key, target_lanlan = self._current_scope(kwargs)
            with self._state_lock:
                validation_state = copy.deepcopy(self._state)
            valid, message_text = engine_delete_manual(
                validation_state,
                key,
                dimension=dimension,
            )
            if not valid:
                return _friendly_error(message_text, "preference_not_found")
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                if not await self._preclear_active_guidance_body(
                    key,
                    target_lanlan=target_lanlan,
                    reason="preference_deleted",
                ):
                    return _friendly_error(
                        "旧提示暂时无法安全清除；偏好未删除，请在真实聊天后重试。",
                        "clearance_failed",
                    )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        ok, message_text = engine_delete_manual(
                            self._state,
                            key,
                            dimension=dimension,
                        )
                        snapshot = profile_snapshot(self._state, key)
                    if not ok:
                        return _friendly_error(
                            message_text,
                            "preference_not_found",
                        )
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "删除结果暂时无法保存，请稍后重试。",
                            "store_failed",
                        )
                finally:
                    self._entry_mutation_lock.release()
                if snapshot["guidance"]:
                    await self._maybe_inject_body(
                        key,
                        target_lanlan=target_lanlan,
                    )
                return Ok(
                    {
                        "deleted": True,
                        "dimension": dimension,
                        "guidance": snapshot["guidance"],
                    }
                )
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("暂时无法删除这条偏好。", "delete_failed")

    @llm_tool(
        name="auto_prompt_harness.analyze_text",
        description="用本地确定性规则模拟分析一段文字，不保存文字或分析结果。",
        parameters=ANALYZE_SCHEMA,
        timeout=15.0,
    )
    @plugin_entry(
        id="analyze_text",
        name="模拟分析文本",
        description="仅在内存副本中模拟推断，不持久化。",
        input_schema=ANALYZE_SCHEMA,
        llm_result_fields=["persisted", "observations", "preferences", "guidance"],
        timeout=15.0,
    )
    async def analyze_text(self, text: str, **kwargs: Any):
        try:
            cleaned = sanitize_text(text)
            if not cleaned:
                return _friendly_error("示例文本不能为空。", "empty_text")
            observations = infer_observations(cleaned)
            # Generic tool arguments can forge ``_ctx`` in the current host.
            # Always simulate in a fresh state so this global tool cannot read
            # any persisted user's profile.
            del kwargs
            simulated = fresh_state()
            with self._state_lock:
                simulated["settings"] = copy.deepcopy(self._state["settings"])
            key = profile_key(
                simulated,
                user_id="isolated-simulation",
                conversation_id="isolated-simulation",
            )
            merge_observations(
                simulated,
                key,
                observations,
                text="",
            )
            snapshot = profile_snapshot(simulated, key)
            return Ok(
                {
                    "persisted": False,
                    "observations": [item.dump() for item in observations],
                    "preferences": snapshot["preferences"],
                    "guidance": snapshot["guidance"],
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("示例文本未能安全分析。", "analysis_failed")

    @plugin_entry(
        id="set_adaptation",
        name="暂停或恢复自适应",
        description="只影响当前范围，不删除已保存的偏好。",
        input_schema=ENABLE_SCHEMA,
        llm_result_fields=["enabled", "profile_id"],
        timeout=15.0,
    )
    async def set_adaptation(self, enabled: bool, **kwargs: Any):
        try:
            if not isinstance(enabled, bool):
                return _friendly_error("enabled 必须是布尔值。", "invalid_enabled")
            key, target_lanlan = self._current_scope(kwargs)
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                with self._state_lock:
                    if key not in self._state["profiles"]:
                        return _friendly_error(
                            "所选档案不存在或已过期，请刷新管理面板后重试。",
                            "profile_not_found",
                        )
                if not enabled and not await self._preclear_active_guidance_body(
                    key,
                    target_lanlan=target_lanlan,
                    reason="profile_paused",
                ):
                    return _friendly_error(
                        "旧提示暂时无法安全清除；自适应仍保持启用，请在真实聊天后重试。",
                        "clearance_failed",
                    )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        if key not in self._state["profiles"]:
                            return _friendly_error(
                                "所选档案不存在或已过期，请刷新管理面板后重试。",
                                "profile_not_found",
                            )
                        engine_set_enabled(self._state, key, enabled=enabled)
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "状态暂时无法保存，请稍后重试。",
                            "store_failed",
                        )
                finally:
                    self._entry_mutation_lock.release()
                if enabled:
                    await self._maybe_inject_body(
                        key,
                        target_lanlan=target_lanlan,
                    )
                return Ok({"enabled": enabled, "profile_id": key})
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("暂时无法更改自适应状态。", "adaptation_failed")

    @plugin_entry(
        id="export_profile",
        name="导出安全 JSON",
        description="导出当前档案、聚合统计与设置，不包含原始消息或身份。",
        input_schema=PROFILE_REQUIRED_SCHEMA,
        llm_result_fields=["profile", "privacy"],
        timeout=15.0,
    )
    async def export_profile(self, **kwargs: Any):
        try:
            key = self._current_key(kwargs)
            with self._state_lock:
                exported = safe_export(self._state, key)
            return Ok(
                {
                    "profile": exported["profile"],
                    "privacy": exported["privacy"],
                    "json": safe_json(exported),
                }
            )
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("当前档案暂时无法导出。", "export_failed")

    @plugin_entry(
        id="import_profile",
        name="导入安全 JSON",
        description="把本插件安全导出中的固定枚举偏好合并到明确选择的档案。",
        input_schema=IMPORT_SCHEMA,
        timeout=15.0,
    )
    async def import_profile(self, document: str, **kwargs: Any):
        valid, message_text, imported_items = self._parse_import_document(document)
        if not valid:
            return _friendly_error(message_text, "invalid_import")
        try:
            key, target_lanlan = self._current_scope(kwargs)
            if not imported_items:
                snapshot = self._snapshot_for_key(key)
                return Ok(
                    {
                        "imported": 0,
                        "profile_id": key,
                        "guidance": snapshot["guidance"],
                    }
                )
            comparison_at = time.time()
            with self._state_lock:
                before_state = copy.deepcopy(self._state)
                validation_state = copy.deepcopy(self._state)
            for dimension, value, locked in imported_items:
                item_ok, item_message, _ = engine_set_manual(
                    validation_state,
                    key,
                    dimension=dimension,
                    value=value,
                    locked=locked,
                    at=comparison_at,
                )
                if not item_ok:
                    return _friendly_error(item_message, "invalid_import")
            if not self._import_items_retained(
                validation_state,
                key,
                imported_items,
            ):
                return _friendly_error(
                    "导入偏好超过当前容量上限；文档未应用。",
                    "invalid_import",
                )
            requires_clearance = self._queued_guidance_would_be_invalidated(
                before_state,
                validation_state,
                key,
                at=comparison_at,
            )
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                with self._state_lock:
                    if key not in self._state["profiles"]:
                        return _friendly_error(
                            "所选档案不存在或已过期，请刷新管理面板后重试。",
                            "profile_not_found",
                        )
                    before_state = copy.deepcopy(self._state)
                    validation_state = copy.deepcopy(self._state)
                for dimension, value, locked in imported_items:
                    item_ok, item_message, _ = engine_set_manual(
                        validation_state,
                        key,
                        dimension=dimension,
                        value=value,
                        locked=locked,
                        at=comparison_at,
                    )
                    if not item_ok:
                        return _friendly_error(item_message, "invalid_import")
                if not self._import_items_retained(
                    validation_state,
                    key,
                    imported_items,
                ):
                    return _friendly_error(
                        "导入偏好超过当前容量上限；文档未应用。",
                        "invalid_import",
                    )
                requires_clearance = self._queued_guidance_would_be_invalidated(
                    before_state,
                    validation_state,
                    key,
                    at=comparison_at,
                )
                if (
                    requires_clearance
                    and not await self._preclear_active_guidance_body(
                        key,
                        target_lanlan=target_lanlan,
                        reason="profile_imported",
                    )
                ):
                    return _friendly_error(
                        "旧提示暂时无法安全清除；导入未应用，请在真实聊天后重试。",
                        "clearance_failed",
                    )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        if key not in self._state["profiles"]:
                            return _friendly_error(
                                "所选档案不存在或已过期，请刷新管理面板后重试。",
                                "profile_not_found",
                            )
                        for dimension, value, locked in imported_items:
                            item_ok, item_message, _ = engine_set_manual(
                                self._state,
                                key,
                                dimension=dimension,
                                value=value,
                                locked=locked,
                                at=comparison_at,
                            )
                            if not item_ok:
                                self._rollback_state(checkpoint)
                                return _friendly_error(
                                    item_message,
                                    "invalid_import",
                                )
                        if not self._import_items_retained(
                            self._state,
                            key,
                            imported_items,
                        ):
                            self._rollback_state(checkpoint)
                            return _friendly_error(
                                "导入偏好超过当前容量上限；文档未应用。",
                                "invalid_import",
                            )
                        snapshot = profile_snapshot(self._state, key)
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "导入结果暂时无法保存，请稍后重试。",
                            "store_failed",
                        )
                finally:
                    self._entry_mutation_lock.release()
                if imported_items:
                    await self._maybe_inject_body(
                        key,
                        target_lanlan=target_lanlan,
                    )
                return Ok(
                    {
                        "imported": len(imported_items),
                        "profile_id": key,
                        "guidance": snapshot["guidance"],
                    }
                )
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("当前档案暂时无法安全导入。", "import_failed")

    # ------------------------------------------------------------------
    # Panel-only state/settings/destructive actions
    # ------------------------------------------------------------------

    @plugin_entry(
        id="create_local_profile",
        name="创建本地猫娘档案",
        description="用本地猫娘名称创建可选择的伪匿名空档案；真实聊天出现前不建立推送路由。",
        input_schema=CREATE_PROFILE_SCHEMA,
        timeout=15.0,
    )
    async def create_local_profile(self, character: str, **_: Any):
        cleaned = sanitize_identity(character, limit=80)
        if (
            not cleaned
            or any(marker in cleaned for marker in ("\n", "\r", "[", "]", "<", ">"))
        ):
            return _friendly_error(
                "猫娘名称必须是 1–80 个字符的普通单行文本。",
                "invalid_character",
            )
        try:
            await self._acquire_thread_lock(self._entry_mutation_lock)
            try:
                with self._state_lock:
                    if self._state["settings"].get("scope") == "conversation":
                        return _friendly_error(
                            "当前宿主没有可信的会话标识；会话隔离范围不能创建合成档案。",
                            "scope_unavailable",
                        )
                checkpoint = self._state_checkpoint()
                with self._state_lock:
                    key = profile_key(
                        self._state,
                        user_id=f"local-character:{cleaned}",
                        conversation_id=f"lanlan:{cleaned}",
                        character_id=cleaned,
                    )
                    if key not in self._state["profiles"] and len(
                        self._state["profiles"]
                    ) >= int(self._state["settings"]["max_users"]):
                        return _friendly_error(
                            "偏好档案数量已达上限；请先导出并重置不再使用的档案。",
                            "profile_capacity",
                        )
                    ensure_profile(self._state, key)
                    enforce_bounds(self._state)
                    if key not in self._state["profiles"]:
                        self._rollback_state(checkpoint)
                        return _friendly_error(
                            "档案容量已被更高优先级的手动档案占满。",
                            "profile_capacity",
                        )
                if not await self._persist_or_rollback(checkpoint):
                    return _friendly_error(
                        "档案暂时无法保存，请稍后重试。",
                        "store_failed",
                    )
            finally:
                self._entry_mutation_lock.release()
            return Ok(
                {
                    "created": True,
                    "profile_id": key,
                    "route_verified": False,
                }
            )
        except Exception:
            return _friendly_error("暂时无法创建本地档案。", "profile_create_failed")

    @plugin_entry(
        id="get_panel_state",
        name="读取管理面板状态",
        description="读取面板需要的安全状态、设置、选项和提示预览。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
    )
    async def get_panel_state(self, **kwargs: Any):
        try:
            requested = self._identity_text(kwargs.get("profile_id"))
            key = self._current_key(kwargs) if requested else ""
            return Ok(self._panel_payload(key))
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("管理面板状态暂时不可用。", "panel_state_failed")

    @plugin_entry(
        id="save_settings",
        name="保存 Auto Prompt Harness 设置",
        description="验证并持久化面板设置。",
        input_schema=SAVE_SETTINGS_SCHEMA,
        timeout=15.0,
    )
    async def save_settings(self, settings: Mapping[str, Any], **kwargs: Any):
        try:
            ok, message_text, patch = self._validate_settings_input(settings)
            if not ok:
                return _friendly_error(message_text, "invalid_settings")
            with self._state_lock:
                current_scope_setting = str(self._state["settings"]["scope"])
                has_profiles = bool(self._state["profiles"])
            if (
                has_profiles
                and "scope" in patch
                and patch["scope"] != current_scope_setting
            ):
                return _friendly_error(
                    "已有档案时不能直接切换隔离范围；请先导出并重置现有档案。",
                    "scope_change_requires_reset",
                )
            self._current_scope(kwargs, require_unambiguous=False)
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                comparison_at = time.time()
                with self._state_lock:
                    self._prune_runtime_targets_locked()
                    before_keys = list(self._state["profiles"])
                    before_targets = {
                        profile_key_value: self._fresh_target_locked(
                            profile_key_value
                        )
                        for profile_key_value in before_keys
                    }
                    settings_changed = any(
                        self._state["settings"].get(name) != value
                        for name, value in patch.items()
                    )
                    before_state = copy.deepcopy(self._state)
                    prospective_state = copy.deepcopy(self._state)
                if settings_changed:
                    prospective_state["settings"] = normalize_settings(
                        {**prospective_state["settings"], **patch}
                    )
                    if not prospective_state["settings"]["debug_excerpts"]:
                        for profile in prospective_state["profiles"].values():
                            if isinstance(profile, dict):
                                profile["debug_excerpts"] = []
                    prune_expired_profiles(
                        prospective_state,
                        at=comparison_at,
                    )
                    affected_keys = [
                        profile_key_value
                        for profile_key_value in set(before_keys)
                        | set(prospective_state["profiles"])
                        if self._queued_guidance_would_be_invalidated(
                            copy.deepcopy(before_state),
                            copy.deepcopy(prospective_state),
                            profile_key_value,
                            at=comparison_at,
                        )
                    ]
                else:
                    affected_keys = []
                if settings_changed:
                    for affected_key in affected_keys:
                        if not await self._preclear_active_guidance_body(
                            affected_key,
                            target_lanlan=before_targets.get(affected_key, ""),
                            reason="settings_changed",
                        ):
                            return _friendly_error(
                                "旧提示暂时无法安全清除；设置未更改，请在各档案出现真实聊天后重试。",
                                "clearance_failed",
                            )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    with self._state_lock:
                        if (
                            self._state["profiles"]
                            and "scope" in patch
                            and patch["scope"] != self._state["settings"]["scope"]
                        ):
                            return _friendly_error(
                                "已有档案时不能直接切换隔离范围；请先导出并重置现有档案。",
                                "scope_change_requires_reset",
                            )
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        merged = {**self._state["settings"], **patch}
                        self._state["settings"] = normalize_settings(merged)
                        if not self._state["settings"]["debug_excerpts"]:
                            for profile in self._state["profiles"].values():
                                if isinstance(profile, dict):
                                    profile["debug_excerpts"] = []
                        if settings_changed:
                            prune_expired_profiles(
                                self._state,
                                at=comparison_at,
                            )
                        after_keys = list(self._state["profiles"])
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "设置暂时无法保存，请稍后重试。",
                            "store_failed",
                        )
                    with self._state_lock:
                        for removed_key in set(before_keys) - set(after_keys):
                            self._profile_targets.pop(removed_key, None)
                            self._profile_target_seen_at.pop(removed_key, None)
                        saved_settings = copy.deepcopy(self._state["settings"])
                finally:
                    self._entry_mutation_lock.release()
                if settings_changed:
                    for affected_key in after_keys:
                        with self._state_lock:
                            affected_profile = self._state["profiles"].get(
                                affected_key
                            )
                            target = self._fresh_target_locked(affected_key)
                            snapshot = (
                                profile_snapshot(self._state, affected_key)
                                if isinstance(affected_profile, Mapping)
                                else None
                            )
                            should_inject = bool(
                                isinstance(affected_profile, Mapping)
                                and snapshot
                                and saved_settings["adaptation_enabled"]
                                and saved_settings["injection_enabled"]
                                and affected_profile.get("enabled", True)
                                and snapshot["guidance"]
                            )
                        if should_inject:
                            await self._maybe_inject_body(
                                affected_key,
                                target_lanlan=target,
                            )
                return Ok(
                    {
                        "saved": True,
                        "settings": saved_settings,
                    }
                )
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("设置暂时无法保存。", "settings_failed")

    @plugin_entry(
        id="reset_settings",
        name="恢复默认设置",
        description="恢复内置默认设置，不删除偏好档案。",
        input_schema=EMPTY_SCHEMA,
        timeout=15.0,
    )
    async def reset_settings(self, **kwargs: Any):
        try:
            self._current_scope(kwargs, require_unambiguous=False)
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                comparison_at = time.time()
                with self._state_lock:
                    if (
                        self._state["profiles"]
                        and self._state["settings"]["scope"]
                        != DEFAULT_SETTINGS["scope"]
                    ):
                        return _friendly_error(
                            "恢复默认设置会改变现有档案的隔离范围；请先导出并重置现有档案。",
                            "scope_change_requires_reset",
                        )
                    self._prune_runtime_targets_locked()
                    before_keys = list(self._state["profiles"])
                    before_targets = {
                        profile_key_value: self._fresh_target_locked(
                            profile_key_value
                        )
                        for profile_key_value in before_keys
                    }
                    settings_changed = self._state["settings"] != DEFAULT_SETTINGS
                    before_state = copy.deepcopy(self._state)
                    prospective_state = copy.deepcopy(self._state)
                if settings_changed:
                    prospective_state["settings"] = copy.deepcopy(DEFAULT_SETTINGS)
                    for profile in prospective_state["profiles"].values():
                        if isinstance(profile, dict):
                            profile["debug_excerpts"] = []
                    enforce_bounds(prospective_state)
                    affected_keys = [
                        profile_key_value
                        for profile_key_value in set(before_keys)
                        | set(prospective_state["profiles"])
                        if self._queued_guidance_would_be_invalidated(
                            copy.deepcopy(before_state),
                            copy.deepcopy(prospective_state),
                            profile_key_value,
                            at=comparison_at,
                        )
                    ]
                else:
                    affected_keys = []
                if settings_changed:
                    for affected_key in affected_keys:
                        if not await self._preclear_active_guidance_body(
                            affected_key,
                            target_lanlan=before_targets.get(affected_key, ""),
                            reason="settings_reset",
                        ):
                            return _friendly_error(
                                "旧提示暂时无法安全清除；默认设置未恢复，请在各档案出现真实聊天后重试。",
                                "clearance_failed",
                            )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        self._state["settings"] = copy.deepcopy(DEFAULT_SETTINGS)
                        for profile in self._state["profiles"].values():
                            if isinstance(profile, dict):
                                profile["debug_excerpts"] = []
                        enforce_bounds(self._state)
                        affected_keys = list(self._state["profiles"])
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "默认设置暂时无法保存。",
                            "store_failed",
                        )
                    with self._state_lock:
                        for removed_key in set(before_keys) - set(affected_keys):
                            self._profile_targets.pop(removed_key, None)
                            self._profile_target_seen_at.pop(removed_key, None)
                finally:
                    self._entry_mutation_lock.release()
                if settings_changed:
                    for affected_key in affected_keys:
                        with self._state_lock:
                            affected_profile = self._state["profiles"].get(
                                affected_key
                            )
                            current_target = self._fresh_target_locked(affected_key)
                            snapshot = profile_snapshot(self._state, affected_key)
                            should_inject = bool(
                                isinstance(affected_profile, Mapping)
                                and affected_profile.get("enabled", True)
                                and snapshot["guidance"]
                            )
                        if should_inject:
                            await self._maybe_inject_body(
                                affected_key,
                                target_lanlan=current_target,
                            )
                return Ok(
                    {
                        "reset": True,
                        "settings": copy.deepcopy(DEFAULT_SETTINGS),
                    }
                    )
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("暂时无法恢复默认设置。", "reset_settings_failed")

    @plugin_entry(
        id="reset_profile",
        name="重置当前偏好档案",
        description="永久删除当前范围的档案；必须明确确认。该操作不是 LLM 工具。",
        input_schema=RESET_SCHEMA,
        timeout=15.0,
    )
    async def reset_profile(self, confirmation: str, **kwargs: Any):
        if confirmation != "RESET":
            return _friendly_error(
                "请输入 RESET 以确认重置当前档案。", "confirmation_required"
            )
        try:
            key, target_lanlan = self._current_scope(kwargs)
            await self._acquire_thread_lock(self._delivery_guard)
            try:
                if not await self._preclear_active_guidance_body(
                    key,
                    target_lanlan=target_lanlan,
                    reason="profile_reset",
                ):
                    return _friendly_error(
                        "旧提示暂时无法安全清除；档案未重置，请在真实聊天后重试。",
                        "clearance_failed",
                    )
                await self._acquire_thread_lock(self._entry_mutation_lock)
                try:
                    checkpoint = self._state_checkpoint()
                    with self._state_lock:
                        existed = self._state["profiles"].pop(key, None) is not None
                        if self._state.get("last_active_profile") == key:
                            self._state["last_active_profile"] = ""
                    if not await self._persist_or_rollback(checkpoint):
                        return _friendly_error(
                            "重置结果暂时无法保存，请稍后重试。",
                            "store_failed",
                        )
                    self._recent_route_digests.clear()
                    if existed:
                        with self._state_lock:
                            self._profile_targets.pop(key, None)
                            self._profile_target_seen_at.pop(key, None)
                finally:
                    self._entry_mutation_lock.release()
                return Ok({"reset": existed, "profile_id": key})
            finally:
                self._delivery_guard.release()
        except SdkError as exc:
            return Err(exc)
        except Exception:
            return _friendly_error("当前档案暂时无法重置。", "reset_profile_failed")


__all__ = ["AutoPromptHarnessPlugin", "PLUGIN_ID"]
