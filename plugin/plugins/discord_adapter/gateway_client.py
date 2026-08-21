"""Discord Gateway WebSocket client (minimal, no zlib, no sharding).

Protocol: Hello(op10) -> heartbeat loop(op1) -> Identify(op2) -> READY dispatch
-> MESSAGE_CREATE dispatch. Resume(op6) on reconnect; re-Identify on
InvalidSession(op9, resumable=false). Exponential backoff with a hard cap.

Host dependency: websockets ~=15.0.1 (declared in pyproject.toml).
"""

from __future__ import annotations

import asyncio
import json
import random
import sys
from typing import Any, Awaitable, Callable, Optional

import websockets

GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"

# GUILDS(1) | GUILD_MESSAGES(512) | DIRECT_MESSAGES(4096) | MESSAGE_CONTENT(32768)
INTENTS = 1 | 512 | 4096 | 32768  # = 37889

OP_DISPATCH = 0
OP_HEARTBEAT = 1
OP_IDENTIFY = 2
OP_RESUME = 6
OP_RECONNECT = 7
OP_INVALID_SESSION = 9
OP_HELLO = 10
OP_HEARTBEAT_ACK = 11


class DiscordGatewayClient:
    """Minimal Discord Gateway client.

    Args:
        token: Bot token.
        on_message_create: Async callback receiving the raw MESSAGE_CREATE
            payload dict.
        on_ready: Async callback receiving the READY payload dict.
        on_state_change: Async callback receiving (state, error) where state is
            one of 'connected' / 'reconnecting' / 'max_retries' / 'closed'.
        reconnect_backoff_seconds: Initial reconnect backoff seconds.
        max_reconnect_attempts: Max consecutive reconnect attempts before giving
            up (reported via on_state_change('max_retries', ...)).
        logger: Logger with info/warning/error methods.
    """

    def __init__(
        self,
        token: str,
        *,
        on_message_create: Callable[[dict[str, Any]], Awaitable[None]],
        on_ready: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
        on_state_change: Optional[Callable[[str, str], Awaitable[None]]] = None,
        reconnect_backoff_seconds: float = 3.0,
        max_reconnect_attempts: int = 5,
        logger: Any = None,
    ):
        self._token = token
        self._on_message_create = on_message_create
        self._on_ready = on_ready
        self._on_state_change = on_state_change
        self._backoff_base = reconnect_backoff_seconds
        self._max_attempts = max_reconnect_attempts
        self._logger = logger

        self._ws: Any = None
        self._seq: Optional[int] = None
        self._session_id: Optional[str] = None
        self._resume_url: Optional[str] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._run_task: Optional[asyncio.Task] = None
        self._closing = False
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def _log(self, level: str, msg: str) -> None:
        if self._logger is not None:
            getattr(self._logger, level, self._logger.info)(f"[DiscordGateway] {msg}")

    async def start(self) -> None:
        """Spawn the connection supervisor task (non-blocking)."""
        self._closing = False
        self._run_task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        """Close the connection and stop the supervisor."""
        self._closing = True
        task, self._run_task = self._run_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self._close_ws()

    async def _close_ws(self) -> None:
        hb, self._heartbeat_task = self._heartbeat_task, None
        if hb is not None:
            hb.cancel()
            try:
                await hb
            except (asyncio.CancelledError, Exception):
                pass
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        self._connected = False

    async def _run_loop(self) -> None:
        attempts = 0
        while not self._closing:
            try:
                await self._connect_once()
                attempts = 0  # Clean session ended; reset backoff.
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._log("warning", f"Gateway connection error: {type(e).__name__}: {e}")
            finally:
                await self._close_ws()

            if self._closing:
                break
            attempts += 1
            if attempts > self._max_attempts:
                self._log("error", "Max reconnect attempts reached; giving up")
                await self._emit_state("max_retries", "max reconnect attempts reached")
                break
            await self._emit_state("reconnecting", "")
            delay = min(self._backoff_base * attempts, 30.0) + random.uniform(0, 1)
            self._log("info", f"Reconnecting in {delay:.1f}s (attempt {attempts})")
            await asyncio.sleep(delay)

    async def _emit_state(self, state: str, error: str) -> None:
        if self._on_state_change is None:
            return
        try:
            await self._on_state_change(state, error)
        except Exception:
            pass

    async def _connect_once(self) -> None:
        url = self._resume_url if (self._session_id and self._resume_url) else GATEWAY_URL
        async with websockets.connect(url, max_size=16 * 1024 * 1024) as ws:
            self._ws = ws
            # --- Hello ---
            hello = await self._recv(ws)
            if hello.get("op") != OP_HELLO:
                raise RuntimeError(f"Expected Hello, got op={hello.get('op')}")
            interval_ms = float(hello["d"]["heartbeat_interval"])
            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(ws, interval_ms / 1000.0)
            )
            # --- Identify or Resume ---
            if self._session_id and self._seq is not None:
                await self._send(ws, OP_RESUME, {
                    "token": self._token,
                    "session_id": self._session_id,
                    "seq": self._seq,
                })
                self._log("info", "Sent Resume")
            else:
                await self._send(ws, OP_IDENTIFY, {
                    "token": self._token,
                    "intents": INTENTS,
                    "properties": {
                        "os": sys.platform,
                        "browser": "N.E.K.O",
                        "device": "N.E.K.O",
                    },
                })
                self._log("info", "Sent Identify")
            # --- Event loop ---
            await self._event_loop(ws)

    async def _event_loop(self, ws: Any) -> None:
        async for raw in ws:
            payload = json.loads(raw)
            op = payload.get("op")
            if op == OP_DISPATCH:
                seq = payload.get("s")
                if seq is not None:
                    self._seq = seq
                event_type = payload.get("t")
                data = payload.get("d") or {}
                if event_type == "READY":
                    self._session_id = data.get("session_id")
                    self._resume_url = data.get("resume_gateway_url")
                    self._connected = True
                    self._log("info", "Gateway READY")
                    await self._emit_state("connected", "")
                    if self._on_ready is not None:
                        asyncio.create_task(self._safe_callback(self._on_ready, data))
                elif event_type == "MESSAGE_CREATE":
                    asyncio.create_task(self._safe_callback(self._on_message_create, data))
            elif op == OP_HEARTBEAT:
                await self._send(ws, OP_HEARTBEAT, self._seq)
            elif op == OP_HEARTBEAT_ACK:
                pass
            elif op == OP_RECONNECT:
                self._log("info", "Server requested reconnect")
                return
            elif op == OP_INVALID_SESSION:
                resumable = bool(payload.get("d"))
                if not resumable:
                    self._log("warning", "Invalid session (not resumable); re-Identify")
                    self._session_id = None
                    self._seq = None
                    self._resume_url = None
                else:
                    self._log("warning", "Invalid session (resumable)")
                await asyncio.sleep(random.uniform(1.0, 5.0))
                return
            else:
                self._log("warning", f"Unknown gateway op: {op}")

    async def _safe_callback(self, cb: Callable[[dict], Awaitable[None]], data: dict) -> None:
        try:
            await cb(data)
        except Exception as e:
            self._log("error", f"Event callback error: {type(e).__name__}: {e}")

    async def _heartbeat_loop(self, ws: Any, interval: float) -> None:
        # First heartbeat with jitter per Discord docs.
        await asyncio.sleep(interval * random.random())
        while True:
            try:
                await self._send(ws, OP_HEARTBEAT, self._seq)
            except Exception:
                return
            await asyncio.sleep(interval)

    async def _send(self, ws: Any, op: int, data: Any) -> None:
        await ws.send(json.dumps({"op": op, "d": data}))

    @staticmethod
    async def _recv(ws: Any) -> dict[str, Any]:
        raw = await ws.recv()
        return json.loads(raw)

    # --- Testable pure helpers ---

    @staticmethod
    def build_identify_payload(token: str) -> dict[str, Any]:
        """Build the Identify payload (op 2)."""
        return {
            "op": OP_IDENTIFY,
            "d": {
                "token": token,
                "intents": INTENTS,
                "properties": {
                    "os": sys.platform,
                    "browser": "N.E.K.O",
                    "device": "N.E.K.O",
                },
            },
        }

    @staticmethod
    def build_resume_payload(token: str, session_id: str, seq: int) -> dict[str, Any]:
        """Build the Resume payload (op 6)."""
        return {
            "op": OP_RESUME,
            "d": {"token": token, "session_id": session_id, "seq": seq},
        }
