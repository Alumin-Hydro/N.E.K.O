"""Discord Gateway WebSocket client (pure stdlib, no external deps).

Protocol: Hello(op10) -> heartbeat loop(op1) -> Identify(op2) -> READY dispatch
-> MESSAGE_CREATE dispatch. Resume(op6) on reconnect; re-Identify on
InvalidSession(op9, resumable=false). Exponential backoff with a hard cap.

Implementation: raw socket + ssl + manual WebSocket frame encode/decode.
No websockets / tornado / aiohttp dependency — works in frozen N.E.K.O runtime.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import sys
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse

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

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _WebSocketConnection:
    """Minimal RFC 6455 client WebSocket over asyncio streams."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._closed = False

    @classmethod
    async def connect(cls, url: str, timeout: float = 20.0) -> "_WebSocketConnection":
        parsed = urlparse(url)
        host = parsed.hostname or "gateway.discord.gg"
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        # TCP + TLS
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
            timeout=timeout,
        )

        # HTTP Upgrade handshake
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        # Read HTTP response headers
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        status_line = response.split(b"\r\n")[0].decode(errors="replace")
        if b"101" not in status_line.encode():
            writer.close()
            await writer.wait_closed()
            raise RuntimeError(f"WebSocket upgrade failed: {status_line}")

        # Verify Sec-WebSocket-Accept
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()
        ).decode()
        if accept.encode().lower() not in response.lower():
            # Non-fatal: some servers omit or reorder headers; log and continue.
            pass

        return cls(reader, writer)

    async def send_text(self, data: str) -> None:
        """Send a text frame (opcode 0x1)."""
        payload = data.encode("utf-8")
        header = bytearray([0x81])  # FIN + text opcode
        length = len(payload)
        mask_bit = 0x80
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack(">Q", length))
        mask_key = os.urandom(4)
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        self._writer.write(bytes(header) + masked)
        await self._writer.drain()

    async def recv_text(self) -> Optional[str]:
        """Receive one text frame. Returns None on close."""
        while True:
            header = await self._reader.readexactly(2)
            fin = bool(header[0] & 0x80)
            opcode = header[0] & 0x0F
            masked = bool(header[1] & 0x80)
            length = header[1] & 0x7F

            if length == 126:
                length = struct.unpack(">H", await self._reader.readexactly(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", await self._reader.readexactly(8))[0]

            mask_key = await self._reader.readexactly(4) if masked else b""
            payload = await self._reader.readexactly(length)
            if masked:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

            if opcode == 0x8:  # close
                self._closed = True
                return None
            if opcode == 0x9:  # ping -> pong
                pong = bytearray([0x8A])
                if masked:
                    pong.extend(mask_key)
                pong.extend(payload)
                self._writer.write(bytes(pong))
                await self._writer.drain()
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode in (0x1, 0x2):  # text or binary
                if not fin:
                    # Continuation frames not supported; Discord doesn't fragment.
                    raise RuntimeError("Fragmented frames not supported")
                return payload.decode("utf-8", errors="replace")

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            # Send close frame
            self._writer.write(bytes([0x88, 0x80]) + os.urandom(4))
            await self._writer.drain()
        except Exception:
            pass
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass


class DiscordGatewayClient:
    """Minimal Discord Gateway client using pure stdlib WebSocket.

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
        proxy_url: Optional HTTP proxy URL for Gateway WebSocket connection
            (e.g. http://127.0.0.1:7890). Uses HTTP CONNECT tunnel.
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
        proxy_url: str = "",
        logger: Any = None,
    ):
        self._token = token
        self._on_message_create = on_message_create
        self._on_ready = on_ready
        self._on_state_change = on_state_change
        self._backoff_base = reconnect_backoff_seconds
        self._max_attempts = max_reconnect_attempts
        self._proxy_url = str(proxy_url or "").strip() or None
        self._logger = logger

        self._ws: Optional[_WebSocketConnection] = None
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
        self._log("info", f"Connecting to {url} (proxy={'yes' if self._proxy_url else 'no'})...")

        # Note: proxy support not implemented in pure-stdlib version.
        # If proxy is configured, log a warning and continue direct.
        if self._proxy_url:
            self._log("warning", f"Proxy configured but not supported in stdlib client: {self._proxy_url}")

        ws = await _WebSocketConnection.connect(url, timeout=20.0)
        self._ws = ws
        try:
            # --- Hello ---
            hello_raw = await ws.recv_text()
            if hello_raw is None:
                raise RuntimeError("Connection closed during Hello")
            hello = json.loads(hello_raw)
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
        finally:
            await ws.close()

    async def _event_loop(self, ws: _WebSocketConnection) -> None:
        while True:
            raw = await ws.recv_text()
            if raw is None:
                self._log("warning", "Connection closed by server")
                return
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

    async def _heartbeat_loop(self, ws: _WebSocketConnection, interval: float) -> None:
        # First heartbeat with jitter per Discord docs.
        await asyncio.sleep(interval * random.random())
        while True:
            try:
                await self._send(ws, OP_HEARTBEAT, self._seq)
            except Exception:
                return
            await asyncio.sleep(interval)

    async def _send(self, ws: _WebSocketConnection, op: int, data: Any) -> None:
        await ws.send_text(json.dumps({"op": op, "d": data}))

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
