"""Discord REST API client (minimal surface for the adapter plugin).

Covers: GET /users/@me, GET /gateway/bot, POST /channels/{id}/messages,
and attachment downloading with domain whitelist + size gates.
Uses httpx (host-provided dependency). Frozen-runtime safe.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx

API_BASE = "https://discord.com/api/v10"

ALLOWED_CDN_HOSTS = {"cdn.discordapp.com", "media.discordapp.net"}


class DiscordRestError(Exception):
    """Discord REST error with optional retry_after from 429 responses."""

    def __init__(self, message: str, *, status: int = 0, retry_after: float = 0.0):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class AttachmentDownloadError(DiscordRestError):
    """Attachment rejected by the domain whitelist or the size gate."""


class DiscordRestClient:
    """Minimal Discord REST client.

    Args:
        token: Bot token (never logged).
        proxy_url: Optional HTTP/SOCKS proxy URL for API requests.
        logger: Optional logger for diagnostics.
        timeout: Default request timeout seconds.
    """

    def __init__(
        self,
        token: str,
        *,
        proxy_url: str = "",
        logger: Any = None,
        timeout: float = 15.0,
    ):
        self._token = token
        self._proxy_url = str(proxy_url or "").strip() or None
        self._logger = logger
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._client_loop: Optional[asyncio.AbstractEventLoop] = None

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bot {self._token}",
            "User-Agent": "N.E.K.O-DiscordAdapter/0.1 (+https://github.com/Project-N-E-K-O/N.E.K.O)",
            "Content-Type": "application/json",
        }

    def _get_client(self) -> httpx.AsyncClient:
        # Host runs startup / command loop / shutdown in separate asyncio.run()
        # loops; a connection pool is bound to the loop that created it.
        loop = asyncio.get_running_loop()
        if (
            self._client is None
            or self._client.is_closed
            or self._client_loop is not loop
        ):
            self._client = httpx.AsyncClient(
                base_url=API_BASE,
                headers=self._headers(),
                timeout=self._timeout,
                follow_redirects=True,
                proxy=self._proxy_url,
            )
            self._client_loop = loop
        return self._client

    async def aclose(self) -> None:
        client, self._client = self._client, None
        if client is not None and not client.is_closed:
            try:
                await client.aclose()
            except Exception:
                pass  # Cross-loop close may fail; process is exiting anyway.

    async def _request(
        self, method: str, path: str, *, json_body: Any = None, _retried: bool = False
    ) -> Any:
        client = self._get_client()
        resp = await client.request(method, path, json=json_body)
        if resp.status_code == 429 and not _retried:
            try:
                data = resp.json()
                retry_after = float(data.get("retry_after", 1.0))
            except Exception:
                retry_after = 1.0
            await asyncio.sleep(min(retry_after, 30.0))
            return await self._request(method, path, json_body=json_body, _retried=True)
        if resp.status_code >= 400:
            retry_after = 0.0
            try:
                data = resp.json()
                retry_after = float(data.get("retry_after", 0.0) or 0.0)
            except Exception:
                pass
            raise DiscordRestError(
                f"Discord API {method} {path} failed: HTTP {resp.status_code}",
                status=resp.status_code,
                retry_after=retry_after,
            )
        if resp.status_code == 204:
            return None
        return resp.json()

    async def get_me(self) -> dict[str, Any]:
        """Return the bot user object (id, username, ...)."""
        return await self._request("GET", "/users/@me")

    async def get_gateway_bot(self) -> dict[str, Any]:
        """Return gateway URL + session start limits."""
        return await self._request("GET", "/gateway/bot")

    async def create_message(
        self,
        channel_id: str,
        content: str = "",
        *,
        embeds: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Send a message. content must be <= 2000 chars (caller splits)."""
        body: dict[str, Any] = {"content": content}
        if embeds:
            body["embeds"] = embeds
        return await self._request("POST", f"/channels/{channel_id}/messages", json_body=body)

    async def create_message_with_attachment(
        self,
        channel_id: str,
        content: str = "",
        *,
        file_bytes: bytes = b"",
        filename: str = "image.png",
        content_type: str = "image/png",
    ) -> dict[str, Any]:
        """Send a message with a single file attachment (multipart/form-data).

        Args:
            channel_id: Target channel ID.
            content: Optional text content (<= 2000 chars).
            file_bytes: Raw file bytes.
            filename: Display filename.
            content_type: MIME type (e.g. image/png, image/jpeg).
        """
        import json as _json

        boundary = "----NekoDiscordBoundary"
        payload_json = _json.dumps({"content": content})

        # Build multipart body manually (httpx multipart is fine too, but
        # manual gives us exact control over the payload_json field name).
        lines: list[bytes] = []
        # payload_json part
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(
            b'Content-Disposition: form-data; name="payload_json"\r\n'
            b"Content-Type: application/json\r\n\r\n"
        )
        lines.append(payload_json.encode())
        lines.append(b"\r\n")
        # files[0] part
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(
            f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n".encode()
        )
        lines.append(file_bytes)
        lines.append(b"\r\n")
        lines.append(f"--{boundary}--\r\n".encode())

        body_bytes = b"".join(lines)
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }

        client = self._get_client()
        resp = await client.post(
            f"/channels/{channel_id}/messages",
            content=body_bytes,
            headers=headers,
        )
        if resp.status_code >= 400:
            raise DiscordRestError(
                f"Discord API POST /channels/{channel_id}/messages failed: HTTP {resp.status_code}",
                status=resp.status_code,
            )
        return resp.json()

    async def download_attachment(
        self, url: str, max_bytes: int = 10 * 1024 * 1024
    ) -> bytes:
        """Download an attachment from the Discord CDN only.

        Args:
            url: Attachment URL; must be on an allowed CDN host.
            max_bytes: Hard size cap; raises AttachmentDownloadError when exceeded.

        Returns:
            The raw attachment bytes.
        """
        from urllib.parse import urlparse

        host = urlparse(str(url or "")).hostname or ""
        if host not in ALLOWED_CDN_HOSTS:
            raise AttachmentDownloadError(f"Attachment host not allowed: {host}")
        client = self._get_client()
        # CDN URLs are pre-signed; no auth header needed, but harmless.
        async with client.stream(
            "GET", url, headers={"User-Agent": "N.E.K.O-DiscordAdapter/0.1"}
        ) as resp:
            if resp.status_code >= 400:
                raise AttachmentDownloadError(
                    f"Attachment download failed: HTTP {resp.status_code}",
                    status=resp.status_code,
                )
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes(65536):
                total += len(chunk)
                if total > max_bytes:
                    raise AttachmentDownloadError("Attachment exceeds size limit")
                chunks.append(chunk)
        return b"".join(chunks)
