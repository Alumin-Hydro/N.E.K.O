"""Inbound attachment pipeline for the Discord adapter plugin.

Classifies Discord attachments by content type, enforces the size/count
gates and bridges supported payloads into the AI session: images become
base64 blobs (or a link placeholder above the inline limit), documents go
through ``utils.document_parser.parse_document`` and everything else falls
back to a placeholder line.
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass, field
from typing import Any

from .rest_client import AttachmentDownloadError

# Images larger than this are not inlined into the AI session (ZMQ inline
# ceiling); they degrade to a link placeholder instead.
MAX_INLINE_IMAGE_BYTES = 256 * 1024

TEXT_EXTENSIONS = {".md", ".markdown", ".html", ".htm", ".txt"}
BINARY_DOCUMENT_EXTENSIONS = {".pdf", ".pptx", ".docx", ".xlsx"}
DOCUMENT_EXTENSIONS = TEXT_EXTENSIONS | BINARY_DOCUMENT_EXTENSIONS

_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass
class ProcessedAttachments:
    """Result of processing the attachments of one Discord message."""

    text_blocks: list[str] = field(default_factory=list)
    images_b64: list[str] = field(default_factory=list)


def classify_attachment(filename: str, content_type: str) -> str:
    """Classify an attachment into ``image`` / ``document`` / ``other``."""
    mime = str(content_type or "").strip().lower()
    if mime.startswith("image/"):
        return "image"
    lower_name = str(filename or "").strip().lower()
    suffix = ""
    if "." in lower_name:
        suffix = "." + lower_name.rsplit(".", 1)[-1]
    if suffix in DOCUMENT_EXTENSIONS:
        return "document"
    return "other"


def decode_text_document(data: bytes, filename: str) -> str:
    """Best-effort decode for plain text-like documents (md/txt/html)."""
    text = data.decode("utf-8", "replace")
    if str(filename or "").lower().endswith((".html", ".htm")):
        text = _TAG_RE.sub(" ", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def build_document_block(filename: str, content: str) -> str:
    return f"[用户发送了文件 {filename}，内容：\n{content}]"


def build_document_error_block(filename: str, reason: str) -> str:
    return f"[文件 {filename} 解析失败：{reason}]"


def build_attachment_placeholder(filename: str, content_type: str) -> str:
    label = str(content_type or "").strip() or "unknown"
    return f"[附件 {filename} ({label})]"


def build_image_link_block(filename: str, url: str) -> str:
    return f"[用户发送了一张图片 {filename}，链接：{url}]"


async def extract_document_text(filename: str, content_type: str, data: bytes) -> str:
    """Parse a document payload into a chat-ready text block.

    Text-like formats are decoded directly; pdf/office formats go through
    ``utils.document_parser.parse_document`` off the event loop thread.
    Failures produce a failure block instead of raising.
    """
    lower_name = str(filename or "").lower()
    try:
        if lower_name.endswith(tuple(TEXT_EXTENSIONS)):
            text = decode_text_document(data, filename)
            if not text:
                return build_document_error_block(filename, "no_readable_text")
            return build_document_block(filename, text)
        from utils.document_parser import parse_document

        parsed = await asyncio.to_thread(parse_document, filename, content_type, data)
        content = str(parsed.get("content") or "").strip()
        if not content:
            return build_document_error_block(filename, "no_readable_text")
        return build_document_block(filename, content)
    except Exception as exc:
        reason = getattr(exc, "code", None) or type(exc).__name__
        return build_document_error_block(filename, str(reason))


class AttachmentProcessor:
    """Downloads and converts Discord attachments for the AI pipeline."""

    def __init__(
        self,
        rest_client: Any,
        *,
        max_attachment_bytes: int = 10 * 1024 * 1024,
        max_total_attachment_bytes: int = 20 * 1024 * 1024,
        max_attachments_per_message: int = 3,
        logger: Any = None,
    ):
        self._rest = rest_client
        self._max_attachment_bytes = max(1, int(max_attachment_bytes))
        self._max_total_attachment_bytes = max(1, int(max_total_attachment_bytes))
        self._max_attachments_per_message = max(0, int(max_attachments_per_message))
        self._logger = logger

    async def process(self, attachments: list[dict[str, Any]]) -> ProcessedAttachments:
        """Process every attachment of one message into text blocks/images."""
        result = ProcessedAttachments()
        if not attachments:
            return result

        total_budget = self._max_total_attachment_bytes
        for attachment in attachments[: self._max_attachments_per_message]:
            filename = str(attachment.get("filename") or "attachment")
            content_type = str(attachment.get("content_type") or "")
            url = str(attachment.get("url") or "")
            declared_size = int(attachment.get("size") or 0)
            kind = classify_attachment(filename, content_type)

            if kind == "other":
                result.text_blocks.append(
                    build_attachment_placeholder(filename, content_type)
                )
                continue

            if kind == "image" and declared_size > MAX_INLINE_IMAGE_BYTES:
                result.text_blocks.append(build_image_link_block(filename, url))
                continue

            if (
                declared_size > self._max_attachment_bytes
                or declared_size > total_budget
            ):
                result.text_blocks.append(
                    build_attachment_placeholder(filename, content_type)
                )
                continue

            try:
                data = await self._rest.download_attachment(
                    url, min(self._max_attachment_bytes, total_budget)
                )
            except AttachmentDownloadError as exc:
                self._log("warning", f"attachment rejected: {filename}: {exc}")
                result.text_blocks.append(
                    build_attachment_placeholder(filename, content_type)
                )
                continue
            except Exception as exc:
                self._log(
                    "warning",
                    f"attachment download failed: {filename}: {type(exc).__name__}",
                )
                result.text_blocks.append(
                    build_attachment_placeholder(filename, content_type)
                )
                continue

            total_budget -= len(data)
            if kind == "image":
                if len(data) > MAX_INLINE_IMAGE_BYTES:
                    result.text_blocks.append(build_image_link_block(filename, url))
                else:
                    result.images_b64.append(base64.b64encode(data).decode("ascii"))
            else:
                result.text_blocks.append(
                    await extract_document_text(filename, content_type, data)
                )

        overflow = len(attachments) - self._max_attachments_per_message
        if overflow > 0:
            result.text_blocks.append(
                f"[还有 {overflow} 个附件未处理（超出数量上限）]"
            )
        return result

    def _log(self, level: str, message: str) -> None:
        logger = self._logger
        if logger is None:
            return
        log_fn = getattr(logger, level, None)
        if callable(log_fn):
            log_fn(f"[DiscordAttachment] {message}")
