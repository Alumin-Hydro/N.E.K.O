from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(slots=True)
class DiscordMemoryQueryResult:
    text: str = ""
    hit_count: int = 0
    elapsed_ms: float = 0.0
    raw_results: list[dict[str, Any]] = field(default_factory=list)


class DiscordMemoryBridge:
    """Discord 插件侧的长期记忆桥。

    封装 memory_server 的三个端点：
    - GET  /new_dialog/{her_name}   → 拉取 system prompt 用的长期记忆文本
    - POST /process/{her_name}      → 推送对话摘要（input_history）
    - POST /query_memory/{her_name} → 语义检索（recall_memory 工具用）

    每个调用独立建 httpx.AsyncClient（与 QQ 旧版 memory_bridge 一致），
    timeout 默认 5s，proxy=None 避免走系统代理到 127.0.0.1。
    """

    def __init__(self, plugin: Any):
        self.plugin = plugin

    @staticmethod
    def _base_url() -> str:
        return "http://127.0.0.1:48912"

    async def fetch_bootstrap_memory(
        self,
        her_name: str,
        *,
        timeout: float = 5.0,
    ) -> str:
        """GET /new_dialog/{her_name} → system prompt 用的长期记忆文本。"""
        async with httpx.AsyncClient(
            timeout=timeout, proxy=None, trust_env=False
        ) as client:
            response = await client.get(f"{self._base_url()}/new_dialog/{her_name}")
            response.raise_for_status()
            return response.text.strip()

    async def query_relevant_memory(
        self,
        her_name: str,
        query: str,
        *,
        timeout: float = 5.0,
        limit: int = 5,
    ) -> DiscordMemoryQueryResult:
        """POST /query_memory/{her_name} → 语义检索记忆条目并渲染。"""
        normalized_query = str(query or "").strip()
        if not normalized_query:
            return DiscordMemoryQueryResult()
        async with httpx.AsyncClient(
            timeout=timeout, proxy=None, trust_env=False
        ) as client:
            response = await client.post(
                f"{self._base_url()}/query_memory/{her_name}",
                json={"query": normalized_query},
            )
            response.raise_for_status()
            payload = response.json()
        results = payload.get("results") if isinstance(payload, dict) else None
        memory_items = (
            [item for item in results if isinstance(item, dict)]
            if isinstance(results, list)
            else []
        )
        rendered = self.render_relevant_memory(memory_items[:limit])
        elapsed_ms = payload.get("elapsed_ms", 0.0) if isinstance(payload, dict) else 0.0
        try:
            normalized_elapsed = float(elapsed_ms or 0.0)
        except (TypeError, ValueError):
            normalized_elapsed = 0.0
        return DiscordMemoryQueryResult(
            text=rendered,
            hit_count=len(memory_items),
            elapsed_ms=normalized_elapsed,
            raw_results=memory_items,
        )

    def render_relevant_memory(self, results: list[dict[str, Any]]) -> str:
        """把检索结果渲染成模型可读的分行文本。"""
        lines: list[str] = []
        for index, item in enumerate(results, start=1):
            text = str(item.get("text") or "").strip()
            if not text:
                continue
            tier = str(item.get("tier") or "memory").strip()
            entity = str(item.get("entity") or "-").strip()
            anchor = str(
                item.get("event_end_at")
                or item.get("event_start_at")
                or item.get("created_at")
                or ""
            ).strip()
            suffix = f" ({anchor[:10]})" if anchor else ""
            lines.append(f"{index}. [{tier}/{entity}] {text}{suffix}")
        return "\n".join(lines)

    async def post_memory_history(
        self,
        endpoint: str,
        her_name: str,
        messages: list[dict[str, Any]],
        *,
        timeout: float = 5.0,
        source_label: str = "",
    ) -> dict[str, Any]:
        """POST /{endpoint}/{her_name} → 推送对话摘要（json={"input_history": ...}）。

        source_label: 非空时在历史开头注入一条 system 消息说明对话来源，
        让 memory_server 摘要时能区分桌面端 / Discord 端用户。
        """
        payload_messages = list(messages)
        if source_label:
            payload_messages = [
                {
                    "role": "system",
                    "content": (
                        f"[对话来源说明] 本段对话来自 {source_label}。"
                        "用户消息可能带 `[频道 #xxx] 用户名:` 或 "
                        "`[来自 Discord 私信用户 xxx（ID: yyy）]` 前缀；"
                        "摘要时请保留用户名/来源标注，避免和桌面端用户混淆。"
                    ),
                }
            ] + payload_messages
        async with httpx.AsyncClient(
            timeout=timeout, proxy=None, trust_env=False
        ) as client:
            response = await client.post(
                f"{self._base_url()}/{endpoint}/{her_name}",
                json={"input_history": json.dumps(payload_messages, ensure_ascii=False)},
            )
            response.raise_for_status()
            return response.json()
