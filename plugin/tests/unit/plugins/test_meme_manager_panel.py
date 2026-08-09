"""Browser-script contract tests for the meme_manager panel."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.plugin_unit

_PANEL_PATH = (
    Path(__file__).parents[3] / "plugins" / "meme_manager" / "static" / "index.html"
)


def _inline_script() -> str:
    html = _PANEL_PATH.read_text(encoding="utf-8", errors="strict")
    scripts = re.findall(
        r"<script(?:\s[^>]*)?>(.*?)</script>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert len(scripts) == 1, "the panel must keep one testable inline script"
    assert "系统默认" in html
    assert "用户上传" in html
    assert 'id="panelStatus"' in html and 'aria-live="polite"' in html
    for operation in ("刷新失败", "保存失败", "恢复默认失败", "试用失败"):
        assert operation in html
    assert 'callEntry("meme_send", { query, source }, 40000)' in html
    return scripts[0]


def test_panel_real_runs_flow_persists_and_formats_object_errors() -> None:
    script = _inline_script()
    harness = r"""
globalThis.__MEME_MANAGER_PANEL_TEST__ = true;

class FakeElement {
  constructor(tagName) {
    this.tagName = String(tagName || "").toUpperCase();
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.attributes = {};
    this.className = "";
    this.textContent = "";
  }
  append(...children) {
    this.children.push(...children);
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }
}

globalThis.document = {
  createElement(tagName) {
    return new FakeElement(tagName);
  },
};

let timerId = 0;
globalThis.setTimeout = (callback, milliseconds = 0) => {
  const id = ++timerId;
  if (milliseconds < 2000) Promise.resolve().then(callback);
  return id;
};
globalThis.clearTimeout = () => {};

const calls = [];
const runs = new Map();
let runNumber = 0;
let persistedUserMemes = [];

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(payload);
    },
  };
}

globalThis.fetch = async (url, options = {}) => {
  const method = options.method || "GET";
  calls.push({ url, method, body: options.body || "" });

  if (url === "/runs" && method === "POST") {
    const request = JSON.parse(options.body);
    const runId = `run-${++runNumber}`;
    runs.set(runId, request);
    return response({
      run_id: runId,
      plugin_id: request.plugin_id,
      entry_id: request.entry_id,
      status: "queued",
    });
  }

  const match = String(url).match(/^\/runs\/([^/]+)(\/export)?$/);
  if (!match) return response({ detail: { message: "route missing" } }, 404);
  const runId = decodeURIComponent(match[1]);
  const request = runs.get(runId);
  if (!request) return response({ detail: { message: "run missing" } }, 404);

  if (!match[2]) {
    if (request.entry_id === "force_object_error") {
      return response({
        run_id: runId,
        plugin_id: request.plugin_id,
        entry_id: request.entry_id,
        status: "failed",
        error: {
          code: "store_disabled",
          message: "PluginStore 不可用",
          details: { detail: "请检查 effective config" },
        },
      });
    }
    return response({
      run_id: runId,
      plugin_id: request.plugin_id,
      entry_id: request.entry_id,
      status: "succeeded",
      error: null,
    });
  }

  let data;
  if (request.entry_id === "add_meme") {
    const meme = {
      id: "meme-persisted",
      name: request.args.name,
      tags: request.args.tags,
      enabled: true,
      origin: "user_upload",
      read_only: false,
      can_delete: true,
      url: "/plugin/meme_manager/ui/memes/safe.png",
    };
    persistedUserMemes = [meme];
    data = { saved: true, message: "已保存", meme };
  } else if (request.entry_id === "get_panel_state") {
    const systemSource = {
      id: "system:neko-online",
      name: "N.E.K.O 系统默认",
      origin: "system_default",
      kind: "online_search",
      read_only: true,
      can_delete: false,
      enabled: true,
    };
    data = {
      system_sources: [systemSource],
      user_memes: persistedUserMemes,
      memes: persistedUserMemes,
      catalog: [systemSource, ...persistedUserMemes],
      total: persistedUserMemes.length,
      enabled_count: persistedUserMemes.length,
      store_ready: true,
    };
  } else {
    data = {};
  }
  return response({
    run_id: runId,
    plugin_id: request.plugin_id,
    entry_id: request.entry_id,
    items: [{ type: "json", json: { success: true, data } }],
  });
};
"""
    assertions = r"""
(async () => {
  const hooks = globalThis.__memeManagerPanelTestHooks;
  if (!hooks) throw new Error("test hooks missing");

  const saved = await hooks.callEntry("add_meme", {
    name: "真机保存",
    filename: "safe.png",
    data_base64: "cG5n",
    tags: ["持久化"],
  });
  if (saved.saved !== true || saved.meme.id !== "meme-persisted") {
    throw new Error(`unexpected save result: ${JSON.stringify(saved)}`);
  }

  const reloaded = hooks.normalizePanelState(
    await hooks.callEntry("get_panel_state", {})
  );
  if (reloaded.systemSources.length !== 1) {
    throw new Error("system default source disappeared after refresh");
  }
  if (reloaded.systemSources[0].available !== null) {
    throw new Error("an unprobed online source was incorrectly reported available");
  }
  if (
    reloaded.userMemes.length !== 1
    || reloaded.userMemes[0].name !== "真机保存"
  ) {
    throw new Error("saved user meme did not survive refresh");
  }
  if (
    hooks.safeUserImageUrl(reloaded.userMemes[0].url)
    !== "/plugin/meme_manager/ui/memes/safe.png"
  ) {
    throw new Error("same-origin user preview path was rejected");
  }

  const card = hooks.createSystemSourceCard(reloaded.systemSources[0]);
  const flattened = [];
  const walk = (node) => {
    flattened.push(node);
    for (const child of node.children || []) walk(child);
  };
  walk(card);
  if (card.dataset.readonly !== "true") {
    throw new Error("system source card is not marked read-only");
  }
  if (flattened.some((node) => node.tagName === "BUTTON")) {
    throw new Error("system source card exposed a mutable action");
  }
  if (!flattened.some((node) => node.textContent === "在线按需搜索")) {
    throw new Error("system source card did not explain its on-demand status");
  }

  const directError = hooks.readableError({
    error: {
      message: "保存失败",
      detail: { error: "磁盘不可写" },
    },
  });
  if (directError !== "保存失败" || directError.includes("[object Object]")) {
    throw new Error(`object error was not readable: ${directError}`);
  }

  let failedMessage = "";
  try {
    await hooks.callEntry("force_object_error", {});
  } catch (error) {
    failedMessage = hooks.readableError(error);
  }
  if (
    !failedMessage.includes("PluginStore 不可用")
    || failedMessage.includes("[object Object]")
  ) {
    throw new Error(`run error was not readable: ${failedMessage}`);
  }

  const entryIds = calls
    .filter((call) => call.url === "/runs" && call.method === "POST")
    .map((call) => JSON.parse(call.body).entry_id);
  if (entryIds.join(",") !== "add_meme,get_panel_state,force_object_error") {
    throw new Error(`unexpected run requests: ${entryIds.join(",")}`);
  }
  if (!calls.some((call) => /\/export$/.test(call.url))) {
    throw new Error("successful runs were not read from /export");
  }

  process.stdout.write("面板契约通过\n");
})().catch((error) => {
  process.stderr.write(`${error && error.stack ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
"""
    completed = subprocess.run(
        ["node", "-"],
        input="\n".join((harness, script, assertions)),
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "面板契约通过\n"
    assert "[object Object]" not in completed.stderr
