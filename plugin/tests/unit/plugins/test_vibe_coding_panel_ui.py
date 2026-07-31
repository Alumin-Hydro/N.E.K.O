from __future__ import annotations

import json
import os
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess

import pytest


PLUGIN_DIR = (
    Path(__file__).resolve().parents[3]
    / "plugins"
    / "vibe_coding_connector"
)
PANEL_PATH = PLUGIN_DIR / "static" / "index.html"
I18N_DIR = PLUGIN_DIR / "i18n"
LOCALES = ("zh-CN", "zh-TW", "en", "ja", "ko", "es", "pt", "ru")


class _PanelStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, str]] = []
        self.ancestors_by_id: dict[str, tuple[tuple[str, str], ...]] = {}
        self.details_open: dict[str, bool] = {}

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        element_id = attributes.get("id") or ""
        if element_id:
            self.ancestors_by_id[element_id] = tuple(self.stack)
        if tag == "details" and element_id:
            self.details_open[element_id] = "open" in attributes
        self.stack.append((tag, element_id))

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


def _read_utf8(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="strict")


def test_panel_managed_runtime_controls_and_advanced_fields_are_honest() -> None:
    html = _read_utf8(PANEL_PATH)
    parser = _PanelStructureParser()
    parser.feed(html)

    assert html.count("<script>") == 1
    assert 'option value="managed_hapi"' in html
    assert 'option value="hapi_external"' in html
    assert 'option value="local_cli"' in html
    assert 'option value="hapi_remote"' not in html
    assert html.index('option value="managed_hapi"') < html.index(
        'option value="hapi_external"'
    )

    advanced_ids = {
        "preferredPort",
        "allowRuntimeDownload",
        "baseUrl",
        "authMode",
        "tokenInput",
        "allowRemote",
        "cliOverrides",
    }
    for element_id in advanced_ids:
        assert ("details", "hapiAdvanced") in parser.ancestors_by_id[element_id]
    assert parser.details_open["hapiAdvanced"] is False

    for element_id in (
        "runtimeState",
        "runtimeActualPort",
        "runtimePlatform",
        "runtimeBundle",
        "runtimeHub",
        "runtimeRunner",
        "workspaceRoots",
        "runtimeStartBtn",
        "runtimeRestartBtn",
        "testConnectionBtn",
    ):
        assert ("details", "hapiAdvanced") not in parser.ancestors_by_id[element_id]

    assert "vibe_coding_runtime_start" in html
    assert "vibe_coding_runtime_restart" in html
    assert "vibe_coding_fresh_secret_envelope" in html
    assert "preferred_port:" in html
    assert "allow_runtime_download:" in html
    assert "settings.backend_mode === \"hapi_external\"" in html
    assert "检测到命令不代表已经登录" in html
    assert "[object Object]" not in html


def test_panel_i18n_bundles_are_strict_utf8_and_have_identical_keys() -> None:
    html = _read_utf8(PANEL_PATH)
    referenced = set(
        re.findall(r'data-i18n(?:-[a-z-]+)?="([^"]+)"', html)
    )
    bundles: dict[str, dict[str, str]] = {}
    for locale in LOCALES:
        text = _read_utf8(I18N_DIR / f"{locale}.json")
        payload = json.loads(text)
        assert isinstance(payload, dict)
        assert all(isinstance(key, str) for key in payload)
        assert all(isinstance(value, str) and value for value in payload.values())
        bundles[locale] = payload

    expected = set(bundles["en"])
    assert all(set(bundle) == expected for bundle in bundles.values())
    assert referenced <= expected
    assert {
        "panel.field.modeManaged",
        "panel.field.modeExternal",
        "panel.runtime.actualPort",
        "panel.runtime.platformUnsupported",
        "panel.local.providerNote",
    } <= expected


def test_panel_node_runtime_error_save_retry_refresh_and_modes() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")

    script = r"""
(async () => {
const fs = require("node:fs");
const assert = require("node:assert/strict");
const { TextDecoder } = require("node:util");

const bytes = fs.readFileSync(process.env.VIBE_PANEL_PATH);
const html = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
assert.equal(html.includes("\uFFFD"), false);
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1);

global.window = {
  __VIBE_CODING_PANEL_TEST_MODE__: true,
  setTimeout,
  clearTimeout,
};
global.document = {
  getElementById() { return null; },
};
global.navigator = { language: "en" };
eval(scripts[0][1]);
const api = window.__VIBE_CODING_PANEL_TEST__;
assert.ok(api);

assert.equal(api.canonicalBackendMode("managed_hapi"), "managed_hapi");
assert.equal(api.canonicalBackendMode("hapi_external"), "hapi_external");
assert.equal(api.canonicalBackendMode("local_cli"), "local_cli");
assert.equal(api.canonicalBackendMode("hapi_remote"), "hapi_external");
assert.equal(api.canonicalBackendMode({}), "managed_hapi");

const runtime = api.normalizeRuntimeStatus({
  state: "ready",
  version: "0.25.1",
  platform: "win32-x64",
  bundled: true,
  actual_port: 43123,
  hub_ready: true,
  runner_ready: true,
  workspace_root_count: 1,
});
const view = api.runtimeView(runtime, "managed_hapi");
assert.equal(view.actualPort, "43123");
assert.equal(view.platform, "win32-x64");
assert.match(view.bundle, /0\.25\.1/);
assert.equal(view.managed, true);
assert.equal(
  api.runtimeView({}, "hapi_external").managed,
  false,
);
assert.match(
  api.runtimeView({}, "local_cli").modeNote,
  /HAPI/,
);

let structured;
try {
  api.unwrapPluginPayload({
    success: false,
    error: {
      code: "structured_failure",
      message: "Readable structured failure",
      detail: { unsafe: "object" },
    },
  });
} catch (error) {
  structured = error;
}
assert.ok(structured instanceof Error);
assert.equal(structured.code, "structured_failure");
assert.equal(structured.message, "Readable structured failure");
assert.equal(structured.message.includes("[object Object]"), false);

const calls = [];
let saveAttempts = 0;
async function retryInvoke(entryId) {
  calls.push(entryId);
  if (entryId === "vibe_coding_fresh_secret_envelope") {
    return {
      secret_envelope: {
        key_id: `${calls.length}`.padStart(32, "a"),
        public_key_spki_b64: "ZmFrZQ==",
      },
    };
  }
  if (entryId === "vibe_coding_save_settings") {
    saveAttempts += 1;
    if (saveAttempts === 1) {
      const error = new Error("used");
      error.code = "secret_envelope_expired_or_used";
      throw error;
    }
    return { summary: "saved" };
  }
  throw new Error(`unexpected entry ${entryId}`);
}
async function fakeEncrypt(payload) {
  calls.push("encrypt");
  assert.equal(payload.settings.backend_mode, "managed_hapi");
  return { encrypted_payload: "cipher", key_id: "wrapped" };
}
await api.saveWithFreshEnvelope(
  { settings: { backend_mode: "managed_hapi" }, token: "" },
  retryInvoke,
  fakeEncrypt,
);
assert.deepEqual(calls, [
  "vibe_coding_fresh_secret_envelope",
  "encrypt",
  "vibe_coding_save_settings",
  "vibe_coding_fresh_secret_envelope",
  "encrypt",
  "vibe_coding_save_settings",
]);
assert.equal(saveAttempts, 2);
assert.equal(
  api.retryableEnvelopeError(
    Object.assign(new Error("invalid"), { code: "encrypted_settings_invalid" }),
  ),
  true,
);
assert.equal(
  api.retryableEnvelopeError(
    Object.assign(new Error("required"), { code: "encrypted_settings_required" }),
  ),
  true,
);
assert.equal(
  api.retryableEnvelopeError(
    Object.assign(new Error("policy"), { code: "workspace_not_allowed" }),
  ),
  false,
);

let nonRetryFresh = 0;
let nonRetrySave = 0;
await assert.rejects(
  api.saveWithFreshEnvelope(
    { settings: { backend_mode: "managed_hapi" } },
    async entryId => {
      if (entryId === "vibe_coding_fresh_secret_envelope") {
        nonRetryFresh += 1;
        return {
          secret_envelope: {
            key_id: "b".repeat(32),
            public_key_spki_b64: "ZmFrZQ==",
          },
        };
      }
      nonRetrySave += 1;
      const error = new Error("do not retry");
      error.code = "workspace_not_allowed";
      throw error;
    },
    async () => ({ encrypted_payload: "cipher", key_id: "wrapped" }),
  ),
  error => error.code === "workspace_not_allowed",
);
assert.equal(nonRetryFresh, 1);
assert.equal(nonRetrySave, 1);

let refreshed = 0;
let rendered = 0;
await api.loadPanelState(
  { quiet: true },
  async entryId => {
    assert.equal(entryId, "vibe_coding_panel_state");
    refreshed += 1;
    return {
      settings: {
        backend_mode: "managed_hapi",
        allowed_workspace_roots: ["C:\\work"],
      },
      runtime: {
        state: "degraded",
        platform: "win32-x64",
        bundled: true,
        actual_port: 4555,
        hub_ready: true,
        runner_ready: false,
        workspace_root_count: 1,
      },
      actual_port: 4555,
    };
  },
  () => { rendered += 1; },
);
const snapshot = api.modelSnapshot();
assert.equal(refreshed, 1);
assert.equal(rendered, 1);
assert.equal(snapshot.settings.backend_mode, "managed_hapi");
assert.equal(snapshot.runtime.actualPort, 4555);
assert.equal(snapshot.actualPort, 4555);
})();
"""
    environment = os.environ.copy()
    environment["VIBE_PANEL_PATH"] = str(PANEL_PATH)
    result = subprocess.run(
        [node, "--unhandled-rejections=strict", "-e", script],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=environment,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout
