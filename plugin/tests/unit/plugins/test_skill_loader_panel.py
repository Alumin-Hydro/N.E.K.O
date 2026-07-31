"""Contract tests for the skill_loader management panel."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest


pytestmark = pytest.mark.plugin_unit

PLUGIN_DIR = Path(__file__).resolve().parents[3] / "plugins" / "skill_loader"
INDEX_HTML = PLUGIN_DIR / "static" / "index.html"
PLUGIN_TOML = PLUGIN_DIR / "plugin.toml"
README = PLUGIN_DIR / "README.md"
I18N_DIR = PLUGIN_DIR / "i18n"
LOCALES = ("zh-CN", "zh-TW", "en", "ja", "ko", "es", "pt", "ru")


def _read_utf8(path: Path) -> str:
    """Decode a panel asset strictly, so malformed UTF-8 fails the test."""

    return path.read_bytes().decode("utf-8", errors="strict")


def _inline_script() -> str:
    source = _read_utf8(INDEX_HTML)
    scripts = re.findall(
        r"<script(?:\s[^>]*)?>(.*?)</script>",
        source,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert len(scripts) == 1, "the panel must keep a single auditable inline script"
    return scripts[0]


NODE_PANEL_CONTRACT = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const sandbox = {
  module: { exports: {} },
  exports: {},
  setTimeout,
  clearTimeout,
  AbortController,
  console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
new vm.Script(input.script, { filename: "skill-loader-panel.js" }).runInContext(sandbox);
const api = sandbox.module.exports;

assert.deepEqual(
  Object.keys(api).sort(),
  [
    "buildSkillViewModel",
    "callEntry",
    "extractExportPayload",
    "formatError",
    "mutateAndRefresh",
  ],
);

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return payload;
    },
  };
}

function sequencedFetch(items, calls) {
  let index = 0;
  return async (url, init = {}) => {
    calls.push({ url: String(url), init });
    assert.ok(index < items.length, `unexpected request ${url}`);
    const item = items[index];
    index += 1;
    return response(item.payload, item.status || 200);
  };
}

async function rejectedMessage(promise) {
  try {
    await promise;
  } catch (error) {
    return String(error && error.message);
  }
  assert.fail("expected promise to reject");
}

(async () => {
  const formatted = api.formatError({
    error: { detail: { message: "settings were rejected" } },
  });
  assert.equal(formatted, "settings were rejected");
  assert.ok(!formatted.includes("[object Object]"));
  const coded = api.formatError({ code: "store_disabled" }, "Save failed");
  assert.equal(coded, "Save failed (store_disabled)");
  assert.ok(!coded.includes("[object Object]"));

  const successCalls = [];
  const successFetch = sequencedFetch([
    { payload: { run_id: "run / 你好", status: "queued" } },
    { payload: { status: "running" } },
    { payload: { status: "succeeded" } },
    {
      payload: {
        items: [{
          label: "trigger_response",
          type: "json",
          json: {
            success: true,
            data: { store_ready: true, skills: [{ id: "deck-maker" }] },
          },
        }],
      },
    },
  ], successCalls);
  const success = await api.callEntry(
    "get_panel_state",
    { refresh: true },
    {
      fetchImpl: successFetch,
      sleep: async () => {},
      now: () => 1000,
    },
  );
  assert.equal(success.store_ready, true);
  assert.equal(success.skills[0].id, "deck-maker");
  assert.deepEqual(
    successCalls.map((call) => call.url),
    [
      "/runs",
      "/runs/run%20%2F%20%E4%BD%A0%E5%A5%BD",
      "/runs/run%20%2F%20%E4%BD%A0%E5%A5%BD",
      "/runs/run%20%2F%20%E4%BD%A0%E5%A5%BD/export",
    ],
  );
  const posted = JSON.parse(successCalls[0].init.body);
  assert.deepEqual(posted, {
    plugin_id: "skill_loader",
    entry_id: "get_panel_state",
    args: { refresh: true },
  });
  assert.equal(successCalls[0].init.method, "POST");
  assert.equal(successCalls[1].init.method, undefined);

  const failedRecordCalls = [];
  const failedRecord = await rejectedMessage(api.callEntry(
    "save_settings",
    { allowed_roots: ["/safe"] },
    {
      fetchImpl: sequencedFetch([
        { payload: { run_id: "failed-record" } },
        {
          payload: {
            status: "failed",
            error: { detail: { message: "persistent store is unavailable" } },
          },
        },
      ], failedRecordCalls),
      sleep: async () => {},
      now: () => 1000,
    },
  ));
  assert.equal(failedRecord, "persistent store is unavailable");
  assert.ok(!failedRecord.includes("[object Object]"));
  assert.deepEqual(
    failedRecordCalls.map((call) => call.url),
    ["/runs", "/runs/failed-record"],
  );

  const failedExportCalls = [];
  const failedExport = await rejectedMessage(api.callEntry(
    "import_skill",
    { path: "/safe/deck-maker" },
    {
      fetchImpl: sequencedFetch([
        { payload: { run_id: "failed-export" } },
        { payload: { status: "succeeded" } },
        {
          payload: {
            items: [{
              label: "trigger_response",
              type: "json",
              json: {
                success: false,
                error: {
                  code: "package_rejected",
                  detail: { message: "linked file escapes the skill root" },
                },
              },
            }],
          },
        },
      ], failedExportCalls),
      sleep: async () => {},
      now: () => 1000,
    },
  ));
  assert.equal(failedExport, "linked file escapes the skill root");
  assert.ok(!failedExport.includes("[object Object]"));
  assert.deepEqual(
    failedExportCalls.map((call) => call.url),
    ["/runs", "/runs/failed-export", "/runs/failed-export/export"],
  );

  const mutationCalls = [];
  const refreshedState = {
    store_ready: true,
    settings: { allowed_roots: ["/safe"] },
    skills: [{ id: "deck-maker" }],
  };
  const refreshed = await api.mutateAndRefresh(
    "save_settings",
    { allowed_roots: ["/safe"] },
    async (entryId, args) => {
      mutationCalls.push({ entryId, args });
      return entryId === "get_panel_state" ? refreshedState : { saved: true };
    },
  );
  assert.deepEqual(JSON.parse(JSON.stringify(mutationCalls)), [
    {
      entryId: "save_settings",
      args: { allowed_roots: ["/safe"] },
    },
    { entryId: "get_panel_state", args: {} },
  ]);
  assert.equal(refreshed, refreshedState);

  const lastRun = {
    status: "succeeded",
    stdout: "created deck.pptx",
    artifacts: [{ path: ".neko-runs/run-1/deck.pptx", size_bytes: 2048 }],
  };
  const model = api.buildSkillViewModel({
    id: "deck-maker",
    name: "Deck Maker",
    description: "Build a presentation",
    enabled: true,
    source: { kind: "path", display: "/safe/deck-maker" },
    manifest_hash: "sha256-current",
    frontmatter: { name: "deck-maker", license: "MIT" },
    linked_files: [
      {
        path: "references/guide.md",
        kind: "reference",
        size_bytes: 12,
        readable: true,
      },
      {
        path: "templates/base.pptx",
        kind: "template",
        size_bytes: 4096,
        readable: false,
      },
      {
        path: "assets/cat.png",
        kind: "asset",
        size_bytes: 512,
        readable: false,
      },
      {
        path: "scripts/build.py",
        kind: "script",
        size_bytes: 88,
        readable: true,
      },
    ],
    scripts: [{
      path: "scripts/build.py",
      supported: true,
      interpreter: "python",
    }],
    authorization: {
      script_execution: true,
      manifest_hash: "sha256-current",
    },
    dependencies: [
      { name: "python", status: "available" },
      { name: "python-pptx", status: "missing", required_by: ["scripts/build.py"] },
    ],
    capabilities: { scripts: true, templates: true },
    last_run: lastRun,
  });
  assert.equal(model.id, "deck-maker");
  assert.equal(model.groups.references[0].path, "references/guide.md");
  assert.equal(model.groups.templates[0].path, "templates/base.pptx");
  assert.equal(model.groups.assets[0].path, "assets/cat.png");
  assert.equal(model.groups.scripts[0].path, "scripts/build.py");
  assert.equal(model.linkedFiles.length, 4);
  assert.equal(model.scriptAuthorized, true);
  assert.equal(model.authorizationManifestHash, "sha256-current");
  assert.deepEqual(
    Array.from(model.dependencyIssues, (dependency) => dependency.name),
    ["python-pptx"],
  );
  assert.equal(model.lastRun, lastRun);
  assert.equal(model.lastRun.artifacts[0].path, ".neko-runs/run-1/deck.pptx");

  process.stdout.write(JSON.stringify({
    ok: true,
    helperCount: Object.keys(api).length,
    requestCount: successCalls.length + failedRecordCalls.length + failedExportCalls.length,
  }));
})().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
"""


def test_panel_helpers_use_real_runs_protocol_and_safe_errors() -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required for the static panel contract test")

    completed = subprocess.run(
        ["node", "-e", NODE_PANEL_CONTRACT],
        input=json.dumps({"script": _inline_script()}, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {"ok": True, "helperCount": 5, "requestCount": 9}


def test_panel_assets_manifest_and_copy_are_honest() -> None:
    html = _read_utf8(INDEX_HTML)
    manifest = tomllib.loads(_read_utf8(PLUGIN_TOML))
    readme = _read_utf8(README)

    assert len(re.findall(r"<script(?:\s[^>]*)?>", html, re.IGNORECASE)) == 1
    assert manifest["plugin"]["entry"] == (
        "plugin.plugins.skill_loader:SkillLoaderPlugin"
    )
    assert manifest["plugin"]["version"] == "0.2.0"
    assert manifest["plugin"]["ui"]["enabled"] is True
    assert manifest["plugin"]["store"]["enabled"] is True

    description = " ".join(
        [
            manifest["plugin"]["description"],
            manifest["plugin"]["short_description"],
        ]
    ).lower()
    assert "python" in description
    assert "授权" in description
    assert "authorization" in description

    assert "/runs" in html
    assert "/export" in html
    assert "linked_files" in html
    assert "script_execution" in html
    assert "dependencies" in html
    assert "last_run" in html

    readme_lower = readme.lower()
    assert "`scripts/*.py`" in readme_lower
    assert "`shell=false`" in readme_lower
    assert "逐技能授权" in readme
    assert "不是操作系统级容器" in readme
    assert "不会模拟 claude code" in readme_lower

    unsupported_claims = (
        "永不执行",
        "never executes",
        "never execute any",
        "fully emulates claude code",
        "完全模拟 claude code",
    )
    combined_copy = f"{description}\n{readme_lower}\n{html.lower()}"
    for unsupported_claim in unsupported_claims:
        assert unsupported_claim not in combined_copy


def test_panel_i18n_bundles_have_identical_nonempty_keys() -> None:
    bundles = {
        locale: json.loads(_read_utf8(I18N_DIR / f"{locale}.json"))
        for locale in LOCALES
    }
    expected_keys = set(bundles["zh-CN"])

    assert len(expected_keys) >= 100
    required_keys = {
        "plugin.name",
        "plugin.description",
        "settings.allowedRoots",
        "skill.references",
        "skill.templates",
        "skill.assets",
        "skill.scripts",
        "skill.dependencies",
        "skill.authorized",
        "skill.lastRun",
        "action.authorize",
        "action.revoke",
        "action.run",
        "run.cancelledStatus",
        "error.pluginFailed",
    }
    assert required_keys <= expected_keys

    for locale, bundle in bundles.items():
        assert set(bundle) == expected_keys, locale
        assert all(
            isinstance(value, str) and value.strip() for value in bundle.values()
        ), locale

        description = bundle["plugin.description"].lower()
        assert "python" in description
        assert "永不执行" not in description
        assert "never executes" not in description
