/* N.E.K.O Discord 适配器管理面板逻辑 */
const RUNS_URL = '/runs';
const pluginMatch = location.pathname.match(/\/plugin\/([^/]+)\/ui\//);
const pluginId = pluginMatch ? decodeURIComponent(pluginMatch[1]) : 'discord_adapter';

const state = { dashboard: null, busy: false };

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function t(key, fallback) {
  return window.I18n ? window.I18n.t(key, fallback) : (fallback || key);
}

/* --- Pure logic helpers (exported for Node tests) --- */

function extractErrorMessage(error) {
  if (!error) return '';
  if (typeof error === 'string') return error;
  if (typeof error.message === 'string' && error.message) return error.message;
  if (typeof error.error === 'string') return error.error;
  return String(error);
}

function validateAdminIds(raw) {
  const ids = String(raw || '').replace(/，/g, ',').split(',')
    .map((s) => s.trim()).filter(Boolean);
  const invalid = ids.filter((s) => !/^\d+$/.test(s));
  return { ids, invalid };
}

function buildSavePayload(values) {
  const payload = {};
  if (values.botToken) payload.bot_token = values.botToken;
  payload.trigger_mode = values.triggerMode || 'mention';
  payload.admin_user_ids = values.adminIds || '';
  payload.permission_mode = values.permissionMode || 'allow_list';
  payload.channel_whitelist = values.channelWhitelist || '';
  payload.guild_whitelist = values.guildWhitelist || '';
  payload.max_concurrent_messages = Number(values.maxConcurrent || 3);
  payload.ai_connect_timeout_seconds = Number(values.connectTimeout || 10);
  payload.ai_turn_timeout_seconds = Number(values.turnTimeout || 60);
  payload.max_attachment_bytes = Number(values.maxAttachmentMb || 10) * 1024 * 1024;
  payload.proxy_url = values.proxyUrl || '';
  return payload;
}

/* --- Host RPC --- */

async function callPlugin(entryId, args = {}) {
  const response = await fetch(RUNS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plugin_id: pluginId, entry_id: entryId, args }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const record = await response.json();
  const runId = record.run_id || record.id;
  if (!runId) throw new Error(t('errors.no_run_id', '未获取到 run_id'));

  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const poll = await fetch(`${RUNS_URL}/${encodeURIComponent(runId)}`);
    if (poll.ok) {
      const run = await poll.json();
      if (run.status === 'succeeded') {
        const exported = await fetch(`${RUNS_URL}/${encodeURIComponent(runId)}/export`);
        if (!exported.ok) return {};
        const payload = await exported.json();
        const item = (payload.items || []).find((c) => c.type === 'json' && c.json) || (payload.items || [])[0];
        let raw = item ? (item.json || {}) : {};
        while (raw && raw.data && typeof raw.data === 'object') raw = raw.data;
        if (raw && raw.error) throw new Error(extractErrorMessage(raw.error) || t('errors.op_failed', '操作失败'));
        return raw && raw.value && typeof raw.value === 'object' ? raw.value : raw;
      }
      if (['failed', 'canceled', 'timeout'].includes(run.status)) {
        throw new Error(extractErrorMessage(run.error) || run.message || run.status);
      }
    }
    await delay(400);
  }
  throw new Error(t('errors.timeout', '调用超时'));
}

/* --- DOM rendering --- */

function showToast(message, error = false) {
  const toast = document.getElementById('toast');
  toast.textContent = String(message || '');
  toast.classList.toggle('error', error);
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 3200);
}

function setBusy(busy) {
  state.busy = busy;
  document.querySelectorAll('button').forEach((button) => { button.disabled = busy; });
}

function setStatusPill(connected, running) {
  const pill = document.getElementById('status-pill');
  const text = document.getElementById('status-text');
  pill.classList.remove('idle', 'ok', 'err');
  if (connected) {
    pill.classList.add('ok');
    text.textContent = t('status.connected', '已连接');
  } else if (running) {
    pill.classList.add('err');
    text.textContent = t('status.connecting', '连接中…');
  } else {
    pill.classList.add('idle');
    text.textContent = t('status.stopped', '未连接');
  }
}

function renderUsers(users) {
  const list = document.getElementById('trusted-users');
  list.replaceChildren();
  const normalized = Array.isArray(users) ? users : [];
  document.getElementById('trusted-count').textContent = `${normalized.length} 人`;
  if (!normalized.length) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = t('users.empty', '暂无信任用户');
    list.appendChild(empty);
    return;
  }
  normalized.forEach((user) => {
    const row = document.createElement('div');
    row.className = 'user-row';
    const meta = document.createElement('div');
    meta.className = 'meta';
    const label = user.nickname ? `${user.nickname}（${user.uid}）` : user.uid;
    meta.textContent = label;
    const level = document.createElement('span');
    level.className = 'level';
    level.textContent = user.level === 'admin' ? t('users.level_admin', '管理员') : t('users.level_trusted', '信任');
    meta.appendChild(level);
    const btn = document.createElement('button');
    btn.className = 'button ghost';
    btn.type = 'button';
    btn.textContent = t('users.remove', '移除');
    btn.addEventListener('click', () => removeTrustedUser(user.uid));
    row.appendChild(meta);
    row.appendChild(btn);
    list.appendChild(row);
  });
}

function applyDashboard(data) {
  state.dashboard = data;
  const status = data.status || {};
  const settings = data.settings || {};
  const credentials = data.credentials || {};

  setStatusPill(Boolean(status.connected), Boolean(status.running));
  document.getElementById('stat-bot').textContent = status.bot_username || '—';
  document.getElementById('stat-guilds').textContent = String(status.guild_count || 0);
  document.getElementById('stat-messages').textContent = String(status.messages_today || 0);
  document.getElementById('stat-error').textContent = status.last_error || '—';

  document.getElementById('btn-start').hidden = Boolean(status.running);
  document.getElementById('btn-stop').hidden = !status.running;

  const tokenSaved = Boolean(credentials.bot_token_configured);
  const credPill = document.getElementById('credential-pill');
  credPill.classList.toggle('idle', !tokenSaved);
  credPill.classList.toggle('ok', tokenSaved);
  credPill.textContent = tokenSaved
    ? (credentials.bot_token_masked || t('basic.token_saved', 'Token 已保存'))
    : t('basic.token_not_saved', 'Token 未保存');
  const tokenState = document.getElementById('state-bot-token');
  tokenState.textContent = tokenSaved
    ? t('basic.token_saved_keep', '已保存（留空则保持不变）')
    : t('basic.token_not_saved', '未保存');
  tokenState.classList.toggle('configured', tokenSaved);

  if (settings.trigger_mode) document.getElementById('cfg-trigger-mode').value = settings.trigger_mode;
  if (settings.permission_mode) document.getElementById('cfg-permission-mode').value = settings.permission_mode;
  if (settings.channel_whitelist !== undefined) document.getElementById('cfg-channel-whitelist').value = settings.channel_whitelist;
  if (settings.guild_whitelist !== undefined) document.getElementById('cfg-guild-whitelist').value = settings.guild_whitelist;
  if (settings.max_concurrent_messages) document.getElementById('cfg-max-concurrent').value = settings.max_concurrent_messages;
  if (settings.ai_connect_timeout_seconds) document.getElementById('cfg-connect-timeout').value = settings.ai_connect_timeout_seconds;
  if (settings.ai_turn_timeout_seconds) document.getElementById('cfg-turn-timeout').value = settings.ai_turn_timeout_seconds;

  renderUsers(data.trusted_users);
}

async function refreshDashboard(silent = false) {
  try {
    applyDashboard(await callPlugin('get_dashboard_state', {}));
  } catch (error) {
    if (!silent) showToast(extractErrorMessage(error) || t('errors.refresh_failed', '刷新失败'), true);
  }
}

/* --- Actions --- */

async function saveSettings() {
  const { invalid } = validateAdminIds(document.getElementById('cfg-admin-ids').value);
  if (invalid.length) {
    showToast(t('errors.invalid_ids', '管理员 ID 必须是纯数字，用逗号分隔'), true);
    return;
  }
  const payload = buildSavePayload({
    botToken: document.getElementById('cfg-bot-token').value.trim(),
    triggerMode: document.getElementById('cfg-trigger-mode').value,
    adminIds: document.getElementById('cfg-admin-ids').value.trim(),
    permissionMode: document.getElementById('cfg-permission-mode').value,
    channelWhitelist: document.getElementById('cfg-channel-whitelist').value.trim(),
    guildWhitelist: document.getElementById('cfg-guild-whitelist').value.trim(),
    maxConcurrent: document.getElementById('cfg-max-concurrent').value,
    connectTimeout: document.getElementById('cfg-connect-timeout').value,
    turnTimeout: document.getElementById('cfg-turn-timeout').value,
    maxAttachmentMb: document.getElementById('cfg-max-attachment').value,
    proxyUrl: document.getElementById('cfg-proxy').value.trim(),
  });
  setBusy(true);
  try {
    applyDashboard(await callPlugin('save_settings', payload));
    showToast(t('actions.saved', '设置已保存'));
  } catch (error) {
    showToast(extractErrorMessage(error) || t('errors.save_failed', '保存失败'), true);
  } finally {
    setBusy(false);
  }
}

async function toggleListening(start) {
  setBusy(true);
  try {
    applyDashboard(await callPlugin(start ? 'start_listening' : 'stop_listening', {}));
    await refreshDashboard(true);
    showToast(start ? t('actions.started', '已开始监听 Discord') : t('actions.stopped', '已停止监听'));
  } catch (error) {
    showToast(extractErrorMessage(error) || t('errors.op_failed', '操作失败'), true);
  } finally {
    setBusy(false);
  }
}

async function testConnection() {
  const result = document.getElementById('test-result');
  result.className = '';
  result.textContent = t('actions.testing', '正在测试连接…');
  const token = document.getElementById('cfg-bot-token').value.trim();
  setBusy(true);
  try {
    const data = await callPlugin('test_connection', token ? { bot_token: token } : {});
    result.classList.add('ok');
    const name = data.bot_username ? `（${data.bot_username}）` : '';
    result.textContent = `✓ ${t('actions.test_ok', '连接成功')} ${name}`;
  } catch (error) {
    result.classList.add('err');
    result.textContent = `✗ ${extractErrorMessage(error)}`;
  } finally {
    setBusy(false);
  }
}

async function addTrustedUser() {
  const uid = document.getElementById('user-uid').value.trim();
  if (!/^\d+$/.test(uid)) {
    showToast(t('errors.invalid_uid', '请输入纯数字 Discord 用户 ID'), true);
    return;
  }
  setBusy(true);
  try {
    await callPlugin('add_trusted_user', {
      uid,
      level: document.getElementById('user-level').value,
      nickname: document.getElementById('user-nickname').value.trim(),
    });
    document.getElementById('user-uid').value = '';
    document.getElementById('user-nickname').value = '';
    await refreshDashboard(true);
    showToast(t('users.added', '信任用户已保存'));
  } catch (error) {
    showToast(extractErrorMessage(error) || t('errors.op_failed', '添加失败'), true);
  } finally {
    setBusy(false);
  }
}

async function removeTrustedUser(uid) {
  if (!uid) return;
  setBusy(true);
  try {
    await callPlugin('remove_trusted_user', { uid });
    await refreshDashboard(true);
    showToast(t('users.removed', '信任用户已移除'));
  } catch (error) {
    showToast(extractErrorMessage(error) || t('errors.op_failed', '移除失败'), true);
  } finally {
    setBusy(false);
  }
}

/* --- Init (browser only; skipped under Node tests) --- */

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  window.addEventListener('DOMContentLoaded', async () => {
  if (window.I18n) window.I18n.scanDOM();
  document.getElementById('btn-refresh').addEventListener('click', () => refreshDashboard(false));
  document.getElementById('btn-save').addEventListener('click', () => saveSettings());
  document.getElementById('btn-reset').addEventListener('click', () => {
    document.getElementById('cfg-bot-token').value = '';
    document.getElementById('cfg-trigger-mode').value = 'mention';
    document.getElementById('cfg-admin-ids').value = '';
    document.getElementById('cfg-permission-mode').value = 'allow_list';
    document.getElementById('cfg-channel-whitelist').value = '';
    document.getElementById('cfg-guild-whitelist').value = '';
    document.getElementById('cfg-max-concurrent').value = 3;
    document.getElementById('cfg-connect-timeout').value = 10;
    document.getElementById('cfg-turn-timeout').value = 60;
    document.getElementById('cfg-max-attachment').value = 10;
    document.getElementById('cfg-proxy').value = '';
    showToast(t('actions.reset_done', '已恢复默认（尚未保存）'));
  });
  document.getElementById('btn-toggle-token').addEventListener('click', () => {
    const input = document.getElementById('cfg-bot-token');
    input.type = input.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('btn-proxy-help').addEventListener('click', () => {
    const guide = document.getElementById('proxy-guide');
    guide.style.display = guide.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('btn-test').addEventListener('click', testConnection);
  document.getElementById('btn-start').addEventListener('click', () => toggleListening(true));
  document.getElementById('btn-stop').addEventListener('click', () => toggleListening(false));
  document.getElementById('btn-add-user').addEventListener('click', addTrustedUser);
  await refreshDashboard(false);
  setInterval(() => refreshDashboard(true), 5000);
  });
}

/* Node test export (no DOM access at import time below this line) */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractErrorMessage, validateAdminIds, buildSavePayload };
}
