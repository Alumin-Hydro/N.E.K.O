# Auto Prompt Harness

Auto Prompt Harness 把经过用户确认的沟通风格建议应用到现有 N.E.K.O
角色卡的受控副本。用户只需要选择一张真实角色卡；插件不会创建第二套需要理解的
用户对象，也不会修改原卡。

## 工作方式

1. 从 `characters.json` 深拷贝所选原卡，生成唯一的
   `原名（自适应）` 副本。插件按旧宿主真实顺序解析 base prompt 与 persona：
   preset/custom persona 会物化到副本，默认 prompt 则保留动态语言解析能力；只在
   副本中清除会导致二次拼接的 persona metadata，并物化其有效角色字段。
2. 在副本 `_reserved.auto_prompt_harness` 中写入插件、绑定、原卡和基础
   prompt 指纹等来源标记。
3. 从宿主只读上下文收集有界、脱敏的证据，经严格 JSON schema 的反思输出形成
   “待确认建议”。
4. 只有批准操作会改写副本的受控 prompt 字段。物化 persona/custom 卡使用
   `_reserved.system_prompt`；动态默认卡使用旧宿主本来就会合入 system prompt 的
   `_reserved.persona_override.prompt_guidance`。写入内容始终是原始有效 prompt
   加一个有界的已批准 adaptation 块；拒绝不会写角色卡，回滚恢复上一个版本。
5. “恢复原角色”、插件禁用和 shutdown 只在当前角色仍是该副本时切回原卡。如果
   用户已主动切到第三张卡，插件不会抢切。

副本默认保留，名称与来源标记都可识别；只有用户在面板输入 `DELETE` 明确确认后，
插件才会删除。若宿主有受控删除接口则使用其完整清理事务；当前旧宿主则由插件
重新载入同一份 fresh snapshot，复核非当前角色、binding、完整来源标记与整卡
SHA-256 后通过 ConfigManager 删除，再重新载入验证。插件绝不调用旧的按名称删除
接口，因此同名角色被替换后不会误删。

## 写入与恢复保证

- 角色配置只通过宿主 `ConfigManager.aload_characters()` /
  `asave_characters()` 读写，沿用原子文件替换和 cloud-save 写入 fence。
- 原卡的深内容指纹在绑定时固化。每次写副本前都会重新载入并核对原卡、来源标记、
  副本非 prompt 字段和当前 prompt 版本；任何冲突都会停止写入，不猜测覆盖。
- 条件恢复与删除不依赖新增 core route。managed-overlay route 存在时只是可选快路；
  route 不存在、返回普通 404 或 shutdown 时不可用，插件会在自身 mutation lock
  内重新 `aload_characters()`，完整复核条件，`asave_characters()` 后再重新 load
  验证。恢复只有在当前角色仍是该副本时写入；第三张卡会原样保留。删除只有在副本
  非当前且完整卡片 SHA-256 仍匹配时执行。
- PluginStore 保存 binding、基础 prompt 指纹、当前版本、建议、证据游标与修改
  历史。旧版哈希数据只做“已检测但未绑定”的安全记录，不会重新暴露为用户概念。
- PluginStore 丢失或进程在中途退出时，可根据副本来源标记恢复唯一绑定；多个候选
  会保持未绑定并提示处理。
- 原卡被删除、改名或修改，或副本来源/非 prompt 字段/prompt 被外部修改时，
  绑定进入冲突状态。插件不会用相似名称猜测对应关系。
- 当前旧宿主无需补丁：批准/回滚保存验证成功后调用已有 `/api/characters/reload`，
  让普通后续对话立即读取新 prompt。默认卡把 adaptation 存在宿主真实等效的
  persona guidance 字段，仍会按当前语言解析默认 prompt；preset/custom persona
  已在副本创建时完整物化并移除二次拼接来源，因此 adaptation 始终只出现一次。

## 安全与隐私

- 公开聊天消息入口永久 fail closed；证据只来自宿主验证过的只读上下文记录。
- 证据在持久化前脱敏并截断，数量和长度均有硬上限。
- 反思模型必须返回无额外字段的单一 JSON 对象；建议是单行、有界的沟通风格文本，
  会拒绝角色覆盖、提示泄露、密钥、危险命令和越狱语义。
- 插件不再用 hidden `push_message` 冒充已修改角色。只有副本 prompt 写入、运行态
  刷新和状态保存成功后，批准操作才报告已应用。
- `analyze_text` 是唯一暴露给模型的工具，而且只做不持久化的窄规则模拟。角色绑定、
  建议批准、恢复和删除都是管理入口。

## 管理入口

- `list_characters`
- `get_panel_state`
- `start_adaptation`
- `reflect_now`
- `resolve_proposal`
- `rollback_last_change`
- `restore_original`
- `delete_overlay`
- `delete_orphan_overlay`
- `save_settings`
- `reset_settings`
- `analyze_text`（同时是无状态 LLM 工具）

## 已知边界

`ConfigManager` 保证单次 JSON 写入的原子替换，但现有宿主没有跨进程的
characters.json compare-and-swap。插件在自己的所有变更间使用互斥锁，并在每次
操作前 fresh-load、校验 current/指纹；若另一个进程恰在 load 与 save 之间直接写
同一文件，仍只能在下一次 reconciliation 检出并安全停写。

当前旧宿主的通用 reload 会更新角色配置和 prompt runtime，但不会强制终止正处于
启动窗口或持续 realtime 连接中的既有会话；这类会话可能要自然重连后才使用新
instructions。package-contained 删除可以安全移除 `characters.json` 中的精确
overlay，但旧宿主没有带完整卡片条件的公开接口来同步清理角色记忆目录、头像目录
和云存档墓碑；这些辅助资源仍需由宿主角色管理功能清理。无论哪种模式，插件无法
保证模型一定采用某条沟通偏好，更高优先级规则和当前任务需要始终优先。

## 开发验证

```bash
export NEKO_STORAGE_SELECTED_ROOT=/tmp/neko-gate-auto-prompt-harness
export NEKO_STORAGE_ANCHOR_ROOT=/tmp/neko-gate-auto-prompt-harness
export PYTHONDONTWRITEBYTECODE=1
export PYDANTIC_DISABLE_PLUGINS=1

uv run python -m pytest plugin/tests/unit/plugins/test_auto_prompt_harness.py -q

uv run python -m pytest \
  plugin/tests/unit/plugins/test_auto_prompt_reflection.py -q

uv run python -m pytest \
  plugin/tests/integration/test_neko_plugin_cli_workflow.py \
  plugin/tests/integration/test_neko_plugin_cli_repo_plugins.py -q

uv run python -m plugin.neko_plugin_cli check plugin/plugins/auto_prompt_harness
uv run python -m plugin.neko_plugin_cli build auto_prompt_harness \
  -o /tmp/auto_prompt_harness.neko-plugin
uv run python -m plugin.neko_plugin_cli inspect \
  /tmp/auto_prompt_harness.neko-plugin
uv run python -m plugin.neko_plugin_cli verify \
  /tmp/auto_prompt_harness.neko-plugin
```
