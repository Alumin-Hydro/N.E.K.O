# Vibe Coding Connector

Vibe Coding Connector 让 N.E.K.O 通过一个**单独运行、由用户管理的 HAPI 服务**访问 Claude Code、Codex 与 OpenCode 会话。插件只负责安全策略、HAPI HTTP/SSE 协议适配、N.E.K.O 工具入口、持久化元数据和管理面板；它不会在宿主机上执行命令。

> HAPI、Claude Code、Codex 和 OpenCode 均不随本插件打包。本插件不会安装、启动或调用这些 CLI；所有开发任务都经配置的 HAPI 服务发送。请先按 [HAPI](https://github.com/tiann/hapi) 的说明独立部署服务及其 runner。

## 架构与责任边界

```text
N.E.K.O / 管理面板
        │  有界的工具参数与结果
        ▼
Vibe Coding Connector
  ├─ URL、provider、workspace 与操作权限策略
  ├─ HAPI HTTP 版本适配和逐事件循环客户端
  ├─ SSE 重连、去重与可选通知
  └─ PluginStore（设置、脱敏 token 状态、有限近期元数据）
        │  HTTP(S) / SSE
        ▼
用户独立运行的 HAPI ── runner ── Claude Code / Codex / OpenCode
```

HAPI 与 runner 决定实际可用的 agent、机器、认证方式及进程生命周期。本插件不会把 HAPI 的存在等同于 runner 已就绪：连接检查会分别展示健康状态、认证结果和在线机器。HAPI 当前没有统一的 provider/capabilities 端点，因此面板中的 provider 能力由本地允许列表、在线机器和已观察会话综合描述，不会虚构远端支持。

## 准备与首次配置

1. 独立部署 HAPI 和至少一个 runner，并在 HAPI 侧配置所需的 Claude Code、Codex 或 OpenCode。官方 HAPI 的常见本地地址为 `http://127.0.0.1:3006`。
2. 启用本插件，打开“Vibe Coding 连接器”面板。
3. 填写 HAPI 地址和 token。token 输入框始终为空；保存后的界面只显示是否已配置，不展示任何 token 片段。
4. 添加允许的工作区根目录。默认列表为空，因此默认不能创建或驱动任何开发会话。
5. 按需开启“创建会话”“发送任务”“停止会话”和“处理审批”。这些写操作默认关闭。
6. 测试连接并刷新会话。确认 provider、工作目录和 runner 都符合预期后再提交任务。

默认只允许回环地址。使用非本机 HAPI 时，必须在面板显式开启远程端点选项且必须使用 HTTPS，并同时采用受限网络和最小权限凭据。

## 支持的 HAPI 合约

插件只实现会话管理所需的 HAPI 路由，并把路径与响应差异隔离在客户端适配层：

| 方法与路径 | 用途 | 主要请求/响应假设 |
| --- | --- | --- |
| `GET /health` | 服务健康和协议版本 | 接受 `status`、`protocolVersion` 等健康字段；无需认证 |
| `POST /api/auth` | 用 HAPI access token 换取 bearer token | 发送 `{"accessToken":"…"}`；读取响应中的 `token` |
| `GET /api/machines` | 查询 runner/机器 | 读取 `{ "machines": [...] }` 或兼容的列表包装 |
| `POST /api/machines/{machineId}/spawn` | 创建会话 | 发送 `directory`、`agent`、`sessionType`、`permissionMode: "default"`，并固定 `yolo: false`；读取 `sessionId` |
| `GET /api/sessions` | 列出近期/活动会话 | 读取 `{ "sessions": [...] }` 或兼容包装 |
| `GET /api/sessions/{sessionId}` | 会话详情与待处理请求 | 读取 `{ "session": {...} }`；审批来自 `agentState.requests` |
| `GET /api/sessions/{sessionId}/messages?limit=N` | 读取有限近期输出 | `N` 始终受本地上限约束；读取 `messages` |
| `POST /api/sessions/{sessionId}/resume`、`/reopen` | HAPI 恢复路由 | 路由真实存在，但当前 HAPI 不能原子保证按请求的安全权限模式恢复；连接器不会自动恢复非活动会话，只会要求用户在受信任的 HAPI 客户端中手动恢复并复核权限 |
| `POST /api/sessions/{sessionId}/messages` | 发送开发指令/继续会话 | 发送 `{ "text": "…" }` |
| `POST /api/sessions/{sessionId}/abort` | 停止运行中的会话 | 发送空 JSON 对象 |
| `POST /api/sessions/{sessionId}/permissions/{requestId}/approve` | 明确批准请求 | 仅响应仍待处理的请求；可附带 HAPI 支持的有界 `answers` 记录 |
| `POST /api/sessions/{sessionId}/permissions/{requestId}/deny` | 明确拒绝请求 | 仅响应仍待处理的请求；发送空 JSON |
| `GET /api/events?all=1` | 全局 SSE 事件 | 解析标准 `data:` 帧、心跳及会话/审批相关事件 |

受支持的响应形态包括当前 HAPI 的具名包装（如 `{sessions: [...]}`）、直接列表以及部分版本使用的 `{data: ...}` 包装。创建会话同时识别 HTTP 成功响应中的 `sessionId` 与 HAPI 的 `{type:"success", sessionId}` 形态；HTTP 成功但 `{type:"error"}` 仍按失败处理。错误正文不会原样传给模型、日志或面板。

HAPI 的会话列表摘要通常不带 `permissionMode`，因此面板会标为“发送时需校验”；提交或批准前插件一定重新读取完整会话详情。旧版 HAPI 若连详情也不报告权限模式，连接器会保持可读、可停止、可拒绝，但拒绝发送或批准，而不会猜测默认权限。

HAPI 协议会演进。插件不依赖未列出的文件、shell 或通用命令端点；若服务器改变了上述路径、认证、权限模式或事件字段，连接检查会返回经过脱敏的兼容性错误。升级 HAPI 后请先在面板重新测试连接。

## 使用示例

可以在面板完成全部操作，也可以让猫娘调用同名工具。例如：

```text
“检查 Vibe Coding 连接，并列出可用 provider。”
“用 codex 在 /Users/me/project 创建会话，然后让它只分析测试失败原因。”
“读取这个会话最近 20 条事件。”
“这个审批请求只允许读取依赖清单；如果请求仍待处理就批准，否则告诉我状态。”
“停止刚才的开发会话。”
```

面板操作顺序示例：

```text
测试连接 → 刷新会话 → 连接器自动确定性选择在线机器，并使用所选 provider 和允许目录
→ 创建会话 → 发送测试指令 → 查看事件/审批 → 必要时停止
```

所有模型可见结果都是有界摘要；若需要更多上下文，应分页或缩小查询范围，而不是返回完整远端 JSON。

## 安全模型

- **无本地执行面。** 插件不使用 `subprocess`、shell、CLI 或任意命令入口；所有执行都发生在配置的 HAPI 一侧。
- **安全的网络默认值。** 默认地址是回环 HTTP 地址。非 `localhost`、`127.0.0.0/8` 或 `::1` 端点必须显式开启远程访问并使用 HTTPS；URL 禁止用户信息、查询参数和片段，HTTP 客户端不跟随重定向且不读取环境代理。
- **工作区允许列表。** 根目录默认为空。创建、发送、停止和审批前都会规范化并检查真实路径，拒绝相对路径、`..`、不存在的目录、符号链接逃逸和根目录外路径。
- **共享文件系统假设。** 本地 HAPI 通常能与 N.E.K.O 对同一路径做一致的 canonical 检查。远程 HAPI 可能看不到相同文件系统；本插件只能验证 N.E.K.O 主机上的路径，无法证明远端 runner 将同一字符串映射到同一目录。远程部署必须由管理员另外实施路径映射、容器/账户隔离和 HAPI 侧允许列表。
- **受限 provider。** 默认且最大允许集合为 `claude`、`codex`、`opencode`；设置不能加入任意 agent 名称。
- **逐项写权限。** 创建、发送、停止和审批各有独立开关。读取状态不自动授予写权限。
- **永不自动批准危险请求。** `yolo` 固定为关闭；插件不实现静默 auto-approve。批准与拒绝都需要明确动作，面板对危险操作进行确认。
- **拒绝盲批。** 面板只展示有界、脱敏的参数预览；预览被截断或详情不足时会禁用批准但保留拒绝。需要逐题回答的 question 审批不能由面板无答案批准，应在原生 HAPI 客户端中审阅，或由显式提供了有界 `answers` 的调用处理。
- **有界资源。** 指令长度、响应体、近期输出、SSE 帧、事件存储、请求速率和并发数均受限；监听器只维持一个可取消的后台任务。
- **凭据不进入 run 参数。** 浏览器为每次保存取得短期一次性公钥，以 RSA-OAEP-SHA256 包装随机 AES-256 密钥，并用 AES-GCM 加密完整设置文档。`/runs` 参数、历史和导出中只有 `encrypted_payload` 与 `key_id`；私钥具有短 TTL、绑定插件/入口、单次原子消费且拒绝重放。明文只在插件进程内解密并写入独立的 PluginStore credential 键。
- **凭据不回显。** 面板和工具只看到 token 是否已配置，不展示任何 token/JWT 片段；空白保存保留旧 token，清除需要显式操作。连接器不记录 token，并从错误、UI、持久化元数据、远端响应和模型结果中剔除配置凭据及常见敏感字段。

这些控制减少误操作和越权面，但不能替代 HAPI、runner、代码仓库、操作系统账户和上游模型自身的权限隔离。

## SSE 与通知

插件运行时可自动启动，但 SSE 监听默认关闭。开启且配置有效时，插件在长生命周期事件循环中启动单个重连监听器，按设置延迟重连，限制帧和事件大小并对近期事件做短窗口去重。插件可将“会话完成”和“出现待审批请求”等重要事件以 `read` 或 `blind` 行为推送到 HUD/聊天；不会使用会立即触发模型回复的 `respond` 行为。普通消息不会触发回调任务，通知带来源和去重信息以避免反馈循环。关闭插件时监听器会被取消，HAPI 暂时不可用也不会使插件崩溃。

PluginStore 中的近期会话和事件只保存脱敏、有限元数据；运行期面板可持有至多 600 字符的脱敏审批参数预览，但不持久化完整指令、完整输出、完整审批参数或 token。

## 灵感与许可边界

本插件是针对 N.E.K.O SDK、`@llm_tool`、PluginStore、push message 和管理面板 API 的 clean-room 实现，设计上受 [AstrBot HAPI Connector](https://github.com/LiJinHao999/astrbot_plugin_hapi_connector) 启发，并以 [HAPI](https://github.com/tiann/hapi) 的公开 HTTP/SSE 合约为互操作依据。代码没有捆绑或替代上述项目；使用 HAPI 及各 coding agent 时，请分别遵守它们的许可、条款和安全说明。
