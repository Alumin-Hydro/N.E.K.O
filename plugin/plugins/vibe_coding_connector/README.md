# Vibe Coding Connector

Vibe Coding Connector 让 N.E.K.O 通过 HAPI 管理 Claude Code、Codex 与
OpenCode 会话。`0.2.0` 的默认模式是**内置 HAPI 服务**：插件自动解包、
启动、检查并监督锁定到 `v0.25.1` 的官方 HAPI hub 和受限 runner。

当前交付包直接包含官方 Windows x64 runtime。Windows 用户不需要另装
HAPI、Bun 或 npm。HAPI 本身不包含 Claude Code、Codex、OpenCode，也不包含
这些服务的账号或订阅；相应 provider CLI 仍需用户单独安装并登录。

## 平台支持

| 平台 | 默认安装包 | 可选方式 |
| --- | --- | --- |
| Windows x64 | 内置 HAPI `v0.25.1` 官方归档 | 也可切换到外部 HAPI 或兼容 CLI 模式 |
| macOS arm64/x64 | 未内置 | 在高级设置显式启用锁版校验下载，或使用外部 HAPI |
| Linux arm64/x64 baseline | 未内置 | 在高级设置显式启用锁版校验下载，或使用外部 HAPI |

面板会显示当前平台、是否随包内置、实际端口、hub/runner readiness 和最近
错误；未内置的平台不会显示为可用。校验下载只允许 manifest 中固定的
`v0.25.1` GitHub release URL，并在解包前验证字节数和 SHA256。它不是
Windows 的默认或唯一安装路径。

## 首次使用

1. 安装并登录至少一个 provider CLI：`claude`、`codex` 或 `opencode`。
2. 打开插件面板，确认“可用编程工具”的检测结果。检测到可执行文件不代表
   登录一定有效；登录状态仍由对应 provider 自己负责。
3. 添加至少一个具体的工作区根目录。文件系统根目录、用户主目录和常见系统
   目录会被拒绝。
4. 保存设置。配置变化会安全重启插件自己拥有的 HAPI 进程树。
5. 在基础区启动或重启服务，并执行连接测试。实际端口可能与首选端口不同。
6. 按需开启创建、发送、停止和审批权限。这些写操作互相独立，危险权限自动
   批准始终关闭。

没有工作区根目录时，插件只启动 hub 并显示 `degraded`；它不会启动 HAPI
runner，因为 HAPI `v0.25.1` 在省略 `--workspace-root` 时会进入不受目录限制
的 legacy 行为。添加根目录后，runner 的每个允许目录都会以独立
`--workspace-root <absolute-path>` 参数传入。

## 运行模式

- `managed_hapi`：默认模式。插件管理锁版 hub/runner、随机内部 access
  token、端口、readiness、日志和进程所有权。
- `hapi_external`：高级模式。连接用户管理的 HAPI URL/token；非回环地址
  必须显式启用、使用 HTTPS，并由管理员保证远端路径映射和隔离。
- `local_cli`：明确的兼容/降级模式。只对允许的 provider 使用经过验证的
  绝对可执行路径和 argv，`shell=False`；它不是内置 HAPI 的替代默认值。

## 托管生命周期

插件以固定 argv 启动官方 runtime：

```text
hapi hub --host 127.0.0.1 --port <actual-port> --no-relay
hapi runner start-sync --workspace-root <root-1> [--workspace-root <root-2> ...]
```

`runner start-sync` 是 HAPI `v0.25.1` 官方源码和安装文档提供的前台模式。
普通 `runner start` 会创建 detached 子进程后退出，因此不用于监督。

- hub 与 runner 共用插件隔离的 `HAPI_HOME`、数据库和随机 token。
- `HAPI_PUBLIC_URL`、`HAPI_API_URL` 和 listen port 每次都使用 actual port；
  禁用 HAPI 自行 binary handoff，避免进程逃离监督。
- 启动前只探测 `127.0.0.1` 首选端口。未知进程占用时绝不终止它，而是在
  有界候选范围内选择空闲端口；所有 HTTP/SSE 客户端随即改用 actual port。
- 只有 ownership marker、PID、OS 进程创建时间、可执行路径、版本、
  精确 argv、runtime 目录和配置指纹都匹配时，才会复用以前由本插件启动的
  进程；跨进程 lifecycle lock 防止两个插件实例同时创建或覆盖所有权。
- Readiness 先检查真实 `GET /health`，配置根目录时再通过 `/api/auth` 和
  `/api/machines` 确认当前 owned runner PID 已在线。监督期间也会用有界连续
  失败阈值复查健康状态。失败会显示有限、可读的诊断和日志名。
- hub 或 runner 崩溃/失去 readiness 后采用有限退避重启；达到上限即锁定
  为失败，普通请求不会重置预算，只有明确启动/重启或新配置会开启新一轮。
- 捕获日志滚动且有大小上限，HAPI 自己的 append-only 日志也会做有界保留。
- reload、模式/端口/root 变化会先停止监听器和旧客户端，再安全重启 runtime。
- shutdown 只递归终止 PID 创建时间和可执行身份仍匹配的自有进程树；不会按
  名称扫描、不会调用 HAPI `doctor clean`、不会终止未知端口占用者。Windows
  先以 suspended 状态创建每个 root process，放入 `KILL_ON_JOB_CLOSE`
  Job Object 后才恢复执行；若宿主不允许建立这个边界，启动会安全失败而
  不会降级成无法保证完整树清理的模式。终止无法确认时，插件保留 ownership
  marker 并报告 `shutdown_failed`，不会谎报已停止。

运行数据位于插件自己的 storage namespace。官方可执行文件、解包版本目录、
HAPI_HOME、token、ownership marker 和日志彼此分离。首次运行还会由官方
HAPI binary 解出自身嵌入的 helper runtime，因此需要额外磁盘空间。

## 工作区和审批边界

- 根目录必须是已存在、绝对、规范化的具体目录；拒绝 `..`、不存在路径、
  symlink escape、文件系统根、home 和系统目录。
- 创建会话、发送、停止和审批前都会重新验证 provider、真实工作目录和会话
  身份；未配置 roots 时执行能力保持关闭。
- provider 最大集合固定为 `claude`、`codex`、`opencode`。
- 创建请求固定使用安全权限模式并令 `yolo=false`。
- 提交或批准前重新读取完整会话权限状态。缺失或危险权限模式保持可读、可
  停止、可拒绝，但不能发送或批准。
- 面板只展示有界且脱敏的审批摘要。自动批准和绕过式权限模式不可用。
- 响应大小、指令长度、SSE frame、近期记录、并发和调用频率均有上限。

外部 HAPI 可能把同一目录字符串映射到另一台机器上的不同位置。插件只能验证
N.E.K.O 主机看见的路径；远端账户、网络和路径映射必须另外隔离。内置 runner
与插件共享本机路径，因此仍应只授权任务实际需要的最小根目录。

非本机 HAPI 必须使用 HTTPS。创建新会话时，连接器会在符合 provider 和路径
策略的在线机器中自动确定性选择；它不会自动恢复已停止或权限状态不明的旧
会话，恢复前应由用户在受信任的 HAPI 客户端中复核权限。

## 设置和凭据

外部 HAPI token 单独存放在 PluginStore。面板保存时每次先申请新的短期一次性
公钥，用 RSA-OAEP-SHA256 包装随机 AES-256 密钥，再以 AES-GCM 加密完整设置
文档。`/runs` 中只有 `encrypted_payload` 和 `key_id`。信封会被原子消费；
若服务明确报告信封已过期或已使用，面板获取 fresh envelope 后最多透明重试
一次。其他错误不会重试，结构化错误对象也不会被显示成
`[object Object]`。

内置模式使用插件生成的独立 token，不在面板回显。外部 token 输入框也始终
为空，只显示是否已配置；空输入保留旧值，清除需要单独确认。

## HAPI 合约

连接器只调用会话管理需要的 HAPI HTTP/SSE 路由：

- `GET /health`
- `POST /api/auth`
- `GET /api/machines`
- `POST /api/machines/{machineId}/spawn`
- `GET /api/sessions` 和 `GET /api/sessions/{sessionId}`
- session messages、abort、permission approve/deny 路由
- `GET /api/events?all=1`

客户端接受 HAPI 当前的具名对象、直接列表和部分 `{data: ...}` 包装，但不会
跟随 HTTP redirect、读取环境代理、调用通用 shell/文件端点或原样显示远端
错误正文。协议升级后应先在面板重新测试连接。

## Runtime 来源与许可

内置文件：

```text
runtime/bundles/hapi-v0.25.1-win32-x64.zip
```

- HAPI release：<https://github.com/tiann/hapi/releases/tag/v0.25.1>
- Source commit：
  <https://github.com/tiann/hapi/commit/f0e7e6ad200256550a3cae35b05b9935ed10ad45>
- Windows x64 size：`68,793,339` bytes
- 官方 archive SHA256：
  `dfef0e27ecee40a18b59ae6e946cf7d177362f2f188d81703cc931f681550698`
- License：`AGPL-3.0-only`

完整锁版清单、官方 checksums、HAPI AGPL license、CLI NOTICE，以及官方
单文件构建内嵌的 Difftastic、ripgrep、tunwg 许可文本位于
[`runtime/`](runtime/)。Windows archive 是未修改的官方 release asset；
官方包本身只有 `hapi.exe`，因此这些许可证和 NOTICE 由插件另行随包保留。

本连接器针对 N.E.K.O SDK 和 HAPI 公开合约独立实现。设计曾参考
[AstrBot HAPI Connector](https://github.com/LiJinHao999/astrbot_plugin_hapi_connector)
的产品方向，但没有复制其 AGPL 源码。
