# Happy MCP 架构与运行语义

本文描述当前实现的真实边界。

## 1. 核心边界

Happy MCP 是 CLI wrapper，不是 Happy 协议客户端。

```text
外部 AI
   |
   | MCP over HTTPS + OAuth bearer token
   v
happy-mcp
   |
   | allowlist + approved roots + independent LLM review
   v
child_process.spawn(HAPPY_AGENT_BIN, argv, { shell: false })
   |
   v
管理员安装并认证的 happy-agent
```

MCP 只知道：

- `happy-agent` 可执行文件路径；
- 公开 CLI 子命令、参数、JSON 输出和退出码；
- 管理员为机器设置的 allowlist、批准目录和自然语言规则。

MCP 不知道：

- Happy server 或 relay URL；
- Happy token、account secret、session key 或加密格式；
- Happy REST、Socket.IO、machine RPC 或 session RPC；
- Happy daemon、CLI 或 server 的内部 TypeScript API。

`happy-agent` 内部如何找到机器、传递消息和加密数据属于它自己的实现细节。替换或升级 Happy 不需要修改本仓库，只要公开 CLI 契约保持兼容。

## 2. 代码模块

| 模块 | 职责 |
|---|---|
| `src/index.ts` | 启动 OAuth/MCP 与本机管理面板，启动前验证 happy-agent |
| `src/happy-agent-cli.ts` | 安全执行 argv、解析原生 JSON、机器/目录策略、按 session 串行化 |
| `src/mcp.ts` | 9 个 MCP 工具、scope 检查、LLM 审查、CLI 参数映射 |
| `src/oauth.ts` | 动态客户端注册、Authorization Code、S256 PKCE、token 和撤销 |
| `src/audit.ts` | 两阶段独立 LLM 审查、结构化输出、失败关闭和日志 |
| `src/storage.ts` | OAuth、管理员、机器策略、审核配置和审核日志 |
| `src/admin.ts` | 仅本机可访问的管理面板 |
| `src/public.ts` | 公网 OAuth/MCP 路由、grant-bound transport session 和限流 |
| `src/policy.ts` | 批准目录规范化与包含关系检查 |

仓库中不存在 Happy 协议适配器或持久 Goal task runner。

## 3. OAuth

当前 scope：

| Scope | 能力 |
|---|---|
| `happy:read` | 机器/session 查询、状态、历史和 wait |
| `happy:control` | 经审查的 spawn、send、resume 和 stop |

OAuth 支持：

- 动态客户端注册；
- Authorization Code；
- S256 PKCE；
- 精确 redirect URI 校验；
- loopback HTTP redirect；
- access token 1 小时；
- refresh token 30 天；
- 客户端和 token 撤销。

公网 MCP transport session 在当前进程内存中保存，绑定 OAuth client 和稳定的 authorization grant，空闲 6 小时清理。access token 刷新会继承 grant，因此可以继续使用同一 MCP session；同一 client 的另一次管理员授权会产生不同 grant，不能复用旧 session。

## 4. 独立 LLM 审查

以下操作必须先通过审查：

- `happy_spawn_session`
- `happy_send_message`
- `happy_resume_session`
- `happy_stop_session`

审查输入分为：

- `ADMIN_POLICY`：全局规则和机器规则；
- `TRUSTED_CONTROL_CONTEXT`：OAuth、已启用机器、批准目录和固定 CLI transport；
- `UNTRUSTED_REQUEST`：外部 AI 提供的 prompt 和参数。

默认可以启用两轮审核。第一轮放行后，第二轮执行对抗复核。每轮最多等待 45 秒；配置缺失、网络错误、非 2xx、输出超限或 JSON schema 不合法时拒绝。

纯查询和 wait 不调用 LLM，但仍受 OAuth、机器 allowlist 和批准目录约束。

## 5. MCP 工具

当前共 9 个工具。

| MCP 工具 | 原生 happy-agent 命令 | Scope | LLM |
|---|---|---|---|
| `happy_list_machines` | `machines [--active] --json` | read | 否 |
| `happy_list_sessions` | `list [--active] --json` | read | 否 |
| `happy_session_status` | `status <id> --json` | read | 否 |
| `happy_session_history` | `history <id> --limit N --json` | read | 否 |
| `happy_spawn_session` | `spawn --machine ... --path ... --json` | control | 是 |
| `happy_send_message` | `send <id> <message> [--yolo] --json` | control | 是 |
| `happy_wait_session` | `wait <id> --timeout N` | read | 否 |
| `happy_resume_session` | `resume <id> --json` | control | 是 |
| `happy_stop_session` | `stop <id>` | control | 是 |

未暴露的操作不是隐藏工具，而是代码中完全不存在。

## 6. 子进程安全

所有调用使用：

```ts
spawn(binary, args, {
  shell: false,
  stdio: ['ignore', 'pipe', 'pipe']
})
```

安全属性：

- 不拼接 shell command；
- message、路径和 ID 各自作为单个 argv 值传递；
- stdin 关闭，不允许命令进入交互模式；
- stdout/stderr 各自受总输出上限保护；
- 每个命令有超时，超时先 SIGTERM，随后 SIGKILL；
- JSON 命令必须返回完整合法 JSON；
- 非零退出码和无效 JSON 失败关闭；
- MCP 不记录完整 argv，因此不会把任务 prompt 写入服务日志。

启动时依次运行 `happy-agent --version` 和 `happy-agent auth status`。二者任一失败，MCP 不监听端口。

## 7. 查询状态

每次查询都会启动一个新的 `happy-agent` 子进程，不读取 relay 或数据库内部状态：

- 机器列表来自 `machines --json`；
- session 列表来自 `list --json`；
- live status 来自 `status --json`；
- 历史来自 `history --json`。

MCP 在 CLI 返回后执行第二层过滤：

1. 机器必须由管理员启用；
2. session metadata 中的 machine ID 必须对应启用机器；
3. session path 必须位于该机器批准目录。

`active`、`busy` 和 status 的准确语义由原生 `happy-agent` 决定。MCP 不补写或伪造状态。

## 8. Send 与等待

`happy_send_message` 分两步：

1. 执行 `happy-agent send ... --json`；
2. 仅在 `wait_seconds>0` 时执行 `happy-agent wait ... --timeout N`。

这样可以明确区分：

- send 成功：CLI 已完成消息投递路径；
- wait completed：原生 wait 观察到 Agent idle；
- wait timed_out：消息已经发送，但等待窗口内没有观察到 idle。

返回示例：

```json
{
  "sessionId": "...",
  "messageDispatched": true,
  "completionStatus": "timed_out"
}
```

wait 超时不会中断远端 turn，也不会自动重发消息。调用者应查询 status/history 后再决定下一步。

原生 send 没有 idempotency key，因此 MCP 不能证明 transport error 后消息一定未送达。MCP 只在 send 子进程以零退出码和合法 JSON 返回后设置 `messageDispatched=true`。

## 9. 并发

MCP 在单个服务进程中按 key 串行化有副作用的命令：

- send/resume/stop：`session:<id>`
- spawn：`machine:<id>`

这防止两个 OAuth 客户端通过同一 MCP 进程同时操作相同 session。它不替代 Happy 自己的跨进程锁；管理员从别的终端直接运行 `happy-agent` 仍属于独立控制者。

`resume` 还有一条外部保护：如果 `happy-agent list --json` 当前报告 session active，MCP 拒绝执行 resume，避免明显的重复实例启动。

## 10. Stop 语义

`happy_stop_session` 只执行官方 `happy-agent stop <id>`。零退出码表示 CLI 接受了操作，MCP 返回 `acknowledged=true`。

MCP 不再：

- 调用 machine stop-session RPC；
- 修改 relay active 字段；
- 等待数据库稳定窗口；
- 自动调用 kill/archive。

因此 stop 是否最终结束远端进程完全遵循当前安装版 `happy-agent` 的原生语义。

## 11. 明确删除的旧能力

以下旧控制面已从源码、依赖和工具目录删除：

- Happy REST/WebSocket/加密实现；
- generic machine/session RPC；
- abort 与 permission response；
- 直接 shell；
- 文件读写、目录树和 ripgrep；
- goal action；
- kill、archive、delete；
- Codex yolo Goal task；
- task 持久化、恢复、取消和 task OAuth scope。

数据库迁移会删除旧 `tasks` 表，但保留 OAuth、管理员、机器策略和审核数据。

## 12. 运维验证

```bash
happy-agent --version
happy-agent auth status
happy-agent machines --json
pnpm typecheck
pnpm test
pnpm build
```

真实 OAuth smoke 只验证 OAuth、MCP 初始化和 9 个工具的发现，不执行任何远端控制命令。
