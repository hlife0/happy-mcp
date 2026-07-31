# Happy MCP

Happy MCP 是安装版 `happy-agent` 的外接安全桥。外部 AI 通过 OAuth 调用 MCP；MCP 在管理员机器策略和独立 LLM 审查通过后，以非交互子进程方式执行与人类相同的 `happy-agent` CLI 命令。

```text
MCP client -> OAuth -> machine/path policy -> LLM review -> happy-agent argv
```

本仓库：

- 不包含 Happy 官方源码；
- 不导入 `happy-agent`、`happy-cli`、`happy-server` 或 relay 内部模块；
- 不实现 Happy 的 REST、WebSocket、加密或 RPC 协议；
- 不要求修改任何 Happy 官方代码；
- 只依赖管理员已经安装、认证并可正常使用的 `happy-agent` 可执行文件。

完整工具和运行语义见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

## 前置条件

```bash
happy-agent --version
happy-agent auth status
happy-agent machines --json
```

三条命令必须在运行 MCP 的同一 OS 用户和环境中成功。MCP 不接管 Happy 登录，也不保存 Happy 账户凭据。

## 安装

要求 Node.js 20 以上和 pnpm 10.11。

```bash
cd /path/to/happy-mcp
pnpm install
pnpm test
pnpm build
```

启动示例：

```bash
HAPPY_MCP_PUBLIC_URL=https://mcp.example.com \
HAPPY_MCP_DATA_DIR=/var/lib/happy-mcp \
HAPPY_AGENT_BIN=/usr/local/bin/happy-agent \
node dist/index.mjs
```

配置示例见 [.env.example](./.env.example)，systemd 示例见 [deploy/happy-mcp.service](./deploy/happy-mcp.service)。

## 管理配置

本机管理面板默认绑定 `127.0.0.1:3021`。管理员在面板中配置：

- 哪些由 `happy-agent machines --json` 发现的机器允许 MCP 使用；
- 每台机器允许的工作目录；
- 每台机器的自然语言放行规则；
- LLM 审查 API、模型、API key、全局规则和双重审核开关；
- OAuth 客户端授权和撤销。

机器默认禁用。审核配置缺失、超时、返回错误或结构化结果不合法时，有副作用的操作失败关闭。

## 暴露的原生操作

当前只包装原生 `happy-agent` 已公开的 9 类操作：

- `machines --json`
- `list --json`
- `status --json`
- `history --json`
- `spawn --json`
- `send --json`
- `wait`
- `resume --json`
- `stop`

没有对应原生命令的 abort、permission、goal、shell、文件、kill、archive、delete 和持久 task 不会通过 MCP 暴露。

## 数据边界

MCP 自己的数据位于 `HAPPY_MCP_DATA_DIR`：

- `happy-mcp.sqlite`
- `storage.key`
- `admin-password.txt`

其中保存 OAuth、管理员会话、机器策略、审核设置和审核日志。审核 API key 与敏感 OAuth 元数据使用 `storage.key` 加密。

Happy 登录凭据由 `happy-agent` 自己管理，不进入 MCP 数据库。

## 验证

```bash
pnpm typecheck
pnpm test
pnpm build
HAPPY_MCP_SMOKE_URL=https://mcp.example.com pnpm smoke
```

OAuth smoke 会注册临时客户端、完成 PKCE、初始化 MCP、验证工具目录，然后撤销临时客户端并确认 token 失效。
