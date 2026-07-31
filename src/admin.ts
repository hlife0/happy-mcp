import { timingSafeEqual } from 'node:crypto';
import type { Express, NextFunction, Request, RequestHandler, Response } from 'express';
import express from 'express';
import type { HappyMcpConfig } from './config';
import type { HappyAgentController } from './happy-agent-cli';
import { escapeHtml } from './security';
import type { AuditLogRecord, AuditSettings, MachinePolicy, Storage } from './storage';

type AdminDeps = {
    config: HappyMcpConfig;
    storage: Storage;
    happy: HappyAgentController;
};

type AdminSession = {
    token: string;
    csrfToken: string;
};

type AdminMachine = Awaited<ReturnType<HappyAgentController['listAllMachinesForAdmin']>>[number];

export function createAdminApp(deps: AdminDeps): Express {
    const app = express();
    const loginAttempts = new Map<string, { startedAt: number; failures: number }>();

    app.disable('x-powered-by');
    app.use(express.urlencoded({ extended: false, limit: '128kb' }));
    app.use((_req, res, next) => {
        setAdminSecurityHeaders(res);
        next();
    });

    app.get('/health', (_req, res) => {
        res.json({ ok: true, service: 'happy-mcp-admin', network: 'localhost-only' });
    });
    app.get('/login', (req, res) => {
        if (readAdminSession(req, deps.storage)) {
            res.redirect(303, '/');
            return;
        }
        res.type('html').send(renderLogin());
    });
    app.post('/login', (req, res) => {
        const key = req.ip || req.socket.remoteAddress || 'unknown';
        if (loginBlocked(loginAttempts, key)) {
            res.status(429).type('html').send(renderLogin('登录尝试过多，请稍后再试。'));
            return;
        }
        const password = formString(req, 'password');
        if (!deps.storage.verifyAdminPassword(password)) {
            recordLoginFailure(loginAttempts, key);
            res.status(401).type('html').send(renderLogin('管理员密码不正确。'));
            return;
        }
        loginAttempts.delete(key);
        const session = deps.storage.createAdminSession();
        res.cookie('happy_mcp_admin', session.token, {
            httpOnly: true,
            sameSite: 'strict',
            path: '/',
            maxAge: 12 * 60 * 60 * 1000,
        });
        res.redirect(303, '/');
    });

    app.use(requireAdmin(deps.storage));

    app.get('/', asyncRoute(async (req, res) => {
        const session = res.locals.admin as AdminSession;
        let machines: AdminMachine[] = [];
        let machineError = '';
        try {
            machines = await deps.happy.listAllMachinesForAdmin();
        } catch (error) {
            machineError = errorMessage(error);
        }
        res.type('html').send(renderDashboard({
            csrfToken: session.csrfToken,
            config: deps.config,
            settings: deps.storage.getAuditSettings(),
            machines,
            machineError,
            clients: deps.storage.listOAuthClients(),
            auditLog: deps.storage.listAuditLog(100),
            notice: noticeText(formString(req, 'saved')),
        }));
    }));

    app.post('/settings/audit', requireCsrf, (req, res) => {
        try {
            const baseUrl = formString(req, 'base_url').trim().replace(/\/+$/, '');
            const model = formString(req, 'model').trim();
            validateAuditEndpoint(baseUrl, model);
            const apiStyle = formString(req, 'api_style') === 'responses' ? 'responses' : 'chat_completions';
            const current = deps.storage.getAuditSettings();
            deps.storage.saveAuditSettings({
                baseUrl,
                model,
                apiStyle,
                globalRules: formString(req, 'global_rules'),
                doubleCheck: formBoolean(req, 'double_check'),
                apiKey: formString(req, 'api_key') || undefined,
            });
            if (formBoolean(req, 'clear_api_key')) deps.storage.clearAuditApiKey();
            if (!current.apiKeyConfigured && !formString(req, 'api_key') && !formBoolean(req, 'clear_api_key')) {
                // An incomplete configuration is allowed, but all writes continue to fail closed.
            }
            res.redirect(303, '/?saved=audit#review');
        } catch (error) {
            renderAdminError(res, error);
        }
    });

    app.post('/machines/:machineId', requireCsrf, asyncRoute(async (req, res) => {
        const machineId = routeParam(req, 'machineId');
        const machines = await deps.happy.listAllMachinesForAdmin();
        if (!machines.some((item) => item.raw.id === machineId)) throw new Error('这台机器当前不在 Happy 账号中。');
        const enabled = deps.storage.getMachinePolicy(machineId).enabled;
        const roots = formString(req, 'roots').split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
        const rules = formString(req, 'rules').trim();
        if (enabled && roots.length === 0) throw new Error('启用机器前至少要填写一个批准目录。');
        if (enabled && !rules) throw new Error('启用机器前必须填写自然语言放行规则。');
        for (const root of roots) {
            if (!root.startsWith('/')) throw new Error(`批准目录必须是绝对路径：${root}`);
        }
        deps.storage.saveMachinePolicy({
            machineId,
            enabled,
            alias: formString(req, 'alias'),
            roots,
            rules,
        });
        res.redirect(303, `/?saved=machine#machine-${encodeURIComponent(machineId)}`);
    }));

    app.post('/machines/:machineId/access', requireCsrf, asyncRoute(async (req, res) => {
        const machineId = routeParam(req, 'machineId');
        const machines = await deps.happy.listAllMachinesForAdmin();
        if (!machines.some((item) => item.raw.id === machineId)) throw new Error('这台机器当前不在 Happy 账号中。');
        const action = formString(req, 'action');
        if (action !== 'enable' && action !== 'disable') throw new Error('无效的 MCP 访问操作。');
        const current = deps.storage.getMachinePolicy(machineId);
        const enabled = action === 'enable';
        if (enabled && current.roots.length === 0) throw new Error('允许 MCP 访问前至少要保存一个批准目录。');
        if (enabled && !current.rules.trim()) throw new Error('允许 MCP 访问前必须保存本机自然语言放行规则。');
        deps.storage.saveMachinePolicy({
            machineId,
            enabled,
            alias: current.alias,
            roots: current.roots,
            rules: current.rules,
        });
        res.redirect(303, `/?saved=machine_access#machine-${encodeURIComponent(machineId)}`);
    }));

    app.post('/clients/:clientId/revoke', requireCsrf, (req, res) => {
        deps.storage.revokeOAuthClient(routeParam(req, 'clientId'));
        res.redirect(303, '/?saved=client#oauth');
    });

    app.post('/password', requireCsrf, (req, res) => {
        const password = formString(req, 'password');
        const confirmation = formString(req, 'password_confirm');
        if (password !== confirmation) {
            renderAdminError(res, new Error('两次输入的密码不一致。'));
            return;
        }
        try {
            deps.storage.changeAdminPassword(password);
            res.clearCookie('happy_mcp_admin', { path: '/' });
            res.redirect(303, '/login');
        } catch (error) {
            renderAdminError(res, error);
        }
    });

    app.post('/logout', requireCsrf, (req, res) => {
        const session = res.locals.admin as AdminSession;
        deps.storage.deleteAdminSession(session.token);
        res.clearCookie('happy_mcp_admin', { path: '/' });
        res.redirect(303, '/login');
    });

    app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
        console.error('[happy-mcp] admin request failed:', error);
        renderAdminError(res, error);
    });
    return app;
}

function requireAdmin(storage: Storage): RequestHandler {
    return (req, res, next) => {
        const session = readAdminSession(req, storage);
        if (!session) {
            res.clearCookie('happy_mcp_admin', { path: '/' });
            res.redirect(303, '/login');
            return;
        }
        res.locals.admin = session;
        next();
    };
}

function requireCsrf(req: Request, res: Response, next: NextFunction): void {
    const session = res.locals.admin as AdminSession | undefined;
    if (!session || !safeTextEqual(formString(req, 'csrf_token'), session.csrfToken)) {
        res.status(403).type('html').send(renderMessagePage('请求已拒绝', 'CSRF 校验失败，请刷新页面后重试。'));
        return;
    }
    next();
}

function readAdminSession(req: Request, storage: Storage): AdminSession | null {
    const token = parseCookies(req.headers.cookie).happy_mcp_admin;
    if (!token) return null;
    const stored = storage.getAdminSession(token);
    return stored ? { token, csrfToken: stored.csrfToken } : null;
}

function parseCookies(header: string | undefined): Record<string, string> {
    const result: Record<string, string> = {};
    if (!header) return result;
    for (const part of header.split(';')) {
        const separator = part.indexOf('=');
        if (separator < 1) continue;
        const key = part.slice(0, separator).trim();
        try {
            result[key] = decodeURIComponent(part.slice(separator + 1).trim());
        } catch {
            // Ignore malformed cookies.
        }
    }
    return result;
}

function asyncRoute(handler: (req: Request, res: Response) => Promise<void>): RequestHandler {
    return (req, res, next) => {
        void handler(req, res).catch(next);
    };
}

function renderDashboard(input: {
    csrfToken: string;
    config: HappyMcpConfig;
    settings: AuditSettings;
    machines: AdminMachine[];
    machineError: string;
    clients: ReturnType<Storage['listOAuthClients']>;
    auditLog: AuditLogRecord[];
    notice: string;
}): string {
    const sortedMachines = [...input.machines].sort((left, right) => {
        if (left.raw.active !== right.raw.active) return left.raw.active ? -1 : 1;
        const leftName = left.machine.displayName || left.machine.host || left.raw.id;
        const rightName = right.machine.displayName || right.machine.host || right.raw.id;
        return leftName.localeCompare(rightName);
    });
    const machineHtml = sortedMachines.length > 0
        ? sortedMachines.map((item) => renderMachine(item, input.csrfToken)).join('')
        : `<p class="empty">${escapeHtml(input.machineError || '没有发现 Happy 机器。')}</p>`;
    const clientRows = input.clients.length > 0
        ? input.clients.map((client) => `<tr><td>${escapeHtml(client.clientName)}</td><td><code>${escapeHtml(shortId(client.clientId))}</code></td><td>${formatTime(client.createdAt)}</td><td>${client.revokedAt ? '<span class="state off">已撤销</span>' : '<span class="state on">有效</span>'}</td><td>${client.revokedAt ? '' : smallPostButton(`/clients/${encodeURIComponent(client.clientId)}/revoke`, input.csrfToken, '撤销')}</td></tr>`).join('')
        : '<tr><td colspan="5" class="empty">暂无 OAuth 客户端</td></tr>';
    const logRows = input.auditLog.length > 0
        ? input.auditLog.map((log) => `<tr><td>${formatTime(log.createdAt)}</td><td>${escapeHtml(log.action)}</td><td>${escapeHtml(shortId(log.machineId || ''))}</td><td><span class="state ${log.decision === 'allow' ? 'on' : 'deny'}">${escapeHtml(log.decision)}</span></td><td>${escapeHtml(log.riskLevel)}</td><td class="wrap">${escapeHtml(log.reason)}</td></tr>`).join('')
        : '<tr><td colspan="6" class="empty">暂无审核记录</td></tr>';
    const auditReady = input.settings.baseUrl && input.settings.model && input.settings.apiKeyConfigured;

    return page('Happy MCP 控制台', `
<header class="topbar"><div><p class="eyebrow">HAPPY MCP</p><h1>远程控制台</h1></div><div class="header-meta"><span class="state ${auditReady ? 'on' : 'deny'}">审核 ${auditReady ? '已就绪' : '未就绪'}</span><form method="post" action="/logout">${csrf(input.csrfToken)}<button class="quiet" type="submit">退出</button></form></div></header>
<nav class="nav"><a href="#machines">机器</a><a href="#review">审核</a><a href="#oauth">OAuth</a><a href="#logs">日志</a><a href="#security">安全</a></nav>
${input.notice ? `<p class="notice" role="status">${escapeHtml(input.notice)}</p>` : ''}
<main>
<section id="machines"><div class="section-head"><div><h2>机器访问</h2><p>${input.machines.filter((item) => item.raw.active).length} 台在线 / ${input.machines.length} 台已发现</p></div><span class="binding">MCP ${escapeHtml(input.config.publicBaseUrl)}/mcp</span></div><div class="machine-list">${machineHtml}</div></section>
<section id="review"><div class="section-head"><div><h2>独立 LLM 审核</h2><p><span class="state ${auditReady ? 'on' : 'deny'}">${auditReady ? '写操作可审核' : '写操作失败关闭'}</span></p></div></div>
<form method="post" action="/settings/audit" class="settings-form">${csrf(input.csrfToken)}
<div class="field span-2"><label for="base_url">API Base URL</label><input id="base_url" name="base_url" type="url" value="${escapeHtml(input.settings.baseUrl)}" placeholder="https://api.example.com/v1"></div>
<div class="field"><label for="model">模型</label><input id="model" name="model" value="${escapeHtml(input.settings.model)}"></div>
<div class="field"><label for="api_style">API 协议</label><select id="api_style" name="api_style"><option value="chat_completions"${selected(input.settings.apiStyle === 'chat_completions')}>Chat Completions</option><option value="responses"${selected(input.settings.apiStyle === 'responses')}>Responses</option></select></div>
<div class="field span-2"><label for="api_key">API Key <span>${input.settings.apiKeyConfigured ? '已保存，留空不变' : '未配置'}</span></label><input id="api_key" name="api_key" type="password" autocomplete="new-password"></div>
<label class="check"><input type="checkbox" name="double_check" value="1"${checked(input.settings.doubleCheck)}> 对放行结果进行第二次对抗审核</label>
<label class="check"><input type="checkbox" name="clear_api_key" value="1"> 清除已保存 API Key</label>
<div class="field span-4"><label for="global_rules">全局放行规则</label><textarea id="global_rules" name="global_rules" rows="5">${escapeHtml(input.settings.globalRules)}</textarea></div>
<div class="actions span-4"><button type="submit">保存审核设置</button></div></form></section>
<section id="oauth"><div class="section-head"><div><h2>OAuth 客户端</h2><p>授权由管理员密码确认</p></div></div><div class="table-scroll"><table><thead><tr><th>客户端</th><th>ID</th><th>注册时间</th><th>状态</th><th></th></tr></thead><tbody>${clientRows}</tbody></table></div></section>
<section id="logs"><div class="section-head"><div><h2>审核日志</h2><p>最近 ${input.auditLog.length} 条</p></div></div><div class="table-scroll"><table><thead><tr><th>时间</th><th>动作</th><th>机器</th><th>决定</th><th>风险</th><th>理由</th></tr></thead><tbody>${logRows}</tbody></table></div></section>
<section id="security"><div class="section-head"><div><h2>管理员安全</h2><p>面板监听 ${escapeHtml(input.config.adminHost)}:${input.config.adminPort}</p></div></div><form method="post" action="/password" class="password-form">${csrf(input.csrfToken)}<div class="field"><label for="password">新密码</label><input id="password" name="password" type="password" autocomplete="new-password" required></div><div class="field"><label for="password_confirm">确认新密码</label><input id="password_confirm" name="password_confirm" type="password" autocomplete="new-password" required></div><div class="actions"><button type="submit">更改密码</button></div></form></section>
</main>`);
}

function renderMachine(item: AdminMachine, csrfToken: string): string {
    const metadata = asRecord(item.raw.metadata);
    const homeDir = textValue(metadata.homeDir);
    const agents = Object.entries(asRecord(metadata.cliAvailability))
        .filter(([, value]) => value === true)
        .map(([name]) => name)
        .join(', ');
    const policy: MachinePolicy = item.policy;
    const name = item.machine.displayName || item.machine.host || shortId(item.raw.id);
    return `<article class="machine" id="machine-${escapeHtml(item.raw.id)}">
<div class="machine-row"><div class="machine-identity"><h3>${escapeHtml(name)}</h3><p>${escapeHtml(item.machine.host)} · ${escapeHtml(item.machine.platform)} · <code>${escapeHtml(shortId(item.raw.id))}</code></p></div>
<div class="machine-online"><span class="state ${item.raw.active ? 'on' : 'off'}">${item.raw.active ? '当前在线' : '当前离线'}</span><small>${formatTime(item.raw.activeAt)}</small></div>
<div class="machine-access"><span class="state ${policy.enabled ? 'on' : 'off'}">MCP ${policy.enabled ? '已允许' : '未允许'}</span><form method="post" action="/machines/${encodeURIComponent(item.raw.id)}/access">${csrf(csrfToken)}<button type="submit" name="action" value="${policy.enabled ? 'disable' : 'enable'}" class="${policy.enabled ? 'danger' : ''}">${policy.enabled ? '禁止 MCP 访问' : '允许 MCP 访问'}</button></form></div></div>
<details class="machine-details"><summary><span>配置详情</span><span>${policy.roots.length} 个批准目录</span></summary>
<div class="machine-facts"><span>机器 ID <code>${escapeHtml(item.raw.id)}</code></span><span>主目录 <code>${escapeHtml(homeDir || '未知')}</code></span><span>可用 Agent ${escapeHtml(agents || '无')}</span></div>
<form method="post" action="/machines/${encodeURIComponent(item.raw.id)}" class="machine-form">${csrf(csrfToken)}
<div class="field"><label>别名</label><input name="alias" value="${escapeHtml(policy.alias)}" placeholder="${escapeHtml(item.machine.displayName || item.machine.host)}"></div>
<div class="field full"><label>批准目录 <span>${escapeHtml(homeDir)}</span></label><textarea name="roots" rows="3" placeholder="${escapeHtml(homeDir)}">${escapeHtml(policy.roots.join('\n'))}</textarea></div>
<div class="field full"><label>本机自然语言放行规则</label><textarea name="rules" rows="5">${escapeHtml(policy.rules)}</textarea></div>
<div class="machine-foot"><span>${policy.enabled ? '修改后的规则立即用于后续审核' : '保存配置后可在摘要行允许访问'}</span><button type="submit">保存机器配置</button></div></form></details></article>`;
}

function renderLogin(error = ''): string {
    return page('Happy MCP 登录', `<main class="login-shell"><section class="login"><p class="eyebrow">HAPPY MCP</p><h1>管理员登录</h1>${error ? `<p class="error-box" role="alert">${escapeHtml(error)}</p>` : ''}<form method="post" action="/login"><div class="field"><label for="password">管理员密码</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus></div><button type="submit">登录</button></form></section></main>`);
}

function page(title: string, body: string): string {
    return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${ADMIN_CSS}</style></head><body>${body}</body></html>`;
}

function renderAdminError(res: Response, error: unknown): void {
    if (res.headersSent) return;
    res.status(400).type('html').send(renderMessagePage('操作失败', errorMessage(error)));
}

function renderMessagePage(title: string, message: string): string {
    return page(title, `<main class="message"><section><p class="eyebrow">HAPPY MCP</p><h1>${escapeHtml(title)}</h1><p class="error-box">${escapeHtml(message)}</p><a class="button-link" href="/">返回控制台</a></section></main>`);
}

function smallPostButton(action: string, csrfToken: string, label: string): string {
    return `<form method="post" action="${escapeHtml(action)}">${csrf(csrfToken)}<button type="submit" class="danger small">${escapeHtml(label)}</button></form>`;
}

function csrf(token: string): string {
    return `<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">`;
}

function formString(req: Request, name: string): string {
    const body = req.body as Record<string, unknown> | undefined;
    const value = body?.[name] ?? (req.query[name] as unknown);
    return typeof value === 'string' ? value : '';
}

function formBoolean(req: Request, name: string): boolean {
    return formString(req, name) === '1';
}

function routeParam(req: Request, name: string): string {
    const value = req.params[name];
    if (!value) throw new Error(`缺少路由参数：${name}`);
    return value;
}

function validateAuditEndpoint(baseUrl: string, model: string): void {
    if (!baseUrl && !model) return;
    if (!baseUrl || !model) throw new Error('API Base URL 和模型必须同时填写。');
    const url = new URL(baseUrl);
    if (url.username || url.password || url.search || url.hash) throw new Error('API Base URL 不能包含凭据、查询参数或片段。');
    if (url.protocol === 'https:') return;
    if (url.protocol === 'http:' && isPrivateHost(url.hostname)) return;
    throw new Error('公网审核 API 必须使用 HTTPS；HTTP 仅允许本机或私网地址。');
}

function isPrivateHost(hostname: string): boolean {
    const host = hostname.toLowerCase();
    if (host === 'localhost' || host === '::1' || host === '[::1]' || host === '127.0.0.1') return true;
    const octets = host.split('.').map(Number);
    if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return false;
    const [a, b] = octets as [number, number, number, number];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

function loginBlocked(attempts: Map<string, { startedAt: number; failures: number }>, key: string): boolean {
    const value = attempts.get(key);
    if (!value) return false;
    if (value.startedAt < Date.now() - 15 * 60 * 1000) {
        attempts.delete(key);
        return false;
    }
    return value.failures >= 10;
}

function recordLoginFailure(attempts: Map<string, { startedAt: number; failures: number }>, key: string): void {
    const current = attempts.get(key);
    if (!current || current.startedAt < Date.now() - 15 * 60 * 1000) {
        attempts.set(key, { startedAt: Date.now(), failures: 1 });
        return;
    }
    current.failures += 1;
}

function safeTextEqual(left: string, right: string): boolean {
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);
    return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function setAdminSecurityHeaders(res: Response): void {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

function noticeText(value: string): string {
    if (value === 'audit') return '审核设置已保存。';
    if (value === 'machine') return '机器策略已保存。';
    if (value === 'machine_access') return '机器 MCP 访问状态已更新。';
    if (value === 'client') return 'OAuth 客户端及其令牌已撤销。';
    return '';
}

function selected(value: boolean): string {
    return value ? ' selected' : '';
}

function checked(value: boolean): string {
    return value ? ' checked' : '';
}

function shortId(value: string): string {
    return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}

function formatTime(value: number): string {
    if (!value) return '';
    return new Date(value).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

function asRecord(value: unknown): Record<string, unknown> {
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function textValue(value: unknown): string {
    return typeof value === 'string' ? value : '';
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

const ADMIN_CSS = `
:root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#18212b;background:#f5f7f8;letter-spacing:0}*{box-sizing:border-box}body{margin:0;font-size:14px}button,input,textarea,select{font:inherit;letter-spacing:0}button{cursor:pointer}.topbar{height:76px;padding:0 max(24px,calc((100vw - 1240px)/2));display:flex;align-items:center;justify-content:space-between;background:#17212a;color:#fff;border-bottom:3px solid #2f855a}.topbar h1{font-size:21px;margin:2px 0 0}.eyebrow{margin:0;color:#68d391;font-size:11px;font-weight:800}.header-meta{display:flex;align-items:center;gap:12px}.nav{height:46px;display:flex;align-items:center;gap:24px;padding:0 max(24px,calc((100vw - 1240px)/2));background:#fff;border-bottom:1px solid #dce2e6;position:sticky;top:0;z-index:2}.nav a{color:#334155;text-decoration:none;font-weight:650}.nav a:hover{color:#166534}main{max-width:1240px;margin:0 auto;padding:0 24px 48px}section{padding:30px 0;border-bottom:1px solid #dce2e6}.section-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:18px;gap:16px}.section-head h2{margin:0 0 4px;font-size:18px}.section-head p{margin:0;color:#64748b}.binding{color:#475569;font-family:ui-monospace,monospace;font-size:12px}.notice{max-width:1192px;margin:18px auto 0;padding:11px 14px;background:#e8f5ed;border:1px solid #93c5a7;border-radius:5px;color:#14532d}.machine-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.machine{background:#fff;border:1px solid #d8dee3;border-radius:6px;overflow:hidden}.machine-head{display:flex;align-items:flex-start;justify-content:space-between;padding:16px 18px;background:#fafbfc;border-bottom:1px solid #e5e9ec}.machine-head h3{font-size:16px;margin:0 0 4px}.machine-head p{margin:0;color:#64748b;font-size:12px}.machine-form{display:grid;grid-template-columns:1fr 150px;gap:14px;padding:16px 18px}.enable{grid-column:1/-1;font-weight:750}.field{display:grid;gap:6px;min-width:0}.field label{font-weight:700;font-size:13px}.field label span{color:#64748b;font-weight:400;margin-left:6px}.field.full,.span-4{grid-column:1/-1}.span-2{grid-column:span 2}input,textarea,select{width:100%;border:1px solid #aeb8c2;border-radius:4px;background:#fff;padding:9px 10px;color:#17202a}input,select{height:40px}textarea{resize:vertical;line-height:1.45}.machine-foot{grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;gap:12px;color:#64748b;font-size:12px}button,.button-link{border:1px solid #236b49;border-radius:4px;background:#236b49;color:#fff;font-weight:700;padding:9px 14px;text-decoration:none;display:inline-block}button:hover,.button-link:hover{background:#185437}.quiet{background:transparent;border-color:#718096;padding:7px 11px}.danger{background:#fff;color:#a32424;border-color:#cf8f8f}.danger:hover{background:#fff1f1}.small{padding:6px 10px;font-size:12px}.settings-form{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.check{display:flex;align-items:center;gap:8px}.check input,.enable input{width:16px;height:16px}.actions{display:flex;justify-content:flex-end;align-items:end}.password-form{display:grid;grid-template-columns:1fr 1fr auto;gap:16px;align-items:end;max-width:850px}.table-scroll{overflow:auto;border:1px solid #d8dee3;border-radius:5px;background:#fff}table{border-collapse:collapse;width:100%;min-width:760px}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #e7ebee;vertical-align:top}th{font-size:11px;text-transform:uppercase;color:#64748b;background:#f8fafb}tbody tr:last-child td{border-bottom:0}td small{display:block;color:#64748b;margin-top:4px;max-width:380px;overflow-wrap:anywhere}.wrap{max-width:420px;overflow-wrap:anywhere}.error-text{color:#a32424}.state{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:800;white-space:nowrap}.state.on{color:#166534;background:#dcfce7}.state.off{color:#475569;background:#e9eef2}.state.deny{color:#991b1b;background:#fee2e2}.state.work{color:#854d0e;background:#fef3c7}.empty{text-align:center;color:#64748b;padding:22px}.login-shell,.message{min-height:100vh;display:grid;place-items:center;padding:24px}.login,.message section{width:min(420px,100%);background:#fff;border:1px solid #d8dee3;border-radius:6px;padding:28px;box-shadow:0 10px 28px rgba(23,33,42,.1)}.login h1,.message h1{font-size:22px;margin:5px 0 22px}.login form{display:grid;gap:16px}.error-box{padding:10px 12px;background:#fff1f1;border:1px solid #e5a4a4;border-radius:4px;color:#8a1c1c;margin:0 0 16px;line-height:1.45}.message p{margin-bottom:18px}.message .eyebrow{margin:0}.message h1{margin-top:5px}
.machine-list{display:grid;grid-template-columns:minmax(0,1fr);gap:10px}.machine-row{display:grid;grid-template-columns:minmax(260px,1fr) auto minmax(230px,auto);align-items:center;gap:20px;padding:14px 18px;background:#fff}.machine-identity{min-width:0}.machine-identity h3{font-size:15px;margin:0 0 4px}.machine-identity p{margin:0;color:#64748b;font-size:12px;overflow-wrap:anywhere}.machine-online{display:grid;justify-items:start;gap:4px}.machine-online small{color:#64748b;font-size:10px}.machine-access{display:flex;align-items:center;justify-content:flex-end;gap:10px}.machine-details{border-top:1px solid #e5e9ec;background:#fafbfc}.machine-details summary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:11px 18px;color:#475569;font-size:12px;font-weight:700;cursor:pointer;list-style-position:inside}.machine-details[open] summary{border-bottom:1px solid #e5e9ec}.machine-facts{display:flex;flex-wrap:wrap;gap:10px 24px;padding:14px 18px 0;color:#64748b;font-size:12px}.machine-facts code{overflow-wrap:anywhere}.machine-details .machine-form{padding:14px 18px 18px}
@media(max-width:800px){.topbar{height:auto;padding:16px 18px}.header-meta{align-items:flex-end;flex-direction:column;gap:7px}.nav{padding:0 18px;gap:18px;overflow-x:auto}main{padding:0 16px 36px}.settings-form{grid-template-columns:1fr}.span-2,.span-4{grid-column:1}.password-form{grid-template-columns:1fr}.section-head{flex-direction:column}.binding{overflow-wrap:anywhere}.machine-row{grid-template-columns:1fr;gap:10px}.machine-online{display:flex;align-items:center;gap:8px}.machine-access{justify-content:space-between;flex-wrap:wrap}.machine-details summary{align-items:flex-start;flex-direction:column;gap:4px}.machine-form{grid-template-columns:1fr}.field.full,.machine-foot{grid-column:1}.machine-foot{align-items:flex-start;flex-direction:column}}
`;
