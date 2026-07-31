import { createHash, randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import { clearInterval, setInterval } from 'node:timers';
import {
    getOAuthProtectedResourceMetadataUrl,
    mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type { RiskAuditor } from './audit';
import type { HappyMcpConfig } from './config';
import type { HappyAgentController } from './happy-agent-cli';
import { createHappyMcpServer } from './mcp';
import { HAPPY_MCP_SCOPES, type HappyOAuthProvider } from './oauth';
import { publicContentSecurityPolicy } from './security';

type PublicServerDeps = {
    config: HappyMcpConfig;
    happy: HappyAgentController;
    auditor: RiskAuditor;
    oauth: HappyOAuthProvider;
};

type McpSession = {
    transport: StreamableHTTPServerTransport;
    server: McpServer;
    clientId: string;
    accessTokenHash: string;
    lastAccessAt: number;
};

export type PublicMcpApp = {
    app: Express;
    close(): Promise<void>;
};

const MAX_MCP_REQUESTS_PER_MINUTE = 240;
const MCP_SESSION_IDLE_MS = 6 * 60 * 60 * 1000;

export function createPublicMcpApp(deps: PublicServerDeps): PublicMcpApp {
    const { config, oauth } = deps;
    const app = express();
    const sessions = new Map<string, McpSession>();
    const rateWindows = new Map<string, { startedAt: number; count: number }>();
    const resourceUrl = new URL(`${config.publicBaseUrl}/mcp`);
    const issuerUrl = new URL(config.publicBaseUrl);
    const allowedHosts = new Set([
        issuerUrl.hostname.toLowerCase(),
        '127.0.0.1',
        'localhost',
        '[::1]',
        '::1',
    ]);

    app.disable('x-powered-by');
    app.set('trust proxy', ['loopback']);
    app.use((req, res, next) => {
        setPublicSecurityHeaders(res);
        if (!hostAllowed(req, allowedHosts)) {
            res.status(421).json({ error: 'misdirected_request' });
            return;
        }
        next();
    });
    app.use(express.json({ limit: '256kb', type: ['application/json', 'application/*+json'] }));

    app.get('/mcp-health', (_req, res) => {
        res.json({ ok: true, service: 'happy-mcp', oauth: true, transport: 'streamable-http' });
    });
    app.get('/mcp-info', (_req, res) => {
        res.json({
            name: 'Happy MCP',
            endpoint: resourceUrl.href,
            authorization: issuerUrl.href,
            scopes: HAPPY_MCP_SCOPES,
        });
    });

    app.use(mcpAuthRouter({
        provider: oauth,
        issuerUrl,
        baseUrl: issuerUrl,
        resourceServerUrl: resourceUrl,
        resourceName: 'Happy remote coding control',
        serviceDocumentationUrl: new URL('/mcp-info', issuerUrl),
        scopesSupported: [...HAPPY_MCP_SCOPES],
    }));

    const bearer = requireBearerAuth({
        verifier: oauth,
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl),
    });

    app.all('/mcp', bearer, (req, res, next) => {
        if (!consumeRateLimit(req, res, rateWindows)) return;
        void handleMcpRequest(req, res, deps, sessions).catch(next);
    });

    app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
        console.error('[happy-mcp] public request failed:', error);
        if (res.headersSent) return;
        res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
        });
    });

    const cleanupTimer = setInterval(() => {
        const cutoff = Date.now() - MCP_SESSION_IDLE_MS;
        for (const [sessionId, entry] of sessions) {
            if (entry.lastAccessAt >= cutoff) continue;
            sessions.delete(sessionId);
            void entry.transport.close().catch((error) => {
                console.error(`[happy-mcp] failed to close idle MCP session ${sessionId}:`, error);
            });
        }
        for (const [key, window] of rateWindows) {
            if (window.startedAt < Date.now() - 2 * 60 * 1000) rateWindows.delete(key);
        }
    }, 60_000);
    return {
        app,
        async close() {
            clearInterval(cleanupTimer);
            const active = [...sessions.values()];
            sessions.clear();
            await Promise.allSettled(active.map((entry) => closeTransport(entry.transport)));
        },
    };
}

async function closeTransport(transport: StreamableHTTPServerTransport): Promise<void> {
    let completed = false;
    const closing = transport.close()
        .catch((error) => console.error('[happy-mcp] failed to close MCP transport:', error))
        .finally(() => { completed = true; });
    await Promise.race([closing, new Promise<void>((resolve) => setTimeout(resolve, 2000))]);
    if (!completed) console.warn('[happy-mcp] MCP transport close exceeded 2 seconds; continuing shutdown');
}

export function listen(app: Express, host: string, port: number): Promise<Server> {
    return new Promise((resolve, reject) => {
        const server = app.listen(port, host, () => resolve(server));
        server.once('error', reject);
    });
}

async function handleMcpRequest(
    req: Request,
    res: Response,
    deps: PublicServerDeps,
    sessions: Map<string, McpSession>,
): Promise<void> {
    const auth = req.auth;
    if (!auth) {
        res.status(401).json({ error: 'invalid_token' });
        return;
    }
    const sessionId = singleHeader(req.headers['mcp-session-id']);
    if (sessionId) {
        const entry = sessions.get(sessionId);
        if (!entry) {
            sendMcpError(res, 404, 'MCP session was not found or has expired.');
            return;
        }
        if (!sameAuthorization(entry, auth)) {
            sendMcpError(res, 403, 'This MCP session belongs to a different OAuth grant.');
            return;
        }
        entry.lastAccessAt = Date.now();
        await entry.transport.handleRequest(req, res, req.method === 'POST' ? req.body : undefined);
        return;
    }

    if (req.method !== 'POST' || !isInitializeRequest(req.body)) {
        sendMcpError(res, 400, 'A valid MCP session ID or initialize request is required.');
        return;
    }

    let entry: McpSession;
    const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: true,
        onsessioninitialized: (newSessionId) => {
            sessions.set(newSessionId, entry);
        },
        onsessionclosed: (closedSessionId) => {
            sessions.delete(closedSessionId);
        },
    });
    const mcpServer = createHappyMcpServer({
        authInfo: auth,
        happy: deps.happy,
        auditor: deps.auditor,
    });
    entry = {
        transport,
        server: mcpServer,
        clientId: auth.clientId,
        accessTokenHash: hashAccessToken(auth.token),
        lastAccessAt: Date.now(),
    };
    transport.onclose = () => {
        const id = transport.sessionId;
        if (id) sessions.delete(id);
    };
    transport.onerror = (error) => console.error('[happy-mcp] transport error:', error);
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
}

function sameAuthorization(entry: McpSession, auth: AuthInfo): boolean {
    return entry.clientId === auth.clientId && entry.accessTokenHash === hashAccessToken(auth.token);
}

function hashAccessToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

function consumeRateLimit(
    req: Request,
    res: Response,
    windows: Map<string, { startedAt: number; count: number }>,
): boolean {
    const auth = req.auth;
    if (!auth) return false;
    const key = hashAccessToken(auth.token);
    const now = Date.now();
    const current = windows.get(key);
    const window = !current || current.startedAt <= now - 60_000
        ? { startedAt: now, count: 0 }
        : current;
    window.count += 1;
    windows.set(key, window);
    res.setHeader('X-RateLimit-Limit', String(MAX_MCP_REQUESTS_PER_MINUTE));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, MAX_MCP_REQUESTS_PER_MINUTE - window.count)));
    if (window.count <= MAX_MCP_REQUESTS_PER_MINUTE) return true;
    res.setHeader('Retry-After', String(Math.max(1, Math.ceil((window.startedAt + 60_000 - now) / 1000))));
    res.status(429).json({ error: 'rate_limit_exceeded' });
    return false;
}

function hostAllowed(req: Request, allowed: Set<string>): boolean {
    const header = req.headers.host;
    if (!header) return false;
    try {
        return allowed.has(new URL(`http://${header}`).hostname.toLowerCase());
    } catch {
        return false;
    }
}

function singleHeader(value: string | string[] | undefined): string | null {
    return typeof value === 'string' && value.length > 0 ? value : null;
}

function sendMcpError(res: Response, status: number, message: string): void {
    res.status(status).json({
        jsonrpc: '2.0',
        error: { code: -32000, message },
        id: null,
    });
}

function setPublicSecurityHeaders(res: Response): void {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', publicContentSecurityPolicy());
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}
