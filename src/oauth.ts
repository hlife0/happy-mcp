import type { Response } from 'express';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import {
    AccessDeniedError,
    InvalidGrantError,
    InvalidScopeError,
    InvalidTargetError,
    InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
    OAuthClientInformationFull,
    OAuthTokenRevocationRequest,
    OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { escapeHtml, publicContentSecurityPolicy, randomToken, safeRedirectUri } from './security';
import type { Storage } from './storage';

export const HAPPY_MCP_SCOPES = ['happy:read', 'happy:control'] as const;

export class HappyOAuthProvider implements OAuthServerProvider {
    readonly clientsStore: OAuthRegisteredClientsStore;
    private readonly resourceUrl: string;

    constructor(
        private readonly storage: Storage,
        publicBaseUrl: string,
    ) {
        this.resourceUrl = `${publicBaseUrl.replace(/\/+$/, '')}/mcp`;
        this.clientsStore = {
            getClient: async (clientId) => this.storage.getOAuthClient(clientId),
            registerClient: async (client) => this.registerClient(client),
        };
    }

    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        const scopes = normalizeScopes(params.scopes);
        this.assertResource(params.resource);
        const redirectOrigin = new URL(params.redirectUri).origin;
        res.setHeader('Content-Security-Policy', publicContentSecurityPolicy([redirectOrigin]));
        const req = res.req;

        if (req.method === 'GET') {
            res.status(200).type('html').send(renderConsentPage(client, params, scopes));
            return;
        }

        const body = req.body as Record<string, unknown> | undefined;
        const decision = typeof body?.decision === 'string' ? body.decision : '';
        if (decision === 'deny') {
            res.redirect(302, safeRedirectUri(params.redirectUri, {
                error: 'access_denied',
                error_description: 'The Happy administrator denied access.',
                state: params.state,
            }));
            return;
        }

        const password = typeof body?.admin_password === 'string' ? body.admin_password : '';
        if (!this.storage.verifyAdminPassword(password)) {
            res.status(401).type('html').send(renderConsentPage(client, params, scopes, 'Incorrect administrator password.'));
            return;
        }

        if (decision !== 'allow') {
            throw new AccessDeniedError('Explicit administrator consent is required');
        }

        const code = randomToken();
        this.storage.saveAuthorizationCode(code, {
            clientId: client.client_id,
            redirectUri: params.redirectUri,
            codeChallenge: params.codeChallenge,
            scopes,
            resource: this.resourceUrl,
            expiresAt: Date.now() + 5 * 60 * 1000,
        });
        res.redirect(302, safeRedirectUri(params.redirectUri, {
            code,
            state: params.state,
        }));
    }

    async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        const code = this.storage.getAuthorizationCode(authorizationCode);
        if (!code || code.clientId !== client.client_id) throw new InvalidGrantError('Invalid or expired authorization code');
        return code.codeChallenge;
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        _codeVerifier?: string,
        redirectUri?: string,
        resource?: URL,
    ): Promise<OAuthTokens> {
        const code = this.storage.consumeAuthorizationCode(authorizationCode);
        if (!code || code.clientId !== client.client_id) throw new InvalidGrantError('Invalid or expired authorization code');
        if (redirectUri !== undefined && redirectUri !== code.redirectUri) throw new InvalidGrantError('redirect_uri does not match authorization request');
        if (resource !== undefined && normalizeUrl(resource) !== code.resource) throw new InvalidTargetError('resource does not match authorization request');
        return this.issueTokenPair(client.client_id, code.scopes, code.resource);
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        scopes?: string[],
        resource?: URL,
    ): Promise<OAuthTokens> {
        const stored = this.storage.getToken(refreshToken);
        if (!stored || stored.type !== 'refresh' || stored.clientId !== client.client_id || stored.revokedAt !== null || stored.expiresAt <= Date.now()) {
            throw new InvalidGrantError('Invalid or expired refresh token');
        }
        const requestedScopes = scopes?.length ? normalizeScopes(scopes) : stored.scopes;
        if (requestedScopes.some((scope) => !stored.scopes.includes(scope))) {
            throw new InvalidScopeError('Refresh scope exceeds the original grant');
        }
        if (resource !== undefined && normalizeUrl(resource) !== stored.resource) {
            throw new InvalidTargetError('resource does not match the original grant');
        }
        this.storage.revokeToken(refreshToken);
        return this.issueTokenPair(client.client_id, requestedScopes, stored.resource);
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const stored = this.storage.getToken(token);
        if (!stored || stored.type !== 'access' || stored.revokedAt !== null || stored.expiresAt <= Date.now()) {
            throw new InvalidTokenError('Invalid or expired access token');
        }
        if (!this.storage.getOAuthClient(stored.clientId)) throw new InvalidTokenError('OAuth client has been revoked');
        return {
            token,
            clientId: stored.clientId,
            scopes: stored.scopes,
            expiresAt: Math.floor(stored.expiresAt / 1000),
            resource: new URL(stored.resource),
            extra: { subject: stored.subject },
        };
    }

    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        const stored = this.storage.getToken(request.token);
        if (stored?.clientId === client.client_id) this.storage.revokeToken(request.token);
    }

    private async registerClient(
        client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
    ): Promise<OAuthClientInformationFull> {
        for (const redirect of client.redirect_uris) {
            const url = new URL(redirect);
            const loopback = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
            if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
                throw new Error('OAuth redirect URIs must use HTTPS or HTTP loopback');
            }
        }
        const full = client as OAuthClientInformationFull;
        if (!full.client_id) throw new Error('OAuth SDK did not generate a client_id');
        this.storage.saveOAuthClient(full);
        return full;
    }

    private assertResource(resource?: URL): void {
        if (resource && normalizeUrl(resource) !== this.resourceUrl) {
            throw new InvalidTargetError(`This authorization server only issues tokens for ${this.resourceUrl}`);
        }
    }

    private issueTokenPair(clientId: string, scopes: string[], resource: string): OAuthTokens {
        const accessToken = randomToken();
        const refreshToken = randomToken();
        const now = Date.now();
        this.storage.saveToken(accessToken, {
            type: 'access',
            clientId,
            subject: 'happy-admin',
            scopes,
            resource,
            expiresAt: now + 60 * 60 * 1000,
        });
        this.storage.saveToken(refreshToken, {
            type: 'refresh',
            clientId,
            subject: 'happy-admin',
            scopes,
            resource,
            expiresAt: now + 30 * 24 * 60 * 60 * 1000,
        });
        return {
            access_token: accessToken,
            refresh_token: refreshToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: scopes.join(' '),
        };
    }
}

function normalizeScopes(scopes?: string[]): string[] {
    const requested = scopes?.length ? [...new Set(scopes)] : [...HAPPY_MCP_SCOPES];
    for (const scope of requested) {
        if (!HAPPY_MCP_SCOPES.includes(scope as typeof HAPPY_MCP_SCOPES[number])) {
            throw new InvalidScopeError(`Unsupported scope: ${scope}`);
        }
    }
    return requested;
}

function normalizeUrl(url: URL): string {
    return url.href.replace(/\/$/, '');
}

function renderConsentPage(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    scopes: string[],
    error = '',
): string {
    const hidden: Record<string, string | undefined> = {
        client_id: client.client_id,
        redirect_uri: params.redirectUri,
        response_type: 'code',
        code_challenge: params.codeChallenge,
        code_challenge_method: 'S256',
        scope: scopes.join(' '),
        state: params.state,
        resource: params.resource?.href,
    };
    const hiddenInputs = Object.entries(hidden)
        .filter((entry): entry is [string, string] => entry[1] !== undefined)
        .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
        .join('');
    const scopeItems = scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code> - ${escapeHtml(scopeDescription(scope))}</li>`).join('');
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Happy MCP</title><style>${CONSENT_CSS}</style></head>
<body><main><header><p class="eyebrow">HAPPY MCP</p><h1>Authorize remote control</h1><p class="lede"><strong>${escapeHtml(client.client_name ?? 'Unnamed MCP client')}</strong> is requesting access to Happy.</p></header>
${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
<section><h2>Requested permissions</h2><ul>${scopeItems}</ul></section>
<section class="warning"><h2>Important</h2><p>Approved clients can ask coding agents to operate allowed machines. Every mutating request is still checked by the independent audit LLM and per-machine policy.</p></section>
<form method="post" action="/authorize">${hiddenInputs}
<label for="admin_password">Administrator password</label><input id="admin_password" name="admin_password" type="password" autocomplete="current-password" required autofocus>
<div class="actions"><button type="submit" name="decision" value="deny" class="secondary">Deny</button><button type="submit" name="decision" value="allow">Authorize</button></div>
</form></main></body></html>`;
}

function scopeDescription(scope: string): string {
    if (scope === 'happy:read') return 'List allowed machines and read allowed session state/history through happy-agent';
    if (scope === 'happy:control') return 'Run audited spawn, send, resume, and stop commands through happy-agent';
    return scope;
}

const CONSENT_CSS = `
:root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#f4f6f8;color:#17202a}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}
main{width:min(620px,100%);background:#fff;border:1px solid #d9e0e7;border-radius:8px;box-shadow:0 12px 36px rgba(23,32,42,.12);overflow:hidden}
header,section,form{padding:22px 26px}header{border-bottom:1px solid #e7ebef;background:#fbfcfd}
.eyebrow{margin:0 0 8px;color:#276749;font-size:12px;font-weight:800}h1{font-size:24px;margin:0 0 8px;letter-spacing:0}h2{font-size:15px;margin:0 0 10px}.lede,p{line-height:1.5;margin:0}
section{border-bottom:1px solid #edf0f2}ul{margin:0;padding-left:20px;display:grid;gap:9px;font-size:14px}code{color:#0f5132}.warning{background:#fff9e8}.warning p{font-size:14px}
label{display:block;font-weight:700;font-size:14px;margin-bottom:7px}input{width:100%;height:42px;border:1px solid #aeb8c2;border-radius:5px;padding:0 11px;font:inherit}
.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}button{height:40px;border:1px solid #1f6f4a;border-radius:5px;background:#1f6f4a;color:white;padding:0 18px;font:inherit;font-weight:700;cursor:pointer}.secondary{background:white;color:#334155;border-color:#aeb8c2}
.error{margin:18px 26px 0;padding:11px 13px;background:#fff0f0;border:1px solid #e5a4a4;color:#8a1c1c;border-radius:5px}
`;
