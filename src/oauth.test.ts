import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { afterEach, describe, expect, it } from 'vitest';
import { HappyOAuthProvider } from './oauth';
import { Storage } from './storage';

const dirs: string[] = [];

function setup(): { storage: Storage; provider: HappyOAuthProvider; client: OAuthClientInformationFull } {
    const dir = mkdtempSync(join(tmpdir(), 'happy-mcp-oauth-'));
    dirs.push(dir);
    const storage = new Storage(dir);
    const provider = new HappyOAuthProvider(storage, 'https://happy.example.com');
    const client: OAuthClientInformationFull = {
        client_id: 'client-1',
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: ['http://127.0.0.1/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        client_name: 'Test MCP Client',
    };
    storage.saveOAuthClient(client);
    return { storage, provider, client };
}

afterEach(() => {
    while (dirs.length > 0) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('HappyOAuthProvider', () => {
    it('exchanges a one-time authorization code and verifies the access token', async () => {
        const { storage, provider, client } = setup();
        storage.saveAuthorizationCode('code-1', {
            clientId: client.client_id,
            redirectUri: client.redirect_uris[0]!,
            codeChallenge: 'challenge',
            scopes: ['happy:read', 'happy:control'],
            resource: 'https://happy.example.com/mcp',
            expiresAt: Date.now() + 60_000,
        });

        expect(await provider.challengeForAuthorizationCode(client, 'code-1')).toBe('challenge');
        const tokens = await provider.exchangeAuthorizationCode(
            client,
            'code-1',
            undefined,
            client.redirect_uris[0],
            new URL('https://happy.example.com/mcp'),
        );
        const info = await provider.verifyAccessToken(tokens.access_token);
        expect(info.clientId).toBe(client.client_id);
        expect(info.scopes).toEqual(['happy:read', 'happy:control']);
        await expect(provider.exchangeAuthorizationCode(client, 'code-1')).rejects.toThrow('Invalid or expired');
        storage.close();
    });

    it('rotates refresh tokens and prevents scope escalation', async () => {
        const { storage, provider, client } = setup();
        storage.saveAuthorizationCode('code-2', {
            clientId: client.client_id,
            redirectUri: client.redirect_uris[0]!,
            codeChallenge: 'challenge',
            scopes: ['happy:read'],
            resource: 'https://happy.example.com/mcp',
            expiresAt: Date.now() + 60_000,
        });
        const tokens = await provider.exchangeAuthorizationCode(client, 'code-2');
        await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!, ['happy:control']))
            .rejects.toThrow('exceeds');

        const rotated = await provider.exchangeRefreshToken(client, tokens.refresh_token!, ['happy:read']);
        expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
        await expect(provider.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow('Invalid or expired');
        storage.close();
    });

    it('invalidates access when the OAuth client is revoked', async () => {
        const { storage, provider, client } = setup();
        storage.saveAuthorizationCode('code-3', {
            clientId: client.client_id,
            redirectUri: client.redirect_uris[0]!,
            codeChallenge: 'challenge',
            scopes: ['happy:read'],
            resource: 'https://happy.example.com/mcp',
            expiresAt: Date.now() + 60_000,
        });
        const tokens = await provider.exchangeAuthorizationCode(client, 'code-3');
        storage.revokeOAuthClient(client.client_id);
        await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow('Invalid or expired');
        storage.close();
    });
});
