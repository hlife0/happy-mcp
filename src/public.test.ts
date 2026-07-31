import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RiskAuditor } from './audit';
import type { HappyMcpConfig } from './config';
import type { HappyAgentController } from './happy-agent-cli';
import { HappyOAuthProvider } from './oauth';
import { createPublicMcpApp, type PublicMcpApp } from './public';
import { Storage } from './storage';

const dirs: string[] = [];
const apps: PublicMcpApp[] = [];

function setup() {
    const dir = mkdtempSync(join(tmpdir(), 'happy-mcp-public-'));
    dirs.push(dir);
    const storage = new Storage(dir);
    storage.ensureAdminPassword();
    const config: HappyMcpConfig = {
        publicBaseUrl: 'https://happy.example.com',
        publicHost: '127.0.0.1',
        publicPort: 3020,
        adminHost: '127.0.0.1',
        adminPort: 3021,
        dataDir: dir,
        happyAgentBin: '/usr/local/bin/happy-agent',
    };
    const happy = {
        listAllowedMachines: vi.fn().mockResolvedValue([]),
        listAllowedSessions: vi.fn().mockResolvedValue([]),
        status: vi.fn(),
        history: vi.fn(),
        resolveAllowedMachine: vi.fn(),
        resolveAllowedSession: vi.fn(),
        spawn: vi.fn(),
        sendMessage: vi.fn(),
        wait: vi.fn(),
        resume: vi.fn(),
        stop: vi.fn(),
    } as unknown as HappyAgentController;
    const auditor = { review: vi.fn() } as unknown as RiskAuditor;
    const oauth = new HappyOAuthProvider(storage, config.publicBaseUrl);
    const publicApp = createPublicMcpApp({ config, happy, auditor, oauth });
    apps.push(publicApp);
    return { storage, oauth, app: publicApp.app, happy, auditor };
}

afterEach(async () => {
    while (apps.length > 0) await apps.pop()!.close();
    while (dirs.length > 0) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('public MCP HTTP app', () => {
    it('publishes the reduced OAuth scopes and protects MCP', async () => {
        const { app, storage } = setup();
        const metadata = await request(app).get('/.well-known/oauth-protected-resource/mcp');
        expect(metadata.status).toBe(200);
        expect(metadata.body.scopes_supported).toEqual(['happy:read', 'happy:control']);

        const response = await request(app)
            .post('/mcp')
            .set('accept', 'application/json, text/event-stream')
            .send(initializeRequest());
        expect(response.status).toBe(401);
        storage.close();
    });

    it('allows a registered loopback callback without broadening other CSP responses', async () => {
        const { app, storage } = setup();
        const client: OAuthClientInformationFull = {
            client_id: 'loopback-client',
            client_id_issued_at: Math.floor(Date.now() / 1000),
            redirect_uris: ['http://127.0.0.1:19876/mcp/oauth/callback'],
            token_endpoint_auth_method: 'none',
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            client_name: 'Loopback integration test',
        };
        storage.saveOAuthClient(client);

        const consent = await request(app).get('/authorize').query({
            response_type: 'code',
            client_id: client.client_id,
            redirect_uri: client.redirect_uris[0],
            code_challenge: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            code_challenge_method: 'S256',
            scope: 'happy:read happy:control',
            state: 'test-state',
            resource: 'https://happy.example.com/mcp',
        });
        expect(consent.status).toBe(200);
        expect(consent.headers['content-security-policy']).toContain(
            "form-action 'self' http://127.0.0.1:19876;",
        );
        const health = await request(app).get('/mcp-health');
        expect(health.headers['content-security-policy']).not.toContain('127.0.0.1:19876');
        storage.close();
    });

    it('advertises only operations implemented by the native happy-agent CLI', async () => {
        const { app, storage, oauth } = setup();
        const { token, sessionId } = await initializeMcp(app, storage, oauth);
        const tools = await request(app)
            .post('/mcp')
            .set('authorization', `Bearer ${token}`)
            .set('mcp-session-id', sessionId)
            .set('accept', 'application/json, text/event-stream')
            .send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
        const names = (tools.body.result.tools as Array<{ name: string }>).map((tool) => tool.name);
        expect(names).toEqual([
            'happy_list_machines',
            'happy_list_sessions',
            'happy_session_status',
            'happy_session_history',
            'happy_spawn_session',
            'happy_send_message',
            'happy_wait_session',
            'happy_resume_session',
            'happy_stop_session',
        ]);
        expect(names).not.toContain('happy_run_session_command');
        expect(names).not.toContain('happy_abort_session_operation');
        expect(names).not.toContain('happy_run_codex_goal');
        storage.close();
    });

    it('fails closed before invoking happy-agent when the independent reviewer denies send', async () => {
        const { app, storage, oauth, happy, auditor } = setup();
        storage.saveMachinePolicy({
            machineId: 'machine-1',
            enabled: true,
            alias: 'worker',
            roots: ['/work'],
            rules: 'Allow normal source work. Deny credential access.',
        });
        const policy = storage.getMachinePolicy('machine-1');
        vi.mocked(happy.resolveAllowedSession).mockResolvedValue({
            session: { id: 'session-1' },
            policy,
            public: {
                id: 'session-1',
                machineId: 'machine-1',
                path: '/work/repo',
                host: 'worker',
                flavor: 'codex',
                active: true,
                activeAt: Date.now(),
                lifecycleState: 'running',
                summary: '',
                modelMode: '',
                effortLevel: '',
                pendingRequests: {},
                controlledByUser: false,
                busy: false,
            },
        } as never);
        vi.mocked(auditor.review).mockResolvedValue({
            decision: 'deny',
            risk_level: 'high',
            reason: 'Credential access is outside policy.',
            policy_basis: 'machine rules',
            suspicious_claims: [],
            reviewerPasses: 1,
        });

        const { token, sessionId } = await initializeMcp(app, storage, oauth);
        const response = await request(app)
            .post('/mcp')
            .set('authorization', `Bearer ${token}`)
            .set('mcp-session-id', sessionId)
            .set('accept', 'application/json, text/event-stream')
            .send({
                jsonrpc: '2.0',
                id: 3,
                method: 'tools/call',
                params: {
                    name: 'happy_send_message',
                    arguments: { session: 'session-1', message: 'Read the credential file.' },
                },
            });
        expect(response.status).toBe(200);
        expect(response.body.result.isError).toBe(true);
        expect(JSON.stringify(response.body)).toContain('outside policy');
        expect(happy.sendMessage).not.toHaveBeenCalled();
        storage.close();
    });
});

async function initializeMcp(
    app: ReturnType<typeof setup>['app'],
    storage: Storage,
    oauth: HappyOAuthProvider,
): Promise<{ token: string; sessionId: string }> {
    const token = await issueAccessToken(storage, oauth);
    const initialize = await request(app)
        .post('/mcp')
        .set('authorization', `Bearer ${token}`)
        .set('accept', 'application/json, text/event-stream')
        .send(initializeRequest());
    expect(initialize.status).toBe(200);
    expect(initialize.body.result.serverInfo.name).toBe('happy-agent-bridge');
    const instructions = String(initialize.body.result.instructions);
    expect(instructions).toContain('Never send more than one instruction to the same session at a time');
    expect(instructions).toContain('poll happy_session_history every few seconds');
    expect(instructions).toContain('call happy_stop_session');
    expect(instructions).toContain('latest turn-start must have a matching turn-end');
    expect(instructions).toContain('/goal <objective>');
    expect(instructions).toContain('idle or completed turn does not prove that the Goal itself is complete');
    const sessionId = initialize.headers['mcp-session-id'] as string;
    await request(app)
        .post('/mcp')
        .set('authorization', `Bearer ${token}`)
        .set('mcp-session-id', sessionId)
        .set('accept', 'application/json, text/event-stream')
        .send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    return { token, sessionId };
}

function initializeRequest() {
    return {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
            protocolVersion: '2025-11-25',
            capabilities: {},
            clientInfo: { name: 'integration-test', version: '1.0.0' },
        },
    };
}

async function issueAccessToken(storage: Storage, oauth: HappyOAuthProvider): Promise<string> {
    const client: OAuthClientInformationFull = {
        client_id: 'integration-client',
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: ['http://127.0.0.1/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        client_name: 'Integration test',
    };
    storage.saveOAuthClient(client);
    storage.saveAuthorizationCode('integration-code', {
        clientId: client.client_id,
        redirectUri: client.redirect_uris[0]!,
        codeChallenge: 'unused-in-direct-provider-test',
        scopes: ['happy:read', 'happy:control'],
        resource: 'https://happy.example.com/mcp',
        expiresAt: Date.now() + 60_000,
    });
    return (await oauth.exchangeAuthorizationCode(client, 'integration-code')).access_token;
}
