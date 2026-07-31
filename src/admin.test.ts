import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAdminApp } from './admin';
import type { HappyMcpConfig } from './config';
import type { HappyAgentController } from './happy-agent-cli';
import { Storage } from './storage';

const dirs: string[] = [];

afterEach(() => {
    while (dirs.length > 0) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('admin panel', () => {
    it('configures policy for machines discovered through happy-agent without task controls', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'happy-mcp-admin-'));
        dirs.push(dir);
        const storage = new Storage(dir);
        const bootstrap = storage.ensureAdminPassword();
        const machineId = 'machine-123';
        const happy = {
            listAllMachinesForAdmin: vi.fn().mockResolvedValue([{
                machine: {
                    id: machineId,
                    alias: '',
                    host: 'worker-1',
                    displayName: 'Worker 1',
                    platform: 'linux',
                    active: true,
                    activeAt: Date.now(),
                    approvedRoots: [],
                    cliAvailability: { codex: true },
                },
                policy: storage.getMachinePolicy(machineId),
                raw: {
                    id: machineId,
                    active: true,
                    activeAt: Date.now(),
                    metadata: { homeDir: '/work', cliAvailability: { codex: true } },
                },
            }]),
        } as unknown as HappyAgentController;
        const app = createAdminApp({ config: testConfig(dir), storage, happy });

        const agent = request.agent(app);
        const login = await agent.post('/login').type('form').send({ password: bootstrap.password });
        expect(login.status).toBe(303);
        const dashboard = await agent.get('/');
        expect(dashboard.status).toBe(200);
        expect(dashboard.text).toContain('Worker 1');
        expect(dashboard.text).toContain('当前在线');
        expect(dashboard.text).toContain('MCP 未允许');
        expect(dashboard.text).not.toContain('Goal 任务');
        const csrf = dashboard.text.match(/name="csrf_token" value="([^"]+)"/)?.[1];
        expect(csrf).toBeTruthy();

        const prematureEnable = await agent.post(`/machines/${machineId}/access`).type('form').send({
            csrf_token: csrf,
            action: 'enable',
        });
        expect(prematureEnable.status).toBe(400);

        const saved = await agent.post(`/machines/${machineId}`).type('form').send({
            csrf_token: csrf,
            alias: 'worker',
            roots: '/work/projects\n/work/scratch',
            rules: 'Allow source maintenance under approved roots. Deny credential access.',
        });
        expect(saved.status).toBe(303);
        expect(storage.getMachinePolicy(machineId)).toMatchObject({
            enabled: false,
            alias: 'worker',
            roots: ['/work/projects', '/work/scratch'],
        });

        const enabled = await agent.post(`/machines/${machineId}/access`).type('form').send({
            csrf_token: csrf,
            action: 'enable',
        });
        expect(enabled.status).toBe(303);
        expect(storage.getMachinePolicy(machineId).enabled).toBe(true);
        storage.close();
    });
});

function testConfig(dir: string): HappyMcpConfig {
    return {
        publicBaseUrl: 'https://happy.example.com',
        publicHost: '127.0.0.1',
        publicPort: 3020,
        adminHost: '127.0.0.1',
        adminPort: 3021,
        dataDir: dir,
        happyAgentBin: '/usr/local/bin/happy-agent',
    };
}
