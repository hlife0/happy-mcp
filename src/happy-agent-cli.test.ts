import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { HappyMcpConfig } from './config';
import {
    HappyAgentController,
    type CliExecutor,
    type ProcessResult,
} from './happy-agent-cli';
import { Storage } from './storage';

const dirs: string[] = [];

function success(value = ''): ProcessResult {
    return { exitCode: 0, stdout: value, stderr: '', timedOut: false };
}

function machine(id = 'machine-1', active = true) {
    return {
        id,
        active,
        activeAt: 10,
        metadata: {
            host: id === 'machine-1' ? 'worker-1' : 'worker-2',
            displayName: id,
            platform: 'linux',
            homeDir: '/work',
            cliAvailability: { codex: true },
        },
        daemonState: null,
    };
}

function session(active = true) {
    return {
        id: 'session-1',
        active,
        activeAt: 20,
        metadata: {
            machineId: 'machine-1',
            path: '/work/repo',
            host: 'worker-1',
            flavor: 'codex',
            lifecycleState: 'running',
        },
        agentState: { controlledByUser: false, requests: {} },
    };
}

function setup(executor: CliExecutor): { storage: Storage; controller: HappyAgentController } {
    const dir = mkdtempSync(join(tmpdir(), 'happy-agent-cli-mcp-'));
    dirs.push(dir);
    const storage = new Storage(dir);
    storage.saveMachinePolicy({
        machineId: 'machine-1',
        enabled: true,
        alias: 'worker',
        roots: ['/work'],
        rules: 'Allow repository maintenance.',
    });
    const config: HappyMcpConfig = {
        publicBaseUrl: 'https://mcp.example.test',
        publicHost: '127.0.0.1',
        publicPort: 3020,
        adminHost: '127.0.0.1',
        adminPort: 3021,
        dataDir: dir,
        happyAgentBin: '/usr/local/bin/happy-agent',
    };
    return { storage, controller: new HappyAgentController(config, storage, executor) };
}

afterEach(() => {
    while (dirs.length > 0) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('HappyAgentController', () => {
    it('uses native JSON commands and filters machines through administrator policy', async () => {
        const calls: string[][] = [];
        const executor = vi.fn<CliExecutor>(async (args) => {
            calls.push(args);
            if (args[0] === 'machines') return success(JSON.stringify([machine(), machine('machine-2')]));
            throw new Error(`Unexpected command: ${args.join(' ')}`);
        });
        const { storage, controller } = setup(executor);

        const machines = await controller.listAllowedMachines(false);

        expect(calls).toEqual([['machines', '--json']]);
        expect(machines).toHaveLength(1);
        expect(machines[0]).toMatchObject({ id: 'machine-1', alias: 'worker' });
        storage.close();
    });

    it('passes an untrusted message as one argv value and reports native wait timeout separately', async () => {
        const calls: string[][] = [];
        const message = 'Run tests; $(touch /tmp/must-not-run) && echo done';
        const executor = vi.fn<CliExecutor>(async (args) => {
            calls.push([...args]);
            if (args[0] === 'list') return success(JSON.stringify([session()]));
            if (args[0] === 'send') return success(JSON.stringify({ sessionId: 'session-1', sent: true }));
            if (args[0] === 'wait') {
                return { exitCode: 1, stdout: '', stderr: 'Timeout waiting for agent to become idle', timedOut: false };
            }
            throw new Error(`Unexpected command: ${args.join(' ')}`);
        });
        const { storage, controller } = setup(executor);

        const result = await controller.sendMessage({
            session: 'session-1',
            message,
            yolo: true,
            waitSeconds: 5,
        });

        expect(calls).toContainEqual(['send', 'session-1', message, '--yolo', '--json']);
        expect(calls).toContainEqual(['wait', 'session-1', '--timeout', '5']);
        expect(result).toEqual({
            sessionId: 'session-1',
            messageDispatched: true,
            completionStatus: 'timed_out',
        });
        storage.close();
    });

    it('serializes mutating happy-agent commands for the same session', async () => {
        let sendCalls = 0;
        let releaseFirst!: () => void;
        let firstStarted!: () => void;
        const started = new Promise<void>((resolve) => { firstStarted = resolve; });
        const blocked = new Promise<void>((resolve) => { releaseFirst = resolve; });
        const executor = vi.fn<CliExecutor>(async (args) => {
            if (args[0] === 'list') return success(JSON.stringify([session()]));
            if (args[0] === 'send') {
                sendCalls += 1;
                if (sendCalls === 1) {
                    firstStarted();
                    await blocked;
                }
                return success(JSON.stringify({ sessionId: 'session-1', sent: true }));
            }
            throw new Error(`Unexpected command: ${args.join(' ')}`);
        });
        const { storage, controller } = setup(executor);

        const first = controller.sendMessage({ session: 'session-1', message: 'first' });
        await started;
        const second = controller.sendMessage({ session: 'session-1', message: 'second' });
        await new Promise((resolve) => setTimeout(resolve, 10));
        expect(sendCalls).toBe(1);

        releaseFirst();
        await Promise.all([first, second]);
        expect(sendCalls).toBe(2);
        storage.close();
    });

    it('refuses to resume a session Happy still reports as active', async () => {
        const executor = vi.fn<CliExecutor>(async (args) => {
            if (args[0] === 'list') return success(JSON.stringify([session(true)]));
            throw new Error(`Unexpected command: ${args.join(' ')}`);
        });
        const { storage, controller } = setup(executor);

        await expect(controller.resume('session-1')).rejects.toThrow('reports as active');
        expect(executor).not.toHaveBeenCalledWith(expect.arrayContaining(['resume']), expect.any(Number));
        storage.close();
    });

    it('maps spawn directly to the documented happy-agent argv surface', async () => {
        const calls: string[][] = [];
        const executor = vi.fn<CliExecutor>(async (args) => {
            calls.push([...args]);
            if (args[0] === 'machines') return success(JSON.stringify([machine()]));
            if (args[0] === 'spawn') {
                return success(JSON.stringify({ type: 'success', sessionId: 'new-session' }));
            }
            throw new Error(`Unexpected command: ${args.join(' ')}`);
        });
        const { storage, controller } = setup(executor);

        const response = await controller.spawn({
            machine: 'worker',
            directory: '/work/new',
            agent: 'codex',
            createDirectory: true,
        });

        expect(calls).toContainEqual([
            'spawn',
            '--machine',
            'machine-1',
            '--path',
            '/work/new',
            '--agent',
            'codex',
            '--create-dir',
            '--json',
        ]);
        expect(response).toMatchObject({ type: 'success', sessionId: 'new-session' });
        storage.close();
    });

    it('fails startup when happy-agent authentication is unavailable', async () => {
        const executor = vi.fn<CliExecutor>(async (args) => {
            if (args[0] === '--version') return success('0.1.0\n');
            return { exitCode: 1, stdout: '', stderr: 'Not authenticated', timedOut: false };
        });
        const { storage, controller } = setup(executor);

        await expect(controller.verifyAvailable()).rejects.toThrow('auth failed');
        storage.close();
    });
});
