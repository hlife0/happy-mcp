import { spawn } from 'node:child_process';
import { z } from 'zod';
import type { HappyMcpConfig } from './config';
import { assertDirectoryAllowed, isDirectoryAllowed } from './policy';
import type { MachinePolicy, Storage } from './storage';

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;

const MachineSchema = z.object({
    id: z.string().min(1),
    active: z.boolean(),
    activeAt: z.number().default(0),
    metadata: z.record(z.string(), z.unknown()).nullable().optional().default(null),
    daemonState: z.unknown().nullable().optional(),
}).passthrough();

const SessionSchema = z.object({
    id: z.string().min(1),
    active: z.boolean(),
    activeAt: z.number().default(0),
    metadata: z.record(z.string(), z.unknown()).nullable().optional().default(null),
    agentState: z.unknown().nullable().optional(),
}).passthrough();

const SpawnResultSchema = z.object({
    type: z.enum(['success', 'requestToApproveDirectoryCreation', 'error']),
    sessionId: z.string().optional(),
    directory: z.string().optional(),
    errorMessage: z.string().optional(),
}).passthrough();

export type CliMachine = z.infer<typeof MachineSchema>;
export type CliSession = z.infer<typeof SessionSchema>;

export type PublicMachine = {
    id: string;
    alias: string;
    host: string;
    displayName: string;
    platform: string;
    active: boolean;
    activeAt: number;
    approvedRoots: string[];
    cliAvailability: unknown;
};

export type PublicSession = {
    id: string;
    machineId: string;
    path: string;
    host: string;
    flavor: string;
    active: boolean;
    activeAt: number;
    lifecycleState: string;
    summary: string;
    modelMode: string;
    effortLevel: string;
    pendingRequests: unknown;
    controlledByUser: boolean;
    busy: boolean;
};

export type ProcessResult = {
    exitCode: number;
    stdout: string;
    stderr: string;
    timedOut: boolean;
};

export type CliExecutor = (args: string[], timeoutMs: number) => Promise<ProcessResult>;

export class HappyAgentCommandError extends Error {
    constructor(
        command: string,
        readonly result: ProcessResult,
    ) {
        const detail = (result.stderr || result.stdout).trim().slice(0, 4000);
        super(result.timedOut
            ? `happy-agent ${command} timed out`
            : `happy-agent ${command} failed with exit code ${result.exitCode}${detail ? `: ${detail}` : ''}`);
        this.name = 'HappyAgentCommandError';
    }
}

export class HappyAgentController {
    private readonly executor: CliExecutor;
    private readonly locks = new Map<string, Promise<void>>();

    constructor(
        private readonly config: HappyMcpConfig,
        private readonly storage: Storage,
        executor?: CliExecutor,
    ) {
        this.executor = executor ?? ((args, timeoutMs) => runProcess(config.happyAgentBin, args, timeoutMs));
    }

    async verifyAvailable(): Promise<string> {
        const version = (await this.invoke(['--version'], 10_000)).stdout.trim();
        if (!version) throw new Error('happy-agent --version returned no output');
        await this.invoke(['auth', 'status'], 10_000);
        return version;
    }

    async listAllowedMachines(activeOnly = false): Promise<PublicMachine[]> {
        const machines = await this.listRawMachines(activeOnly);
        return machines
            .map((machine) => ({ machine, policy: this.storage.getMachinePolicy(machine.id) }))
            .filter(({ policy }) => policy.enabled)
            .map(({ machine, policy }) => publicMachine(machine, policy));
    }

    async listAllMachinesForAdmin(): Promise<Array<{
        machine: PublicMachine;
        policy: MachinePolicy;
        raw: CliMachine;
    }>> {
        const machines = await this.listRawMachines(false);
        return machines.map((machine) => {
            const policy = this.storage.getMachinePolicy(machine.id);
            return { machine: publicMachine(machine, policy), policy, raw: machine };
        });
    }

    async resolveAllowedMachine(reference: string): Promise<{
        machine: CliMachine;
        policy: MachinePolicy;
        public: PublicMachine;
    }> {
        const candidates = (await this.listRawMachines(false))
            .map((machine) => ({ machine, policy: this.storage.getMachinePolicy(machine.id) }))
            .filter(({ policy }) => policy.enabled)
            .filter(({ machine, policy }) => machineMatches(machine, policy, reference));
        if (candidates.length === 0) throw new Error(`No enabled machine matches "${reference}".`);
        if (candidates.length > 1) throw new Error(`Machine reference "${reference}" is ambiguous.`);
        const selected = candidates[0]!;
        return { ...selected, public: publicMachine(selected.machine, selected.policy) };
    }

    async listAllowedSessions(activeOnly = false): Promise<PublicSession[]> {
        return (await this.listRawSessions(activeOnly))
            .filter((session) => this.sessionIsAllowed(session))
            .map(publicSession);
    }

    async resolveAllowedSession(reference: string): Promise<{
        session: CliSession;
        policy: MachinePolicy;
        public: PublicSession;
    }> {
        return this.resolveAllowedSessionFrom(await this.listRawSessions(false), reference);
    }

    async status(reference: string): Promise<PublicSession> {
        const target = await this.resolveAllowedSession(reference);
        const raw = SessionSchema.parse(await this.invokeJson(['status', target.session.id, '--json'], 15_000));
        const refreshed = this.resolveAllowedSessionFrom([raw], raw.id);
        return refreshed.public;
    }

    async history(reference: string, limit = 50): Promise<unknown[]> {
        const target = await this.resolveAllowedSession(reference);
        const bounded = Math.max(1, Math.min(150, Math.trunc(limit)));
        const value = await this.invokeJson(['history', target.session.id, '--limit', String(bounded), '--json'], 30_000);
        if (!Array.isArray(value)) throw new Error('happy-agent history returned non-array JSON');
        return value;
    }

    async spawn(options: {
        machine: string;
        directory: string;
        agent?: 'claude' | 'codex' | 'gemini' | 'openclaw' | 'agy';
        createDirectory?: boolean;
    }): Promise<unknown> {
        const target = await this.resolveAllowedMachine(options.machine);
        assertDirectoryAllowed(options.directory, target.policy);
        return this.serial(`machine:${target.machine.id}`, async () => {
            const args = ['spawn', '--machine', target.machine.id, '--path', options.directory];
            if (options.agent) args.push('--agent', options.agent);
            if (options.createDirectory) args.push('--create-dir');
            args.push('--json');
            const result = SpawnResultSchema.parse(await this.invokeJson(args, 45_000));
            if (result.type !== 'success') {
                throw new Error(result.errorMessage
                    || (result.directory ? `Directory creation was not approved for ${result.directory}` : 'happy-agent spawn failed'));
            }
            return result;
        });
    }

    async sendMessage(options: {
        session: string;
        message: string;
        yolo?: boolean;
        waitSeconds?: number;
    }): Promise<{
        sessionId: string;
        messageDispatched: true;
        completionStatus: 'not_requested' | 'completed' | 'timed_out';
    }> {
        const target = await this.resolveAllowedSession(options.session);
        return this.serial(`session:${target.session.id}`, async () => {
            const args = ['send', target.session.id, options.message];
            if (options.yolo) args.push('--yolo');
            args.push('--json');
            await this.invokeJson(args, 30_000);

            const waitSeconds = Math.max(0, Math.min(55, Math.trunc(options.waitSeconds ?? 0)));
            if (waitSeconds === 0) {
                return {
                    sessionId: target.session.id,
                    messageDispatched: true,
                    completionStatus: 'not_requested' as const,
                };
            }

            const completionStatus = await this.waitNative(target.session.id, waitSeconds)
                ? 'completed' as const
                : 'timed_out' as const;
            return {
                sessionId: target.session.id,
                messageDispatched: true,
                completionStatus,
            };
        });
    }

    async wait(reference: string, timeoutSeconds: number): Promise<{
        sessionId: string;
        completionStatus: 'completed' | 'timed_out';
    }> {
        const target = await this.resolveAllowedSession(reference);
        const bounded = Math.max(1, Math.min(55, Math.trunc(timeoutSeconds)));
        return {
            sessionId: target.session.id,
            completionStatus: await this.waitNative(target.session.id, bounded) ? 'completed' : 'timed_out',
        };
    }

    async resume(reference: string): Promise<unknown> {
        const target = await this.resolveAllowedSession(reference);
        if (target.session.active) {
            throw new Error('Refusing to resume a session that Happy currently reports as active.');
        }
        return this.serial(`session:${target.session.id}`, async () => {
            return this.invokeJson(['resume', target.session.id, '--json'], 45_000);
        });
    }

    async stop(reference: string): Promise<{ sessionId: string; acknowledged: true }> {
        const target = await this.resolveAllowedSession(reference);
        return this.serial(`session:${target.session.id}`, async () => {
            await this.invoke(['stop', target.session.id], 30_000);
            return { sessionId: target.session.id, acknowledged: true as const };
        });
    }

    private async listRawMachines(activeOnly: boolean): Promise<CliMachine[]> {
        const args = ['machines'];
        if (activeOnly) args.push('--active');
        args.push('--json');
        return z.array(MachineSchema).parse(await this.invokeJson(args, 30_000));
    }

    private async listRawSessions(activeOnly: boolean): Promise<CliSession[]> {
        const args = ['list'];
        if (activeOnly) args.push('--active');
        args.push('--json');
        return z.array(SessionSchema).parse(await this.invokeJson(args, 30_000));
    }

    private resolveAllowedSessionFrom(sessions: CliSession[], reference: string): {
        session: CliSession;
        policy: MachinePolicy;
        public: PublicSession;
    } {
        const matches = sessions.filter((session) => session.id === reference || session.id.startsWith(reference));
        if (matches.length === 0) throw new Error(`No session matches "${reference}".`);
        if (matches.length > 1) throw new Error(`Session reference "${reference}" is ambiguous.`);
        const session = matches[0]!;
        const machineId = sessionMachineId(session);
        const policy = this.storage.getMachinePolicy(machineId);
        if (!policy.enabled) throw new Error('The session belongs to a machine that is disabled in the MCP control panel.');
        if (!isDirectoryAllowed(sessionDirectory(session), policy)) {
            throw new Error('The session directory is outside the approved roots for its machine.');
        }
        return { session, policy, public: publicSession(session) };
    }

    private sessionIsAllowed(session: CliSession): boolean {
        try {
            const policy = this.storage.getMachinePolicy(sessionMachineId(session));
            return policy.enabled && isDirectoryAllowed(sessionDirectory(session), policy);
        } catch {
            return false;
        }
    }

    private async waitNative(sessionId: string, timeoutSeconds: number): Promise<boolean> {
        const result = await this.executor(
            ['wait', sessionId, '--timeout', String(timeoutSeconds)],
            (timeoutSeconds + 5) * 1000,
        );
        if (result.exitCode === 0 && !result.timedOut) return true;
        const detail = `${result.stderr}\n${result.stdout}`;
        if (result.timedOut || detail.includes('Timeout waiting for agent to become idle')) return false;
        throw new HappyAgentCommandError('wait', result);
    }

    private async invokeJson(args: string[], timeoutMs: number): Promise<unknown> {
        const output = (await this.invoke(args, timeoutMs)).stdout.trim();
        if (!output) throw new Error(`happy-agent ${args[0] ?? ''} returned no JSON`);
        try {
            return JSON.parse(output);
        } catch {
            throw new Error(`happy-agent ${args[0] ?? ''} returned invalid JSON`);
        }
    }

    private async invoke(args: string[], timeoutMs = DEFAULT_COMMAND_TIMEOUT_MS): Promise<ProcessResult> {
        const result = await this.executor(args, timeoutMs);
        if (result.timedOut || result.exitCode !== 0) throw new HappyAgentCommandError(args[0] ?? 'command', result);
        return result;
    }

    private async serial<T>(key: string, operation: () => Promise<T>): Promise<T> {
        const previous = this.locks.get(key) ?? Promise.resolve();
        let release!: () => void;
        const gate = new Promise<void>((resolve) => { release = resolve; });
        const queued = previous.catch(() => undefined).then(() => gate);
        this.locks.set(key, queued);
        await previous.catch(() => undefined);
        try {
            return await operation();
        } finally {
            release();
            if (this.locks.get(key) === queued) this.locks.delete(key);
        }
    }
}

export function sessionMachineId(session: CliSession): string {
    const value = record(session.metadata).machineId;
    if (typeof value !== 'string' || !value) throw new Error(`Session ${session.id} has no machine ID.`);
    return value;
}

export function sessionDirectory(session: CliSession): string {
    const value = record(session.metadata).path;
    if (typeof value !== 'string' || !value) throw new Error(`Session ${session.id} has no working directory.`);
    return value;
}

async function runProcess(binary: string, args: string[], timeoutMs: number): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
        const child = spawn(binary, args, {
            shell: false,
            stdio: ['ignore', 'pipe', 'pipe'],
            env: process.env,
        });
        const stdout: Buffer[] = [];
        const stderr: Buffer[] = [];
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let timedOut = false;
        let settled = false;

        const finish = (result: ProcessResult) => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            resolve(result);
        };
        const fail = (error: Error) => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            reject(error);
        };
        const collect = (chunks: Buffer[], chunk: Buffer, current: number): number => {
            const next = current + chunk.length;
            if (next > MAX_OUTPUT_BYTES) {
                child.kill('SIGKILL');
                fail(new Error(`happy-agent ${args[0] ?? ''} exceeded the output limit`));
                return next;
            }
            chunks.push(chunk);
            return next;
        };

        child.stdout.on('data', (chunk: Buffer) => {
            stdoutBytes = collect(stdout, chunk, stdoutBytes);
        });
        child.stderr.on('data', (chunk: Buffer) => {
            stderrBytes = collect(stderr, chunk, stderrBytes);
        });
        child.once('error', fail);
        child.once('close', (code) => {
            finish({
                exitCode: code ?? 1,
                stdout: Buffer.concat(stdout).toString('utf8'),
                stderr: Buffer.concat(stderr).toString('utf8'),
                timedOut,
            });
        });
        const timeout = setTimeout(() => {
            timedOut = true;
            child.kill('SIGTERM');
            setTimeout(() => {
                if (!settled) child.kill('SIGKILL');
            }, 1000).unref();
        }, timeoutMs);
        timeout.unref();
    });
}

function machineMatches(machine: CliMachine, policy: MachinePolicy, reference: string): boolean {
    const needle = reference.trim().toLowerCase();
    if (!needle) return false;
    const metadata = record(machine.metadata);
    const values = [machine.id, policy.alias, metadata.host, metadata.displayName]
        .filter((value): value is string => typeof value === 'string' && value.length > 0)
        .map((value) => value.toLowerCase());
    return machine.id.toLowerCase().startsWith(needle) || values.includes(needle);
}

function publicMachine(machine: CliMachine, policy: MachinePolicy): PublicMachine {
    const metadata = record(machine.metadata);
    return {
        id: machine.id,
        alias: policy.alias,
        host: stringValue(metadata.host),
        displayName: stringValue(metadata.displayName),
        platform: stringValue(metadata.platform),
        active: machine.active,
        activeAt: machine.activeAt,
        approvedRoots: policy.roots,
        cliAvailability: metadata.cliAvailability ?? null,
    };
}

function publicSession(session: CliSession): PublicSession {
    const metadata = record(session.metadata);
    const agentState = record(session.agentState);
    const requests = record(agentState.requests);
    return {
        id: session.id,
        machineId: stringValue(metadata.machineId),
        path: stringValue(metadata.path),
        host: stringValue(metadata.host),
        flavor: stringValue(metadata.flavor),
        active: session.active,
        activeAt: session.activeAt,
        lifecycleState: stringValue(metadata.lifecycleState),
        summary: stringValue(record(metadata.summary).text),
        modelMode: stringValue(metadata.modelMode),
        effortLevel: stringValue(metadata.effortLevel),
        pendingRequests: agentState.requests ?? {},
        controlledByUser: agentState.controlledByUser === true,
        busy: agentState.controlledByUser === true || Object.keys(requests).length > 0,
    };
}

function record(value: unknown): Record<string, unknown> {
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringValue(value: unknown): string {
    return typeof value === 'string' ? value : '';
}
