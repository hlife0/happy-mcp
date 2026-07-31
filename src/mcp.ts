import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { z } from 'zod';
import type { RiskAuditor } from './audit';
import type { HappyAgentController } from './happy-agent-cli';
import type { MachinePolicy } from './storage';

export const HAPPY_MCP_INSTRUCTIONS = [
    'Control administrator-approved Happy sessions only through the installed happy-agent CLI. Mutating operations are independently audited.',
    'SESSION COMMAND SAFETY: Never send more than one instruction to the same session at a time. Before sending another instruction, first establish that the previous turn is no longer running. Poll happy_wait_session, then confirm with happy_session_history and happy_session_status. When history contains turn events, the latest turn-start must have a matching turn-end. If the state is missing, stale, or ambiguous, wait and query again instead of sending.',
    'AFTER SEND: For long-running work, prefer happy_send_message with wait_seconds=0 so control returns immediately. Then poll happy_session_history every few seconds for incremental agent replies, reasoning, tool calls, and turn events. Track message id, seq, or createdAt to avoid treating repeated history entries as new. Use happy_session_status to inspect session connectivity and pending requests; active=true means the session is connected, not that a turn is necessarily running.',
    'A messageDispatched=true response means the instruction was sent. completionStatus=timed_out means only that waiting expired; it does not mean dispatch failed. Never resend after a timeout or uncertain response until status and history prove whether the instruction was accepted and the turn has ended.',
    'INTERRUPTION: There is no turn-only abort tool. To interrupt work, call happy_stop_session, which stops the entire session and therefore its current turn. The response is only a native happy-agent acknowledgement. Poll happy_session_status or happy_list_sessions until the session is inactive before treating it as stopped or attempting resume.',
    'GOAL MODE: On compatible Codex or Claude sessions, an exact /goal <objective> message sets or edits the native Goal and /goal clear clears it. Send Goal commands only when no turn is running. A persistent Goal can span multiple turns, so an idle or completed turn does not prove that the Goal itself is complete; this MCP does not expose structured Goal status.',
].join('\n');

export function createHappyMcpServer(deps: {
    authInfo: AuthInfo;
    happy: HappyAgentController;
    auditor: RiskAuditor;
}): McpServer {
    const { authInfo, happy, auditor } = deps;
    const server = new McpServer({ name: 'happy-agent-bridge', version: '0.2.0' }, {
        instructions: HAPPY_MCP_INSTRUCTIONS,
    });

    server.registerTool('happy_list_machines', {
        title: 'List allowed Happy machines',
        description: 'Run happy-agent machines --json and return only administrator-enabled machines.',
        inputSchema: { active_only: z.boolean().optional().default(false) },
        annotations: { readOnlyHint: true, openWorldHint: false },
    }, async ({ active_only }) => {
        requireScope(authInfo, 'happy:read');
        return result({ machines: await happy.listAllowedMachines(active_only) });
    });

    server.registerTool('happy_list_sessions', {
        title: 'List allowed Happy sessions',
        description: 'Run happy-agent list --json and return sessions on enabled machines inside approved directories.',
        inputSchema: { active_only: z.boolean().optional().default(false) },
        annotations: { readOnlyHint: true, openWorldHint: false },
    }, async ({ active_only }) => {
        requireScope(authInfo, 'happy:read');
        return result({ sessions: await happy.listAllowedSessions(active_only) });
    });

    server.registerTool('happy_session_status', {
        title: 'Get Happy session status',
        description: 'Run happy-agent status --json for an allowed session. Use it with history after sending; active means connected and status alone does not prove that a turn ended.',
        inputSchema: { session: z.string().min(1).describe('Session ID or unambiguous prefix') },
        annotations: { readOnlyHint: true, openWorldHint: false },
    }, async ({ session }) => {
        requireScope(authInfo, 'happy:read');
        return result({ session: await happy.status(session) });
    });

    server.registerTool('happy_session_history', {
        title: 'Read Happy session history',
        description: 'Poll native happy-agent history --json for incremental replies, reasoning, tool calls, and turn events. Compare message id/seq/createdAt and match turn-start with turn-end before sending another instruction.',
        inputSchema: {
            session: z.string().min(1),
            limit: z.number().int().min(1).max(150).optional().default(50),
        },
        annotations: { readOnlyHint: true, openWorldHint: false },
    }, async ({ session, limit }) => {
        requireScope(authInfo, 'happy:read');
        return result({ messages: await happy.history(session, limit) });
    });

    server.registerTool('happy_spawn_session', {
        title: 'Spawn through happy-agent',
        description: 'After independent review, run the native happy-agent spawn command on an enabled machine.',
        inputSchema: {
            machine: z.string().min(1).describe('Enabled machine ID, prefix, alias, host, or display name'),
            directory: z.string().min(1).max(4096),
            agent: z.enum(['codex', 'claude', 'gemini', 'openclaw', 'agy']).optional(),
            create_directory: z.boolean().optional().default(false),
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    }, async (args) => {
        requireScope(authInfo, 'happy:control');
        const target = await happy.resolveAllowedMachine(args.machine);
        await requireAudit(auditor, {
            clientId: authInfo.clientId,
            action: 'happy_agent_spawn',
            machineId: target.machine.id,
            machineLabel: target.public.alias || target.public.host || target.machine.id,
            prompt: `Start ${args.agent ?? 'the default agent'} in ${args.directory}.`,
            context: {
                cliCommand: 'spawn',
                directory: args.directory,
                agent: args.agent ?? null,
                createDirectory: args.create_directory,
            },
            trustedContext: { transport: 'installed happy-agent CLI' },
        }, target.policy);
        return result(await happy.spawn({
            machine: target.machine.id,
            directory: args.directory,
            agent: args.agent,
            createDirectory: args.create_directory,
        }));
    });

    server.registerTool('happy_send_message', {
        title: 'Send through happy-agent',
        description: 'Send one audited instruction through native happy-agent. Never call while an earlier turn in this session is running or uncertain. For long work prefer wait_seconds=0, then poll history/status/wait. A timed_out result does not mean the message was not sent.',
        inputSchema: {
            session: z.string().min(1),
            message: z.string().min(1).max(100_000),
            yolo: z.boolean().optional().default(false),
            wait_seconds: z.number().int().min(0).max(55).optional().default(0),
        },
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    }, async (args) => {
        requireScope(authInfo, 'happy:control');
        const target = await happy.resolveAllowedSession(args.session);
        await requireAudit(auditor, sessionAuditRequest(
            authInfo.clientId,
            target,
            'happy_agent_send',
            args.message,
            {
                cliCommand: 'send',
                yolo: args.yolo,
                waitSeconds: args.wait_seconds,
            },
        ), target.policy);
        return result(await happy.sendMessage({
            session: target.session.id,
            message: args.message,
            yolo: args.yolo,
            waitSeconds: args.wait_seconds,
        }));
    });

    server.registerTool('happy_wait_session', {
        title: 'Wait through happy-agent',
        description: 'Wait for native happy-agent to report the session idle. This does not interrupt the turn. After completion, confirm the matching turn-end in history before sending again; idle does not prove a persistent Goal completed.',
        inputSchema: {
            session: z.string().min(1),
            timeout_seconds: z.number().int().min(1).max(55).optional().default(30),
        },
        annotations: { readOnlyHint: true, openWorldHint: false },
    }, async ({ session, timeout_seconds }) => {
        requireScope(authInfo, 'happy:read');
        return result(await happy.wait(session, timeout_seconds));
    });

    server.registerTool('happy_resume_session', {
        title: 'Resume through happy-agent',
        description: 'After independent review, run happy-agent resume --json. The bridge refuses sessions Happy currently reports as active.',
        inputSchema: { session: z.string().min(1) },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    }, async ({ session }) => {
        requireScope(authInfo, 'happy:control');
        const target = await happy.resolveAllowedSession(session);
        await requireAudit(auditor, sessionAuditRequest(
            authInfo.clientId,
            target,
            'happy_agent_resume',
            'Resume this inactive coding session using the installed happy-agent CLI.',
            { cliCommand: 'resume' },
        ), target.policy);
        return result(await happy.resume(target.session.id));
    });

    server.registerTool('happy_stop_session', {
        title: 'Stop through happy-agent',
        description: 'The available interruption mechanism: stop the entire session and its current turn through native happy-agent. There is no turn-only abort. The result is only an acknowledgement; poll status/list until inactive.',
        inputSchema: { session: z.string().min(1) },
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    }, async ({ session }) => {
        requireScope(authInfo, 'happy:control');
        const target = await happy.resolveAllowedSession(session);
        await requireAudit(auditor, sessionAuditRequest(
            authInfo.clientId,
            target,
            'happy_agent_stop',
            'Stop this coding session using the installed happy-agent CLI.',
            { cliCommand: 'stop' },
        ), target.policy);
        return result(await happy.stop(target.session.id));
    });

    return server;
}

async function requireAudit(
    auditor: RiskAuditor,
    request: Parameters<RiskAuditor['review']>[0],
    policy: MachinePolicy,
): Promise<void> {
    const decision = await auditor.review(request, policy);
    if (decision.decision !== 'allow') {
        throw new Error(`Independent audit denied the request: ${decision.reason}`);
    }
}

function sessionAuditRequest(
    clientId: string,
    target: Awaited<ReturnType<HappyAgentController['resolveAllowedSession']>>,
    action: string,
    prompt: string,
    context: Record<string, unknown>,
): Parameters<RiskAuditor['review']>[0] {
    return {
        clientId,
        action,
        machineId: target.public.machineId,
        machineLabel: target.public.host || target.public.machineId,
        prompt,
        context: {
            sessionId: target.public.id,
            directory: target.public.path,
            agent: target.public.flavor,
            ...context,
        },
        trustedContext: { transport: 'installed happy-agent CLI' },
    };
}

function requireScope(authInfo: AuthInfo, scope: 'happy:read' | 'happy:control'): void {
    if (!authInfo.scopes.includes(scope)) {
        throw new Error(`OAuth scope ${scope} is required.`);
    }
}

function result(value: unknown) {
    return {
        content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }],
        structuredContent: value && typeof value === 'object' && !Array.isArray(value)
            ? value as Record<string, unknown>
            : { result: value },
    };
}
