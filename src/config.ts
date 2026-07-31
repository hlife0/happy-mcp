import { homedir } from 'node:os';
import { join } from 'node:path';

export type HappyMcpConfig = {
    publicBaseUrl: string;
    publicHost: string;
    publicPort: number;
    adminHost: string;
    adminPort: number;
    dataDir: string;
    happyAgentBin: string;
};

function port(name: string, fallback: number): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
        throw new Error(`${name} must be a valid TCP port`);
    }
    return parsed;
}

export function loadConfig(): HappyMcpConfig {
    const configuredPublicUrl = process.env.HAPPY_MCP_PUBLIC_URL?.trim();
    if (!configuredPublicUrl) {
        throw new Error('HAPPY_MCP_PUBLIC_URL is required');
    }
    const publicBaseUrl = configuredPublicUrl.replace(/\/+$/, '');
    const parsedPublicUrl = new URL(publicBaseUrl);
    if (parsedPublicUrl.protocol !== 'https:' && parsedPublicUrl.hostname !== '127.0.0.1' && parsedPublicUrl.hostname !== 'localhost') {
        throw new Error('HAPPY_MCP_PUBLIC_URL must use HTTPS');
    }

    return {
        publicBaseUrl,
        publicHost: process.env.HAPPY_MCP_HOST ?? '127.0.0.1',
        publicPort: port('HAPPY_MCP_PORT', 3020),
        adminHost: process.env.HAPPY_MCP_ADMIN_HOST ?? '127.0.0.1',
        adminPort: port('HAPPY_MCP_ADMIN_PORT', 3021),
        dataDir: process.env.HAPPY_MCP_DATA_DIR ?? join(homedir(), 'happy-mcp-data'),
        happyAgentBin: process.env.HAPPY_AGENT_BIN?.trim() || 'happy-agent',
    };
}
