import type { Server } from 'node:http';
import { clearTimeout, setTimeout } from 'node:timers';
import { createAdminApp } from './admin';
import { RiskAuditor } from './audit';
import { loadConfig } from './config';
import { HappyAgentController } from './happy-agent-cli';
import { HappyOAuthProvider } from './oauth';
import { createPublicMcpApp, listen } from './public';
import { Storage } from './storage';

async function main(): Promise<void> {
    const config = loadConfig();
    const storage = new Storage(config.dataDir);
    const bootstrap = storage.ensureAdminPassword();
    const happy = new HappyAgentController(config, storage);
    const happyAgentVersion = await happy.verifyAvailable();
    const auditor = new RiskAuditor(storage);
    const oauth = new HappyOAuthProvider(storage, config.publicBaseUrl);
    const publicMcp = createPublicMcpApp({ config, happy, auditor, oauth });
    const admin = createAdminApp({ config, storage, happy });

    let publicServer: Server;
    let adminServer: Server;
    try {
        [publicServer, adminServer] = await Promise.all([
            listen(publicMcp.app, config.publicHost, config.publicPort),
            listen(admin, config.adminHost, config.adminPort),
        ]);
    } catch (error) {
        await publicMcp.close();
        storage.close();
        throw error;
    }

    console.log(`[happy-mcp] public MCP listening at http://${config.publicHost}:${config.publicPort}/mcp`);
    console.log(`[happy-mcp] public OAuth issuer: ${config.publicBaseUrl}`);
    console.log(`[happy-mcp] admin panel listening at http://${config.adminHost}:${config.adminPort}/`);
    console.log(`[happy-mcp] happy-agent CLI ready (version ${happyAgentVersion})`);
    console.log(`[happy-mcp] admin password file: ${bootstrap.passwordFile}`);
    if (bootstrap.created) console.log('[happy-mcp] a new bootstrap admin password was generated');

    let closing = false;
    const shutdown = async (signal: string) => {
        if (closing) return;
        closing = true;
        console.log(`[happy-mcp] received ${signal}, shutting down`);
        const forcedExit = setTimeout(() => process.exit(0), 12_000);
        await publicMcp.close();
        await Promise.allSettled([closeServer(publicServer), closeServer(adminServer)]);
        storage.close();
        clearTimeout(forcedExit);
        process.exit(0);
    };
    process.once('SIGTERM', () => void shutdown('SIGTERM'));
    process.once('SIGINT', () => void shutdown('SIGINT'));
}

function closeServer(server: Server): Promise<void> {
    return new Promise((resolve) => {
        let completed = false;
        const finish = () => {
            if (completed) return;
            completed = true;
            clearTimeout(timeout);
            resolve();
        };
        const timeout = setTimeout(() => {
            server.closeAllConnections();
            finish();
        }, 2000);
        server.close(finish);
        server.closeIdleConnections();
    });
}

void main().catch((error) => {
    console.error('[happy-mcp] startup failed:', error);
    process.exitCode = 1;
});
