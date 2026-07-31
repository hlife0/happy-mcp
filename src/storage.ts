import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { hashPassword, openString, randomToken, sealString, tokenHash, verifyPassword, type PasswordRecord } from './security';

export type MachinePolicy = {
    machineId: string;
    enabled: boolean;
    alias: string;
    roots: string[];
    rules: string;
    updatedAt: number;
};

export type AuditSettings = {
    baseUrl: string;
    model: string;
    apiStyle: 'chat_completions' | 'responses';
    globalRules: string;
    doubleCheck: boolean;
    apiKeyConfigured: boolean;
};

export type StoredAuthorizationCode = {
    clientId: string;
    grantId: string;
    redirectUri: string;
    codeChallenge: string;
    scopes: string[];
    resource: string;
    expiresAt: number;
};

export type StoredToken = {
    tokenHash: string;
    type: 'access' | 'refresh';
    clientId: string;
    grantId: string;
    subject: string;
    scopes: string[];
    resource: string;
    expiresAt: number;
    revokedAt: number | null;
};

export type AuditLogRecord = {
    id: string;
    clientId: string;
    action: string;
    machineId: string | null;
    decision: string;
    riskLevel: string;
    reason: string;
    promptPreview: string;
    createdAt: number;
};

export class Storage {
    readonly db: Database.Database;
    readonly dataDir: string;
    private readonly encryptionKey: Buffer;

    constructor(dataDir: string) {
        this.dataDir = dataDir;
        mkdirSync(dataDir, { recursive: true, mode: 0o700 });
        chmodSync(dataDir, 0o700);
        this.encryptionKey = this.loadOrCreateEncryptionKey();
        const databasePath = join(dataDir, 'happy-mcp.sqlite');
        this.db = new Database(databasePath);
        chmodSync(databasePath, 0o600);
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('foreign_keys = ON');
        this.migrate();
    }

    close(): void {
        this.db.close();
    }

    private loadOrCreateEncryptionKey(): Buffer {
        const path = join(this.dataDir, 'storage.key');
        if (!existsSync(path)) {
            writeFileSync(path, Buffer.from(randomToken(32), 'utf8'), { mode: 0o600, flag: 'wx' });
        }
        chmodSync(path, 0o600);
        const material = readFileSync(path);
        return createHash('sha256').update(material).digest();
    }

    private migrate(): void {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS machine_policies (
                machine_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                alias TEXT NOT NULL DEFAULT '',
                roots_json TEXT NOT NULL DEFAULT '[]',
                rules TEXT NOT NULL DEFAULT '',
                max_concurrent INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                encrypted_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS oauth_codes (
                code_hash TEXT PRIMARY KEY,
                encrypted_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS oauth_tokens (
                token_hash TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                client_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                resource TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                FOREIGN KEY(client_id) REFERENCES oauth_clients(client_id)
            );
            CREATE INDEX IF NOT EXISTS oauth_tokens_client_idx ON oauth_tokens(client_id);

            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                action TEXT NOT NULL,
                machine_id TEXT,
                decision TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                prompt_preview TEXT NOT NULL,
                encrypted_detail TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log(created_at DESC);

            DROP TABLE IF EXISTS tasks;
        `);

        const tokenColumns = this.db.pragma('table_info(oauth_tokens)') as Array<{ name: string }>;
        if (!tokenColumns.some((column) => column.name === 'grant_id')) {
            this.db.exec('ALTER TABLE oauth_tokens ADD COLUMN grant_id TEXT');
        }
        this.db.prepare(`
            UPDATE oauth_tokens
            SET grant_id = 'legacy:' || client_id
            WHERE grant_id IS NULL OR grant_id = ''
        `).run();
        this.db.exec('CREATE INDEX IF NOT EXISTS oauth_tokens_grant_idx ON oauth_tokens(client_id, grant_id)');
    }

    getSetting(key: string): string | null {
        const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
        return row?.value ?? null;
    }

    setSetting(key: string, value: string): void {
        this.db.prepare(`
            INSERT INTO settings(key, value, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        `).run(key, value, Date.now());
    }

    deleteSetting(key: string): void {
        this.db.prepare('DELETE FROM settings WHERE key = ?').run(key);
    }

    getSecretSetting(key: string): string | null {
        const value = this.getSetting(key);
        return value ? openString(value, this.encryptionKey) : null;
    }

    setSecretSetting(key: string, value: string): void {
        this.setSetting(key, sealString(value, this.encryptionKey));
    }

    ensureAdminPassword(): { password: string; created: boolean; passwordFile: string } {
        const passwordFile = join(this.dataDir, 'admin-password.txt');
        const existing = this.getSetting('admin_password');
        if (existing) {
            return { password: '', created: false, passwordFile };
        }
        const password = randomToken(18);
        this.setSetting('admin_password', JSON.stringify(hashPassword(password)));
        writeFileSync(passwordFile, `${password}\n`, { mode: 0o600, flag: 'w' });
        return { password, created: true, passwordFile };
    }

    verifyAdminPassword(password: string): boolean {
        const value = this.getSetting('admin_password');
        if (!value) return false;
        try {
            return verifyPassword(password, JSON.parse(value) as PasswordRecord);
        } catch {
            return false;
        }
    }

    changeAdminPassword(password: string): void {
        if (password.length === 0) throw new Error('Admin password must not be empty');
        this.setSetting('admin_password', JSON.stringify(hashPassword(password)));
        this.db.prepare('DELETE FROM admin_sessions').run();
        const passwordFile = join(this.dataDir, 'admin-password.txt');
        writeFileSync(passwordFile, `${password}\n`, { mode: 0o600, flag: 'w' });
    }

    createAdminSession(ttlMs = 12 * 60 * 60 * 1000): { token: string; csrfToken: string } {
        const token = randomToken();
        const csrfToken = randomToken(24);
        const now = Date.now();
        this.db.prepare('INSERT INTO admin_sessions(session_hash, csrf_token, created_at, expires_at) VALUES(?, ?, ?, ?)')
            .run(tokenHash(token), csrfToken, now, now + ttlMs);
        return { token, csrfToken };
    }

    getAdminSession(token: string): { csrfToken: string; expiresAt: number } | null {
        const row = this.db.prepare(`
            SELECT csrf_token, expires_at FROM admin_sessions
            WHERE session_hash = ? AND expires_at > ?
        `).get(tokenHash(token), Date.now()) as { csrf_token: string; expires_at: number } | undefined;
        return row ? { csrfToken: row.csrf_token, expiresAt: row.expires_at } : null;
    }

    deleteAdminSession(token: string): void {
        this.db.prepare('DELETE FROM admin_sessions WHERE session_hash = ?').run(tokenHash(token));
    }

    getAuditSettings(): AuditSettings {
        return {
            baseUrl: this.getSetting('audit_base_url') ?? '',
            model: this.getSetting('audit_model') ?? '',
            apiStyle: this.getSetting('audit_api_style') === 'responses' ? 'responses' : 'chat_completions',
            globalRules: this.getSetting('audit_global_rules') ?? '',
            doubleCheck: this.getSetting('audit_double_check') !== 'false',
            apiKeyConfigured: Boolean(this.getSecretSetting('audit_api_key')),
        };
    }

    saveAuditSettings(settings: Omit<AuditSettings, 'apiKeyConfigured'> & { apiKey?: string }): void {
        this.setSetting('audit_base_url', settings.baseUrl.trim().replace(/\/+$/, ''));
        this.setSetting('audit_model', settings.model.trim());
        this.setSetting('audit_api_style', settings.apiStyle);
        this.setSetting('audit_global_rules', settings.globalRules);
        this.setSetting('audit_double_check', String(settings.doubleCheck));
        if (settings.apiKey?.trim()) this.setSecretSetting('audit_api_key', settings.apiKey.trim());
    }

    getAuditApiKey(): string | null {
        return this.getSecretSetting('audit_api_key');
    }

    clearAuditApiKey(): void {
        this.deleteSetting('audit_api_key');
    }

    getMachinePolicy(machineId: string): MachinePolicy {
        const row = this.db.prepare('SELECT * FROM machine_policies WHERE machine_id = ?').get(machineId) as Record<string, unknown> | undefined;
        if (!row) {
            return {
                machineId,
                enabled: false,
                alias: '',
                roots: [],
                rules: '',
                updatedAt: 0,
            };
        }
        return machinePolicyFromRow(row);
    }

    listMachinePolicies(): MachinePolicy[] {
        const rows = this.db.prepare('SELECT * FROM machine_policies ORDER BY alias, machine_id').all() as Record<string, unknown>[];
        return rows.map(machinePolicyFromRow);
    }

    saveMachinePolicy(policy: Omit<MachinePolicy, 'updatedAt'>): void {
        const roots = [...new Set(policy.roots.map((root) => root.trim()).filter(Boolean))];
        this.db.prepare(`
            INSERT INTO machine_policies(machine_id, enabled, alias, roots_json, rules, max_concurrent, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(machine_id) DO UPDATE SET
                enabled = excluded.enabled,
                alias = excluded.alias,
                roots_json = excluded.roots_json,
                rules = excluded.rules,
                max_concurrent = excluded.max_concurrent,
                updated_at = excluded.updated_at
        `).run(policy.machineId, policy.enabled ? 1 : 0, policy.alias.trim(), JSON.stringify(roots), policy.rules, 1, Date.now());
    }

    getOAuthClient(clientId: string): OAuthClientInformationFull | undefined {
        const row = this.db.prepare(`
            SELECT encrypted_json FROM oauth_clients WHERE client_id = ? AND revoked_at IS NULL
        `).get(clientId) as { encrypted_json: string } | undefined;
        if (!row) return undefined;
        return JSON.parse(openString(row.encrypted_json, this.encryptionKey)) as OAuthClientInformationFull;
    }

    saveOAuthClient(client: OAuthClientInformationFull): void {
        this.db.prepare(`
            INSERT INTO oauth_clients(client_id, encrypted_json, created_at, revoked_at)
            VALUES(?, ?, ?, NULL)
            ON CONFLICT(client_id) DO UPDATE SET encrypted_json = excluded.encrypted_json, revoked_at = NULL
        `).run(client.client_id, sealString(JSON.stringify(client), this.encryptionKey), Date.now());
    }

    listOAuthClients(): Array<{ clientId: string; clientName: string; createdAt: number; revokedAt: number | null }> {
        const rows = this.db.prepare('SELECT client_id, encrypted_json, created_at, revoked_at FROM oauth_clients ORDER BY created_at DESC').all() as Array<{
            client_id: string;
            encrypted_json: string;
            created_at: number;
            revoked_at: number | null;
        }>;
        return rows.map((row) => {
            const client = JSON.parse(openString(row.encrypted_json, this.encryptionKey)) as OAuthClientInformationFull;
            return {
                clientId: row.client_id,
                clientName: client.client_name ?? 'Unnamed MCP client',
                createdAt: row.created_at,
                revokedAt: row.revoked_at,
            };
        });
    }

    revokeOAuthClient(clientId: string): void {
        const now = Date.now();
        this.db.transaction(() => {
            this.db.prepare('UPDATE oauth_clients SET revoked_at = ? WHERE client_id = ?').run(now, clientId);
            this.db.prepare('UPDATE oauth_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL').run(now, clientId);
        })();
    }

    saveAuthorizationCode(code: string, value: StoredAuthorizationCode): void {
        this.db.prepare(`
            INSERT INTO oauth_codes(code_hash, encrypted_json, created_at, expires_at, used_at)
            VALUES(?, ?, ?, ?, NULL)
        `).run(tokenHash(code), sealString(JSON.stringify(value), this.encryptionKey), Date.now(), value.expiresAt);
    }

    getAuthorizationCode(code: string): StoredAuthorizationCode | null {
        const row = this.db.prepare(`
            SELECT encrypted_json FROM oauth_codes
            WHERE code_hash = ? AND expires_at > ? AND used_at IS NULL
        `).get(tokenHash(code), Date.now()) as { encrypted_json: string } | undefined;
        return row ? JSON.parse(openString(row.encrypted_json, this.encryptionKey)) as StoredAuthorizationCode : null;
    }

    consumeAuthorizationCode(code: string): StoredAuthorizationCode | null {
        const value = this.getAuthorizationCode(code);
        if (!value) return null;
        const result = this.db.prepare('UPDATE oauth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL').run(Date.now(), tokenHash(code));
        return result.changes === 1 ? value : null;
    }

    saveToken(rawToken: string, token: Omit<StoredToken, 'tokenHash' | 'revokedAt'>): void {
        this.db.prepare(`
            INSERT INTO oauth_tokens(token_hash, type, client_id, grant_id, subject, scopes_json, resource, created_at, expires_at, revoked_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        `).run(tokenHash(rawToken), token.type, token.clientId, token.grantId, token.subject, JSON.stringify(token.scopes), token.resource, Date.now(), token.expiresAt);
    }

    getToken(rawToken: string): StoredToken | null {
        const row = this.db.prepare('SELECT * FROM oauth_tokens WHERE token_hash = ?').get(tokenHash(rawToken)) as Record<string, unknown> | undefined;
        if (!row) return null;
        return {
            tokenHash: String(row.token_hash),
            type: row.type === 'refresh' ? 'refresh' : 'access',
            clientId: String(row.client_id),
            grantId: typeof row.grant_id === 'string' && row.grant_id
                ? row.grant_id
                : `legacy:${String(row.client_id)}`,
            subject: String(row.subject),
            scopes: parseStringArray(row.scopes_json),
            resource: String(row.resource),
            expiresAt: Number(row.expires_at),
            revokedAt: row.revoked_at == null ? null : Number(row.revoked_at),
        };
    }

    revokeToken(rawToken: string): void {
        this.db.prepare('UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').run(Date.now(), tokenHash(rawToken));
    }

    appendAuditLog(input: Omit<AuditLogRecord, 'id' | 'createdAt'> & { detail: unknown }): AuditLogRecord {
        const record: AuditLogRecord = { ...input, id: randomToken(12), createdAt: Date.now() };
        this.db.prepare(`
            INSERT INTO audit_log(id, client_id, action, machine_id, decision, risk_level, reason, prompt_preview, encrypted_detail, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            record.id,
            record.clientId,
            record.action,
            record.machineId,
            record.decision,
            record.riskLevel,
            record.reason,
            record.promptPreview,
            sealString(JSON.stringify(input.detail), this.encryptionKey),
            record.createdAt,
        );
        return record;
    }

    listAuditLog(limit = 100): AuditLogRecord[] {
        const rows = this.db.prepare(`
            SELECT id, client_id, action, machine_id, decision, risk_level, reason, prompt_preview, created_at
            FROM audit_log ORDER BY created_at DESC LIMIT ?
        `).all(Math.max(1, Math.min(limit, 500))) as Array<Record<string, unknown>>;
        return rows.map((row) => ({
            id: String(row.id),
            clientId: String(row.client_id),
            action: String(row.action),
            machineId: row.machine_id == null ? null : String(row.machine_id),
            decision: String(row.decision),
            riskLevel: String(row.risk_level),
            reason: String(row.reason),
            promptPreview: String(row.prompt_preview),
            createdAt: Number(row.created_at),
        }));
    }

}

function parseStringArray(value: unknown): string[] {
    try {
        const parsed = JSON.parse(String(value));
        return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
    } catch {
        return [];
    }
}

function machinePolicyFromRow(row: Record<string, unknown>): MachinePolicy {
    return {
        machineId: String(row.machine_id),
        enabled: Number(row.enabled) === 1,
        alias: String(row.alias ?? ''),
        roots: parseStringArray(row.roots_json),
        rules: String(row.rules ?? ''),
        updatedAt: Number(row.updated_at) || 0,
    };
}
