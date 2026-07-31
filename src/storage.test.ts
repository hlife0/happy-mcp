import Database from 'better-sqlite3';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Storage } from './storage';

const dirs: string[] = [];

function createStorage(): Storage {
    const dir = mkdtempSync(join(tmpdir(), 'happy-mcp-storage-'));
    dirs.push(dir);
    return new Storage(dir);
}

afterEach(() => {
    while (dirs.length > 0) {
        rmSync(dirs.pop()!, { recursive: true, force: true });
    }
});

describe('Storage', () => {
    it('creates and verifies a bootstrap admin password', () => {
        const storage = createStorage();
        const bootstrap = storage.ensureAdminPassword();
        expect(bootstrap.created).toBe(true);
        expect(bootstrap.password.length).toBeGreaterThanOrEqual(20);
        expect(storage.verifyAdminPassword(bootstrap.password)).toBe(true);
        expect(storage.verifyAdminPassword('wrong-password')).toBe(false);
        expect(readFileSync(bootstrap.passwordFile, 'utf8').trim()).toBe(bootstrap.password);
        expect(storage.ensureAdminPassword().created).toBe(false);
        storage.close();
    });

    it('allows a non-empty short admin password and rejects an empty password', () => {
        const storage = createStorage();
        storage.ensureAdminPassword();

        storage.changeAdminPassword('short');
        expect(storage.verifyAdminPassword('short')).toBe(true);
        expect(() => storage.changeAdminPassword('')).toThrow('must not be empty');
        storage.close();
    });

    it('encrypts the audit API key at rest and does not create the removed task plane', () => {
        const storage = createStorage();
        storage.setSecretSetting('audit_api_key', 'secret-api-key');

        const bytes = readFileSync(join(storage.dataDir, 'happy-mcp.sqlite'));
        expect(bytes.includes(Buffer.from('secret-api-key'))).toBe(false);
        expect(storage.getSecretSetting('audit_api_key')).toBe('secret-api-key');
        expect(storage.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'tasks'").get()).toBeUndefined();
        storage.close();
    });

    it('stores machine policies with disabled-by-default behavior', () => {
        const storage = createStorage();
        expect(storage.getMachinePolicy('machine-1').enabled).toBe(false);
        storage.saveMachinePolicy({
            machineId: 'machine-1',
            enabled: true,
            alias: 'build-host',
            roots: ['/work/a', '/work/a', ' /work/b '],
            rules: 'Allow repository maintenance, reject credential access.',
        });
        expect(storage.getMachinePolicy('machine-1')).toMatchObject({
            enabled: true,
            alias: 'build-host',
            roots: ['/work/a', '/work/b'],
        });
        storage.close();
    });

    it('consumes OAuth authorization codes once', () => {
        const storage = createStorage();
        storage.saveAuthorizationCode('code-1', {
            clientId: 'client-1',
            grantId: 'grant-1',
            redirectUri: 'http://127.0.0.1/callback',
            codeChallenge: 'challenge',
            scopes: ['happy:read'],
            resource: 'https://example.com/mcp',
            expiresAt: Date.now() + 60_000,
        });
        expect(storage.consumeAuthorizationCode('code-1')?.clientId).toBe('client-1');
        expect(storage.consumeAuthorizationCode('code-1')).toBeNull();
        storage.close();
    });

    it('migrates legacy OAuth tokens to a stable compatibility grant', () => {
        const dir = mkdtempSync(join(tmpdir(), 'happy-mcp-storage-'));
        dirs.push(dir);
        const databasePath = join(dir, 'happy-mcp.sqlite');
        const legacy = new Database(databasePath);
        legacy.exec(`
            CREATE TABLE oauth_tokens (
                token_hash TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                client_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                resource TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER
            );
        `);
        legacy.prepare(`
            INSERT INTO oauth_tokens(token_hash, type, client_id, subject, scopes_json, resource, created_at, expires_at, revoked_at)
            VALUES('hash', 'access', 'legacy-client', 'happy-admin', '[]', 'https://example.com/mcp', 1, 2, NULL)
        `).run();
        legacy.close();

        const storage = new Storage(dir);
        const row = storage.db.prepare("SELECT grant_id FROM oauth_tokens WHERE token_hash = 'hash'").get() as { grant_id: string };
        expect(row.grant_id).toBe('legacy:legacy-client');
        storage.close();
    });
});
