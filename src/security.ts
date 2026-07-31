import {
    createCipheriv,
    createDecipheriv,
    createHash,
    randomBytes,
    scryptSync,
    timingSafeEqual,
} from 'node:crypto';

export function randomToken(bytes = 32): string {
    return randomBytes(bytes).toString('base64url');
}

export function tokenHash(value: string): string {
    return createHash('sha256').update(value, 'utf8').digest('hex');
}

export type PasswordRecord = {
    algorithm: 'scrypt-v1';
    salt: string;
    hash: string;
};

export function hashPassword(password: string): PasswordRecord {
    const salt = randomBytes(16);
    const hash = scryptSync(password, salt, 32);
    return {
        algorithm: 'scrypt-v1',
        salt: salt.toString('base64'),
        hash: hash.toString('base64'),
    };
}

export function verifyPassword(password: string, record: PasswordRecord): boolean {
    if (record.algorithm !== 'scrypt-v1') return false;
    const expected = Buffer.from(record.hash, 'base64');
    const actual = scryptSync(password, Buffer.from(record.salt, 'base64'), expected.length);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function sealString(value: string, key: Buffer): string {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, tag, ciphertext]).toString('base64');
}

export function openString(value: string, key: Buffer): string {
    const bundle = Buffer.from(value, 'base64');
    if (bundle.length < 29) throw new Error('Encrypted value is malformed');
    const nonce = bundle.subarray(0, 12);
    const tag = bundle.subarray(12, 28);
    const ciphertext = bundle.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

export function escapeHtml(value: unknown): string {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

export function publicContentSecurityPolicy(formActionOrigins: string[] = []): string {
    const formActions = ["'self'", ...formActionOrigins].join(' ');
    return `default-src 'none'; style-src 'unsafe-inline'; form-action ${formActions}; frame-ancestors 'none'; base-uri 'none'`;
}

export function safeRedirectUri(base: string, params: Record<string, string | undefined>): string {
    const url = new URL(base);
    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined) url.searchParams.set(key, value);
    }
    return url.href;
}
