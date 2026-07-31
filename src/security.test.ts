import { describe, expect, it } from 'vitest';
import { hashPassword, openString, sealString, verifyPassword } from './security';

describe('security helpers', () => {
    it('verifies scrypt password records', () => {
        const record = hashPassword('a sufficiently long password');
        expect(verifyPassword('a sufficiently long password', record)).toBe(true);
        expect(verifyPassword('another password', record)).toBe(false);
    });

    it('round-trips authenticated encrypted settings', () => {
        const key = Buffer.alloc(32, 7);
        const sealed = sealString('private value', key);
        expect(sealed).not.toContain('private value');
        expect(openString(sealed, key)).toBe('private value');
    });
});
