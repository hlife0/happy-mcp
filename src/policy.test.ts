import { describe, expect, it } from 'vitest';
import { isDirectoryAllowed } from './policy';
import type { MachinePolicy } from './storage';

const policy: MachinePolicy = {
    machineId: 'machine-1',
    enabled: true,
    alias: 'worker',
    roots: ['/work/repos', '/srv/project'],
    rules: '',
    updatedAt: 1,
};

describe('isDirectoryAllowed', () => {
    it('accepts roots and descendants', () => {
        expect(isDirectoryAllowed('/work/repos', policy)).toBe(true);
        expect(isDirectoryAllowed('/work/repos/app', policy)).toBe(true);
    });

    it('rejects traversal, sibling prefixes, relative paths and disabled machines', () => {
        expect(isDirectoryAllowed('/work/repos/../secrets', policy)).toBe(false);
        expect(isDirectoryAllowed('/work/repos-evil', policy)).toBe(false);
        expect(isDirectoryAllowed('work/repos', policy)).toBe(false);
        expect(isDirectoryAllowed('/work/repos', { ...policy, enabled: false })).toBe(false);
    });
});
