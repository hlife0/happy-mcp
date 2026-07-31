import { posix } from 'node:path';
import type { MachinePolicy } from './storage';

export function isDirectoryAllowed(directory: string, policy: MachinePolicy): boolean {
    if (!policy.enabled || policy.roots.length === 0 || !directory.startsWith('/')) return false;
    const normalized = posix.normalize(directory);
    return policy.roots.some((root) => {
        if (!root.startsWith('/')) return false;
        const normalizedRoot = posix.normalize(root).replace(/\/$/, '');
        return normalized === normalizedRoot || normalized.startsWith(`${normalizedRoot}/`);
    });
}

export function assertDirectoryAllowed(directory: string, policy: MachinePolicy): void {
    if (!isDirectoryAllowed(directory, policy)) {
        throw new Error('The requested directory is outside the administrator-approved roots for this machine.');
    }
}
