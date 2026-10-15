import type { Patch, VerificationRun } from '@proofpatch/shared';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
export interface VerificationEngine {
  verify(
    input: { patch: Patch; workspace: WorkspaceHandle },
    signal: AbortSignal,
  ): Promise<CapabilityResult<VerificationRun[]>>;
}
