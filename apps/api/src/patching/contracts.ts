import type { Finding, Patch } from '@proofpatch/shared';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
export interface PatchGenerationAgent {
  generate(
    input: { finding: Finding; workspace: WorkspaceHandle },
    signal: AbortSignal,
  ): Promise<CapabilityResult<Patch>>;
}
