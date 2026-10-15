import type { Repository } from '@proofpatch/shared';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
export interface RepositoryIngestionService {
  ingest(repository: Repository, signal: AbortSignal): Promise<CapabilityResult<WorkspaceHandle>>;
}
export const ingestionLimits = {
  cloneTimeoutMs: 60_000,
  maxBytes: 100 * 1024 * 1024,
  maxFiles: 20_000,
} as const;
// Registration does not assert that a URL exists or is public. A future ingestion
// adapter must validate GitHub visibility and reject submodules, LFS and symlinks.
