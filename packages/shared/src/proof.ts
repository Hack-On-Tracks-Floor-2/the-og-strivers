import type { VerificationRun } from './index.js';

/**
 * The single proof rule for a recorded verification stage, shared by the reviewer UI and the backend
 * approval gate so they can never disagree.
 *  - reproduction must FAIL on the original code by assertion (exit 1, failing tests, no errors);
 *  - every other stage must exit 0;
 *  - a skipped, empty or erroring test run never counts as proof.
 */
export function stageHasProof(record: VerificationRun | undefined): boolean {
  if (
    !record ||
    record.status !== 'passed' ||
    record.exitCode !== (record.stage === 'reproduction' ? 1 : 0) ||
    !record.completedAt ||
    !record.logs.trim() ||
    !record.artifactId
  )
    return false;
  if (['baseline', 'reproduction', 'security_retest', 'regression'].includes(record.stage)) {
    if (!record.tests || record.tests.total === 0 || record.tests.skipped === record.tests.total) return false;
    if (record.stage === 'reproduction') return record.tests.failed > 0 && record.tests.errors === 0;
    return record.tests.passed > 0 && record.tests.failed === 0 && record.tests.errors === 0;
  }
  return true;
}

/** Stages that must all be proven before a reviewer may approve a patch. */
export const REQUIRED_PROOF_STAGES = ['baseline', 'reproduction', 'patch_application', 'security_retest', 'regression'] as const;
