import { z } from 'zod';
import { TestSummarySchema } from '@proofpatch/shared';

export const RecordedVerificationSchema = z.object({
  runId: z.string().min(1), createdAt: z.string().datetime(), verdict: z.string(),
  scenario: z.string(), patchSource: z.string(), aiReason: z.string().optional(),
  execution: z.string().optional(), nodeVersion: z.string().optional(), unifiedDiff: z.string(),
  originalCode: z.string().optional(), proposedCode: z.string().optional(),
  securityTest: z.string().optional(), functionalTests: z.string().optional(),
  provenance: z.object({ commit: z.string(), reportPath: z.string() }).optional(),
  integrity: z.object({ fixtureSourceUnchanged: z.boolean(), functionalTestsUnchanged: z.boolean(), securityTestsIdentical: z.boolean() }).optional(),
  comparison: z.object({ ok: z.boolean(), broken: z.array(z.unknown()) }).optional(),
  stages: z.array(z.object({
    stage: z.string(), executable: z.string().optional(), argv: z.array(z.string()).optional(),
    cwd: z.string().optional(), startedAt: z.string().optional(), durationMs: z.number().nonnegative().optional(),
    exitCode: z.number().int().nullable(), signal: z.string().nullable().optional(), error: z.string().nullable().optional(),
    stdout: z.string(), stderr: z.string(), summary: TestSummarySchema.nullable().optional(),
  }).passthrough()),
}).passthrough();
export type RecordedVerification = z.infer<typeof RecordedVerificationSchema>;
export const recordedStages = [
  ['baseline', 'Baseline functional tests'], ['security-before', 'Security tests before patch'],
  ['security-after', 'Security tests after patch'], ['regression', 'Post-patch regression tests'],
] as const;

/** A recorded label alone cannot establish a completed proof. Missing tests never count as passing. */
export function recordedVerdict(report: RecordedVerification): 'Verified recorded run' | 'Verification failed' | 'Verification incomplete' {
  if (report.verdict === 'FAILED') return 'Verification failed';
  const stages = recordedStages.map(([name]) => {
    const matches = report.stages.filter(s => s.stage === name);
    return matches.length === 1 ? matches[0] : undefined;
  });
  const allRecorded = stages.every((s) => {
    const t = s?.summary;
    return s && !s.error && !s.signal && s.stdout.trim() && s.argv?.length && s.executable &&
      t && t.total > 0 && t.cases.length === t.total && t.errors === 0 && t.skipped === 0 &&
      t.total === t.passed + t.failed + t.errors + t.skipped && new Set(t.cases.map(c => c.id)).size === t.total;
  });
  if (!allRecorded) return 'Verification incomplete';
  const [baseline, before, after, regression] = stages;
  const passing = (s: typeof baseline) => s?.exitCode === 0 && s.summary?.passed === s.summary?.total && s.summary?.failed === 0 && s.summary?.cases.every(c => c.outcome === 'passed');
  const reproduced = before?.exitCode === 1 && before.summary!.failed > 0 && before.summary!.cases.some(c => c.outcome === 'failed') && before.stdout.includes('ERR_ASSERTION');
  const preserves = (first: NonNullable<typeof baseline>, last: NonNullable<typeof baseline>) =>
    first.summary!.cases.every(c => c.outcome !== 'passed' || last.summary!.cases.some(other => other.id === c.id && other.outcome === 'passed'));
  const sameSecurity = before!.summary!.cases.length === after!.summary!.cases.length && before!.summary!.cases.every(c => after!.summary!.cases.some(other => other.id === c.id));
  if (!passing(baseline) || !reproduced || !passing(after) || !passing(regression) || !preserves(baseline!, regression!) || !sameSecurity) return 'Verification failed';
  if (report.verdict !== 'VERIFIED' || !report.unifiedDiff.trim() || !report.originalCode || !report.proposedCode ||
    report.originalCode === report.proposedCode || !report.integrity?.fixtureSourceUnchanged || !report.integrity.functionalTestsUnchanged ||
    !report.integrity.securityTestsIdentical || !report.comparison?.ok || report.comparison.broken.length) return 'Verification incomplete';
  return 'Verified recorded run';
}
