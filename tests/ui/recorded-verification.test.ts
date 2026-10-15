import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RecordedVerificationSchema, recordedVerdict } from '../../apps/web/src/lib/recorded-verification';
const root = process.cwd();
const load = () => RecordedVerificationSchema.parse(JSON.parse(readFileSync(join(root, 'apps/web/public/evidence/regression-demo.json'), 'utf8')));

describe('recorded regression proof', () => {
  it('packages the exact executed outcomes and saved source without changing evidence', () => {
    const report = load();
    const original = JSON.parse(readFileSync(join(root, 'evidence/regression-demo/latest.json'), 'utf8'));
    expect(report.stages).toEqual(original.stages);
    expect(report.unifiedDiff).toBe(original.unifiedDiff);
    expect(report.stages.map(s => s.exitCode)).toEqual([0, 1, 0, 0]);
    expect(report.patchSource).toBe('deterministic');
    expect(report.originalCode).toBe(readFileSync(join(root, 'evidence/regression-demo', report.runId, 'vulnerable/src/reports.cjs'), 'utf8'));
    expect(report.proposedCode).toBe(readFileSync(join(root, 'evidence/regression-demo', report.runId, 'patched/src/reports.cjs'), 'utf8'));
    expect(report.stages[1].stdout).toContain('Traversal leaked controlled data: CONTROLLED_PRIVATE_MARKER');
    expect(recordedVerdict(report)).toBe('Verified recorded run');
  });
  it.each(['baseline', 'security-before', 'security-after', 'regression'])('requires the %s execution record', name => {
    const report = load();
    report.stages = report.stages.filter(s => s.stage !== name);
    expect(recordedVerdict(report)).toBe('Verification incomplete');
  });
  it('does not accept an empty, skipped, errored, or log-free test run', () => {
    for (const change of [
      (r: ReturnType<typeof load>) => { r.stages[3].summary!.total = 0; },
      (r: ReturnType<typeof load>) => { r.stages[3].summary!.skipped = 5; },
      (r: ReturnType<typeof load>) => { r.stages[3].error = 'timed out'; },
      (r: ReturnType<typeof load>) => { r.stages[3].stdout = ''; },
    ]) { const report = load(); change(report); expect(recordedVerdict(report)).toBe('Verification incomplete'); }
  });
  it('rejects a passing security baseline and a broken original test', () => {
    const report = load(); report.stages[1].exitCode = 0;
    expect(recordedVerdict(report)).toBe('Verification failed');
    const broken = load(); broken.stages[3].summary!.cases[0].id = 'different_test';
    expect(recordedVerdict(broken)).toBe('Verification failed');
  });
  it('requires test integrity, code, and a successful comparison', () => {
    const report = load(); report.integrity!.functionalTestsUnchanged = false;
    expect(recordedVerdict(report)).toBe('Verification incomplete');
    const raw = RecordedVerificationSchema.parse(JSON.parse(readFileSync(join(root, 'evidence/regression-demo/latest.json'), 'utf8')));
    expect(recordedVerdict(raw)).toBe('Verification incomplete');
    const comparison = load(); comparison.comparison!.ok = false;
    expect(recordedVerdict(comparison)).toBe('Verification incomplete');
  });
  it('rejects malformed uploads instead of inventing a report', () => {
    expect(RecordedVerificationSchema.safeParse({ verdict: 'VERIFIED' }).success).toBe(false);
  });
});
