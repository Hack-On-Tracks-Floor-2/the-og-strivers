import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import {
  FindingSchema,
  PatchSchema,
  VerificationRunSchema,
  type VerificationRun,
} from '@proofpatch/shared';
import {
  codeLanguage,
  diffStatistics,
  distinctFindings,
  durationMs,
  findingState,
  normalizeCategory,
  normalizeSeverity,
  recordedMetadata,
  requiredStages,
  stageHasProof,
  verificationState,
} from '../../apps/web/src/lib/security-data';

const runId = randomUUID(),
  ownerId = randomUUID(),
  findingId = randomUUID(),
  patchId = randomUUID();
const createdAt = '2026-10-15T08:00:00.000Z',
  completedAt = '2026-10-15T08:00:02.000Z';
const finding = FindingSchema.parse({
  id: findingId,
  runId,
  ownerId,
  category: 'SQL injection',
  severity: 'high',
  confidence: 0.93,
  file: 'src/store.py',
  startLine: 2,
  endLine: 3,
  rootCause: 'Untrusted input reaches the query.',
  evidence: [],
  recommendation: 'Bind the query parameter.',
  createdAt,
  cwe: 'CWE-89',
});
const patch = PatchSchema.parse({
  id: patchId,
  runId,
  ownerId,
  findingId,
  status: 'proposed',
  files: [],
  unifiedDiff: '',
  createdAt,
  updatedAt: createdAt,
});
function stage(name: VerificationRun['stage'], overrides: Partial<VerificationRun> = {}) {
  const reproduction = name === 'reproduction';
  return VerificationRunSchema.parse({
    id: randomUUID(),
    runId,
    patchId,
    ownerId,
    stage: name,
    status: 'passed',
    exitCode: reproduction ? 1 : 0,
    command: ['python', '-m', 'pytest'],
    logs: 'Test execution output',
    artifactId: 'a'.repeat(40),
    createdAt,
    completedAt,
    tests: ['patch_application', 'final_decision'].includes(name)
      ? null
      : {
          total: 1,
          passed: reproduction ? 0 : 1,
          failed: reproduction ? 1 : 0,
          errors: 0,
          skipped: 0,
          cases: [{ id: 'test_security', outcome: reproduction ? 'failed' : 'passed' }],
        },
    ...overrides,
  });
}
const complete = () => [...requiredStages, 'final_decision' as const].map((name) => stage(name));

describe('evidence-backed frontend states', () => {
  it('requires recorded checks even when a person approved the patch', () => {
    expect(verificationState({ ...patch, status: 'approved' }, [])).toBe('not_available');
    expect(findingState(finding, [{ ...patch, status: 'approved' }], [])).toBe('patch_proposed');
  });
  it('requires all execution stages and the recorded verification decision', () => {
    expect(verificationState(patch, complete())).toBe('checks_passed');
    expect(
      verificationState(
        patch,
        complete().filter((record) => record.stage !== 'final_decision'),
      ),
    ).toBe('not_available');
    for (const name of requiredStages)
      expect(
        verificationState(
          patch,
          complete().filter((record) => record.stage !== name),
        ),
      ).toBe('not_available');
  });
  it('recognizes the expected failing reproduction test', () => {
    expect(stageHasProof(stage('reproduction'))).toBe(true);
    expect(stageHasProof(stage('reproduction', { exitCode: 0 }))).toBe(false);
  });
  it('never turns skipped, empty, or absent suites into passing evidence', () => {
    for (const tests of [
      null,
      { total: 0, passed: 0, failed: 0, errors: 0, skipped: 0, cases: [] },
      {
        total: 1,
        passed: 0,
        failed: 0,
        errors: 0,
        skipped: 1,
        cases: [{ id: 'test', outcome: 'skipped' as const }],
      },
    ]) {
      const records = complete().map((record) =>
        record.stage === 'security_retest' ? { ...record, tests } : record,
      );
      expect(verificationState(patch, records)).toBe('not_available');
    }
  });
  it('requires completed logs and an artifact reference, not just a status', () => {
    for (const missing of [
      { logs: ' ' },
      { artifactId: null },
      { completedAt: null },
      { exitCode: null },
    ])
      expect(stageHasProof(stage('regression', missing))).toBe(false);
  });
  it('uses the latest execution of each stage', () => {
    const failed = stage('regression', {
      status: 'failed',
      exitCode: 1,
      createdAt: '2026-10-15T09:00:00.000Z',
    });
    expect(verificationState(patch, [failed, ...complete()])).toBe('failed');
    expect(findingState(finding, [patch], [...complete(), failed])).toBe('failed_verification');
  });
  it('does not mix evidence belonging to another patch or run', () => {
    expect(
      verificationState(
        patch,
        complete().map((record) => ({ ...record, patchId: randomUUID() })),
      ),
    ).toBe('not_available');
    expect(
      verificationState(
        patch,
        complete().map((record) => ({ ...record, runId: randomUUID() })),
      ),
    ).toBe('not_available');
  });
  it('tracks pending and active verification without claiming success', () => {
    expect(verificationState(patch, [stage('security_retest', { status: 'running' })])).toBe(
      'running',
    );
    expect(findingState(finding, [patch], [stage('security_retest', { status: 'pending' })])).toBe(
      'under_verification',
    );
  });
  it('preserves human review as a separate finding state', () => {
    expect(findingState(finding, [{ ...patch, status: 'needs_review' }], complete())).toBe(
      'needs_review',
    );
    expect(findingState(finding, [patch], complete())).toBe('verified_checks');
  });
  it('uses the latest patch attempt and reopens a rejected finding', () => {
    const newer = { ...patch, id: randomUUID(), attempt: 2, status: 'rejected' as const };
    expect(findingState(finding, [newer, patch], complete())).toBe('open');
  });
});

describe('honest chart classification and recorded metadata', () => {
  it('deduplicates by stable finding ID, without merging distinct findings', () => {
    expect(distinctFindings([finding, finding, { ...finding, id: randomUUID() }])).toHaveLength(2);
  });
  it('normalizes supported CWE and category names, keeping unknowns explicit', () => {
    expect(normalizeCategory({ category: 'unfamiliar scanner label', cwe: 'CWE-89' })).toBe(
      'SQL injection',
    );
    expect(normalizeCategory({ category: 'XSS', cwe: null })).toBe('Cross-site scripting');
    expect(normalizeCategory({ category: 'IDOR', cwe: null })).toBe('Access control');
    expect(normalizeCategory({ category: 'unsafe dependency', cwe: null })).toBe(
      'Vulnerable dependencies',
    );
    expect(normalizeCategory({ category: 'unmapped', cwe: null })).toBe('Other / Unknown');
    expect(normalizeSeverity('HIGH')).toBe('high');
    expect(normalizeSeverity('unmapped')).toBe('info');
  });
  it('does not guess missing repository metadata', () => {
    expect(recordedMetadata([])).toEqual({
      commitSha: null,
      filesAnalyzed: null,
      languages: [],
      frameworks: [],
    });
  });
  it('extracts only the established upstream event formats', () => {
    const messages = [
      `Cloned at commit ${'a'.repeat(40)}.`,
      'Mapped: Python, JavaScript · Flask · test command ["pytest"].',
      'Search funnel: 12 source files → 3 candidates.',
    ];
    const events = messages.map((message) => ({
      id: randomUUID(),
      runId,
      ownerId,
      message,
      kind: 'stage_completed' as const,
      artifactId: null,
      createdAt,
    }));
    expect(recordedMetadata(events)).toEqual({
      commitSha: 'a'.repeat(40),
      filesAnalyzed: 12,
      languages: ['Python', 'JavaScript'],
      frameworks: ['Flask'],
    });
  });
  it('does not invent elapsed time for absent or invalid completion dates', () => {
    expect(durationMs(createdAt, null)).toBeNull();
    expect(durationMs(createdAt, 'invalid')).toBeNull();
    expect(durationMs(completedAt, createdAt)).toBeNull();
    expect(durationMs(createdAt, completedAt)).toBe(2000);
  });
});

describe('recorded Git diff statistics and source language', () => {
  it('counts changes separately across multiple file hunks', () => {
    const diff =
      '--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n unchanged\n-old\n+new\n+extra\n--- a/b.ts\n+++ b/b.ts\n@@ -1 +1 @@\n-unsafe\n+safe\n';
    expect(diffStatistics(diff)).toEqual({
      files: { 'a.py': { added: 2, removed: 1 }, 'b.ts': { added: 1, removed: 1 } },
      added: 3,
      removed: 2,
    });
  });
  it('counts literal source that resembles Git headers inside a hunk', () => {
    expect(
      diffStatistics(
        '--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n--- literal source\n+++ literal revision\n',
      ).files['a.txt'],
    ).toEqual({ added: 1, removed: 1 });
  });
  it('handles newly created empty-origin files without counting headers', () => {
    expect(
      diffStatistics('--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+one\n+two\n').files['new.py'],
    ).toEqual({ added: 2, removed: 0 });
    expect(diffStatistics('')).toEqual({ files: {}, added: 0, removed: 0 });
  });
  it('falls back to readable plain text for unsupported source types', () => {
    expect(codeLanguage('src/store.py')).toBe('python');
    expect(codeLanguage('src/app.tsx')).toBe('typescript');
    expect(codeLanguage('file.unknown')).toBe('plaintext');
  });
  it('attributes deleted files to their current source path and handles CRLF', () => {
    expect(
      diffStatistics('--- a/removed.py\r\n+++ /dev/null\r\n@@ -1,2 +0,0 @@\r\n-old\r\n-code\r\n')
        .files['removed.py'],
    ).toEqual({ added: 0, removed: 2 });
  });
});
