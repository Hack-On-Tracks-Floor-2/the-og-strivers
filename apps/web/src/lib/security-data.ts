import type {
  AnalysisRun,
  Finding,
  Patch,
  Repository,
  RunEvent,
  VerificationRun,
} from '@proofpatch/shared';

export type RunBundle = {
  run: AnalysisRun;
  findings: Finding[];
  patches: Patch[];
  verification: VerificationRun[];
  events: RunEvent[];
};
export const ACTIVE_RUNS = new Set([
  'received',
  'queued',
  'mapping',
  'analyzing',
  'patching',
  'verifying',
]);
export const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const categoryLabels = [
  'SQL injection',
  'Cross-site scripting',
  'Access control',
  'Path traversal',
  'Command injection',
  'Authentication',
  'Vulnerable dependencies',
  'Other / Unknown',
] as const;
export function normalizeCategory(finding: Pick<Finding, 'category' | 'cwe'>): string {
  const text = `${finding.cwe ?? ''} ${finding.category}`.toLowerCase();
  if (/cwe-89\b|sql.?injection/.test(text)) return categoryLabels[0];
  if (/cwe-79\b|cross.?site.?scripting|\bxss\b/.test(text)) return categoryLabels[1];
  if (/cwe-(?:639|862|863|284)\b|\bidor\b|access.?control|authorization/.test(text))
    return categoryLabels[2];
  if (/cwe-22\b|path.?traversal|directory.?traversal/.test(text)) return categoryLabels[3];
  if (/cwe-(?:78|77)\b|command.?injection|shell.?injection/.test(text)) return categoryLabels[4];
  if (/cwe-(?:287|306|307|798)\b|authentication|credentials|password/.test(text))
    return categoryLabels[5];
  if (/cwe-1104\b|dependenc|outdated.?package|supply.?chain/.test(text)) return categoryLabels[6];
  return categoryLabels[7];
}
export function normalizeSeverity(value: string): (typeof severityOrder)[number] {
  return severityOrder.includes(value.toLowerCase() as (typeof severityOrder)[number])
    ? (value.toLowerCase() as (typeof severityOrder)[number])
    : 'info';
}
export function distinctFindings(findings: Finding[]): Finding[] {
  return [...new Map(findings.map((finding) => [finding.id, finding])).values()];
}
export function latestStages(records: VerificationRun[]): VerificationRun[] {
  const stages = new Map<string, VerificationRun>();
  for (const record of records) {
    const previous = stages.get(record.stage);
    if (!previous || record.createdAt >= previous.createdAt) stages.set(record.stage, record);
  }
  return [...stages.values()];
}
export const requiredStages = [
  'baseline',
  'reproduction',
  'patch_application',
  'security_retest',
  'regression',
] as const;
export const stageLabels: Record<VerificationRun['stage'], string> = {
  baseline: 'Baseline test suite',
  reproduction: 'Vulnerability reproduction',
  patch_application: 'Patch application',
  security_retest: 'Security retest',
  regression: 'Regression test suite',
  final_decision: 'Verification decision',
};
export function patchEvidence(patch: Patch, records: VerificationRun[]): VerificationRun[] {
  return latestStages(
    records.filter((record) => record.patchId === patch.id && record.runId === patch.runId),
  );
}
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
  // A skipped or empty test suite does not prove a security or regression check.
  if (['baseline', 'reproduction', 'security_retest', 'regression'].includes(record.stage)) {
    if (!record.tests || record.tests.total === 0 || record.tests.skipped === record.tests.total)
      return false;
    if (record.stage === 'reproduction')
      return record.tests.failed > 0 && record.tests.errors === 0;
    return record.tests.passed > 0 && record.tests.failed === 0 && record.tests.errors === 0;
  }
  return true;
}
export type VerificationState =
  'checks_passed' | 'failed' | 'running' | 'pending' | 'not_available';
export function verificationState(patch: Patch, records: VerificationRun[]): VerificationState {
  const stages = patchEvidence(patch, records);
  if (stages.some((stage) => stage.status === 'failed')) return 'failed';
  if (stages.some((stage) => stage.status === 'running')) return 'running';
  if (
    requiredStages.every((name) => stageHasProof(stages.find((stage) => stage.stage === name))) &&
    stageHasProof(stages.find((stage) => stage.stage === 'final_decision'))
  )
    return 'checks_passed';
  if (stages.some((stage) => stage.status === 'pending')) return 'pending';
  return 'not_available';
}
export type FindingState =
  | 'open'
  | 'patch_proposed'
  | 'under_verification'
  | 'verified_checks'
  | 'failed_verification'
  | 'needs_review';
export const findingStateLabels: Record<FindingState, string> = {
  open: 'Open',
  patch_proposed: 'Patch proposed',
  under_verification: 'Under verification',
  verified_checks: 'Verified by available checks',
  failed_verification: 'Verification failed',
  needs_review: 'Needs review',
};
export function findingState(
  finding: Finding,
  patches: Patch[],
  verification: VerificationRun[],
): FindingState {
  const patch = patches
    .filter((item) => item.findingId === finding.id && item.runId === finding.runId)
    .sort((a, b) => b.attempt - a.attempt || b.createdAt.localeCompare(a.createdAt))[0];
  if (!patch || patch.status === 'rejected') return 'open';
  const outcome = verificationState(patch, verification);
  if (outcome === 'failed') return 'failed_verification';
  if (outcome === 'running' || outcome === 'pending') return 'under_verification';
  if (patch.status === 'needs_review') return 'needs_review';
  if (outcome === 'checks_passed') return 'verified_checks';
  return 'patch_proposed';
}
export function repositoryLabel(run: AnalysisRun | undefined, repositories: Repository[]): string {
  if (!run) return 'Repository unavailable';
  const repository = repositories.find((repo) => repo.id === run.repositoryId);
  return repository
    ? `${repository.owner}/${repository.name}`
    : `Repository ${run.repositoryId.slice(0, 8)}`;
}
export function recordedMetadata(events: RunEvent[], repository?: Repository) {
  const commitSha =
    events
      .map((event) => /^Cloned at commit ([0-9a-f]{40})\./i.exec(event.message)?.[1])
      .find(Boolean) ?? null;
  const map = events
    .map((event) => /^Mapped: (.+?) · test command /.exec(event.message)?.[1])
    .find(Boolean)
    ?.split(' · ');
  const count = events
    .map((event) => /^Search funnel: (\d+) source files/.exec(event.message)?.[1])
    .find(Boolean);
  return {
    commitSha,
    filesAnalyzed: count === undefined ? null : Number(count),
    languages: repository?.language
      ? [repository.language]
      : (map?.[0]?.split(', ').filter(Boolean) ?? []),
    frameworks: repository?.framework
      ? [repository.framework]
      : (map?.[1]?.split(', ').filter(Boolean) ?? []),
  };
}
export function durationMs(start: string, end: string | null): number | null {
  if (!end) return null;
  const elapsed = new Date(end).getTime() - new Date(start).getTime();
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : null;
}
export function formatDuration(value: number | null): string {
  if (value === null) return 'Not recorded';
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60000) return `${(value / 1000).toFixed(1)} s`;
  return `${Math.floor(value / 60000)}m ${Math.round((value % 60000) / 1000)}s`;
}
export function diffStatistics(diff: string) {
  const files: Record<string, { added: number; removed: number }> = {};
  let path = '';
  let previousPath = '';
  let oldRemaining = 0;
  let newRemaining = 0;
  for (const rawLine of diff.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (!oldRemaining && !newRemaining && line.startsWith('--- ')) {
      previousPath = line.slice(4).replace(/^a\//, '').replace(/\t.*$/, '');
      continue;
    }
    if (!oldRemaining && !newRemaining && line.startsWith('+++ ')) {
      path = line.slice(4).replace(/^b\//, '').replace(/\t.*$/, '');
      if (path === '/dev/null') path = previousPath;
      files[path] ??= { added: 0, removed: 0 };
      continue;
    }
    const hunk = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
    if (hunk) {
      oldRemaining = Number(hunk[1] ?? 1);
      newRemaining = Number(hunk[2] ?? 1);
      continue;
    }
    if (!oldRemaining && !newRemaining) continue;
    if (line.startsWith('+')) {
      (files[path] ??= { added: 0, removed: 0 }).added++;
      newRemaining--;
    } else if (line.startsWith('-')) {
      (files[path] ??= { added: 0, removed: 0 }).removed++;
      oldRemaining--;
    } else if (line.startsWith(' ')) {
      oldRemaining--;
      newRemaining--;
    }
  }
  return {
    files,
    added: Object.values(files).reduce((sum, file) => sum + file.added, 0),
    removed: Object.values(files).reduce((sum, file) => sum + file.removed, 0),
  };
}
export function codeLanguage(path: string): string {
  const extension = path.split('.').pop()?.toLowerCase();
  return (
    (
      {
        ts: 'typescript',
        tsx: 'typescript',
        js: 'javascript',
        jsx: 'javascript',
        mjs: 'javascript',
        cjs: 'javascript',
        py: 'python',
        json: 'json',
        html: 'html',
        css: 'css',
        scss: 'scss',
        go: 'go',
        rs: 'rust',
        java: 'java',
        c: 'c',
        h: 'c',
        cpp: 'cpp',
        cs: 'csharp',
        php: 'php',
        rb: 'ruby',
        sh: 'shell',
        bash: 'shell',
        yml: 'yaml',
        yaml: 'yaml',
        sql: 'sql',
        md: 'markdown',
        toml: 'ini',
        xml: 'xml',
      } as Record<string, string>
    )[extension ?? ''] ?? 'plaintext'
  );
}
