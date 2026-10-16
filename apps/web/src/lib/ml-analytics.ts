import type { Finding, FindingML, Patch, VerificationRun } from '@proofpatch/shared';
import { codeLanguage, distinctFindings, verificationState } from './security-data';

export function cweReference(value: string | null | undefined) {
  const match = /^CWE-([1-9]\d{0,5})$/i.exec(value?.trim() ?? '');
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : null;
}
export function cweModelInsight(finding: Finding, ml: FindingML | null) {
  const language = codeLanguage(finding.file);
  const supported = language === 'python' || language === 'java';
  const prediction = supported && ml?.language === language && ml.findingId === finding.id && ml.runId === finding.runId ? ml.prediction : undefined;
  const comparable = prediction?.status === 'predicted' && !!prediction.cwe && !!cweReference(finding.cwe);
  return { language, supported, prediction, agreement: comparable ? prediction.cwe === finding.cwe?.trim().toUpperCase() ? 'Agrees' : 'Disagrees' : 'Not comparable' };
}
/** Counts only stored records for this run; missing responses never become zero or proof. */
export function mlAnalytics(runId: string, input: Finding[], patchInput: Patch[] | undefined, verification: VerificationRun[] | undefined) {
  const findings = distinctFindings(input.filter(row => row.runId === runId));
  const ids = new Set(findings.map(row => row.id));
  const patches = patchInput === undefined ? undefined : [...new Map(patchInput.filter(row => row.runId === runId && ids.has(row.findingId)).map(row => [row.id, row])).values()];
  const states = new Map<string, 'verified' | 'failed' | 'pending' | 'unavailable'>();
  if (patches && verification) for (const patch of patches) {
    const state = verificationState(patch, verification);
    states.set(patch.id, state === 'failed' ? 'failed' : state === 'checks_passed' && !['proposed', 'rejected'].includes(patch.status) ? 'verified' : ['approved', 'rejected'].includes(patch.status) ? 'unavailable' : 'pending');
  }
  const complete = patches !== undefined && verification !== undefined;
  const count = (state: string) => complete ? [...states.values()].filter(value => value === state).length : null;
  let resolved = 0, pendingFindings = 0;
  for (const finding of findings) {
    const latest = patches?.filter(row => row.findingId === finding.id).sort((a,b) => b.attempt - a.attempt || b.createdAt.localeCompare(a.createdAt))[0];
    if (latest && states.get(latest.id) === 'verified') resolved++;
    if (latest && states.get(latest.id) === 'pending') pendingFindings++;
  }
  // Only persisted patch attempts are available on main. Do not infer unrecorded generation retries.
  const retries = patches ? new Set(patches.filter(row => row.attempt > 1).map(row => `${row.findingId}:${row.attempt}`)).size : null;
  const verified = count('verified'), failed = count('failed');
  const concluded = verified !== null && failed !== null ? verified + failed : null;
  const categories = new Map<string, number>();
  for (const finding of findings) {
    const key = cweReference(finding.cwe) ? finding.cwe!.trim().toUpperCase() : 'Unassigned CWE';
    categories.set(key, (categories.get(key) ?? 0) + 1);
  }
  return { findings, patches, states, total: findings.length,
    severities: (['critical','high','medium','low'] as const).map(name => ({name, count: findings.filter(row => row.severity === name).length})),
    informational: findings.filter(row => row.severity === 'info').length,
    categories: [...categories].map(([name,count]) => ({name,count})).sort((a,b) => b.count-a.count || a.name.localeCompare(b.name)),
    resolved: complete ? resolved : null, unresolved: complete ? findings.length - resolved : null, pendingFindings: complete ? pendingFindings : null,
    verified, failed, pending: count('pending'), unavailable: count('unavailable'), retries, concluded,
    successRate: concluded ? verified! / concluded : null,
  };
}
export type MLAnalytics = ReturnType<typeof mlAnalytics>;
