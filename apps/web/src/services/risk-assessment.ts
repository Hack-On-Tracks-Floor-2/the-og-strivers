import type { Finding, Patch, VerificationRun } from '@proofpatch/shared';
import { patchEvidence, stageHasProof, verificationState } from '../lib/security-data';

export const RISK_POLICY_VERSION = 'risk-priority-v1';
export const RISK_SCORE_LABEL = 'Evidence-Based Risk Priority Score';
export const RISK_LEVELS = ['Critical', 'High', 'Medium', 'Low'] as const;
export type RiskLevel = typeof RISK_LEVELS[number];
type Factor = { id: string; label: string; points: number; status: 'observed' | 'unknown' | 'policy'; source: string; explanation: string; verificationIds: string[] };
type Unknown = { id: string; label: string; explanation: string };
const severityPoints: Record<string, number> = { critical: 85, high: 65, medium: 45, low: 25, info: 15 };
const toolNames = new Map([['semgrep','Semgrep'], ['bandit','Bandit'], ['proof patch rules','Proof Patch rules'], ['proofpatch rules','Proof Patch rules']]);
const statusOrder = { passed: 0, pending: 1, not_configured: 2, running: 3, failed: 4 };
export const riskLevel = (score: number): RiskLevel => score >= 85 ? 'Critical' : score >= 65 ? 'High' : score >= 40 ? 'Medium' : 'Low';

/** Read-only policy service over authenticated saved records. No inference, source execution or writes. */
export function assessFindingRisk(finding: Finding, patchInput: Patch[] | undefined, records: VerificationRun[] | undefined) {
  const patches = [...new Map((patchInput ?? []).filter(p => p.findingId === finding.id && p.runId === finding.runId && p.ownerId === finding.ownerId).map(p => [p.id,p])).values()]
    .sort((a,b) => b.attempt-a.attempt || b.createdAt.localeCompare(a.createdAt) || a.id.localeCompare(b.id));
  // Stable worst-status tie breaking prevents input order deciding a contradictory stage outcome.
  const scoped = (records ?? []).filter(r => r.runId === finding.runId && r.ownerId === finding.ownerId)
    .sort((a,b) => a.createdAt.localeCompare(b.createdAt) || statusOrder[a.status]-statusOrder[b.status] || a.id.localeCompare(b.id));
  const stages = (patch: Patch) => patchEvidence(patch, scoped);
  const sameTest = (patch: Patch, original: VerificationRun | undefined, retest: VerificationRun | undefined) => !!patch.securityTest?.path && !!patch.securityTest.content.trim()
    && !!original?.command.length && !!retest && JSON.stringify(original.command) === JSON.stringify(retest.command);
  const originalsFailing = (record: VerificationRun | undefined) => record?.tests?.cases.filter(c => c.outcome === 'failed').map(c => c.id) ?? [];
  const matchingCases = (original: VerificationRun | undefined, retest: VerificationRun | undefined, outcome: 'passed' | 'failed') => originalsFailing(original).some(id => retest?.tests?.cases.some(c => c.id === id && c.outcome === outcome));
  const proof = patches.map(patch => {
    const rows = stages(patch), baseline = rows.find(r=>r.stage==='baseline'), original = rows.find(r=>r.stage==='reproduction'), retest = rows.find(r=>r.stage==='security_retest');
    const binding = sameTest(patch,original,retest) && stageHasProof(baseline) && stageHasProof(original);
    const redGreen = binding && stageHasProof(retest) && matchingCases(original,retest,'passed');
    const securityFailure = binding && retest?.status === 'failed' && retest.exitCode === 1 && !!retest.completedAt && !!retest.artifactId && !!retest.logs.trim()
      && !!retest.tests && retest.tests.failed > 0 && retest.tests.errors === 0 && matchingCases(original,retest,'failed');
    return { patch, redGreen, securityFailure, ids: [baseline,original,retest].filter((r):r is VerificationRun=>!!r).map(r=>r.id) };
  });
  const reproduced = proof.find(row=>row.redGreen);
  const latest = patches[0];
  const latestSecurityFailure = proof[0]?.securityFailure === true;
  const knownSeverity = Object.hasOwn(severityPoints, finding.severity);
  const base = knownSeverity ? severityPoints[finding.severity] : 65;
  const scanners = ['scanner','scanner+ai'].includes(finding.source) ? [...new Set(finding.scanners.map(name=>toolNames.get(name.toLowerCase())).filter((name):name is string=>!!name))].sort() : [];
  const factors: Factor[] = [
    { id:'severity', label:'Recorded analysis severity', points:base, status:knownSeverity?'observed':'unknown', source:'findings.severity / analysis verdict', explanation:knownSeverity ? `${finding.severity}: ${base} policy points. This may be AI-assigned analysis severity, not raw scanner severity.` : 'Severity unavailable: conservative High baseline of 65; no low-risk assumption.', verificationIds:[] },
    { id:'sandbox_reproduction', label:'Matched sandbox red/green test', points:reproduced?20:0, status:reproduced?'observed':'unknown', source:'baseline + reproduction + security_retest records and patch.securityTest', explanation:reproduced ? 'A named test fails by assertion on original source and passes on the candidate, with matching commands, baseline proof and completed artifacts. This supports test-workspace reproduction, not internet exploitability.' : 'No matched, artifact-backed red/green proof established. Missing, skipped, erroring or unrelated tests do not qualify.', verificationIds:reproduced?.ids ?? [] },
    { id:'scanner_corroboration', label:'Static-tool corroboration', points:scanners.length>=2?5:0, status:scanners.length?'observed':'unknown', source:'findings.scanners + findings.source', explanation:scanners.length>=2 ? `${scanners.join(', ')} reported the finding: +5 once. Tools may share patterns; this is not independent exploit probability.` : scanners.length ? `${scanners[0]} recorded; no multi-tool bonus.` : 'No recognized static-tool provenance recorded; AI confidence and trained-model scores are not substituted.', verificationIds:[] },
    { id:'latest_security_failure', label:'Latest candidate security assertion still failing', points:latestSecurityFailure?10:0, status:latestSecurityFailure || proof[0]?.redGreen ? 'observed':'unknown', source:'latest patch security_retest + baseline/reproduction records', explanation:latestSecurityFailure ? 'The same reproduced assertion remains failing on the latest candidate without execution errors: +10 repair-triage points. This does not establish a production exploit.' : proof[0]?.redGreen ? 'The latest candidate passes the matched security retest: no failing-check bonus. Source risk is not reduced without verified deployment.' : 'No qualifying failed security assertion on the latest candidate. Zero added points does not prove the source safe.', verificationIds:latestSecurityFailure || proof[0]?.redGreen ? proof[0].ids:[] },
  ];
  const unknowns: Unknown[] = [
    {id:'network_exposure',label:'Runtime reachability unknown',explanation:'No verified deployment/network reachability is stored. File names, CWE and AI prose do not establish public exposure.'},
    {id:'authentication',label:'Authentication requirements unknown',explanation:'No structured verified access-control context is stored.'},
    {id:'business_impact',label:'Business impact unknown',explanation:'Affected production assets, data sensitivity and business consequences have not been verified.'},
    {id:'deployment',label:'Production repair state unknown',explanation:'Passing candidate tests and published pull requests do not establish deployment of the fix.'},
  ];
  if (!knownSeverity) unknowns.push({id:'severity',label:'Severity unknown',explanation:'A conservative 65-point baseline is used.'});
  if (!scanners.length) unknowns.push({id:'scanner_provenance',label:'Static-tool provenance unknown',explanation:'No recognized static scanner is associated with this finding.'});
  if (!reproduced) unknowns.push({id:'exploit_validation',label:'Matched exploit validation unavailable',explanation:'No qualifying original-fail/candidate-pass test pair is recorded.'});
  if (patchInput === undefined || records === undefined) unknowns.push({id:'verification',label:'Repair evidence unavailable',explanation:'At least one saved-evidence endpoint did not return data.'});
  const subtotal = factors.reduce((sum,f)=>sum+f.points,0);
  const floor = Math.max(0,40-subtotal);
  factors.push({id:'uncertainty_floor',label:'Missing-context priority floor',points:floor,status:'policy',source:'risk-priority-v1 conservative policy',explanation:`Runtime exposure and business context are unknown. Apply a minimum Medium score of 40 (+${floor}); this is a policy safeguard, not evidence of an exploit.`,verificationIds:[]});
  const score = Math.min(100, subtotal+floor);
  const state = latest && records !== undefined ? verificationState(latest,scoped) : null;
  const repairStatus = patchInput === undefined || records === undefined ? 'unknown' : !latest ? 'no_candidate' : state === 'checks_passed' && !['proposed','rejected'].includes(latest.status) ? 'verified_candidate' : state === 'failed' ? 'failed_checks' : ['approved','rejected'].includes(latest.status) ? 'unknown' : 'pending_checks';
  return { findingId:finding.id, runId:finding.runId, policyVersion:RISK_POLICY_VERSION, label:RISK_SCORE_LABEL, score, level:riskLevel(score),
    factors, unknowns, provisional:true, mlContributes:false,
    explanation:`${factors.map(f=>`${f.label}: ${f.points}`).join(' + ')} = ${subtotal+floor}${subtotal+floor>100?' (capped at 100)':''}. ${riskLevel(score)} priority for the submitted source. No compromise probability is estimated; candidate repair status does not lower source risk without verified deployment.`,
    repair:{status:repairStatus,patchId:latest?.id ?? null},
  };
}
export type RiskAssessment = ReturnType<typeof assessFindingRisk>;

export function assessRunRisk(runId: string, input: Finding[], patches: Patch[] | undefined, records: VerificationRun[] | undefined) {
  const findings = [...new Map(input.filter(f=>f.runId===runId).map(f=>[f.id,f])).values()];
  return findings.map(finding=>({finding,assessment:assessFindingRisk(finding,patches,records)}))
    .sort((a,b)=>b.assessment.score-a.assessment.score || b.assessment.unknowns.length-a.assessment.unknowns.length || a.finding.file.localeCompare(b.finding.file) || a.finding.startLine-b.finding.startLine || a.finding.id.localeCompare(b.finding.id));
}
