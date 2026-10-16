import { Link } from 'react-router-dom';
import type { Finding, FindingML, Patch, VerificationRun } from '@proofpatch/shared';
import { assessRunRisk, RISK_LEVELS, RISK_POLICY_VERSION, RISK_SCORE_LABEL } from '../../services/risk-assessment';
import { cweModelInsight, cweReference } from '../../lib/ml-analytics';

const repairLabels: Record<string,string> = {verified_candidate:'Verified candidate · deployment unknown',failed_checks:'Verification failed',pending_checks:'Awaiting complete proof',no_candidate:'No patch recorded',unknown:'Repair evidence unavailable'};
export function RiskAssessmentSection({ findings, patches, verification, rows, runId, repositoryId }: {
  findings: Finding[]; patches: Patch[] | undefined; verification: VerificationRun[] | undefined;
  rows: {finding:Finding;ml:FindingML|null}[]; runId:string; repositoryId:string;
}) {
  const ranked = assessRunRisk(runId,findings,patches,verification);
  const distribution = RISK_LEVELS.map(level=>({level,count:ranked.filter(row=>row.assessment.level===level).length}));
  const maximum = Math.max(1,...distribution.map(row=>row.count));
  return <section className="panel ml-risk-section" aria-label="Risk Assessment">
    <div className="ml-chart-title"><div><span className="ml-kicker">RISK ASSESSMENT · PROVISIONAL</span><h3>{RISK_SCORE_LABEL}</h3></div><span>{RISK_POLICY_VERSION}</span></div>
    <p className="ml-risk-intro">A documented 0–100 triage priority from saved evidence. This is not ML-predicted exploitability or a probability of compromise. Missing exposure and business context prevents a Low rating.</p>
    <h4 className="ml-risk-distribution-title">Risk priority distribution</h4>
    <div className="ml-risk-distribution" role="img" aria-label={`Priority distribution: ${distribution.map(row=>`${row.level} ${row.count}`).join(', ')}`}>
      {distribution.map(({level,count})=><div key={level}><span>{level}<strong>{count}</strong></span><span className="ml-bar-track"><i className={`ml-risk-fill-${level.toLowerCase()}`} style={{width:`${count/maximum*100}%`}}/></span></div>)}
    </div>
    {!ranked.length ? <p>No saved findings in this analysis to assess.</p> : <ol className="ml-risk-list">{ranked.map(({finding,assessment:risk},index)=>{
      const ml = rows.find(row=>row.finding.id===finding.id)?.ml ?? null;
      const classifier = cweModelInsight(finding,ml);
      const reference = cweReference(finding.cwe);
      return <li key={finding.id}>
        <div className="ml-risk-heading"><div><span className="ml-kicker">PRIORITY {index+1} · {reference ? <a href={reference} target="_blank" rel="noreferrer">{finding.cwe}</a> : finding.cwe ?? 'CWE unassigned'}</span><h4>{finding.file}:{finding.startLine}</h4><span>{finding.category} · Recorded severity: {finding.severity}</span></div><div className={`ml-risk-score ml-risk-${risk.level.toLowerCase()}`} aria-label={`${risk.level} risk priority, ${risk.score} out of 100`}><strong>{risk.score}<small>/100</small></strong><span>{risk.level}</span></div></div>
        <div className="ml-risk-context"><span>Repair: <strong>{repairLabels[risk.repair.status]}</strong></span><span>{risk.unknowns.length} context gaps · source risk retained until deployment is verified</span></div>
        <p className="ml-risk-classifier">{!classifier.supported ? 'No trained CWE model for this language.' : classifier.prediction ? <>Existing CWE model: {classifier.prediction.cwe ?? classifier.prediction.predicted_category ?? classifier.prediction.status} · {classifier.prediction.modelVersion}{classifier.prediction.probability !== null ? ` · ${(classifier.prediction.probability*100).toFixed(2)}% uncalibrated classification score` : ''}.</> : 'No saved CWE prediction for this finding.'} <strong>ML contributes no points to this risk score.</strong></p>
        <details><summary>Score factors, evidence and unknowns</summary><p>{risk.explanation}</p><ul className="ml-risk-factors">{risk.factors.map(factor=><li key={factor.id}><div><strong>{factor.label}</strong><span>{factor.points>0?'+':''}{factor.points} · {factor.status}</span></div><p>{factor.explanation}</p><small>Source: {factor.source}</small>{factor.verificationIds.map(id=>{
          const record = verification?.find(row=>row.id===id && row.runId===finding.runId && row.ownerId===finding.ownerId);
          return record?.artifactId ? <a key={id} href={`/api/runs/${runId}/artifacts/${record.artifactId}`} target="_blank" rel="noreferrer">{record.stage.replaceAll('_',' ')} log ↗</a> : null;
        })}</li>)}</ul><h5>Unknown indicators</h5><ul>{risk.unknowns.map(item=><li key={item.id}><strong>{item.label}:</strong> {item.explanation}</li>)}</ul></details>
        <Link className="text-button" to={risk.repair.patchId ? `/reviewer/app/patches?repository=${repositoryId}&run=${runId}&patch=${risk.repair.patchId}` : `/reviewer/app/findings?repository=${repositoryId}&run=${runId}&finding=${finding.id}`}>Inspect finding & evidence ↗</Link>
      </li>;
    })}</ol>}
    <details className="ml-risk-policy"><summary>Scoring policy and limits</summary><p>Base points: Critical 85, High 65, Medium 45, Low 25, Informational 15; unavailable severity uses 65. Add at most 20 for matched sandbox red/green proof, 5 for two recognized static tools, and 10 for a reproduced assertion still failing on the latest candidate. Apply a 40-point uncertainty floor and cap at 100. Bands: Critical 85–100, High 65–84, Medium 40–64, Low 0–39.</p><p>Weights are a versioned triage policy, not trained or calibrated metrics. No verified runtime exposure, access requirements or business impact is currently collected. CWE, free-text claims, model probabilities and AI confidence do not affect the score. Candidate proof does not establish a production repair. No records are changed by this calculation.</p></details>
  </section>;
}
