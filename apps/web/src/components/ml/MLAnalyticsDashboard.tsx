import { Link } from 'react-router-dom';
import { Activity, ArrowUpRight, Cpu, Flame, ScanLine, ShieldCheck, ShieldAlert, TimerReset, TriangleAlert } from 'lucide-react';
import type { Finding, FindingML } from '@proofpatch/shared';
import { cweModelInsight, type MLAnalytics } from '../../lib/ml-analytics';
import { Status } from '../ui';
import '../../styles/ml-analytics.css';

const colors = ['#fa7f8c', '#f5b275', '#e7d480', '#8ecdb9'];
const number = (value: number | null) => value === null ? '—' : value.toLocaleString();

export function MLAnalyticsDashboard({ analytics: a, rows, repositoryId, runId }: {
  analytics: MLAnalytics; rows: {finding: Finding; ml: FindingML | null}[]; repositoryId: string; runId: string;
}) {
  const cards = [
    {label:'Discovered findings', value:a.total, icon:ScanLine, tone:'lime', note:'Distinct findings in this run'},
    {label:'Critical', value:a.severities[0].count, icon:Flame, tone:'critical', note:'Scanner severity'},
    {label:'High risk', value:a.severities[1].count, icon:TriangleAlert, tone:'high', note:'Scanner severity'},
    {label:'Verified resolutions', value:a.resolved, icon:ShieldCheck, tone:'safe', note:'Current patches with complete proofs'},
    {label:'Unresolved', value:a.unresolved, icon:ShieldAlert, tone:'muted', note:'Includes pending and failed checks'},
    {label:'Pending verification', value:a.pendingFindings, icon:TimerReset, tone:'muted', note:'Findings awaiting complete checks'},
  ];
  const rated = a.severities.reduce((sum,row) => sum + row.count, 0);
  let offset = 0;
  const arcs = a.severities.map((row,i) => { const length = rated ? row.count / rated * 314.159 : 0; const arc = {...row, length, offset, color:colors[i]}; offset += length; return arc; });
  const classified = rows.filter(row => cweModelInsight(row.finding,row.ml).prediction?.status === 'predicted').length;
  const history = [...(a.patches ?? [])].sort((left,right) => right.createdAt.localeCompare(left.createdAt) || right.attempt-left.attempt);
  return <div className="ml-analytics">
    <div className="ml-analytics-intro"><div><span className="ml-kicker"><Activity size={13}/> RUN INTELLIGENCE</span><h2>Vulnerability & repair analytics</h2><p>Scanner findings, model signals and repair proofs for the selected analysis.</p></div><span className="ml-scope-badge">RUN {runId.slice(0,8)}</span></div>
    <div className="ml-stat-grid">{cards.map(({label,value,icon:Icon,tone,note}) => <article className={`ml-stat ml-tone-${tone}`} key={label}><div><span>{label}</span><Icon size={17}/></div><strong>{number(value)}</strong><small>{value === null ? 'Evidence unavailable' : note}</small></article>)}</div>
    <p className="ml-evidence-note">Verified resolutions describe tested patch candidates. Repository merge and deployment are separate actions.</p>
    <div className="ml-chart-grid">
      <section className="panel ml-chart"><div className="ml-chart-title"><div><span className="ml-kicker">SCANNER EVIDENCE</span><h3>Severity distribution</h3></div><span>{a.total} findings</span></div>
        {rated ? <div className="ml-severity"><svg viewBox="0 0 140 140" role="img" aria-label={a.severities.map(row=>`${row.name}: ${row.count}`).join(', ')}><circle cx="70" cy="70" r="50" fill="none" stroke="#25282b" strokeWidth="14"/>{arcs.filter(row=>row.count).map(row=><circle key={row.name} cx="70" cy="70" r="50" fill="none" stroke={row.color} strokeWidth="14" strokeDasharray={`${row.length} ${314.159-row.length}`} strokeDashoffset={-row.offset} transform="rotate(-90 70 70)"/>)}<text x="70" y="69" textAnchor="middle" className="ml-donut-count">{rated}</text><text x="70" y="86" textAnchor="middle" className="ml-donut-label">RATED FINDINGS</text></svg><div className="ml-severity-legend">{a.severities.map((row,i)=><div key={row.name}><span><i style={{background:colors[i]}}/>{row.name}</span><strong>{row.count}</strong></div>)}</div></div> : <div className="ml-chart-empty">No critical, high, medium or low findings recorded.</div>}
        <p className="ml-chart-foot">Scanner severity · not an ML prediction{a.informational > 0 ? ` · ${a.informational} informational findings outside this chart` : ''}</p>
      </section>
      <section className="panel ml-chart"><div className="ml-chart-title"><div><span className="ml-kicker">WEAKNESS LANDSCAPE</span><h3>Most frequent CWEs</h3></div><span>Finding count</span></div>
        {a.categories.length ? <div className="ml-cwe-bars">{a.categories.slice(0,6).map(row=><div key={row.name}><div><span>{row.name}</span><strong>{row.count}</strong></div><span className="ml-bar-track"><i style={{width:`${row.count / a.categories[0].count * 100}%`}}/></span></div>)}</div> : <div className="ml-chart-empty">CWE rankings appear when scanner findings are recorded.</div>}
        <p className="ml-chart-foot">Top {Math.min(a.categories.length,6)} categories · each finding counted once</p>
      </section>
    </div>
    <section className="panel ml-repair-summary"><div className="ml-chart-title"><div><span className="ml-kicker">REPAIR PERFORMANCE</span><h3>From proposal to proof</h3></div><ShieldCheck size={20}/></div>
      <div className="ml-repair-metrics">{[['Verified patches',a.verified],['Failed verification attempts',a.failed],['Pending patches',a.pending],['Recorded patch retries',a.retries]].map(([label,value])=><div key={String(label)}><strong>{number(value as number|null)}</strong><span>{label}</span></div>)}<div className="ml-success"><strong>{a.successRate === null ? '—' : `${(a.successRate*100).toFixed(1)}%`}</strong><span>Completed verification success</span></div></div>
      {!!a.patches?.length && a.verified !== null && <div className="ml-outcome-bar" role="img" aria-label={`${a.verified} verified, ${a.failed} failed, ${a.pending} pending, ${a.unavailable} unavailable`}>{[[a.verified,'verified'],[a.failed,'failed'],[a.pending,'pending'],[a.unavailable,'unavailable']].map(([count,key])=>!!count && <span key={String(key)} className={`ml-outcome-${key}`} style={{flex:Number(count)}}/>)}</div>}
      <p className="ml-chart-foot">{a.concluded ? `${a.verified} verified / ${a.concluded} concluded patch attempts. Pending/incomplete evidence and generation failures are excluded from this rate.` : 'No reliable completed-attempt denominator available; no success percentage is inferred.'} {a.unavailable ? `${a.unavailable} patch records lack a conclusive eligible outcome.` : ''} Patch retries are distinct recorded finding/attempt pairs beyond attempt one; unrecorded generation retries are unavailable.</p>
    </section>
    <div className="ml-model-strip"><div><Cpu size={19}/><span><strong>{classified} saved classifier predictions</strong><small>Existing Python & Java CWE classifiers</small></span></div><span>Source-bound evidence · no inference triggered by this dashboard</span></div>
    <section className="panel ml-patch-insights"><div className="ml-chart-title"><div><span className="ml-kicker">SECURITY & REGRESSION EVIDENCE</span><h3>Patch verification evidence</h3></div><span>{a.patches?.length ?? '—'} recorded patch attempts</span></div>
      {!a.patches ? <p>Patch evidence is unavailable from this backend.</p> : !history.length ? <p>No patch attempts recorded for this run. No verification outcome is inferred.</p> : <div className="ml-evidence-list">{history.map(patch=><article key={patch.id}><div className="ml-evidence-heading"><div><span className="ml-kicker">Attempt {patch.attempt} · Finding {patch.findingId.slice(0,8)}</span><h4>{patch.files.map(file=>file.path).join(', ') || `Patch ${patch.id.slice(0,8)}`}</h4></div><Status value={a.states.get(patch.id) ?? 'not_available'}/></div><div className="ml-evidence-tags"><span>Patch status: {patch.status.replaceAll('_',' ')}</span></div><p>Verification uses the recorded security and regression proof stages. A proposed patch or approval alone does not establish a fix.</p><Link className="text-button" to={`/reviewer/app/patches?repository=${repositoryId}&run=${runId}&patch=${patch.id}`}>Inspect patch & evidence <ArrowUpRight size={13}/></Link></article>)}</div>}
    </section>
  </div>;
}
