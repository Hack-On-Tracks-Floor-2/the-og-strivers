import { useEffect, useState, type ChangeEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Download, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { RecordedVerificationSchema, recordedStages, recordedVerdict, type RecordedVerification } from '../lib/recorded-verification';
import { requiredStages, stageLabels, verificationState } from '../lib/security-data';
import { useAuth } from '../features/auth';
import { useWorkspaceIndex, useRunBundle } from '../hooks/useSecurityData';
import { Brand, PageTitle, Eyebrow, ErrorBox, Loading, Status, EmptyState, date } from '../components/ui';
import { EvidenceTimeline } from '../components/artifacts';
import { PatchWorkspace } from '../components/patches/PatchWorkspace';

function RecordedTestRun() {
  const [report, setReport] = useState<RecordedVerification>();
  const [source, setSource] = useState('Bundled execution evidence');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  async function loadBundled() {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('/evidence/regression-demo.json');
      if (!response.ok) throw new Error('Recorded report unavailable. Load a report JSON file below.');
      setReport(RecordedVerificationSchema.parse(await response.json()));
      setSource('Bundled execution evidence');
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not load the report.'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void loadBundled(); }, []);
  async function loadBackend() {
    setError('');
    try {
      setReport(await api('/regression-demo/evidence', RecordedVerificationSchema));
      setSource('Saved backend demo report');
    } catch (reason) { setError(`${reason instanceof Error ? reason.message : 'Backend unavailable.'} The recorded report below remains available.`); }
  }
  async function importReport(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error('Report must be smaller than 2 MB.');
      setReport(RecordedVerificationSchema.parse(JSON.parse(await file.text())));
      setSource(`Imported report: ${file.name} (source not independently authenticated)`);
      setError('');
    } catch { setError('Invalid verification report. Existing evidence remains displayed; no test results were inferred.'); }
    event.target.value = '';
  }
  const outcome = report ? recordedVerdict(report) : 'Verification incomplete';
  return <>
    <section className="panel details recorded-notice">
      <Eyebrow>Recorded Test Run</Eyebrow>
      <p>This report records an earlier execution on a controlled local fixture. Opening this page does not run tests. It does not verify another repository or a current deployment.</p>
      <div className="verification-controls">
        <button className="button secondary small-button" onClick={() => void loadBundled()}>Load recorded demo</button>
        <button className="button secondary small-button" onClick={() => void loadBackend()}>Load backend demo report</button>
        <label className="button secondary small-button">Load report JSON<input aria-label="Load report JSON" type="file" accept=".json,application/json" onChange={importReport} /></label>
        <a className="text-button" href="/evidence/regression-demo.json" download><Download size={15} /> Download authentic demo report</a>
      </div>
    </section>
    {error && <ErrorBox message={error} />}
    {loading ? <Loading /> : !report ? <EmptyState title="Verification incomplete" description="Not yet executed: no readable verification evidence is loaded." /> : <>
      <section className="panel details recorded-verdict" aria-label="Final verification status">
        <div className="section-header"><div><Eyebrow>FINAL VERIFICATION STATUS</Eyebrow><h2>{outcome}</h2></div><ShieldCheck size={25} /></div>
        <h3>{report.scenario}</h3>
        <p>{source} · {date(report.createdAt)} · Run <code>{report.runId}</code></p>
        <p>Patch source: <strong>{report.patchSource}</strong>. {report.aiReason}</p>
        <p>{report.execution} {report.nodeVersion && `Runtime: ${report.nodeVersion}.`}</p>
        {report.provenance && <p>Evidence commit <code>{report.provenance.commit}</code> · <code>{report.provenance.reportPath}</code></p>}
        {report.integrity && <p>Original functional tests: {report.integrity.functionalTestsUnchanged ? 'unchanged' : 'integrity not established'}. Security tests before and after: {report.integrity.securityTestsIdentical ? 'identical' : 'integrity not established'}.</p>}
      </section>
      <div className="recorded-code-grid">
        <section className="panel details"><Eyebrow>01 / ORIGINAL VULNERABLE CODE</Eyebrow><h3>src/reports.cjs</h3><pre className="code-block">{report.originalCode || 'Original source unavailable — verification incomplete.'}</pre></section>
        <section className="panel details"><Eyebrow>02 / PROPOSED PATCH</Eyebrow><h3>src/reports.cjs</h3><pre className="code-block">{report.proposedCode || 'Proposed source unavailable — verification incomplete.'}</pre></section>
      </div>
      <details className="panel details"><summary>Unified code diff</summary><pre className="code-block">{report.unifiedDiff || 'No diff recorded.'}</pre></details>
      {recordedStages.map(([name, label]) => {
        const stage = report.stages.find(item => item.stage === name);
        const summary = stage?.summary;
        return <section className="panel details recorded-stage" key={name}>
          <div className="section-header"><h3>{label}</h3><Status value={!stage || !summary?.total ? 'not_available' : stage.exitCode === 0 ? 'passed' : 'failed'} /></div>
          {!stage ? <p>Not yet executed</p> : <>
            {name === 'security-before' && <p className="evidence-context">Expected failure against vulnerable code: exit 1 demonstrates the attack was reproduced. This is not a passing security check.</p>}
            <p>Exit code: <strong>{stage.exitCode ?? 'Not recorded'}</strong>{stage.durationMs !== undefined && ` · ${stage.durationMs} ms`}{stage.startedAt && ` · ${date(stage.startedAt)}`}</p>
            <p>{summary?.total ? `${summary.passed} passed · ${summary.failed} failed · ${summary.errors} errors · ${summary.skipped} skipped · ${summary.total} total` : 'Not yet executed — test results unavailable'}</p>
            <details><summary>Individual test results</summary>{summary?.cases.map(test => <p key={test.id}><code>{test.id}</code> <Status value={test.outcome} /></p>)}</details>
            <h4>Executed command</h4><pre className="code-block">{stage.executable && stage.argv ? JSON.stringify([stage.executable, ...stage.argv]) : 'Command not recorded'}</pre>
            <p>Working directory: <code>{stage.cwd || 'Not recorded'}</code></p>
            <details open={name === 'security-before'}><summary>Actual execution logs</summary><pre className="code-block execution-log">{stage.stdout || 'No stdout recorded'}{stage.stderr ? `\nSTDERR:\n${stage.stderr}` : ''}{stage.error ? `\nERROR: ${stage.error}` : ''}</pre></details>
          </>}
        </section>;
      })}
      <details className="panel details"><summary>Unchanged original functional tests</summary><pre className="code-block">{report.functionalTests || 'Test source unavailable'}</pre></details>
      <details className="panel details"><summary>Security regression test source</summary><pre className="code-block">{report.securityTest || 'Test source unavailable'}</pre></details>
    </>}
  </>;
}

function SavedVerification() {
  const [params, setParams] = useSearchParams();
  const index = useWorkspaceIndex();
  const selected = index.data?.runs.find(run => run.id === params.get('run')) ?? index.data?.runs[0];
  const state = useRunBundle(selected?.id);
  const bundle = state.data;
  const patch = bundle?.patches.find(p => p.id === params.get('patch')) ?? bundle?.patches[0];
  return <>
    <p>Saved analysis records from the verification API. No execution is started by this viewer.</p>
    {index.error && <ErrorBox message={index.error} retry={index.reload} />}
    {state.error && <ErrorBox message={state.error} retry={state.reload} />}
    {(index.loading || state.loading) && <Loading />}
    <div className="verification-controls"><label>Analysis run <select value={selected?.id ?? ''} onChange={event => setParams({ source: 'records', run: event.target.value })}>
      {!index.data?.runs.length && <option value="">No saved runs</option>}
      {index.data?.runs.map(run => <option key={run.id} value={run.id}>{run.id.slice(0, 8)} · {run.status} · {date(run.createdAt)}</option>)}
    </select></label><label>Patch <select value={patch?.id ?? ''} onChange={event => setParams({ source: 'records', run: selected!.id, patch: event.target.value })}>
      {!bundle?.patches.length && <option value="">No saved patches</option>}
      {bundle?.patches.map(p => <option key={p.id} value={p.id}>{p.id.slice(0, 8)} · Attempt {p.attempt}</option>)}
    </select></label></div>
    {!patch || !bundle ? <EmptyState title="Verification incomplete" description="Not yet executed: select a saved run with a patch and execution records, or open Recorded Test Run." /> : <>
      <h2>{verificationState(patch, bundle.verification) === 'checks_passed' ? 'Verified by saved execution records' : 'Verification incomplete or failed'}</h2>
      <PatchWorkspace patch={patch} bundle={bundle} repositories={index.data?.repositories} />
      {requiredStages.filter(stage => !bundle.verification.some(v => v.patchId === patch.id && v.stage === stage)).map(stage => <p key={stage}>{stageLabels[stage]}: Not yet executed</p>)}
      <EvidenceTimeline events={[]} verification={bundle.verification.filter(v => v.patchId === patch.id)} />
    </>}
  </>;
}

export function VerificationPage({ publicReport = false }: { publicReport?: boolean }) {
  const [params] = useSearchParams();
  const { user } = useAuth();
  const records = !publicReport && (params.get('source') === 'records' || (!!params.get('run') && params.get('source') !== 'recorded'));
  const content = <>
    <PageTitle eyebrow="EVIDENCE FIRST / REGRESSION ENGINE" title="REGRESSION VERIFICATION" description="Inspect original source, the proposed patch, executed tests, logs, and the final recorded verdict." />
    {!publicReport && <div className="verification-controls" aria-label="Verification evidence source"><Link className={`button ${!records ? 'primary' : 'secondary'} small-button`} to="?source=recorded">Recorded Test Run</Link><Link className={`button ${records ? 'primary' : 'secondary'} small-button`} to="?source=records">Saved analysis records</Link></div>}
    {records ? <SavedVerification /> : <RecordedTestRun />}
  </>;
  return publicReport ? <div className="public-verification workspace-content"><header className="verification-public-header"><Brand /><Link className="text-button" to={user ? `/${user.role}/app/verification` : '/'}>{user ? 'Open dashboard' : 'Back to portals'}</Link></header>{content}</div> : content;
}
