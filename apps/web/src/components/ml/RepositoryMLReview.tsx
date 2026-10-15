import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { z } from 'zod';
import { AnalysisRunSchema, FindingMLSchema, FindingSchema } from '@proofpatch/shared';
import { api } from '../../lib/api';
import { ACTIVE_RUNS } from '../../lib/security-data';
import { useWorkspaceIndex } from '../../hooks/useSecurityData';
import { useResource } from '../../hooks/useResource';
import { RunScope } from '../RunScope';
import { EmptyState, ErrorBox, Loading, Status, date } from '../ui';

const rowsSchema = z.array(z.object({ finding: FindingSchema, ml: FindingMLSchema.nullable() }));

/** Reviewer-only repository evidence. Reading this page never launches classification. */
export function RepositoryMLReview() {
  const index = useWorkspaceIndex();
  const [params, setParams] = useSearchParams();
  const runs = index.data?.runs ?? [];
  const repositories = index.data?.repositories ?? [];
  const requestedRun = runs.find((run) => run.id === params.get('run'));
  const repositoryId = requestedRun?.repositoryId ??
    repositories.find((repo) => repo.id === params.get('repository'))?.id ?? repositories[0]?.id ?? '';
  const scoped = runs.filter((run) => run.repositoryId === repositoryId);
  const selected = scoped.find((run) => run.id === params.get('run')) ?? scoped[0];
  const evidence = useResource(async () => {
    if (!selected) return undefined;
    const [run, rows] = await Promise.all([
      api(`/runs/${selected.id}`, AnalysisRunSchema),
      api(`/runs/${selected.id}/ml-findings`, rowsSchema),
    ]);
    return { run, rows };
  }, [selected?.id]);
  const data = evidence.data?.run.id === selected?.id ? evidence.data : undefined;
  useEffect(() => {
    if (!data || !ACTIVE_RUNS.has(data.run.status)) return;
    const timer = setTimeout(evidence.reload, 5000);
    return () => clearTimeout(timer);
  }, [data, evidence.reload]);
  function selectRepository(id: string) {
    const next = new URLSearchParams(params);
    next.set('repository', id);
    next.delete('run');
    setParams(next);
  }
  function selectRun(id: string) {
    const next = new URLSearchParams(params);
    next.set('repository', repositoryId);
    next.set('run', id);
    setParams(next);
  }
  return (
    <section className="security-intelligence" aria-label="Repository ML findings">
      <div className="intelligence-heading">
        <div><span className="eyebrow">AUTOMATIC / FINDING-LEVEL CLASSIFICATION</span><h2>Repository predictions</h2></div>
        {data && <Status value={data.run.status} />}
      </div>
      <p>Saved predictions accompany findings from the submitted source revision. ML does not confirm vulnerabilities, change scanner severity, or determine approval.</p>
      {index.error && <ErrorBox message={index.error} retry={index.reload} />}
      {index.loading ? <Loading /> : (
        <RunScope repositories={repositories} runs={runs} repositoryId={repositoryId} runId={selected?.id ?? ''}
          onRepository={selectRepository} onRun={selectRun} refresh={() => { index.reload(); evidence.reload(); }} />
      )}
      {evidence.error && <ErrorBox message={evidence.error} retry={evidence.reload} />}
      {!index.loading && !selected ? (
        <section className="panel"><EmptyState title="No analysis selected."
          description="Choose a submitted repository with an analysis run. New runs classify supported findings automatically; no code pasting is required." /></section>
      ) : evidence.loading ? <Loading /> : data && (
        <>
          {data.run.status === 'not_configured' && <p className="analysis-notice" role="status">This run has not executed. Configure the existing analysis pipeline before repository findings can be produced.</p>}
          {!data.rows.length ? (
            <section className="panel"><EmptyState title="No findings recorded."
              description="ML runs only after a finding is saved. An empty list does not prove that this repository is safe." /></section>
          ) : data.rows.map(({ finding, ml }) => (
            <article className="panel details" key={finding.id} aria-label={`ML finding ${finding.file}:${finding.startLine}`}>
              <div className="artifact-heading">
                <div><h3>{finding.file}:{finding.startLine}{finding.endLine !== finding.startLine ? `–${finding.endLine}` : ''}</h3><p>{finding.category}</p></div>
                <Status value={ml?.status ?? (ACTIVE_RUNS.has(data.run.status) ? 'pending' : 'not_recorded')} />
              </div>
              <dl>
                <dt>Source language</dt><dd>{ml?.language ?? 'Not recorded'}</dd>
                <dt>Scanner CWE</dt><dd>{finding.cwe ?? 'Not assigned'}</dd>
                <dt>Scanner severity</dt><dd><Status value={finding.severity} /></dd>
                <dt>ML predicted CWE</dt><dd>{ml?.prediction?.status === 'predicted'
                  ? ml.prediction.cwe ?? 'Benchmark-negative estimate (not a safety guarantee)'
                  : ml?.status === 'unsupported' ? 'Unsupported language' : 'No category prediction'}</dd>
                <dt>Model version</dt><dd><code>{ml?.prediction?.modelVersion ?? 'No model prediction recorded'}</code></dd>
                <dt>Source commit</dt><dd><code>{ml?.commitSha ?? 'No recorded ML provenance'}</code></dd>
                <dt>Finding ID</dt><dd><code>{finding.id}</code></dd>
                {ml?.prediction?.probability !== null && ml?.prediction?.probability !== undefined && <>
                  <dt>Model probability</dt><dd>{(ml.prediction.probability * 100).toFixed(2)}% · uncalibrated</dd>
                </>}
                {ml?.snippet && <><dt>Classified source range</dt><dd>Lines {ml.snippet.startLine}–{ml.snippet.endLine} · {ml.snippet.characters.toLocaleString()} characters · {ml.snippet.transformation}</dd></>}
                {ml && <><dt>Recorded</dt><dd>{date(ml.createdAt)}</dd></>}
              </dl>
              {ml?.comparison === 'disagrees' && <p className="analysis-notice" role="status">Scanner and ML disagree. The scanner finding is retained; a reviewer must assess its evidence.</p>}
              {ml?.comparison === 'agrees' && <p>Scanner and ML categories agree. This is not verification or execution evidence.</p>}
              {ml?.reason && <p role="status">{ml.reason}</p>}
              {!ml && <p role="status">{ACTIVE_RUNS.has(data.run.status)
                ? 'Automatic ML classification has not been recorded yet. The original finding remains available while analysis continues.'
                : 'No saved ML record exists for this finding. Older analyses need a new scan to capture source-bound predictions; nothing is inferred from the current repository HEAD.'}</p>}
              {ml?.prediction?.scope && <p>{ml.prediction.scope}</p>}
              <Link className="text-button" to={`/reviewer/app/findings?repository=${repositoryId}&run=${selected!.id}`}>Inspect original findings</Link>
              {ml?.sourceSha256 && <details><summary>Prediction provenance</summary>
                <p>Repository: {ml.repositoryUrl}</p><p>File SHA-256: <code>{ml.sourceSha256}</code></p>
                {ml.snippet && <p>Classified snippet SHA-256: <code>{ml.snippet.sha256}</code></p>}
                <p>Source text was parsed as data and was not executed by ML.</p>
              </details>}
            </article>
          ))}
        </>
      )}
    </section>
  );
}
