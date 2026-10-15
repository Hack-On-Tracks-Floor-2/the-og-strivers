import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { z } from 'zod';
import { Play, Circle, Check, ArrowUpRight, Info } from 'lucide-react';
import { RepositorySchema, AnalysisRunSchema, RunEventSchema } from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, EmptyState, ErrorBox, Loading, Status, Eyebrow, date } from '../components/ui';
export function ScannerPage() {
  const [params, setParams] = useSearchParams();
  const state = useResource(async () => ({
    repos: await api('/repositories', z.array(RepositorySchema)),
    runs: await api('/runs', z.array(AnalysisRunSchema)),
  }));
  const [repository, setRepository] = useState(params.get('repository') ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const selected = params.get('run') ?? state.data?.runs[0]?.id;
  const events = useResource(
    () =>
      selected ? api(`/runs/${selected}/events`, z.array(RunEventSchema)) : Promise.resolve([]),
    [selected],
  );
  const run = state.data?.runs.find((r) => r.id === selected);
  async function create() {
    setError('');
    setBusy(true);
    try {
      const run = await api('/runs', AnalysisRunSchema, {
        repositoryId: repository || state.data?.repos[0]?.id,
      });
      setParams({ run: run.id });
      state.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageTitle
        eyebrow="02 / ANALYSIS CONTROL"
        title="SECURITY SCANNER"
        description="Request an analysis. Follow the real state of every job."
      />
      <div className="capability-banner">
        <Info size={19} />
        <div>
          <strong>Agent integration pending</strong>
          <p>
            Jobs are saved to your workspace. Repository inspection and automated scanning are not
            configured.
          </p>
        </div>
        <Status value="not_configured" />
      </div>
      {error && <ErrorBox message={error} />}
      <section className="panel details">
        <Eyebrow>NEW ANALYSIS JOB</Eyebrow>
        <div className="scanner-controls">
          <label className="grow">
            Repository
            <select
              value={repository || state.data?.repos[0]?.id || ''}
              onChange={(e) => setRepository(e.target.value)}
              disabled={!state.data?.repos.length}
            >
              <option value="" disabled>
                Select a repository
              </option>
              {state.data?.repos.map((repo) => (
                <option value={repo.id} key={repo.id}>
                  {repo.owner}/{repo.name}
                </option>
              ))}
            </select>
          </label>
          <button
            className="button primary"
            disabled={busy || !state.data?.repos.length}
            onClick={create}
          >
            <Play size={16} />
            {busy ? 'Creating…' : 'Create analysis job'}
          </button>
        </div>
        {!state.data?.repos.length && !state.loading && (
          <p className="field-help">
            Add a repository first.{' '}
            <Link to="/developer/app/repositories" className="lime-text">
              Go to repositories ↗
            </Link>
          </p>
        )}
      </section>
      {state.loading ? (
        <Loading />
      ) : state.error ? (
        <ErrorBox message={state.error} retry={state.reload} />
      ) : !state.data?.runs.length ? (
        <section className="panel">
          <EmptyState
            title="No jobs on the rail."
            description="Your analysis requests and their actual execution state will appear here."
          />
        </section>
      ) : (
        <div className="scanner-grid">
          <section className="panel">
            <div className="panel-heading">
              <h2>Analysis jobs</h2>
            </div>
            {state.data.runs.map((item) => (
              <button
                className={`record-row job-row ${item.id === selected ? 'selected' : ''}`}
                key={item.id}
                onClick={() => setParams({ run: item.id })}
              >
                <div>
                  <strong>
                    {state.data!.repos.find((r) => r.id === item.repositoryId)?.name ??
                      item.id.slice(0, 8)}
                  </strong>
                  <span>{date(item.createdAt)}</span>
                  <span className="mono">RUN / {item.id.slice(0, 8)}</span>
                </div>
                <Status value={item.status} />
              </button>
            ))}
          </section>
          <section className="panel details">
            <div className="panel-heading flush">
              <h2>Pipeline & events</h2>
              {run && <Status value={run.status} />}
            </div>
            <div className="pipeline">
              {[
                'Request received',
                'Source mapping',
                'Vulnerability analysis',
                'Patch generation',
                'Verification',
                'Security review',
              ].map((step, i) => (
                <div key={step} className={i === 0 ? 'pipeline-step recorded' : 'pipeline-step'}>
                  {i === 0 ? <Check size={16} /> : <Circle size={13} />}
                  <span>{step}</span>
                  <small>{i === 0 ? 'RECORDED' : 'NOT EXECUTED'}</small>
                </div>
              ))}
            </div>
            {run?.error && <ErrorBox message={run.error} />}
            <Eyebrow>RECORDED EVENTS</Eyebrow>
            {events.loading ? (
              <Loading />
            ) : events.error ? (
              <ErrorBox message={events.error} retry={events.reload} />
            ) : (
              events.data?.map((event) => (
                <div className="event-item" key={event.id}>
                  <span className="mono">{date(event.createdAt)}</span>
                  <p>{event.message}</p>
                  <code>EVENT / {event.id}</code>
                </div>
              ))
            )}
          </section>
        </div>
      )}
    </>
  );
}
