import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { z } from 'zod';
import { Play, Circle, Check, ArrowUpRight, Info, X } from 'lucide-react';
import {
  RepositorySchema,
  AnalysisRunSchema,
  RunEventSchema,
  HealthSchema,
  type AnalysisRun,
  type RunEvent,
} from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, EmptyState, ErrorBox, Loading, Status, Eyebrow, date } from '../components/ui';
const ACTIVE = ['received', 'queued', 'mapping', 'analyzing', 'patching', 'verifying'];
const STEPS: [string, AnalysisRun['status'][]][] = [
  ['Request received', ['received', 'queued']],
  ['Clone & source mapping', ['mapping']],
  ['Baseline tests & vulnerability search', ['analyzing']],
  ['Patch generation', ['patching']],
  ['Exploit test & regression proof', ['verifying']],
  ['Security review', ['needs_review', 'verified']],
];
// For failed runs, find how far the pipeline got from its recorded events.
const REACHED: RegExp[] = [/registered/, /^Cloned at|^Mapped/, /^Baseline:|^Search funnel/, /^Generating patch/, /^Reproduced|^Security retest|^Regression/, /^Proof complete/];
function reachedStep(events: RunEvent[] | undefined) {
  let reached = 0;
  for (const e of events ?? [])
    REACHED.forEach((re, i) => {
      if (re.test(e.message)) reached = Math.max(reached, i);
    });
  return reached;
}
function stepState(run: AnalysisRun | undefined, index: number, events?: RunEvent[]) {
  if (!run || run.status === 'not_configured') return index === 0 ? 'done' : 'idle';
  if (run.status === 'failed') {
    const reached = reachedStep(events);
    // The step after the last completed milestone is where it stopped.
    const stoppedAt = Math.min(reached + 1, STEPS.length - 1);
    return index < stoppedAt ? 'done' : index === stoppedAt ? 'failed' : 'idle';
  }
  const current = STEPS.findIndex(([, statuses]) => statuses.includes(run.status));
  if (index < current || (index === current && index === STEPS.length - 1)) return 'done';
  return index === current ? 'active' : 'idle';
}
export function ScannerPage() {
  const [params, setParams] = useSearchParams();
  const health = useResource(() => api('/health', HealthSchema));
  const available = health.data?.analysis === 'available';
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
  const [live, setLive] = useState<{ run?: AnalysisRun; events?: RunEvent[] }>({});
  const baseRun = state.data?.runs.find((r) => r.id === selected);
  const run = live.run?.id === selected ? live.run : baseRun;
  const eventList = live.run?.id === selected && live.events ? live.events : events.data;
  // Poll the selected run while it is executing, without flashing loading states.
  useEffect(() => {
    setLive({});
    if (!selected) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const [r, e] = await Promise.all([
          api(`/runs/${selected}`, AnalysisRunSchema),
          api(`/runs/${selected}/events`, z.array(RunEventSchema)),
        ]);
        if (!alive) return;
        setLive({ run: r, events: e });
        if (ACTIVE.includes(r.status)) timer = setTimeout(tick, 2000);
      } catch {
        if (alive) timer = setTimeout(tick, 4000);
      }
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [selected]);
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
      {!health.loading && (
        <div className="capability-banner">
          <Info size={19} />
          <div>
            <strong>{available ? 'Agent pipeline ready' : 'Agent pipeline unavailable'}</strong>
            <p>
              {available
                ? `Clones the repository, runs its tests in an offline Docker sandbox, locates the bug, writes a patch and proves it. AI: ${health.data?.ai?.join(' → ') ?? ''}.`
                : (health.data?.reason ??
                  'Repository inspection and automated scanning are not configured.')}
            </p>
          </div>
          <Status value={available ? 'available' : 'not_configured'} />
        </div>
      )}
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
            {busy ? 'Starting…' : available ? 'Find, patch & prove' : 'Create analysis job'}
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
                <Status value={live.run?.id === item.id ? live.run.status : item.status} />
              </button>
            ))}
          </section>
          <section className="panel details">
            <div className="panel-heading flush">
              <h2>Pipeline & events</h2>
              {run && <Status value={run.status} />}
            </div>
            <div className="pipeline">
              {STEPS.map(([step], i) => {
                const s = stepState(run, i, eventList);
                return (
                  <div key={step} className={s === 'done' ? 'pipeline-step recorded' : 'pipeline-step'}>
                    {s === 'done' ? (
                      <Check size={16} />
                    ) : s === 'failed' ? (
                      <X size={16} style={{ color: 'var(--danger, #ff5a4e)' }} />
                    ) : (
                      <Circle size={13} />
                    )}
                    <span>{step}</span>
                    <small>
                      {s === 'done'
                        ? 'COMPLETED'
                        : s === 'active'
                          ? 'RUNNING…'
                          : s === 'failed'
                            ? 'STOPPED HERE'
                            : 'NOT EXECUTED'}
                    </small>
                  </div>
                );
              })}
            </div>
            {run?.error && <ErrorBox message={run.error} />}
            <Eyebrow>RECORDED EVENTS</Eyebrow>
            {events.loading && !eventList ? (
              <Loading />
            ) : events.error && !eventList ? (
              <ErrorBox message={events.error} retry={events.reload} />
            ) : (
              eventList?.map((event) => (
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
