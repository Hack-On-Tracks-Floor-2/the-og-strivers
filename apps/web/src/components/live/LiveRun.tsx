import { useEffect, useMemo, useRef, useState } from 'react';
import { z } from 'zod';
import { Play, Square, Radio, Rewind, ShieldCheck, Cpu, MemoryStick, WifiOff, Wifi, Box } from 'lucide-react';
import { VerificationRunSchema, type AnalysisRun, type RunEvent, type VerificationRun } from '@proofpatch/shared';
import { api } from '../../lib/api';
import { useRunStream, type LiveContainer } from '../../hooks/useRunStream';
import { NODES, pipelineView, seconds, type NodeId } from '../../lib/live-pipeline';
import './live.css';

const ACTIVE = ['received', 'queued', 'mapping', 'analyzing', 'patching', 'verifying'];
const STAGE_EVENT = /^(Baseline:|Reproduced:|Security retest:|Regression:|Proof complete)/;

/**
 * Live view of one analysis run: pipeline map, scanner funnel, test-by-test board and the sandbox
 * terminal. Live runs stream over SSE; finished runs can be replayed from their recorded events and
 * recorded sandbox logs (clearly labelled as a replay).
 */
export function LiveRun({ run }: { run: AnalysisRun }) {
  const stream = useRunStream(run.id);
  const running = ACTIVE.includes(run.status);
  const [replay, setReplay] = useState<{ index: number; lines: string[]; container?: LiveContainer } | null>(null);
  const [verification, setVerification] = useState<VerificationRun[]>([]);
  const [, tick] = useState(0);

  // Live clock for the active stage and the running container.
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 500);
    return () => clearInterval(t);
  }, []);

  // Recorded per-test evidence: refreshed whenever a proof stage completes.
  const stageEvents = stream.events.filter((e) => STAGE_EVENT.test(e.message)).length;
  useEffect(() => {
    let alive = true;
    api(`/runs/${run.id}/verification`, z.array(VerificationRunSchema))
      .then((v) => alive && setVerification(v))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [run.id, stageEvents]);

  // Replay: advance through the recorded events with compressed real timing.
  useEffect(() => {
    if (!replay) return;
    if (replay.index >= stream.events.length) return;
    const prev = stream.events[replay.index - 1];
    const next = stream.events[replay.index];
    const gap = prev ? new Date(next.createdAt).getTime() - new Date(prev.createdAt).getTime() : 0;
    const t = setTimeout(() => {
      setReplay((r) => (r ? { ...r, ...replayOutput(next, verification, r), index: r.index + 1 } : r));
    }, Math.max(350, Math.min(1600, gap / 6)));
    return () => clearTimeout(t);
  }, [replay, stream.events, verification]);

  const events = replay ? stream.events.slice(0, replay.index) : stream.events;
  const finishedReplay = replay && replay.index >= stream.events.length;
  const view = useMemo(() => pipelineView(events, !replay ? run.status === 'failed' : !!finishedReplay && run.status === 'failed'), [events, replay, finishedReplay, run.status]);
  const lines = replay ? replay.lines : stream.lines;
  const container = replay ? replay.container : stream.container;
  const shownVerification = replay
    ? verification.filter((v) => events.some((e) => e.createdAt >= v.createdAt))
    : verification;

  return (
    <section className="panel live-run">
      <div className="live-head">
        {replay ? (
          <span className="live-badge replay"><Rewind size={14} /> REPLAY · recorded run {run.id.slice(0, 8)} · {new Date(run.createdAt).toLocaleString()}</span>
        ) : running ? (
          <span className="live-badge live"><Radio size={14} /> LIVE · {stream.connected ? 'streaming from the backend' : 'reconnecting…'}</span>
        ) : (
          <span className="live-badge done"><ShieldCheck size={14} /> Recorded run · {events.length} events</span>
        )}
        <div className="live-finding">
          {view.finding && <span>Fixing <b>{view.finding}</b> · {view.attempt}</span>}
          {view.proven > 0 && <span className="proven">{view.proven} proven</span>}
        </div>
        {!running &&
          (replay ? (
            <button className="button secondary small-button" onClick={() => setReplay(null)}><Square size={13} /> Stop replay</button>
          ) : (
            <button className="button primary small-button" disabled={!stream.events.length} onClick={() => setReplay({ index: 0, lines: [] })}>
              <Play size={13} /> Replay this run
            </button>
          ))}
      </div>

      <PipelineMap view={view} now={replay ? events[events.length - 1]?.createdAt : undefined} />
      {view.funnel && <Funnel funnel={view.funnel} />}

      <div className="live-grid">
        <TestBoard records={shownVerification} />
        <Terminal lines={lines} container={container} live={running && !replay} />
      </div>
    </section>
  );
}

/** During a replay, show each recorded stage's sandbox log when its completion event plays. */
function replayOutput(event: RunEvent, records: VerificationRun[], state: { lines: string[]; container?: LiveContainer }) {
  const stage = /^Baseline:/.test(event.message) ? 'baseline' : /^Reproduced:/.test(event.message) ? 'reproduction' : /^Security retest:/.test(event.message) ? 'security_retest' : /^Regression:/.test(event.message) ? 'regression' : null;
  const header = `❯ ${event.message}`;
  if (!stage) return { lines: [...state.lines, header].slice(-800) };
  const record = [...records].filter((r) => r.stage === stage && r.createdAt <= event.createdAt).sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  if (!record) return { lines: [...state.lines, header].slice(-800) };
  const container: LiveContainer = { image: 'recorded sandbox run', argv: record.command, network: 'none', memoryMb: 1024, cpus: 1, startedAt: record.createdAt, finishedAt: record.completedAt ?? record.createdAt, exitCode: record.exitCode ?? undefined };
  const body = record.logs.split('\n').filter((l) => l.trim()).slice(0, 60);
  return { lines: [...state.lines, header, `$ ${record.command.join(' ')}`, ...body, `[exit ${record.exitCode}]`].slice(-800), container };
}

function PipelineMap({ view, now }: { view: ReturnType<typeof pipelineView>; now?: string }) {
  return (
    <div className="pmap">
      {NODES.map((node, i) => {
        const n = view.nodes[node.id as NodeId];
        return (
          <div className="pmap-cell" key={node.id}>
            <div className={`pmap-node ${n.state}`}>
              <div className="pmap-dot" />
              <strong>{node.label}</strong>
              <small>{n.detail || node.hint}</small>
              <em>
                {n.state === 'done' && n.startedAt ? seconds(n.startedAt, n.finishedAt) : n.state === 'active' ? seconds(n.startedAt, now) : n.state === 'retry' ? 'retrying' : n.state === 'failed' ? 'stopped' : ''}
              </em>
            </div>
            {i < NODES.length - 1 && <div className={`pmap-link ${n.state === 'done' ? 'done' : ''}`} />}
          </div>
        );
      })}
    </div>
  );
}

function useCountUp(target: number) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    let frame: number;
    const startAt = performance.now();
    const from = 0;
    const step = (now: number) => {
      const p = Math.min(1, (now - startAt) / 700);
      setValue(Math.round(from + (target - from) * p));
      if (p < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [target]);
  return value;
}

function Funnel({ funnel }: { funnel: NonNullable<ReturnType<typeof pipelineView>['funnel']> }) {
  const steps: [string, number, string][] = [
    ['source files', funnel.files, 'scanned locally, 0 tokens'],
    ['scanner hits', funnel.hits, `rules · Bandit ${funnel.bandit} · Semgrep ${funnel.semgrep}`],
    ['snippets to AI', funnel.snippets, 'only the enclosing function'],
    ['confirmed', funnel.confirmed, 'real, exploitable'],
    ['proven fixes', funnel.proven, 'attack red → green, suite intact'],
  ];
  return (
    <div className="funnel">
      {steps.map(([label, value, hint]) => (
        <FunnelStep key={label} label={label} value={value} hint={hint} />
      ))}
    </div>
  );
}
function FunnelStep({ label, value, hint }: { label: string; value: number; hint: string }) {
  const shown = useCountUp(value);
  return (
    <div className="funnel-step">
      <b>{shown}</b>
      <span>{label}</span>
      <small>{hint}</small>
    </div>
  );
}

function TestBoard({ records }: { records: VerificationRun[] }) {
  const latest = (stage: string) => [...records].filter((r) => r.stage === stage).sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  const rows: [string, string, VerificationRun | undefined][] = [
    ['Before the patch', 'original test suite', latest('baseline')],
    ['Attack test on original', 'must FAIL: proves the bug', latest('reproduction')],
    ['Attack test on patch', 'must PASS: fix blocks it', latest('security_retest')],
    ['After the patch', 'full suite: nothing may break', latest('regression')],
  ];
  return (
    <div className="board">
      <div className="board-title">Test-by-test proof</div>
      {rows.map(([title, hint, record]) => (
        <div className="board-row" key={title}>
          <div className="board-label">
            <b>{title}</b>
            <small>{hint}</small>
          </div>
          <div className="board-tiles">
            {record?.tests?.cases.length ? (
              record.tests.cases.slice(0, 120).map((c) => <span key={c.id} className={`tile-${c.outcome}`} title={`${c.id}: ${c.outcome}`} />)
            ) : (
              <span className="board-wait">{record ? `exit ${record.exitCode}` : 'waiting…'}</span>
            )}
          </div>
          {record?.tests && (
            <div className="board-count">
              {record.tests.passed}/{record.tests.total}
            </div>
          )}
        </div>
      ))}
      <div className="board-legend">
        <span><i className="tile-passed" /> pass</span>
        <span><i className="tile-failed" /> fail</span>
        <span><i className="tile-error" /> error</span>
        <span><i className="tile-skipped" /> skipped</span>
      </div>
    </div>
  );
}

function Terminal({ lines, container, live }: { lines: string[]; container?: LiveContainer; live: boolean }) {
  const body = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = body.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);
  const runningContainer = container && !container.finishedAt;
  return (
    <div className="term">
      <div className="term-head">
        <span className={`term-light ${runningContainer ? 'on' : ''}`} />
        <span className="term-title"><Box size={13} /> {container?.image ?? 'sandbox'}</span>
        {container && (
          <>
            <span className={`term-chip ${container.network === 'none' ? 'ok' : 'warn'}`}>
              {container.network === 'none' ? <WifiOff size={12} /> : <Wifi size={12} />} network {container.network === 'none' ? 'off' : 'on (install only)'}
            </span>
            <span className="term-chip"><MemoryStick size={12} /> {container.memoryMb} MB</span>
            <span className="term-chip"><Cpu size={12} /> {container.cpus} CPU</span>
            <span className="term-chip">read-only · non-root</span>
            <span className="term-time">
              {runningContainer ? `running ${seconds(container.startedAt)}` : container.exitCode !== undefined ? `exit ${container.exitCode} · ${seconds(container.startedAt, container.finishedAt)}` : ''}
            </span>
          </>
        )}
      </div>
      <div className="term-body" ref={body}>
        {container && <div className="term-cmd">$ {container.argv.join(' ').slice(0, 220)}</div>}
        {lines.length ? (
          lines.map((line, i) => (
            <div key={i} className={/FAIL|failed|Error|ERROR|AddressSanitizer|Traceback|assert/i.test(line) ? 'bad' : /PASS|passed|\bok\b|✔|Tests run: \d+, Failures: 0/i.test(line) ? 'good' : line.startsWith('❯') ? 'step' : ''}>
              {line}
            </div>
          ))
        ) : (
          <div className="term-empty">{live ? 'Waiting for the sandbox to start…' : 'No live output for this run. Press “Replay this run” to replay its recorded sandbox logs.'}</div>
        )}
        {live && <span className="term-cursor">▌</span>}
      </div>
    </div>
  );
}
