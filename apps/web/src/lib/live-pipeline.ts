import type { RunEvent } from '@proofpatch/shared';

/** The stages drawn on the live pipeline map, in execution order. */
export const NODES = [
  { id: 'clone', label: 'Clone', hint: 'pinned commit' },
  { id: 'map', label: 'Map', hint: 'language + tests' },
  { id: 'install', label: 'Install', hint: 'only stage with network' },
  { id: 'baseline', label: 'Baseline', hint: 'original test suite' },
  { id: 'scan', label: 'Scanners', hint: 'rules · Bandit · Semgrep' },
  { id: 'ai', label: 'AI review', hint: 'confirms real bugs' },
  { id: 'patch', label: 'Patch', hint: 'fix + attack test' },
  { id: 'attack', label: 'Attack', hint: 'must fail on original' },
  { id: 'retest', label: 'Retest', hint: 'must pass on patch' },
  { id: 'regression', label: 'Regression', hint: 'nothing else breaks' },
  { id: 'review', label: 'Human review', hint: 'reviewer decides' },
] as const;
export type NodeId = (typeof NODES)[number]['id'];
export type NodeState = 'pending' | 'active' | 'done' | 'retry' | 'failed';
export interface NodeView {
  state: NodeState;
  detail: string;
  startedAt?: string;
  finishedAt?: string;
}
export interface PipelineView {
  nodes: Record<NodeId, NodeView>;
  funnel: { files: number; hits: number; bandit: number; semgrep: number; snippets: number; confirmed: number; proven: number } | null;
  finding: string | null;
  attempt: string | null;
  proven: number;
  failedReason: string | null;
}

const LOOP: NodeId[] = ['patch', 'attack', 'retest', 'regression'];

/** Rebuilds the map state from recorded events (works for live runs and for replays). */
export function pipelineView(events: RunEvent[], runFailed: boolean): PipelineView {
  const nodes = Object.fromEntries(NODES.map((n) => [n.id, { state: 'pending', detail: '' } as NodeView])) as Record<NodeId, NodeView>;
  let funnel: PipelineView['funnel'] = null;
  let finding: string | null = null;
  let attempt: string | null = null;
  let proven = 0;
  let current: NodeId | null = null;
  const start = (id: NodeId, at: string, detail = '') => {
    nodes[id] = { ...nodes[id], state: 'active', startedAt: nodes[id].state === 'pending' ? at : nodes[id].startedAt ?? at, detail: detail || nodes[id].detail };
    current = id;
  };
  const done = (id: NodeId, at: string, detail: string) => {
    nodes[id] = { ...nodes[id], state: 'done', detail, startedAt: nodes[id].startedAt ?? at, finishedAt: at };
  };
  for (const e of events) {
    const m = e.message;
    const at = e.createdAt;
    let r: RegExpExecArray | null;
    if (/^Cloning /.test(m)) start('clone', at);
    else if ((r = /^Cloned at commit (\w{7})/.exec(m))) done('clone', at, `commit ${r[1]}`);
    else if ((r = /^Mapped: (.*)$/.exec(m))) {
      const parts = r[1].split(' · ');
      done('map', at, parts.find((p) => /pytest|test|jest|mocha|vitest|maven|cargo|ctest|phpunit|rspec|detection/i.test(p)) ?? parts[0]);
    } else if (/^Installing declared dependencies/.test(m)) start('install', at);
    else if (/^Dependencies installed/.test(m)) done('install', at, 'then network cut off');
    else if ((r = /^Dependency audit \(OWASP A06\): (.*)$/.exec(m))) nodes.install.detail = r[1].startsWith('no ') ? 'no vulnerable deps' : r[1].replace(/ —.*$/, '');
    else if (/^Running the original test suite/.test(m)) start('baseline', at);
    else if ((r = /^Baseline: (\d+) passed, (\d+) failed.*\((\d+) tests\)/.exec(m))) {
      done('baseline', at, `${r[1]}/${r[3]} passing`);
      start('scan', at); // scanners run right after a green baseline
    }
    else if (/^Semgrep /.test(m)) {
      start('scan', at, m.replace(/^Semgrep ([\d.]+).*: (\d+) finding.*$/, 'Semgrep $2 hits'));
    } else if ((r = /^Search funnel: (\d+) source files → (\d+) scanner hits(?: \((?:Bandit (\d+))?(?:, )?(?:Semgrep (\d+))?\))?.*?→ (\d+) snippets sent to AI → (\d+) confirmed/.exec(m))) {
      funnel = { files: +r[1], hits: +r[2], bandit: +(r[3] ?? 0), semgrep: +(r[4] ?? 0), snippets: +r[5], confirmed: +r[6], proven: 0 };
      done('scan', at, `${r[2]} hits → ${r[5]} snippets`);
      done('ai', at, `${r[6]} confirmed`);
    } else if (e.kind === 'ai_usage' && /^Detection reviewed/.test(m)) {
      if (nodes.ai.state === 'pending') start('ai', at);
      nodes.ai.detail = m.replace(/^.*?: (\w+) .*?(\d+) in \+ (\d+) out.*$/, '$1 · $2+$3 tokens');
    } else if ((r = /^Generating patch for (\S+) \((CWE-\d+)\), attempt (\d+)\/(\d+)/.exec(m))) {
      if (finding !== `${r[1]} ${r[2]}`) for (const id of LOOP) nodes[id] = { state: 'pending', detail: '' };
      finding = `${r[2]} · ${r[1]}`;
      attempt = `attempt ${r[3]}/${r[4]}`;
      for (const id of LOOP) if (nodes[id].state !== 'pending') nodes[id] = { state: 'pending', detail: '' };
      start('patch', at, attempt);
    } else if (e.kind === 'ai_usage' && /^Patch proposal/.test(m)) {
      nodes.patch.detail = m.replace(/^.*?: (\w+) .*?(\d+) in \+ (\d+) out.*$/, '$1 · $2+$3 tokens');
    } else if ((r = /^Reproduced: .*?\((\d+) passed, (\d+) failed/.exec(m))) {
      done('patch', at, attempt ?? '');
      done('attack', at, `${r[2]} failing → bug is real`);
      start('retest', at);
    } else if (/^Security retest: /.test(m)) {
      done('retest', at, 'attack now blocked');
      start('regression', at);
    } else if ((r = /^Regression: (\d+) passed.*\((\d+) tests\)/.exec(m))) done('regression', at, `${r[1]}/${r[2]} still pass`);
    else if (/^Proof complete for/.test(m)) {
      proven += 1;
      done('review', at, `${proven} proven fix${proven > 1 ? 'es' : ''}`);
      nodes.review.state = 'active';
    } else if ((r = /^(\d+) of (\d+) confirmed vulnerabilit/.exec(m))) {
      done('review', at, `${r[1]}/${r[2]} proven · awaiting reviewer`);
      nodes.review.state = 'active';
    } else if (e.kind === 'stage_failed' && /^Attempt \d+:/.test(m)) {
      const target: NodeId = /did not reproduce/.test(m) ? 'attack' : /still fails/.test(m) ? 'retest' : /broke/.test(m) ? 'regression' : 'patch';
      nodes[target] = { ...nodes[target], state: 'retry', detail: m.replace(/^Attempt \d+: /, '').slice(0, 70) };
      current = target;
    } else if (e.kind === 'review_decision') {
      nodes.review = { ...nodes.review, state: 'done', detail: m.split(':')[0] };
    }
  }
  if (funnel) funnel = { ...funnel, proven };
  let failedReason: string | null = null;
  if (runFailed) {
    const last = [...events].reverse().find((e) => e.kind === 'stage_failed' || e.kind === 'error');
    failedReason = last?.message ?? 'Run failed.';
    const active = (Object.keys(nodes) as NodeId[]).find((id) => nodes[id].state === 'active');
    const target = active ?? current ?? 'clone';
    nodes[target] = { ...nodes[target], state: 'failed', detail: failedReason.slice(0, 80) };
  }
  return { nodes, funnel, finding, attempt, proven, failedReason };
}

export function seconds(a?: string, b?: string) {
  if (!a) return '';
  const ms = (b ? new Date(b).getTime() : Date.now()) - new Date(a).getTime();
  return ms < 1000 ? '<1 s' : ms < 60_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60000)} m ${Math.round((ms % 60000) / 1000)} s`;
}
