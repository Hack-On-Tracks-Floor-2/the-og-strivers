import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import { openDatabase, type Database } from '../../apps/api/src/database/index.js';
import { createApp } from '../../apps/api/src/app.js';
import { provisionReviewer } from '../../apps/api/src/services/auth.js';
import { WorkspaceStore } from '../../apps/api/src/repositories/clone.js';
import { createPipeline, type PipelineSandbox } from '../../apps/api/src/pipeline/orchestrator.js';
import { createAiClient, TokenBudget, type AiClient } from '../../apps/api/src/ai/client.js';
import { findCandidates } from '../../apps/api/src/scanners/funnel.js';
import { applyEdits, unifiedDiff, changedLineCount, EditError } from '../../apps/api/src/patching/edits.js';
import { parseJUnit, compareSuites } from '../../apps/api/src/verification/junit.js';
import { DockerSandbox, hardeningArgs } from '../../apps/api/src/verification/docker.js';
import { inspectRepository } from '../../apps/api/src/agents/intelligence.js';
import { randomUUID } from 'node:crypto';

const FIXTURE = join(__dirname, 'fixtures', 'vulnapp');
const VULN_LINE = `    rows = db.execute("SELECT id, name, email FROM users WHERE name = '%s'" % name).fetchall()`;
const SAFE_LINE = `    rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()`;
const SECURITY_TEST = `from vulnapp.store import connect, find_user


def test_injection_does_not_return_all_users():
    assert find_user(connect(), "x' OR '1'='1") == []
`;

describe('search funnel (local, zero AI tokens)', () => {
  it('maps the fixture as Python with a pytest command', async () => {
    const map = await inspectRepository(FIXTURE);
    expect(map.languages[0]).toBe('Python');
    expect(map.testCommands[0]).toEqual(['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider']);
  });
  it('ranks the SQL injection first and sends only the enclosing function', async () => {
    const { candidates, filesScanned } = await findCandidates(FIXTURE);
    expect(filesScanned).toBe(2); // tests/ excluded
    expect(candidates[0]).toMatchObject({ file: 'vulnapp/store.py', cwe: 'CWE-89', id: 'C1' });
    expect(candidates[0].snippet).toContain("WHERE name = '%s'");
    expect(candidates[0].snippet).toContain('def find_user');
    expect(candidates[0].snippet).not.toContain('def connect'); // function-level, not whole file
  });
});

describe('patch edits and diffs', () => {
  const read = (p: string) => (p === 'a.py' ? 'x = 1\ny = 2\nz = 3\n' : null);
  it('applies exact search/replace edits and emits a unified diff', () => {
    const [change] = applyEdits([{ file: 'a.py', search: 'y = 2', replace: 'y = 20' }], read);
    const diff = unifiedDiff(change.path, change.original, change.proposed);
    expect(diff).toContain('-y = 2');
    expect(diff).toContain('+y = 20');
    expect(changedLineCount(diff)).toBe(2);
  });
  it('rejects missing, ambiguous and unsafe edits', () => {
    expect(() => applyEdits([{ file: 'a.py', search: 'nope', replace: '' }], read)).toThrow(EditError);
    expect(() => applyEdits([{ file: '../etc/passwd', search: 'x', replace: '' }], read)).toThrow(EditError);
    expect(() =>
      applyEdits([{ file: 'a.py', search: ' = ', replace: '=' }], () => 'a = 1\nb = 2\n'),
    ).toThrow(/not unique/);
  });
});

describe('JUnit parsing and the regression gate', () => {
  const xml = (cases: [string, string][]) =>
    `<testsuites><testsuite>${cases
      .map(([n, o]) => `<testcase classname="t" name="${n}">${o === 'failed' ? '<failure message="x"/>' : o === 'error' ? '<error/>' : o === 'skipped' ? '<skipped/>' : ''}</testcase>`)
      .join('')}</testsuite></testsuites>`;
  it('counts outcomes', () => {
    const s = parseJUnit(xml([['a', 'passed'], ['b', 'failed'], ['c', 'skipped'], ['d', 'error']]));
    expect([s.total, s.passed, s.failed, s.skipped, s.errors]).toEqual([4, 1, 1, 1, 1]);
  });
  it('fails only when a previously passing test stops passing', () => {
    const before = parseJUnit(xml([['a', 'passed'], ['b', 'failed']]));
    expect(compareSuites(before, parseJUnit(xml([['a', 'passed'], ['b', 'passed'], ['new', 'passed']]))).ok).toBe(true);
    const broken = compareSuites(before, parseJUnit(xml([['a', 'failed'], ['b', 'failed']])));
    expect(broken.ok).toBe(false);
    expect(broken.broken).toEqual([{ id: 't::a', after: 'failed' }]);
  });
});

describe('AI client', () => {
  const ok = (text: string) => new Response(JSON.stringify({ candidates: [{ finishReason: 'STOP', content: { parts: [{ text }] } }], usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 20 } }));
  const groqOk = (text: string) => new Response(JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: text } }], usage: { prompt_tokens: 90, completion_tokens: 10 } }));
  const req = { task: 't', instructions: 'i', data: 'd', schema: { type: 'object' }, maxOutputTokens: 200 };
  it('uses Groq first by default and Gemini as the fallback', async () => {
    const urls: string[] = [];
    const ai = createAiClient({ GEMINI_API_KEY: 'g', GROQ_API_KEY: 'q', AI_RETRY_DELAY_MS: '0' }, {
      fetchImpl: (async (url: string) => {
        urls.push(String(url));
        return String(url).includes('groq') ? new Response('', { status: 503 }) : ok('{"b":2}');
      }) as typeof fetch,
    })!;
    expect(ai.providers[0]).toMatch(/^Groq/);
    const result = await ai.completeJSON<{ b: number }>(req, new TokenBudget(10_000), new AbortController().signal);
    expect(result.usage.provider).toBe('Gemini');
    expect(urls[0]).toContain('api.groq.com');
  });
  it('redacts secrets before sending and restores them in the answer', async () => {
    let sent = '';
    const secret = 'sk-live-THIS_IS_A_FAKE_SECRET_123456';
    const ai = createAiClient({ GROQ_API_KEY: 'q' }, {
      fetchImpl: (async (_url: string, init: RequestInit) => {
        sent = String(init.body);
        const placeholder = sent.match(/«SECRET_\d+»/)![0];
        return groqOk(JSON.stringify({ search: `KEY = "${placeholder}"` }));
      }) as typeof fetch,
    })!;
    const result = await ai.completeJSON<{ search: string }>(
      { ...req, data: `KEY = "${secret}"
password = "hunter2-very-secret"` },
      new TokenBudget(10_000),
      new AbortController().signal,
    );
    expect(sent).not.toContain(secret);
    expect(sent).not.toContain('hunter2-very-secret');
    expect(result.value.search).toBe(`KEY = "${secret}"`);
    expect(result.usage.redacted).toBe(2);
  });
  it('falls back across providers, charges the budget and caches repeat prompts', async () => {
    let calls = 0;
    const ai = createAiClient({ GEMINI_API_KEY: 'g', GROQ_API_KEY: 'q', AI_PROVIDER_ORDER: 'gemini,groq', AI_RETRY_DELAY_MS: '0' }, {
      fetchImpl: (async (url: string) => {
        calls++;
        return String(url).includes('generativelanguage') ? new Response('', { status: 429 }) : groqOk('{"a":1}');
      }) as typeof fetch,
    })!;
    const budget = new TokenBudget(10_000);
    const first = await ai.completeJSON<{ a: number }>(req, budget, new AbortController().signal);
    expect(first.value.a).toBe(1);
    expect(first.usage.provider).toBe('Groq');
    expect(budget.used).toBe(100);
    const second = await ai.completeJSON(req, budget, new AbortController().signal);
    expect(second.usage.cached).toBe(true);
    expect(calls).toBe(3); // Gemini 429, one retry, then Groq; the repeat is served from cache
  });
  it('refuses work that would exceed the run budget', async () => {
    const ai = createAiClient({ GEMINI_API_KEY: 'g' }, { fetchImpl: (async () => ok('{}')) as typeof fetch })!;
    await expect(ai.completeJSON(req, new TokenBudget(50), new AbortController().signal)).rejects.toThrow(/budget/i);
  });
});

describe('Docker sandbox hardening', () => {
  it('runs tests with no network, read-only root, non-root user and dropped capabilities', async () => {
    let args: string[] = [];
    const spawnImpl = ((_cmd: string, a: string[]) => {
      args = a;
      const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter };
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      setTimeout(() => child.emit('close', 0), 5);
      return child;
    }) as never;
    const folder = await mkdtemp(join(tmpdir(), 'pp-docker-'));
    const sandbox = new DockerSandbox({ image: 'img', workspacePath: () => folder, scratchRoot: folder, spawnImpl });
    const ws = { id: randomUUID(), repositoryId: randomUUID(), commitSha: 'abc' };
    const res = await sandbox.executeWith(
      { workspace: ws, argv: ['python', '-m', 'pytest'], timeoutMs: 5000, memoryMb: 512, cpuLimit: 1, network: 'none', readOnlyRoot: true, maxOutputBytes: 1000 },
      ws.id,
      new AbortController().signal,
    );
    expect(res.state).toBe('completed');
    for (const flag of ['--network', 'none', '--read-only', '--cap-drop', 'ALL', 'no-new-privileges', '--pids-limit'])
      expect(args).toContain(flag);
    expect(args.join(' ')).toMatch(/target=\/src,readonly/);
    expect(hardeningArgs(512, 1)).toContain('10001:10001');
    await rm(folder, { recursive: true, force: true });
  });
});

/* ---------------- end-to-end orchestration with fake AI + fake sandbox ---------------- */

/** Imitates pytest on the fixture by reading the workspace files (no real code execution). */
function fakeSandbox(store: WorkspaceStore, options: { breakSuite?: boolean } = {}): PipelineSandbox & { calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    ready: async () => null,
    prepare: async () => ({ exitCode: 0, stdout: 'prepared', stderr: '', timedOut: false }),
    cleanup: async () => {},
    async executeWith(request) {
      calls.push(request.argv);
      const root = store.path(request.workspace.id);
      if (request.argv[0] === 'bandit')
        return { state: 'completed', data: { exitCode: 1, stdout: '', stderr: '', durationMs: 1, artifactId: '', timedOut: false, files: { 'bandit.json': JSON.stringify({ results: [{ filename: './vulnapp/store.py', line_number: 16, test_id: 'B608', issue_text: 'Possible SQL injection', issue_cwe: { id: 89 } }] }) } } };
      const store_ = await readFile(join(root, 'vulnapp', 'store.py'), 'utf8');
      const vulnerable = store_.includes("'%s'\" % name");
      const broken = options.breakSuite && !vulnerable;
      const secPath = request.argv.find((a) => a.includes('proofpatch_security'));
      const hasSec = existsSync(join(root, 'tests', 'proofpatch_security'));
      const cases: [string, boolean][] = secPath
        ? [['test_injection_does_not_return_all_users', !vulnerable]]
        : [
            ['test_finds_existing_user', !broken],
            ['test_unknown_user_is_empty', true],
            ['test_checksum_is_stable', true],
            ...(hasSec ? ([['test_injection_does_not_return_all_users', !vulnerable]] as [string, boolean][]) : []),
          ];
      const xml = `<testsuites><testsuite>${cases.map(([n, p]) => `<testcase classname="tests" name="${n}">${p ? '' : '<failure message="assert"/>'}</testcase>`).join('')}</testsuite></testsuites>`;
      const failed = cases.some(([, p]) => !p);
      return { state: 'completed', data: { exitCode: failed ? 1 : 0, stdout: `${cases.length} tests`, stderr: '', durationMs: 5, artifactId: '', timedOut: false, files: { 'junit.xml': xml } } };
    },
  };
}

function fakeAi(patchAttempts: string[][]): AiClient & { tasks: string[] } {
  const tasks: string[] = [];
  let patchCall = 0;
  return {
    tasks,
    providers: ['Fake (test)'],
    async completeJSON<T>(req: { task: string }, budget: TokenBudget) {
      tasks.push(req.task);
      budget.charge(500);
      const usage = { provider: 'Fake', model: 'test', inputTokens: 400, outputTokens: 100, cached: false, redacted: 0 };
      if (req.task === 'detect')
        return { value: { verdicts: [{ candidateId: 'C1', vulnerable: true, confidence: 0.95, cwe: 'CWE-89', severity: 'high', rootCause: 'User input is formatted into SQL.', evidence: ['name flows into execute'], recommendation: 'Use a parameterized query.' }] } as T, usage };
      const [search, replace] = patchAttempts[Math.min(patchCall++, patchAttempts.length - 1)];
      return { value: { edits: [{ file: 'vulnapp/store.py', search, replace }], securityTest: { filename: 'test_sqli.py', content: SECURITY_TEST }, explanation: 'Bind the name as a parameter.' } as T, usage };
    },
  };
}

describe.sequential('end-to-end pipeline', () => {
  const origin = 'http://127.0.0.1:5173';
  const password = 'correct-horse-battery-99';
  let folder: string;
  let db: Database;
  beforeAll(async () => {
    folder = await mkdtemp(join(tmpdir(), 'pp-e2e-'));
  });
  afterAll(async () => {
    await db?.close();
    await rm(folder, { recursive: true, force: true });
  });

  async function setup(ai: AiClient, sandboxOptions: { breakSuite?: boolean } = {}) {
    await db?.close();
    db = await openDatabase(join(folder, randomUUID(), 'db'));
    await provisionReviewer(db, { email: 'reviewer@example.com', password, name: 'Reviewer' });
    const store = new WorkspaceStore(join(folder, 'ws'));
    const sandbox = fakeSandbox(store, sandboxOptions);
    const pipeline = createPipeline({
      db,
      store,
      sandbox,
      ai,
      ingestion: {
        async ingest(repository) {
          const id = randomUUID();
          await cp(FIXTURE, store.path(id), { recursive: true });
          return { state: 'completed', data: { id, repositoryId: repository.id, commitSha: 'f1x7ure' } };
        },
      },
    });
    const app = await createApp(db, { origin, pipeline });
    const dev = request.agent(app);
    await dev.post('/api/auth/register').set('Origin', origin).send({ name: 'Dev', email: 'dev@example.com', password });
    const repo = await dev.post('/api/repositories').set('Origin', origin).send({ url: 'https://github.com/example/vulnapp' });
    const run = await dev.post('/api/runs').set('Origin', origin).send({ repositoryId: repo.body.data.id });
    expect(run.status).toBe(201);
    expect(run.body.data.status).toBe('queued');
    await pipeline.idle();
    return { app, dev, runId: run.body.data.id as string, sandbox };
  }

  it('finds the bug, reproduces it, patches it, proves it, and lets a reviewer approve', async () => {
    const ai = fakeAi([[VULN_LINE, SAFE_LINE]]);
    const { app, dev, runId, sandbox } = await setup(ai);
    const run = (await dev.get(`/api/runs/${runId}`)).body.data;
    expect(run.status).toBe('needs_review');
    const findings = (await dev.get(`/api/runs/${runId}/findings`)).body.data;
    expect(findings[0]).toMatchObject({ cwe: 'CWE-89', source: 'scanner+ai', file: 'vulnapp/store.py' });
    const [patch] = (await dev.get(`/api/runs/${runId}/patches`)).body.data;
    expect(patch.status).toBe('needs_review');
    expect(patch.unifiedDiff).toContain('+    rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()');
    expect(patch.securityTest.path).toBe('tests/proofpatch_security/test_sqli.py');
    const stages = (await dev.get(`/api/runs/${runId}/verification`)).body.data.map((v: { stage: string; status: string; exitCode: number }) => `${v.stage}:${v.status}:${v.exitCode}`);
    expect(stages).toEqual(['baseline:passed:0', 'reproduction:passed:1', 'patch_application:passed:0', 'security_retest:passed:0', 'regression:passed:0', 'final_decision:passed:0']);
    expect(sandbox.calls.every((argv) => !argv.includes('--network'))).toBe(true);
    const events = (await dev.get(`/api/runs/${runId}/events`)).body.data.map((e: { kind: string; message: string }) => e.message).join('\n');
    expect(events).toMatch(/Search funnel: 2 source files/);
    expect(events).toMatch(/tokens/);
    const artifacts = (await dev.get(`/api/runs/${runId}/artifacts`)).body.data;
    expect(artifacts.some((a: { kind: string }) => a.kind === 'report')).toBe(true);
    const download = await dev.get(`/api/runs/${runId}/artifacts/${artifacts[0].id}`);
    expect(download.status).toBe(200);
    expect(ai.tasks).toEqual(['detect', 'patch']);
    // The corrected approval guard accepts real evidence (reproduction exits 1 by design).
    const reviewer = request.agent(app);
    await reviewer.post('/api/auth/login').set('Origin', origin).send({ email: 'reviewer@example.com', password, role: 'reviewer' });
    const decision = await reviewer.post(`/api/reviews/${patch.id}/decision`).set('Origin', origin).send({ decision: 'approved', reason: 'Exploit test red→green, suite intact.' });
    expect(decision.status).toBe(201);
  });

  it('retries with feedback when a patch breaks existing tests, then gives up honestly', async () => {
    const ai = fakeAi([[VULN_LINE, SAFE_LINE]]);
    const { dev, runId } = await setup(ai, { breakSuite: true });
    const run = (await dev.get(`/api/runs/${runId}`)).body.data;
    expect(run.status).toBe('failed');
    expect(run.error).toMatch(/No patch passed all proofs within 3 attempts/);
    expect(ai.tasks).toEqual(['detect', 'patch', 'patch', 'patch']);
    const patches = (await dev.get(`/api/runs/${runId}/patches`)).body.data;
    expect(patches.map((p: { status: string }) => p.status)).toEqual(['rejected', 'rejected', 'rejected']);
  });

  it('feeds edit errors back to the AI and succeeds on a later attempt', async () => {
    const ai = fakeAi([['this text is not in the file', 'x'], [VULN_LINE, SAFE_LINE]]);
    const { dev, runId } = await setup(ai);
    expect((await dev.get(`/api/runs/${runId}`)).body.data.status).toBe('needs_review');
    const [patch] = (await dev.get(`/api/runs/${runId}/patches`)).body.data;
    expect(patch.attempt).toBe(2);
  });
});
