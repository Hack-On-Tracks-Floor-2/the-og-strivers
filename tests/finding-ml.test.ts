import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FindingSchema, type AnalysisRun, type Finding, type Repository } from '@proofpatch/shared';
import { openDatabase, type Database } from '../apps/api/src/database/index.js';
import { createApp } from '../apps/api/src/app.js';
import { provisionReviewer } from '../apps/api/src/services/auth.js';
import { githubIngestion, runGit, WorkspaceStore } from '../apps/api/src/repositories/clone.js';
import type { WorkspaceHandle } from '../apps/api/src/agents/contracts.js';
import { recordFindingML } from '../apps/api/src/services/finding-ml.js';
import { classifySource, closeMLWorker } from '../apps/api/src/services/mini-ml.js';

const origin = 'http://127.0.0.1:5173';
const password = 'ephemeral-ml-test-account-2026';
let folder: string;
let db: Database;
let app: Awaited<ReturnType<typeof createApp>>;
let developer: ReturnType<typeof request.agent>;
let reviewer: ReturnType<typeof request.agent>;
let repository: Repository;
let run: AnalysisRun;
let workspace: WorkspaceHandle;
let root: string;
let pythonCode: string;
let javaCode: string;
let pythonFinding: Finding;
const git = (args: string[], cwd: string) => execFileSync('git', args, { cwd, encoding: 'utf8', windowsHide: true }).trim();
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

beforeAll(async () => {
  folder = await mkdtemp(join(tmpdir(), 'pp-finding-ml-'));
  db = await openDatabase(join(folder, 'db'));
  await provisionReviewer(db, { email: 'ml-reviewer@example.test', password, name: 'ML Reviewer Test' });
  app = await createApp(db, { origin });
  developer = request.agent(app);
  reviewer = request.agent(app);
  await developer.post('/api/auth/register').set('Origin', origin)
    .send({ name: 'ML Developer Test', email: 'ml-developer@example.test', password });
  await reviewer.post('/api/auth/login').set('Origin', origin)
    .send({ email: 'ml-reviewer@example.test', password, role: 'reviewer' });
  const registered = await developer.post('/api/repositories').set('Origin', origin)
    .send({ url: 'https://github.com/example/ml-source-test' });
  expect(registered.status).toBe(201);
  repository = registered.body.data;
  [run] = (await reviewer.get('/api/runs')).body.data;

  // A real local Git source/clone, using attributed held-out benchmark source as interface fixtures.
  // GitHub metadata is substituted only for offline ingestion; inference always uses saved weights.
  const seed = join(folder, 'seed');
  await mkdir(join(seed, 'src'), { recursive: true });
  await cp('ml/multilang_classifier/artifacts/python/heldout-example.py', join(seed, 'src/sample.py'));
  await writeFile(join(seed, 'src/nested.py'), `${'# nonexecuted source context\n'.repeat(100)}${await readFile(join(seed, 'src/sample.py'), 'utf8')}`);
  await cp('ml/mini_classifier/artifacts/heldout-example.java', join(seed, 'src/Sample.java'));
  await writeFile(join(seed, 'src/sample.js'), 'throw new Error("ML must never execute this source");\n');
  await writeFile(join(seed, 'src/unknown.py'), 'print("hello")\n');
  await writeFile(join(seed, 'src/large.py'), '#'.repeat(1024 * 1024 + 1));
  git(['init', '-q'], seed);
  git(['add', '.'], seed);
  git(['-c', 'user.email=ml-test@example.test', '-c', 'user.name=ML Fixture Test', 'commit', '-qm', 'Attributed classifier integration fixture'], seed);
  const commit = git(['rev-parse', 'HEAD'], seed);
  const store = new WorkspaceStore(join(folder, 'workspaces'));
  const ingestion = githubIngestion(store, {
    fetchImpl: (async () => new Response(JSON.stringify({ private: false, size: 20 }))) as typeof fetch,
    git: async (args, options) => {
      const mapped = args.flatMap((arg, index) =>
        arg === 'protocol.file.allow=never' || (arg === '-c' && args[index + 1] === 'protocol.file.allow=never') ? []
          : [arg === `${repository.url}.git` ? seed : arg]);
      // This trusted test-only clone stays local; production still forbids file:// cloning.
      return runGit(['-c', 'protocol.file.allow=always', ...mapped], options);
    },
  });
  const ingested = await ingestion.ingest(repository, new AbortController().signal);
  expect(ingested.state).toBe('completed');
  if (ingested.state !== 'completed') throw new Error('Local ingestion failed');
  workspace = ingested.data;
  expect(workspace.commitSha).toBe(commit);
  root = store.path(workspace.id);
  pythonCode = await readFile(join(root, 'src/sample.py'), 'utf8');
  javaCode = await readFile(join(root, 'src/Sample.java'), 'utf8');
});
afterAll(async () => {
  closeMLWorker();
  await db?.close();
  if (folder) await rm(folder, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

async function saveFinding(file: string, startLine: number, endLine = startLine, cwe: string | null = 'CWE-22') {
  const finding = FindingSchema.parse({ id: randomUUID(), runId: run.id, ownerId: run.ownerId,
    category: 'Normalized scanner integration fixture', file, startLine, endLine, cwe, source: 'scanner',
    severity: 'high', confidence: 0.9, rootCause: 'Test interface over real attributed source.',
    evidence: ['Normalized finding interface, not an invented model prediction'], recommendation: 'Review evidence.', createdAt: new Date().toISOString() });
  await db.query('INSERT INTO findings(id,run_id,owner_id,document) VALUES($1,$2,$3,$4)', [finding.id, run.id, run.ownerId, finding]);
  return Object.freeze(finding);
}
const input = (finding: Finding) => ({ run, repository, workspace, root, finding });

describe.sequential('automatic finding classification and source provenance', () => {
  it('classifies a pinned Python repository finding with the genuine model and preserves the finding', async () => {
    const line = pythonCode.split('\n').findIndex((value) => value.includes('fileTarget = codecs.open')) + 1;
    pythonFinding = await saveFinding('src/sample.py', line);
    const result = await recordFindingML(db, input(pythonFinding));
    const saved = JSON.parse(await readFile('ml/multilang_classifier/artifacts/python/heldout-inference.json', 'utf8'));
    expect(result.persisted).toBe(true);
    expect(result.record).toMatchObject({ findingId: pythonFinding.id, runId: run.id, repositoryId: repository.id,
      commitSha: workspace.commitSha, file: 'src/sample.py', language: 'python', status: 'predicted', scannerCwe: 'CWE-22', comparison: 'agrees' });
    expect(result.record?.prediction?.cwe).toBe(saved.prediction.cwe);
    expect(result.record?.prediction?.probability).toBeCloseTo(saved.prediction.probability, 8);
    expect(result.record?.prediction?.confirmed).toBe(false);
    expect(result.record?.sourceSha256).toBe(sha(await readFile(join(root, pythonFinding.file))));
    expect(result.record?.snippet?.sha256).toBe(sha(pythonCode.split(/\r\n|\n|\r/).join('\n')));
    expect((await db.query<{ document: Finding }>('SELECT document FROM findings WHERE id=$1', [pythonFinding.id])).rows[0].document).toEqual(pythonFinding);
  }, 90_000);

  it('routes a bounded Java crypto-region finding to the genuine preserved Java classifier', async () => {
    const lines = javaCode.split('\n');
    const start = lines.findIndex((line) => line.includes('javax.crypto.Cipher c =')) + 1;
    const end = lines.findIndex((line) => line.includes('byte[] result = c.doFinal')) + 1;
    expect(end - start + 1).toBeLessThanOrEqual(80);
    const finding = await saveFinding('src/Sample.java', start, end, 'CWE-327');
    const result = await recordFindingML(db, input(finding));
    expect(result.persisted).toBe(true);
    expect(result.record).toMatchObject({ language: 'java', status: 'predicted', scannerCwe: 'CWE-327' });
    expect(result.record?.prediction?.cwe).toBe('CWE-327');
    expect(result.record?.prediction?.modelVersion).toBe('owasp-java-1.2-024e31bf77f4');
    expect(result.record?.snippet).toMatchObject({ startLine: start, endLine: end });
  }, 90_000);

  it('dedents a complete nested Python finding while retaining original source line provenance', async () => {
    const source = await readFile(join(root, 'src/nested.py'), 'utf8');
    const lines = source.split('\n');
    const start = lines.findIndex((line) => line.includes('def BenchmarkTest00001_post')) + 1;
    const end = lines.findLastIndex((line) => line.trim() === 'return RESPONSE') + 1;
    const finding = await saveFinding('src/nested.py', start, end);
    let classified = '';
    const result = await recordFindingML(db, input(finding), { predict: async (value) => {
      classified = value.code;
      return classifySource(value);
    } });
    expect(result.record?.snippet).toMatchObject({ startLine: start, endLine: end, transformation: 'dedent', sha256: sha(classified) });
    expect(classified).toMatch(/^def BenchmarkTest/);
    expect(result.record?.status).toBe('predicted');
    expect(result.record?.prediction?.cwe).toBe('CWE-22');
  }, 90_000);

  it('records unsupported JavaScript without invoking a model or changing scanner severity', async () => {
    const finding = await saveFinding('src/sample.js', 1, 1, 'CWE-79');
    let called = false;
    const result = await recordFindingML(db, input(finding), { predict: async () => { called = true; throw new Error('must not call'); } });
    expect(called).toBe(false);
    expect(result.record).toMatchObject({ status: 'unsupported', language: 'javascript', file: finding.file, commitSha: workspace.commitSha });
    expect(result.record?.prediction).toBeUndefined();
    expect(finding.severity).toBe('high');
    expect(finding.cwe).toBe('CWE-79');
  });

  it('persists real unknown/OOD classifications without claiming a vulnerability', async () => {
    const finding = await saveFinding('src/unknown.py', 1);
    const result = await recordFindingML(db, input(finding));
    expect(result.record?.status).toBe('unknown');
    expect(result.record?.prediction?.cwe).toBeNull();
    expect(result.persisted).toBe(true);
  });

  it('preserves findings when the configured model executable is unavailable', async () => {
    closeMLWorker();
    const previous = process.env.MINI_ML_PYTHON;
    process.env.MINI_ML_PYTHON = join(folder, 'missing-runtime.exe');
    try {
      const finding = await saveFinding('src/sample.py', pythonFinding.startLine);
      const result = await recordFindingML(db, input(finding));
      expect(result.persisted).toBe(true);
      expect(result.record?.status).toBe('unknown');
      expect(result.record?.prediction?.cwe).toBeNull();
      expect(result.record?.reason).toMatch(/unavailable|runtime|artifacts/i);
    } finally {
      closeMLWorker();
      if (previous === undefined) delete process.env.MINI_ML_PYTHON; else process.env.MINI_ML_PYTHON = previous;
    }
  });

  it.each(['../outside.py', '/etc/passwd.py', 'C:\\private.py', 'src/large.py', 'src/missing.py'])('rejects unsafe or unavailable source %s nonblockingly', async (file) => {
    const finding = await saveFinding(file, 1);
    let called = false;
    const result = await recordFindingML(db, input(finding), { predict: async () => { called = true; throw new Error('must not call'); } });
    expect(called).toBe(false);
    expect(result.record?.status).toBe('unavailable');
    expect(result.record?.prediction).toBeUndefined();
    expect(result.persisted).toBe(true);
  });

  it('records an invalid finding range without classifying or suppressing it', async () => {
    const finding = await saveFinding('src/unknown.py', 100);
    const result = await recordFindingML(db, input(finding));
    expect(result.record?.status).toBe('invalid_input');
    expect(result.persisted).toBe(true);
  });

  it('bounds inference time and records failure without leaking internal errors', async () => {
    const finding = await saveFinding('src/sample.py', pythonFinding.startLine);
    const result = await recordFindingML(db, input(finding), { timeoutMs: 10, predict: () => new Promise(() => {}) });
    expect(result.record?.status).toBe('unavailable');
    expect(result.record?.reason).not.toContain(folder);
    expect(result.persisted).toBe(true);
  });

  it('returns a nonblocking result when ML persistence fails, retaining the original finding', async () => {
    const finding = await saveFinding('src/sample.js', 1);
    const broken = { query: async () => { throw new Error('simulated sidecar storage outage'); } } as unknown as Database;
    const result = await recordFindingML(broken, input(finding));
    expect(result.persisted).toBe(false);
    expect(result.record?.status).toBe('unsupported');
    expect((await db.query('SELECT id FROM findings WHERE id=$1', [finding.id])).rows).toHaveLength(1);
  });

  it('rejects cross-run/repository/owner association and preserves existing prediction snapshots', async () => {
    expect((await recordFindingML(db, { ...input(pythonFinding), workspace: { ...workspace, repositoryId: randomUUID() } })).persisted).toBe(false);
    const before = (await db.query<{ document: unknown }>('SELECT document FROM finding_ml WHERE finding_id=$1', [pythonFinding.id])).rows[0].document;
    await recordFindingML(db, input(pythonFinding), { predict: async () => { throw new Error('simulated later outage'); } });
    expect((await db.query<{ document: unknown }>('SELECT document FROM finding_ml WHERE finding_id=$1', [pythonFinding.id])).rows[0].document).toEqual(before);
  });

  it('serves persisted predictions only to authenticated reviewers and isolates analysis runs', async () => {
    const path = `/api/runs/${run.id}/ml-findings`;
    expect((await request(app).get(path)).status).toBe(401);
    expect((await developer.get(path)).status).toBe(403);
    const response = await reviewer.get(path);
    expect(response.status).toBe(200);
    const row = response.body.data.find((entry: { finding: Finding }) => entry.finding.id === pythonFinding.id);
    expect(row.finding).toEqual(pythonFinding);
    expect(row.ml.commitSha).toBe(workspace.commitSha);
    expect(row.ml.prediction.cwe).toBe('CWE-22');
    const other = await reviewer.post('/api/runs').set('Origin', origin).send({ repositoryId: repository.id });
    expect((await reviewer.get(`/api/runs/${other.body.data.id}/ml-findings`)).body.data).toEqual([]);
    expect((await reviewer.get(`/api/runs/${randomUUID()}/ml-findings`)).status).toBe(404);
    expect((await reviewer.get('/api/runs/not-a-uuid/ml-findings')).status).toBe(400);
  });

  it('reports legacy findings with no ML record explicitly instead of synthesizing predictions', async () => {
    const legacy = await saveFinding('src/unknown.py', 1);
    const response = await reviewer.get(`/api/runs/${run.id}/ml-findings`);
    expect(response.body.data.find((row: { finding: Finding }) => row.finding.id === legacy.id).ml).toBeNull();
  });

  it('retains genuine predictions and source provenance after reopening the database', async () => {
    closeMLWorker();
    await db.close();
    db = await openDatabase(join(folder, 'db'));
    app = await createApp(db, { origin });
    reviewer = request.agent(app);
    await reviewer.post('/api/auth/login').set('Origin', origin).send({ email: 'ml-reviewer@example.test', password, role: 'reviewer' });
    const response = await reviewer.get(`/api/runs/${run.id}/ml-findings`);
    expect(response.status).toBe(200);
    const saved = response.body.data.find((entry: { finding: Finding }) => entry.finding.id === pythonFinding.id);
    expect(saved.ml.prediction.modelVersion).toBe('owasp-python-0.1-b20e1accbd58');
    expect(saved.ml.commitSha).toBe(workspace.commitSha);
    expect(saved.ml.sourceSha256).toBe(sha(await readFile(join(root, pythonFinding.file))));
  });
});
