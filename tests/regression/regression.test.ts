import { it, expect } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { runRegressionDemo } from '../../apps/api/src/verification/regression-demo.js';
import { openDatabase } from '../../apps/api/src/database/index.js';
import { createApp } from '../../apps/api/src/app.js';

it('executes a real red/green regression proof and serves only authenticated evidence', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'patchproof-engine-'));
  const previous = process.env.REGRESSION_EVIDENCE_DIR;
  process.env.REGRESSION_EVIDENCE_DIR = folder;
  const db = await openDatabase(join(folder, 'db'));
  try {
    const report = await runRegressionDemo({ outputDir: folder, env: { GROQ_API_KEY: '' } });
    expect(report.verdict).toBe('VERIFIED');
    expect(report.patchSource).toBe('deterministic');
    expect(report.stages.map(s => s.exitCode)).toEqual([0, 1, 0, 0]);
    expect(report.stages.map(s => [s.summary.passed, s.summary.failed])).toEqual([[5, 0], [0, 3], [3, 0], [5, 0]]);
    expect(report.stages[1].stdout).toContain('Traversal leaked controlled data: CONTROLLED_PRIVATE_MARKER');
    expect(report.integrity.functionalTestsUnchanged).toBe(true);
    expect(report.integrity.securityTestsIdentical).toBe(true);
    expect(report.comparison).toEqual({ ok: true, broken: [], fixed: [] });
    expect(await readFile(join(report.runDir, 'patch.diff'), 'utf8')).toBe(report.unifiedDiff);
    const origin = 'http://127.0.0.1:5173';
    const app = await createApp(db, { origin });
    expect((await request(app).get('/api/regression-demo/evidence')).status).toBe(401);
    const agent = request.agent(app);
    expect((await agent.post('/api/auth/register').set('Origin', origin).send({ name: 'Regression demo', email: 'regression@example.test', password: 'controlled-demo-password-42' })).status).toBe(201);
    const evidence = await agent.get('/api/regression-demo/evidence');
    expect(evidence.status).toBe(200);
    expect(evidence.body.data.runId).toBe(report.runId);
    expect(evidence.body.data.stages[1].exitCode).toBe(1);
    process.env.REGRESSION_EVIDENCE_DIR = join(folder, 'missing');
    expect((await agent.get('/api/regression-demo/evidence')).status).toBe(404);
  } finally {
    if (previous === undefined) delete process.env.REGRESSION_EVIDENCE_DIR;
    else process.env.REGRESSION_EVIDENCE_DIR = previous;
    await db.close();
    await rm(folder, { recursive: true, force: true });
  }
// PGlite's real WASM database startup can exceed the suite's 30-second test default.
}, 90_000);
