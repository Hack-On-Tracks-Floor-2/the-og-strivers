import { beforeAll, afterAll, it, expect } from 'vitest';
import request from 'supertest';
import { readFile } from 'node:fs/promises';
import { openDatabase, type Database } from '../apps/api/src/database/index.js';
import { createApp } from '../apps/api/src/app.js';
import { closeMLWorker } from '../apps/api/src/services/mini-ml.js';
let db: Database;
let app: Awaited<ReturnType<typeof createApp>>;
let agent: ReturnType<typeof request.agent>;
const origin = 'http://127.0.0.1:5173';
beforeAll(async () => {
  db = await openDatabase();
  app = await createApp(db, { origin });
  agent = request.agent(app);
  await agent
    .post('/api/auth/register')
    .set('Origin', origin)
    .send({
      name: 'ML integration test',
      email: 'ml-integration@example.test',
      password: 'isolated-test-only-2026',
    });
});
afterAll(async () => {
  closeMLWorker();
  await db?.close();
});
it('requires authentication for model information and prediction', async () => {
  expect((await request(app).get('/api/ml/model-info')).status).toBe(401);
  expect(
    (
      await request(app)
        .post('/api/ml/classify')
        .set('Origin', origin)
        .send({ code: 'class Test {}', language: 'java' })
    ).status,
  ).toBe(401);
});
it('reads actual recorded evaluation values', async () => {
  const saved = JSON.parse(await readFile('ml/mini_classifier/artifacts/evaluation.json', 'utf8'));
  const response = await agent.get('/api/ml/model-info');
  expect(response.status).toBe(200);
  expect(response.body.data.metrics.f1Macro).toBe(saved.evaluation.f1_macro);
  expect(response.body.data.training.testSamples).toBe(saved.split.test_samples);
});
it('explicitly rejects unsupported languages without running code', async () => {
  const response = await agent
    .post('/api/ml/classify')
    .set('Origin', origin)
    .send({ code: 'print("untrusted input is just text")', language: 'python' });
  expect(response.status).toBe(200);
  expect(response.body.data.status).toBe('unsupported');
  expect(response.body.data.cwe).toBeNull();
});
it('does not accept a caller-supplied model file or command', async () => {
  const response = await agent
    .post('/api/ml/classify')
    .set('Origin', origin)
    .send({
      code: 'public class Test {}',
      language: 'java',
      model: 'untrusted.joblib',
      command: 'whoami',
    });
  expect(response.status).toBe(400);
});
it('performs genuine Python inference on the saved held-out example', async () => {
  const code = await readFile('ml/mini_classifier/artifacts/heldout-example.java', 'utf8');
  const saved = JSON.parse(
    await readFile('ml/mini_classifier/artifacts/heldout-inference.json', 'utf8'),
  );
  const response = await agent
    .post('/api/ml/classify')
    .set('Origin', origin)
    .send({ code, language: 'java' });
  expect(response.status).toBe(200);
  expect(response.body.data.status).toBe(saved.prediction.status);
  expect(response.body.data.cwe).toBe(saved.prediction.cwe);
  expect(response.body.data.probability).toBeCloseTo(saved.prediction.probability, 8);
}, 90_000);
