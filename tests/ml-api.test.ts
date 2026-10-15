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
    .send({ code: 'const value = "untrusted input is just text";', language: 'javascript' });
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

it('exposes actual per-language evaluation and explicit unsupported catalog entries', async () => {
  expect((await request(app).get('/api/ml/models')).status).toBe(401);
  const response = await agent.get('/api/ml/models');
  expect(response.status).toBe(200);
  const python = response.body.data.models.find((entry: {language:string}) => entry.language === 'python');
  const saved = JSON.parse(await readFile('ml/multilang_classifier/artifacts/python/evaluation.json', 'utf8'));
  expect(python.status).toBe('available');
  expect(python.info.metrics.f1Macro).toBe(saved.evaluation.f1_macro);
  expect(python.info.metrics.negativeFalsePositiveRate).toBeCloseTo(saved.evaluation.negative_false_positive_rate, 12);
  expect(python.info.training.testSamples).toBe(saved.split.test_samples);
  for (const language of ['javascript', 'typescript']) {
    const unsupported = response.body.data.models.find((entry: {language:string}) => entry.language === language);
    expect(unsupported.status).toBe('unsupported');
    expect(unsupported.info).toBeUndefined();
  }
});

it('routes genuine Python inference and preserves Java inference after switching languages', async () => {
  const source = await agent.get('/api/ml/example?language=python');
  expect(source.status).toBe(200);
  const saved = JSON.parse(await readFile('ml/multilang_classifier/artifacts/python/heldout-inference.json','utf8'));
  const prediction = await agent.post('/api/ml/classify').set('Origin',origin)
    .send({code:source.body.data.code,language:'python',filePath:'src/example.py'});
  expect(prediction.status).toBe(200);
  expect(prediction.body.data.cwe).toBe(saved.prediction.cwe);
  expect(prediction.body.data.probability).toBeCloseTo(saved.prediction.probability,8);
  expect(prediction.body.data.modelVersion).toMatch(/^owasp-python-/);
  const metadata = JSON.parse(await readFile('ml/multilang_classifier/artifacts/python/metadata.json', 'utf8'));
  expect(prediction.body.data.modelVersion).toBe(metadata.model_version);
  expect(prediction.body.data.filePath).toBe('src/example.py');
  expect(prediction.body.data.confirmed).toBe(false);
  expect(prediction.body.data.probabilityKind).toBe('uncalibrated');
  const java = await agent.get('/api/ml/example');
  const again = await agent.post('/api/ml/classify').set('Origin',origin).send({code:java.body.data.code,language:'java'});
  const javaSaved = JSON.parse(await readFile('ml/mini_classifier/artifacts/heldout-inference.json','utf8'));
  expect(again.body.data.probability).toBeCloseTo(javaSaved.prediction.probability,8);
},90_000);

it('keeps unsupported model metadata explicit and rejects oversized or malformed path metadata', async () => {
  expect((await agent.get('/api/ml/model-info?language=typescript')).status).toBe(404);
  for (const language of ['constructor','__proto__','../../java']) {
    expect((await agent.get(`/api/ml/example?language=${encodeURIComponent(language)}`)).status).toBe(404);
    expect((await agent.get(`/api/ml/model-info?language=${encodeURIComponent(language)}`)).status).toBe(404);
  }
  expect((await agent.get('/api/ml/model-info?language[]=python')).status).toBe(400);
  for (const body of [
    {code:'x'.repeat(20001),language:'java'},
    {code:'class Test {}',language:'java',filePath:'bad\0path.java'},
    {code:'class Test {}',language:'java',filePath:'x'.repeat(501)},
  ]) {
    const response = await agent.post('/api/ml/classify').set('Origin',origin).send(body);
    expect(response.status).toBe(400);
  }
});

it('returns unknown for Python out-of-distribution text and retains genuine negative-example errors', async () => {
  const unknown = await agent.post('/api/ml/classify').set('Origin',origin).send({code:'not source code at all',language:'python'});
  expect(unknown.body.data.status).toBe('unknown');
  expect(unknown.body.data.cwe).toBeNull();
  const code = await readFile('ml/multilang_classifier/artifacts/python/heldout-negative.py','utf8');
  const saved = JSON.parse(await readFile('ml/multilang_classifier/artifacts/python/heldout-inference.json','utf8'));
  const negative = await agent.post('/api/ml/classify').set('Origin',origin).send({code,language:'python'});
  expect(negative.body.data.predicted_category).toBe(saved.negative_example.prediction.predicted_category);
  expect(negative.body.data.probability).toBeCloseTo(saved.negative_example.prediction.probability,8);
});
