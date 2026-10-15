import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import request from 'supertest';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase, type Database } from '../apps/api/src/database/index.js';
import { createApp } from '../apps/api/src/app.js';
import { provisionReviewer } from '../apps/api/src/services/auth.js';
const origin = 'http://127.0.0.1:5173';
const password = 'correct-horse-battery-99';
let db: Database;
let app: Awaited<ReturnType<typeof createApp>>;
let folder: string;
let developer: ReturnType<typeof request.agent>;
let other: ReturnType<typeof request.agent>;
let reviewer: ReturnType<typeof request.agent>;
let repositoryId: string;
let runId: string;
let developerId: string;
beforeAll(async () => {
  folder = await mkdtemp(join(tmpdir(), 'proofpatch-test-'));
  db = await openDatabase(join(folder, 'nested', 'db'));
  await provisionReviewer(db, { email: 'reviewer@example.com', password, name: 'Reviewer' });
  app = await createApp(db, { origin });
  developer = request.agent(app);
  other = request.agent(app);
  reviewer = request.agent(app);
});
afterAll(async () => {
  await db?.close();
  if (folder) await rm(folder, { recursive: true, force: true });
});
describe.sequential('real authentication, records and roles', () => {
  it('serves database health', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.data.database).toBe('ready');
  });
  it('blocks anonymous access', async () =>
    expect((await request(app).get('/api/repositories')).status).toBe(401));
  it('returns a structured error for malformed JSON', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Origin', origin)
      .set('Content-Type', 'application/json')
      .send('{broken');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_BODY');
  });
  it('blocks cross-origin registration', async () =>
    expect(
      (
        await request(app)
          .post('/api/auth/register')
          .set('Origin', 'https://evil.example')
          .send({ name: 'Dev', email: 'dev@example.com', password })
      ).status,
    ).toBe(403));
  it('rejects reviewer role injection', async () =>
    expect(
      (
        await request(app)
          .post('/api/auth/register')
          .set('Origin', origin)
          .send({ name: 'Dev', email: 'dev@example.com', password, role: 'reviewer' })
      ).status,
    ).toBe(400));
  it('registers developer and sets HttpOnly session cookie', async () => {
    const res = await developer
      .post('/api/auth/register')
      .set('Origin', origin)
      .send({ name: 'Developer', email: 'dev@example.com', password });
    expect(res.status).toBe(201);
    expect(res.body.data.role).toBe('developer');
    developerId = res.body.data.id;
    expect(res.headers['set-cookie'][0]).toContain('HttpOnly');
    expect(res.headers['set-cookie'][0]).toContain('SameSite=Lax');
    expect(JSON.stringify(res.body)).not.toContain('password');
  });
  it('stores a salted password hash and hashed session tokens', async () => {
    const row = (
      await db.query<{ password_hash: string }>('SELECT password_hash FROM users WHERE id=$1', [
        developerId,
      ])
    ).rows[0];
    expect(row.password_hash).not.toContain(password);
    expect(row.password_hash.split(':')[1]).toHaveLength(128);
    const sessions = await db.query<{ token_hash: string }>(
      'SELECT token_hash FROM sessions WHERE user_id=$1',
      [developerId],
    );
    expect(sessions.rows[0].token_hash).toMatch(/^[a-f0-9]{64}$/);
  });
  it('rejects invalid repository URLs', async () =>
    expect(
      (
        await developer
          .post('/api/repositories')
          .set('Origin', origin)
          .send({ url: 'https://evil.example/a/b' })
      ).status,
    ).toBe(400));
  it('persists a registered repository with unknown inspection fields', async () => {
    const res = await developer
      .post('/api/repositories')
      .set('Origin', origin)
      .send({ url: 'https://github.com/expressjs/express.git' });
    expect(res.status).toBe(201);
    repositoryId = res.body.data.id;
    expect(res.body.data.language).toBeNull();
    expect(res.body.data.url).toBe('https://github.com/expressjs/express');
  });
  it('prevents case-insensitive duplicate registrations', async () =>
    expect(
      (
        await developer
          .post('/api/repositories')
          .set('Origin', origin)
          .send({ url: 'https://github.com/ExpressJS/Express' })
      ).status,
    ).toBe(409));
  it('starts the scan on submission and hides every result from the developer', async () => {
    const runs = await db.query<{ document: { id: string; status: string } }>(
      'SELECT document FROM runs WHERE repository_id=$1',
      [repositoryId],
    );
    expect(runs.rows).toHaveLength(1);
    runId = runs.rows[0].document.id;
    expect(runs.rows[0].document.status).toBe('not_configured');
    const events = await db.query<{ kind: string }>(
      "SELECT document->>'kind' AS kind FROM events WHERE run_id=$1 ORDER BY document->>'createdAt'",
      [runId],
    );
    expect(events.rows.map((e) => e.kind).sort()).toEqual(['capability_unavailable', 'job_received']);
    for (const endpoint of ['', '/events', '/findings', '/patches', '/verification', '/artifacts'])
      expect((await developer.get(`/api/runs/${runId}${endpoint}`)).status).toBe(403);
    expect((await developer.get('/api/runs')).status).toBe(403);
    expect((await developer.get('/api/overview')).status).toBe(403);
    expect((await developer.post('/api/runs').set('Origin', origin).send({ repositoryId })).status).toBe(403);
    const submissions = (await developer.get('/api/submissions')).body.data;
    expect(submissions).toHaveLength(1);
    expect(submissions[0]).toMatchObject({ repositoryId, status: 'submitted' });
    expect(Object.keys(submissions[0]).sort()).toEqual(['branch', 'name', 'owner', 'pullRequestUrl', 'repositoryId', 'status', 'submittedAt', 'updatedAt', 'url']);
  });
  it('isolates other developer records, events and job creation', async () => {
    await other
      .post('/api/auth/register')
      .set('Origin', origin)
      .send({ name: 'Other', email: 'other@example.com', password });
    expect((await other.get(`/api/repositories/${repositoryId}`)).status).toBe(404);
    expect((await other.get(`/api/runs/${runId}/events`)).status).toBe(403);
    expect(
      (await other.post('/api/runs').set('Origin', origin).send({ repositoryId })).status,
    ).toBe(403);
    expect((await other.get('/api/repositories')).body.data).toEqual([]);
    expect((await other.get('/api/submissions')).body.data).toEqual([]);
  });
  it('enforces reviewer portal roles on login and API', async () => {
    expect((await developer.get('/api/reviews/queue')).status).toBe(403);
    expect(
      (
        await reviewer
          .post('/api/auth/login')
          .set('Origin', origin)
          .send({ email: 'reviewer@example.com', password, role: 'developer' })
      ).status,
    ).toBe(401);
    expect(
      (
        await reviewer
          .post('/api/auth/login')
          .set('Origin', origin)
          .send({ email: 'reviewer@example.com', password, role: 'reviewer' })
      ).status,
    ).toBe(200);
    expect((await reviewer.get('/api/repositories')).body.data).toHaveLength(1);
    expect((await reviewer.get(`/api/runs/${runId}`)).body.data.id).toBe(runId);
    expect((await reviewer.get('/api/submissions')).status).toBe(403);
    expect(
      (await reviewer.post('/api/repositories').set('Origin', origin).send({ url: 'https://github.com/a/b' })).status,
    ).toBe(403);
    expect((await reviewer.get('/api/reviews/queue')).body.data).toEqual([]);
  });
  it('rejects approval without test evidence and records a real rejection', async () => {
    const now = new Date().toISOString();
    const findingId = randomUUID();
    const patchId = randomUUID();
    const finding = {
      id: findingId,
      runId,
      ownerId: developerId,
      category: 'test fixture',
      severity: 'low',
      confidence: 1,
      file: 'fixture.ts',
      startLine: 1,
      endLine: 1,
      rootCause: 'Test-only fixture',
      evidence: [],
      recommendation: 'Test',
      createdAt: now,
    };
    const patch = {
      id: patchId,
      runId,
      findingId,
      ownerId: developerId,
      status: 'needs_review',
      files: [],
      unifiedDiff: '',
      createdAt: now,
      updatedAt: now,
    };
    await db.query('INSERT INTO findings(id,run_id,owner_id,document) VALUES($1,$2,$3,$4)', [
      findingId,
      runId,
      developerId,
      finding,
    ]);
    await db.query(
      'INSERT INTO patches(id,run_id,finding_id,owner_id,document) VALUES($1,$2,$3,$4,$5)',
      [patchId, runId, findingId, developerId, patch],
    );
    expect((await reviewer.get('/api/reviews/queue')).body.data).toHaveLength(1);
    expect(
      (
        await reviewer
          .post(`/api/reviews/${patchId}/decision`)
          .set('Origin', origin)
          .send({ decision: 'approved', reason: 'Attempt without actual test evidence' })
      ).status,
    ).toBe(409);
    const rejected = await reviewer
      .post(`/api/reviews/${patchId}/decision`)
      .set('Origin', origin)
      .send({ decision: 'rejected', reason: 'Missing all required execution evidence.' });
    expect(rejected.status).toBe(201);
    expect((await reviewer.get('/api/reviews/decisions')).body.data).toHaveLength(1);
    expect((await reviewer.get('/api/reviews/queue')).body.data).toEqual([]);
    expect((await developer.get('/api/submissions')).body.data[0].status).toBe('rejected');
  });
  it('returns real overview counts', async () => {
    const res = await reviewer.get('/api/overview');
    expect(res.body.data.repositories).toBe(1);
    expect(res.body.data.runs).toBe(1);
    expect(res.body.data.verified).toBe(0);
  });
  it('revokes sessions on logout and allows developer login', async () => {
    expect((await developer.post('/api/auth/logout').set('Origin', origin).send({})).status).toBe(
      200,
    );
    expect((await developer.get('/api/auth/me')).status).toBe(401);
    expect(
      (
        await developer
          .post('/api/auth/login')
          .set('Origin', origin)
          .send({ email: 'dev@example.com', password, role: 'developer' })
      ).status,
    ).toBe(200);
  });
  it('rejects expired sessions', async () => {
    await db.query('UPDATE sessions SET expires_at=$1 WHERE user_id=$2', [
      new Date(Date.now() - 60000).toISOString(),
      developerId,
    ]);
    expect((await developer.get('/api/auth/me')).status).toBe(401);
  });
  it('uses secure cookies in production', async () => {
    const secureApp = await createApp(db, {
      origin: 'https://proofpatch.example',
      production: true,
    });
    const res = await request(secureApp)
      .post('/api/auth/login')
      .set('Origin', 'https://proofpatch.example')
      .send({ email: 'reviewer@example.com', password, role: 'reviewer' });
    expect(res.status).toBe(200);
    expect(res.headers['set-cookie'][0]).toContain('Secure');
  });
  it('retains repositories and jobs after reopening the database', async () => {
    await db.close();
    db = await openDatabase(join(folder, 'nested', 'db'));
    expect(
      (await db.query('SELECT id FROM repositories WHERE id=$1', [repositoryId])).rows,
    ).toHaveLength(1);
    expect((await db.query('SELECT id FROM runs WHERE id=$1', [runId])).rows).toHaveLength(1);
    const restarted = await createApp(db, { origin });
    expect((await request(restarted).get('/api/health')).status).toBe(200);
  });
});
