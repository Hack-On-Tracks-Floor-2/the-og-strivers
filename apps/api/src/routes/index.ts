import { Router, type Request } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { rateLimit } from 'express-rate-limit';
import {
  API_VERSION,
  RegisterSchema,
  LoginSchema,
  RepositoryInputSchema,
  AnalysisInputSchema,
  DecisionInputSchema,
  Id,
  type User,
  type AnalysisRun,
  type Patch,
  type VerificationRun,
} from '@proofpatch/shared';
import type { Database } from '../database/index.js';
import { authenticate, currentUser, requireRole } from '../middleware/auth.js';
import {
  createUser,
  createSession,
  verifyPassword,
  sessionDigest,
  hashPassword,
} from '../services/auth.js';
import { registerRepository, listRepositories } from '../repositories/service.js';
import { createAnalysisRun } from '../scanners/service.js';
import { HttpError } from '../utils/errors.js';

const reviewable = `EXISTS (SELECT 1 FROM patches p WHERE p.run_id=runs.id AND p.document->>'status' IN ('needs_review','approved','rejected'))`;
export async function apiRouter(db: Database, production: boolean) {
  const router = Router();
  const cookie = {
    httpOnly: true,
    secure: production,
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 7 * 86400000,
  };
  const limiter = rateLimit({
    windowMs: 15 * 60_000,
    limit: 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_req, res) =>
      res
        .status(429)
        .json({
          error: { code: 'RATE_LIMITED', message: 'Too many attempts. Try again later.' },
          version: API_VERSION,
        }),
  });
  const dummyHash = await hashPassword(randomUUID());
  const send = (res: import('express').Response, data: unknown, status = 200) =>
    res.status(status).json({ data, version: API_VERSION });
  const id = (req: Request) => Id.parse(req.params.id);
  async function accessibleRun(req: Request) {
    const user = currentUser(req);
    const result = await db.query<{ document: AnalysisRun }>(
      `SELECT document FROM runs WHERE id=$1 AND ${user.role === 'developer' ? 'owner_id=$2' : reviewable}`,
      user.role === 'developer' ? [id(req), user.id] : [id(req)],
    );
    if (!result.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Analysis run not found.');
    return result.rows[0].document;
  }
  router.get('/health', (_req, res) =>
    send(res, { status: 'ok', database: 'ready', analysis: 'not_configured' }),
  );
  router.post('/auth/register', limiter, async (req, res) => {
    const user = await createUser(db, RegisterSchema.parse(req.body));
    res.cookie('pp_session', await createSession(db, user.id), cookie);
    send(res, user, 201);
  });
  router.post('/auth/login', limiter, async (req, res) => {
    const input = LoginSchema.parse(req.body);
    const result = await db.query<{ document: User; password_hash: string }>(
      'SELECT document,password_hash FROM users WHERE email=$1',
      [input.email],
    );
    const row = result.rows[0];
    const valid = await verifyPassword(input.password, row?.password_hash ?? dummyHash);
    if (!row || !valid || row.document.role !== input.role)
      throw new HttpError(
        401,
        'INVALID_CREDENTIALS',
        'Email, password or portal role is incorrect.',
      );
    const oldToken = req.cookies?.pp_session;
    if (typeof oldToken === 'string')
      await db.query('DELETE FROM sessions WHERE token_hash=$1', [sessionDigest(oldToken)]);
    res.cookie('pp_session', await createSession(db, row.document.id), cookie);
    send(res, row.document);
  });
  router.post('/auth/logout', async (req, res) => {
    if (typeof req.cookies?.pp_session === 'string')
      await db.query('DELETE FROM sessions WHERE token_hash=$1', [
        sessionDigest(req.cookies.pp_session),
      ]);
    res.clearCookie('pp_session', { ...cookie, maxAge: undefined });
    send(res, { loggedOut: true });
  });
  router.use(authenticate(db));
  router.get('/auth/me', (req, res) => send(res, currentUser(req)));
  router.get('/repositories', requireRole('developer'), async (req, res) =>
    send(res, await listRepositories(db, currentUser(req))),
  );
  router.post('/repositories', requireRole('developer'), async (req, res) =>
    send(
      res,
      await registerRepository(db, currentUser(req), RepositoryInputSchema.parse(req.body).url),
      201,
    ),
  );
  router.get('/repositories/:id', requireRole('developer'), async (req, res) => {
    const result = await db.query<{ document: unknown }>(
      'SELECT document FROM repositories WHERE id=$1 AND owner_id=$2',
      [id(req), currentUser(req).id],
    );
    if (!result.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Repository not found.');
    send(res, result.rows[0].document);
  });
  router.get('/runs', async (req, res) => {
    const user = currentUser(req);
    const result = await db.query<{ document: unknown }>(
      `SELECT document FROM runs WHERE ${user.role === 'developer' ? 'owner_id=$1' : reviewable} ORDER BY document->>'createdAt' DESC`,
      user.role === 'developer' ? [user.id] : [],
    );
    send(
      res,
      result.rows.map((r) => r.document),
    );
  });
  router.post('/runs', requireRole('developer'), async (req, res) => {
    const { repositoryId } = AnalysisInputSchema.parse(req.body);
    const own = await db.query('SELECT id FROM repositories WHERE id=$1 AND owner_id=$2', [
      repositoryId,
      currentUser(req).id,
    ]);
    if (!own.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Repository not found.');
    const run = await createAnalysisRun(db, currentUser(req), repositoryId);
    // Job registration succeeds; execution capability explicitly remains unavailable.
    res
      .status(201)
      .json({
        data: run,
        version: API_VERSION,
        capability: {
          code: 'CAPABILITY_UNAVAILABLE',
          state: 'not_configured',
          message: 'Agent integration pending. No analysis has been executed.',
        },
      });
  });
  router.get('/runs/:id', async (req, res) => send(res, await accessibleRun(req)));
  for (const [path, table] of Object.entries({
    events: 'events',
    findings: 'findings',
    patches: 'patches',
    verification: 'verifications',
  })) {
    router.get(`/runs/:id/${path}`, async (req, res) => {
      const run = await accessibleRun(req);
      const result = await db.query<{ document: unknown }>(
        `SELECT document FROM ${table} WHERE run_id=$1 ORDER BY document->>'createdAt' ASC`,
        [run.id],
      );
      send(
        res,
        result.rows.map((r) => r.document),
      );
    });
  }
  router.get('/overview', async (req, res) => {
    const user = currentUser(req);
    const owner = user.role === 'developer' ? 'runs.owner_id=$1' : reviewable;
    const result = await db.query<{ document: AnalysisRun }>(
      `SELECT document FROM runs WHERE ${owner}`,
      user.role === 'developer' ? [user.id] : [],
    );
    const runIds = result.rows.map((r) => r.document.id);
    const count = async (table: string) =>
      Number(
        (
          await db.query<{ count: number }>(
            `SELECT count(*)::int AS count FROM ${table} WHERE run_id=ANY($1::uuid[])`,
            [runIds],
          )
        ).rows[0].count,
      );
    send(res, {
      repositories: user.role === 'developer' ? (await listRepositories(db, user)).length : 0,
      runs: runIds.length,
      findings: await count('findings'),
      patches: await count('patches'),
      verified: result.rows.filter((r) => r.document.status === 'verified').length,
      awaitingReview: Number(
        (
          await db.query<{ count: number }>(
            `SELECT count(*)::int AS count FROM patches WHERE run_id=ANY($1::uuid[]) AND document->>'status'='needs_review'`,
            [runIds],
          )
        ).rows[0].count,
      ),
    });
  });
  router.get('/reviews/queue', requireRole('reviewer'), async (_req, res) => {
    const result = await db.query<{ document: unknown }>(
      `SELECT document FROM patches WHERE document->>'status'='needs_review' ORDER BY document->>'createdAt' ASC`,
    );
    send(
      res,
      result.rows.map((r) => r.document),
    );
  });
  router.get('/reviews/decisions', requireRole('reviewer'), async (_req, res) => {
    const result = await db.query<{ document: unknown }>(
      `SELECT document FROM decisions ORDER BY document->>'createdAt' DESC`,
    );
    send(
      res,
      result.rows.map((r) => r.document),
    );
  });
  router.post('/reviews/:id/decision', requireRole('reviewer'), async (req, res) => {
    const input = DecisionInputSchema.parse(req.body);
    const patchId = id(req);
    const reviewer = currentUser(req);
    const decision = await db.transaction(async (tx) => {
      const result = await tx.query<{ document: Patch }>(
        `SELECT document FROM patches WHERE id=$1 FOR UPDATE`,
        [patchId],
      );
      const patch = result.rows[0]?.document;
      if (!patch || patch.status !== 'needs_review')
        throw new HttpError(409, 'NOT_REVIEWABLE', 'This patch is not awaiting review.');
      if (input.decision === 'approved') {
        const evidence = await tx.query<{ document: VerificationRun }>(
          'SELECT document FROM verifications WHERE patch_id=$1 AND run_id=$2',
          [patch.id, patch.runId],
        );
        const stages = [
          'baseline',
          'reproduction',
          'patch_application',
          'security_retest',
          'regression',
        ];
        if (
          !stages.every((stage) => {
            const record = evidence.rows
              .map((r) => r.document)
              .filter((v) => v.stage === stage)
              .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
            return (
              record &&
              record.status === 'passed' &&
              record.exitCode === 0 &&
              record.logs.trim() &&
              record.artifactId &&
              record.completedAt
            );
          })
        )
          throw new HttpError(
            409,
            'EVIDENCE_REQUIRED',
            'Approval requires recorded passing baseline, reproduction, patch application, security retest and regression evidence with exit codes, logs and artifact references.',
          );
      }
      const now = new Date().toISOString();
      const record = {
        id: randomUUID(),
        runId: patch.runId,
        patchId,
        reviewerId: reviewer.id,
        ...input,
        createdAt: now,
      };
      await tx.query(
        'INSERT INTO decisions(id,run_id,patch_id,reviewer_id,document) VALUES($1,$2,$3,$4,$5)',
        [record.id, patch.runId, patchId, reviewer.id, record],
      );
      await tx.query('UPDATE patches SET document=$1 WHERE id=$2', [
        { ...patch, status: input.decision, updatedAt: now },
        patchId,
      ]);
      const event = {
        id: randomUUID(),
        runId: patch.runId,
        ownerId: patch.ownerId,
        kind: 'review_decision',
        message: `Patch ${input.decision}: ${input.reason}`,
        artifactId: record.id,
        createdAt: now,
      };
      await tx.query('INSERT INTO events(id,run_id,owner_id,document) VALUES($1,$2,$3,$4)', [
        event.id,
        patch.runId,
        patch.ownerId,
        event,
      ]);
      return record;
    });
    send(res, decision, 201);
  });
  return router;
}
