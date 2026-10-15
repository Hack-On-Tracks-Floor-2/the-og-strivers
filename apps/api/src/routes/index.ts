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
  ClassifyInputSchema,
  type User,
  type AnalysisRun,
  type Patch,
  type VerificationRun,
  SubmissionSchema,
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
import type { Pipeline } from '../pipeline/orchestrator.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { defaultRegressionEvidence } from '../verification/regression-demo.js';
import { modelInfo, classifySource, heldoutExample } from '../services/mini-ml.js';

const reviewable = `EXISTS (SELECT 1 FROM patches p WHERE p.run_id=runs.id AND p.document->>'status' IN ('needs_review','approved','rejected'))`;
/** One plain status a developer may see for their submission. */
function submissionStatus(run: AnalysisRun | undefined, patchStates: string[]) {
  if (!run) return 'submitted';
  if (patchStates.includes('approved')) return 'approved';
  if (patchStates.includes('needs_review')) return 'in_review';
  if (patchStates.length && patchStates.every((s) => s === 'rejected')) return 'rejected';
  if (run.status === 'failed') return 'scan_failed';
  if (run.status === 'not_configured') return 'submitted';
  if (['needs_review', 'verified'].includes(run.status)) return 'in_review';
  return 'scanning';
}
export async function apiRouter(db: Database, production: boolean, pipeline?: Pipeline) {
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
      res.status(429).json({
        error: { code: 'RATE_LIMITED', message: 'Too many attempts. Try again later.' },
        version: API_VERSION,
      }),
  });
  const dummyHash = await hashPassword(randomUUID());
  const send = (res: import('express').Response, data: unknown, status = 200) =>
    res.status(status).json({ data, version: API_VERSION });
  const id = (req: Request) => Id.parse(req.params.id);
  /** Runs, findings, patches and evidence are reviewer-only; routes using this also require the reviewer role. */
  async function accessibleRun(req: Request) {
    const result = await db.query<{ document: AnalysisRun }>('SELECT document FROM runs WHERE id=$1', [id(req)]);
    if (!result.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Analysis run not found.');
    return result.rows[0].document;
  }
  router.get('/health', async (_req, res) => {
    const status = pipeline ? await pipeline.status() : null;
    send(res, {
      status: 'ok',
      database: 'ready',
      analysis: status?.available ? 'available' : 'not_configured',
      sandbox: status?.available ? 'docker' : 'not_configured',
      ai: status?.ai ?? [],
      ...(status?.reason ? { reason: status.reason } : {}),
    });
  });
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
  router.get('/ml/model-info', async (_req, res) => send(res, await modelInfo()));
  router.get('/ml/example', async (_req, res) => send(res, await heldoutExample()));
  router.post(
    '/ml/classify',
    rateLimit({ windowMs: 60_000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false }),
    async (req, res) => send(res, await classifySource(ClassifyInputSchema.parse(req.body))),
  );
  // Read-only evidence for the trusted local demo; never launches caller-supplied code.
  router.get('/regression-demo/evidence', async (_req, res) => {
    const text = await readFile(join(defaultRegressionEvidence(), 'latest.json'), 'utf8').catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT')
          throw new HttpError(404, 'EVIDENCE_NOT_FOUND', 'Run npm run demo:regression first.');
        throw error;
      },
    );
    const report = JSON.parse(text);
    let sourceFiles: { path: string; original: string; proposed: string }[] = [];
    if (Id.safeParse(report.runId).success) {
      const base = join(defaultRegressionEvidence(), report.runId);
      const snapshots = await Promise.all([
        readFile(join(base, 'vulnerable/src/reports.cjs'), 'utf8').catch(() => null),
        readFile(join(base, 'patched/src/reports.cjs'), 'utf8').catch(() => null),
      ]);
      if (snapshots[0] !== null && snapshots[1] !== null)
        sourceFiles = [{ path: 'src/reports.cjs', original: snapshots[0], proposed: snapshots[1] }];
    }
    send(res, { ...report, sourceFiles });
  });
  router.get('/auth/me', (req, res) => send(res, currentUser(req)));
  router.get('/repositories', async (req, res) => {
    const user = currentUser(req);
    if (user.role === 'developer') return send(res, await listRepositories(db, user));
    const all = await db.query<{ document: unknown }>("SELECT document FROM repositories ORDER BY document->>'createdAt' DESC");
    send(res, all.rows.map((r) => r.document));
  });
  // Developers submit a repository; the security scan starts automatically. They never see its results.
  router.post('/repositories', requireRole('developer'), async (req, res) => {
    const user = currentUser(req);
    const repository = await registerRepository(db, user, RepositoryInputSchema.parse(req.body).url);
    const status = pipeline ? await pipeline.status() : null;
    const run = await createAnalysisRun(db, user, repository.id, !!status?.available);
    if (status?.available) pipeline!.start(run);
    send(res, repository, 201);
  });
  /** Developer view: one status per submitted repository. No findings, patches or evidence. */
  router.get('/submissions', requireRole('developer'), async (req, res) => {
    const user = currentUser(req);
    const repos = await listRepositories(db, user);
    const runs = await db.query<{ document: AnalysisRun }>(
      "SELECT document FROM runs WHERE owner_id=$1 ORDER BY document->>'createdAt' DESC",
      [user.id],
    );
    const decisions = await db.query<{ run_id: string; document: Patch }>(
      'SELECT run_id, document FROM patches WHERE owner_id=$1',
      [user.id],
    );
    send(
      res,
      repos.map((repo) => {
        const run = runs.rows.map((r) => r.document).find((r) => r.repositoryId === repo.id);
        const runPatches = decisions.rows.filter((d) => d.run_id === run?.id).map((d) => d.document);
        const patchStates = runPatches.map((p) => p.status);
        const merged = runPatches.find((p) => p.merge?.status === 'merged');
        const merging = runPatches.some((p) => p.merge && ['merging', 'awaiting_review'].includes(p.merge.status));
        return SubmissionSchema.parse({
          repositoryId: repo.id,
          url: repo.url,
          owner: repo.owner,
          name: repo.name,
          status: merged ? 'fix_branch_ready' : merging ? 'merging' : submissionStatus(run, patchStates),
          branch: merged?.merge?.branch ?? null,
          pullRequestUrl: merged?.merge?.pullRequestUrl ?? null,
          submittedAt: repo.createdAt,
          updatedAt: run?.updatedAt ?? repo.updatedAt,
        });
      }),
    );
  });
  router.get('/repositories/:id', async (req, res) => {
    const user = currentUser(req);
    const result = await db.query<{ document: unknown }>(
      user.role === 'developer'
        ? 'SELECT document FROM repositories WHERE id=$1 AND owner_id=$2'
        : 'SELECT document FROM repositories WHERE id=$1',
      user.role === 'developer' ? [id(req), user.id] : [id(req)],
    );
    if (!result.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Repository not found.');
    send(res, result.rows[0].document);
  });
  router.get('/runs', requireRole('reviewer'), async (_req, res) => {
    const result = await db.query<{ document: unknown }>("SELECT document FROM runs ORDER BY document->>'createdAt' DESC");
    send(
      res,
      result.rows.map((r) => r.document),
    );
  });
  // Reviewers can (re)scan any submitted repository; the run stays owned by the submitting developer.
  router.post('/runs', requireRole('reviewer'), async (req, res) => {
    const { repositoryId } = AnalysisInputSchema.parse(req.body);
    const repo = await db.query<{ owner_id: string }>('SELECT owner_id FROM repositories WHERE id=$1', [repositoryId]);
    if (!repo.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Repository not found.');
    const status = pipeline ? await pipeline.status() : null;
    const owner = { ...currentUser(req), id: repo.rows[0].owner_id };
    const run = await createAnalysisRun(db, owner, repositoryId, !!status?.available);
    if (status?.available) {
      pipeline!.start(run);
      send(res, run, 201);
      return;
    }
    // Job registration succeeds; execution capability explicitly remains unavailable.
    res.status(201).json({
      data: run,
      version: API_VERSION,
      capability: {
        code: 'CAPABILITY_UNAVAILABLE',
        state: 'not_configured',
        message: status?.reason ?? 'Agent integration pending. No analysis has been executed.',
      },
    });
  });
  router.post('/runs/:id/cancel', requireRole('reviewer'), async (req, res) => {
    const run = await accessibleRun(req);
    send(res, { cancelled: pipeline?.cancel(run.id) ?? false });
  });
  router.get('/runs/:id/artifacts', requireRole('reviewer'), async (req, res) => {
    const run = await accessibleRun(req);
    const result = await db.query<{ document: unknown }>(
      `SELECT document FROM artifacts WHERE run_id=$1 ORDER BY document->>'createdAt' ASC`,
      [run.id],
    );
    send(
      res,
      result.rows.map((r) => r.document),
    );
  });
  router.get('/runs/:id/artifacts/:artifactId', requireRole('reviewer'), async (req, res) => {
    const run = await accessibleRun(req);
    const artifactId = z
      .string()
      .regex(/^[0-9a-f]{40}$/)
      .parse(req.params.artifactId);
    const result = await db.query<{ content: string; document: { kind: string } }>(
      'SELECT content,document FROM artifacts WHERE id=$1 AND run_id=$2',
      [artifactId, run.id],
    );
    if (!result.rows.length) throw new HttpError(404, 'NOT_FOUND', 'Artifact not found.');
    const row = result.rows[0];
    res
      .type('text/plain')
      .setHeader(
        'Content-Disposition',
        `attachment; filename="${row.document.kind}-${artifactId.slice(0, 12)}.txt"`,
      );
    res.send(row.content);
  });
  router.get('/runs/:id', requireRole('reviewer'), async (req, res) => send(res, await accessibleRun(req)));
  for (const [path, table] of Object.entries({
    events: 'events',
    findings: 'findings',
    patches: 'patches',
    verification: 'verifications',
  })) {
    router.get(`/runs/:id/${path}`, requireRole('reviewer'), async (req, res) => {
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
  router.get('/overview', requireRole('reviewer'), async (_req, res) => {
    const result = await db.query<{ document: AnalysisRun }>('SELECT document FROM runs');
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
      repositories: Number((await db.query<{ count: number }>('SELECT count(*)::int AS count FROM repositories')).rows[0].count),
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
  // Merge an approved fix onto the latest code; publishes a GitHub branch + PR when every proof passes again.
  router.post('/reviews/:id/merge', requireRole('reviewer'), async (req, res) => {
    const patch = (await db.query<{ document: Patch }>('SELECT document FROM patches WHERE id=$1', [id(req)])).rows[0]?.document;
    if (!patch) throw new HttpError(404, 'NOT_FOUND', 'Patch not found.');
    if (patch.status !== 'approved') throw new HttpError(409, 'NOT_APPROVED', 'Only an approved patch can be merged.');
    if (patch.merge && !['failed'].includes(patch.merge.status))
      throw new HttpError(409, 'MERGE_EXISTS', `This patch's merge is already ${patch.merge.status.replace('_', ' ')}.`);
    if (!pipeline) throw new HttpError(503, 'UNAVAILABLE', 'The agent pipeline is not available.');
    pipeline.merge(patch.id);
    send(res, { queued: true }, 202);
  });
  // Human check for AI-resolved merge conflicts: nothing is pushed until a reviewer confirms.
  router.post('/reviews/:id/merge/confirm', requireRole('reviewer'), async (req, res) => {
    const patch = (await db.query<{ document: Patch }>('SELECT document FROM patches WHERE id=$1', [id(req)])).rows[0]?.document;
    if (!patch) throw new HttpError(404, 'NOT_FOUND', 'Patch not found.');
    if (patch.merge?.status !== 'awaiting_review')
      throw new HttpError(409, 'NOT_AWAITING', 'This merge is not awaiting confirmation.');
    if (!pipeline) throw new HttpError(503, 'UNAVAILABLE', 'The agent pipeline is not available.');
    pipeline.confirmMerge(patch.id);
    send(res, { queued: true }, 202);
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
            // Reproduction proves the vulnerability: the security test must FAIL on the
            // original code (pytest exit 1). Every other stage must exit 0.
            return (
              record &&
              record.status === 'passed' &&
              record.exitCode === (stage === 'reproduction' ? 1 : 0) &&
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
