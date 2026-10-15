/**
 * Live demo without GitHub: runs the full agent pipeline (real AI + real Docker sandbox)
 * on a local folder and prints every step.  Usage:
 *   npm run demo:local -- "D:/PS1 - Agnel/demo-targets/report-tool"
 */
import { config } from 'dotenv';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { openDatabase } from '../apps/api/src/database/index.ts';
import { WorkspaceStore } from '../apps/api/src/repositories/clone.ts';
import { DockerSandbox } from '../apps/api/src/verification/docker.ts';
import { createAiClient } from '../apps/api/src/ai/client.ts';
import { createPipeline } from '../apps/api/src/pipeline/orchestrator.ts';
import { createAnalysisRun } from '../apps/api/src/scanners/service.ts';

config({ path: resolve('.env'), quiet: true });
const source = process.argv[2];
if (!source) throw new Error('Pass the path of a local Python repository with a pytest suite.');
const name = basename(resolve(source));
const work = resolve(process.env.WORK_PATH ?? '.data/work');
const folder = await mkdtemp(join(tmpdir(), 'pp-demo-'));
const db = await openDatabase(join(folder, 'db'));
const store = new WorkspaceStore(join(work, 'workspaces'));
const sandbox = new DockerSandbox({
  image: process.env.SANDBOX_IMAGE ?? 'proofpatch-runner:py312',
  docker: process.env.DOCKER_BIN || 'docker',
  workspacePath: (id) => store.path(id),
  scratchRoot: join(work, 'scratch'),
});
const ai = createAiClient(process.env);
const pipeline = createPipeline({
  db, store, sandbox, ai,
  tokenBudget: Number(process.env.RUN_TOKEN_BUDGET) > 0 ? Number(process.env.RUN_TOKEN_BUDGET) : 30_000,
  ingestion: {
    async ingest(repository) {
      const id = randomUUID();
      await cp(resolve(source), store.path(id), { recursive: true, filter: (p) => !/[\/]\.git([\/]|$)/.test(p) });
      return { state: 'completed', data: { id, repositoryId: repository.id, commitSha: 'local-folder' } };
    },
  },
});
const status = await pipeline.status();
if (!status.available) throw new Error(status.reason ?? 'Pipeline unavailable');
const now = new Date().toISOString();
const user = { id: randomUUID(), name: 'Demo', email: 'demo@example.test', role: 'developer' as const, createdAt: now };
const repoId = randomUUID();
await db.query('INSERT INTO users(id,email,password_hash,document) VALUES($1,$2,$3,$4)', [user.id, user.email, '-', user]);
await db.query('INSERT INTO repositories(id,owner_id,canonical_url,document) VALUES($1,$2,$3,$4)', [repoId, user.id, `local:${name}`,
  { id: repoId, ownerId: user.id, url: `https://github.com/local/${name}`, name, owner: 'local', language: null, framework: null, createdAt: now, updatedAt: now }]);
console.log(`\n▶ ProofPatch agent on ${name}  (AI: ${status.ai.join(' → ')}, sandbox: Docker, network off)\n`);
const run = await createAnalysisRun(db, user, repoId, true);
const started = Date.now();
let shown = 0;
const timer = setInterval(async () => {
  const rows = (await db.query<{ document: { kind: string; message: string } }>(
    "SELECT document FROM events WHERE run_id=$1 ORDER BY document->>'createdAt'", [run.id])).rows;
  for (const r of rows.slice(shown)) console.log(`  [${r.document.kind.replace('_', ' ')}] ${r.document.message}`);
  shown = rows.length;
}, 300);
pipeline.start(run);
await pipeline.idle();
await new Promise((r) => setTimeout(r, 400));
clearInterval(timer);
const final = (await db.query<{ document: { status: string; error: string | null } }>('SELECT document FROM runs WHERE id=$1', [run.id])).rows[0].document;
const patch = (await db.query<{ document: { unifiedDiff: string; securityTest: { path: string; content: string } | null } }>(
  "SELECT document FROM patches WHERE run_id=$1 AND document->>'status'='needs_review'", [run.id])).rows[0]?.document;
if (patch) {
  console.log(`\n── Patch ─────────────────────────────\n${patch.unifiedDiff}`);
  console.log(`\n── Exploit test (${patch.securityTest?.path}) ──\n${patch.securityTest?.content}`);
}
console.log(`\n■ Result: ${final.status === 'needs_review' ? 'PROVEN FIX — awaiting human review' : `FAILED — ${final.error}`} (${Math.round((Date.now() - started) / 1000)} s)\n`);
await db.close();
await rm(folder, { recursive: true, force: true });
