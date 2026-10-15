import { config } from 'dotenv';
import { resolve } from 'node:path';
import { z } from 'zod';
import { openDatabase } from './database/index.js';
import { provisionReviewer, provisionDemoDeveloper } from './services/auth.js';
import { createApp } from './app.js';
import { createAiClient } from './ai/client.js';
import { githubIngestion, WorkspaceStore } from './repositories/clone.js';
import { DockerSandbox } from './verification/docker.js';
import { createPipeline } from './pipeline/orchestrator.js';
import { createLocator } from './scanners/locator.js';
// npm workspace commands run in apps/api, so resolve config from project root.
const root = process.cwd().endsWith('api') ? resolve(process.cwd(), '../..') : process.cwd();
config({ path: resolve(root, '.env'), quiet: true });
const port = z.coerce
  .number()
  .int()
  .min(1)
  .max(65535)
  // API_PORT wins over PORT: tools that launch the web dev server often set PORT for Vite.
  .parse(process.env.API_PORT ?? process.env.PORT ?? 3001);
const origin = z
  .string()
  .url()
  .parse(process.env.APP_ORIGIN ?? 'http://127.0.0.1:5173');
const production = process.env.NODE_ENV === 'production';
if (production && !origin.startsWith('https://'))
  throw new Error('Production APP_ORIGIN requires HTTPS.');
if (!!process.env.REVIEWER_EMAIL !== !!process.env.REVIEWER_PASSWORD)
  throw new Error('Set both REVIEWER_EMAIL and REVIEWER_PASSWORD.');
const db = await openDatabase(resolve(root, process.env.DATABASE_PATH ?? '.data/proofpatch'));
await provisionReviewer(
  db,
  process.env.REVIEWER_EMAIL
    ? {
        email: process.env.REVIEWER_EMAIL,
        password: process.env.REVIEWER_PASSWORD!,
        name: process.env.REVIEWER_NAME ?? 'Security Reviewer',
      }
    : undefined,
);
// PUBLIC_DEMO=true also creates the demo developer in production (hackathon demo only).
if ((!production || process.env.PUBLIC_DEMO === 'true') && process.env.DEVELOPER_DEMO_EMAIL && process.env.DEVELOPER_DEMO_PASSWORD)
  await provisionDemoDeveloper(db, {
    email: process.env.DEVELOPER_DEMO_EMAIL,
    password: process.env.DEVELOPER_DEMO_PASSWORD,
    name: 'Demo Developer',
  });
const dataRoot = resolve(root, process.env.WORK_PATH ?? '.data/work');
const store = new WorkspaceStore(resolve(dataRoot, 'workspaces'));
const sandbox = new DockerSandbox({
  image: process.env.SANDBOX_IMAGE ?? 'proofpatch-runner:py312',
  docker: process.env.DOCKER_BIN || 'docker',
  workspacePath: (id) => store.path(id),
  scratchRoot: resolve(dataRoot, 'scratch'),
});
const pipeline = createPipeline({
  db,
  ingestion: githubIngestion(store),
  store,
  sandbox,
  ai: createAiClient(process.env),
  locator: createLocator(process.env),
  tokenBudget: Number(process.env.RUN_TOKEN_BUDGET) > 0 ? Number(process.env.RUN_TOKEN_BUDGET) : 30_000,
});
const capability = await pipeline.status();
console.log(
  capability.available
    ? `Agent pipeline ready (AI: ${capability.ai.join(', ')}; sandbox: Docker).`
    : `Agent pipeline unavailable: ${capability.reason}`,
);
const app = await createApp(db, { origin, production, pipeline });
const server = app.listen(port, '127.0.0.1', () =>
  console.log(`ProofPatch API ready at http://127.0.0.1:${port}/api/health`),
);
server.on('error', async (error) => {
  console.error(error.message);
  await db.close();
  process.exitCode = 1;
});
async function shutdown() {
  server.close(async () => {
    await pipeline.shutdown();
    await db.close();
    process.exit(0);
  });
}
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
