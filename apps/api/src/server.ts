import { config } from 'dotenv';
import { resolve } from 'node:path';
import { z } from 'zod';
import { openDatabase } from './database/index.js';
import { provisionReviewer } from './services/auth.js';
import { createApp } from './app.js';
// npm workspace commands run in apps/api, so resolve config from project root.
const root = process.cwd().endsWith('api') ? resolve(process.cwd(), '../..') : process.cwd();
config({ path: resolve(root, '.env'), quiet: true });
const port = z.coerce
  .number()
  .int()
  .min(1)
  .max(65535)
  .parse(process.env.PORT ?? 3001);
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
const app = await createApp(db, { origin, production });
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
    await db.close();
    process.exit(0);
  });
}
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
