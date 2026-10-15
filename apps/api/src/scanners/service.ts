import { randomUUID } from 'node:crypto';
import { AnalysisRunSchema, RunEventSchema, type User } from '@proofpatch/shared';
import type { Database } from '../database/index.js';
export async function createAnalysisRun(db: Database, user: User, repositoryId: string) {
  const now = new Date().toISOString();
  const run = AnalysisRunSchema.parse({
    id: randomUUID(),
    repositoryId,
    ownerId: user.id,
    status: 'not_configured',
    capability: 'not_configured',
    error: null,
    createdAt: now,
    updatedAt: now,
  });
  const events = [
    {
      kind: 'job_received',
      message: 'Analysis request registered. No repository code has been cloned or executed.',
    },
    {
      kind: 'capability_unavailable',
      message:
        'Agent integration pending. Configure repository intelligence, detection and isolated verification adapters to enable analysis.',
    },
  ].map((e) =>
    RunEventSchema.parse({
      ...e,
      id: randomUUID(),
      runId: run.id,
      ownerId: user.id,
      artifactId: null,
      createdAt: now,
    }),
  );
  await db.transaction(async (tx) => {
    await tx.query('INSERT INTO runs(id,repository_id,owner_id,document) VALUES($1,$2,$3,$4)', [
      run.id,
      repositoryId,
      user.id,
      run,
    ]);
    for (const event of events)
      await tx.query('INSERT INTO events(id,run_id,owner_id,document) VALUES($1,$2,$3,$4)', [
        event.id,
        run.id,
        user.id,
        event,
      ]);
  });
  return run;
}
