import { randomUUID } from 'node:crypto';
import { RunEventSchema, type RunEvent } from '@proofpatch/shared';
import type { Database } from '../database/index.js';
export interface EvidenceService {
  recordEvent(input: Omit<RunEvent, 'id' | 'createdAt'>): Promise<RunEvent>;
}
export function evidenceService(db: Database): EvidenceService {
  return {
    async recordEvent(input) {
      const event = RunEventSchema.parse({
        ...input,
        id: randomUUID(),
        createdAt: new Date().toISOString(),
      });
      await db.query('INSERT INTO events(id,run_id,owner_id,document) VALUES($1,$2,$3,$4)', [
        event.id,
        event.runId,
        event.ownerId,
        event,
      ]);
      return event;
    },
  };
}
