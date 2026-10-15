import { PGlite } from '@electric-sql/pglite';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { migrations } from './migrations.js';
export async function openDatabase(path?: string) {
  if (path) await mkdir(dirname(path), { recursive: true });
  const db = new PGlite(path);
  await db.waitReady;
  await db.exec(
    'CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())',
  );
  for (const migration of migrations) {
    const applied = await db.query('SELECT version FROM schema_migrations WHERE version=$1', [
      migration.version,
    ]);
    if (!applied.rows.length)
      await db.transaction(async (tx) => {
        await tx.exec(migration.sql);
        await tx.query('INSERT INTO schema_migrations(version) VALUES($1)', [migration.version]);
      });
  }
  return db;
}
export type Database = Awaited<ReturnType<typeof openDatabase>>;
