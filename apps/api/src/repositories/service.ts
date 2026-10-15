import { randomUUID } from 'node:crypto';
import { RepositorySchema, type Repository, type User } from '@proofpatch/shared';
import type { Database } from '../database/index.js';
import { HttpError } from '../utils/errors.js';
export async function listRepositories(db: Database, user: User): Promise<Repository[]> {
  const result = await db.query<{ document: Repository }>(
    "SELECT document FROM repositories WHERE owner_id=$1 ORDER BY document->>'createdAt' DESC",
    [user.id],
  );
  return result.rows.map((r) => RepositorySchema.parse(r.document));
}
export async function registerRepository(db: Database, user: User, url: string) {
  const [, , , owner, name] = url.split('/');
  const now = new Date().toISOString();
  const repository = RepositorySchema.parse({
    id: randomUUID(),
    ownerId: user.id,
    url,
    owner,
    name,
    language: null,
    framework: null,
    createdAt: now,
    updatedAt: now,
  });
  try {
    await db.query(
      'INSERT INTO repositories(id,owner_id,canonical_url,document) VALUES($1,$2,$3,$4)',
      [repository.id, user.id, url.toLowerCase(), repository],
    );
  } catch (error) {
    if ((error as { code?: string }).code === '23505')
      throw new HttpError(
        409,
        'REPOSITORY_EXISTS',
        'This repository is already in your workspace.',
      );
    throw error;
  }
  return repository;
}
