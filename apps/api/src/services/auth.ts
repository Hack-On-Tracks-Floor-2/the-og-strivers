import {
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
  createHash,
} from 'node:crypto';
import { promisify } from 'node:util';
import type { Database } from '../database/index.js';
import { UserSchema, type User } from '@proofpatch/shared';
import { HttpError } from '../utils/errors.js';
const scrypt = promisify(scryptCallback);
export const sessionDigest = (token: string) => createHash('sha256').update(token).digest('hex');
export async function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  const hash = (await scrypt(password, salt, 64)) as Buffer;
  return `${salt}:${hash.toString('hex')}`;
}
export async function verifyPassword(password: string, stored: string) {
  const [salt, hex] = stored.split(':');
  const actual = (await scrypt(password, salt, 64)) as Buffer;
  const expected = Buffer.from(hex, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export async function createUser(
  db: Database,
  input: { name: string; email: string; password: string },
  role: User['role'] = 'developer',
) {
  const user = UserSchema.parse({
    id: randomUUID(),
    name: input.name,
    email: input.email,
    role,
    createdAt: new Date().toISOString(),
  });
  const hash = await hashPassword(input.password);
  try {
    await db.query('INSERT INTO users(id,email,password_hash,document) VALUES($1,$2,$3,$4)', [
      user.id,
      user.email,
      hash,
      user,
    ]);
  } catch (error) {
    if ((error as { code?: string }).code === '23505')
      throw new HttpError(409, 'ACCOUNT_EXISTS', 'An account with this email already exists.');
    throw error;
  }
  return user;
}
export async function createSession(db: Database, userId: string) {
  const token = randomBytes(32).toString('base64url');
  await db.query('DELETE FROM sessions WHERE expires_at <= now()');
  await db.query('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)', [
    sessionDigest(token),
    userId,
    new Date(Date.now() + 7 * 86400000).toISOString(),
  ]);
  return token;
}
/** Local demo only: creates the demo developer account if it does not exist yet. */
export async function provisionDemoDeveloper(
  db: Database,
  config?: { email: string; password: string; name: string },
) {
  if (!config) return;
  if (config.password.length < 12 || config.password.length > 128)
    throw new Error('DEVELOPER_DEMO_PASSWORD must have 12–128 characters.');
  const email = config.email.trim().toLowerCase();
  const existing = await db.query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (!existing.rows.length) await createUser(db, { ...config, email }, 'developer');
}
export async function provisionReviewer(
  db: Database,
  config?: { email: string; password: string; name: string },
) {
  if (!config) return;
  if (config.password.length < 12 || config.password.length > 128)
    throw new Error('REVIEWER_PASSWORD must have 12–128 characters.');
  const email = config.email.trim().toLowerCase();
  const result = await db.query<{ document: User }>('SELECT document FROM users WHERE email=$1', [
    email,
  ]);
  if (!result.rows.length) {
    await createUser(db, { ...config, email }, 'reviewer');
    return;
  }
  if (UserSchema.parse(result.rows[0].document).role !== 'reviewer')
    throw new Error('Reviewer email belongs to a developer. Choose a different email.');
  await db.query('UPDATE users SET password_hash=$1 WHERE email=$2', [
    await hashPassword(config.password),
    email,
  ]);
  await db.query('DELETE FROM sessions WHERE user_id=$1', [result.rows[0].document.id]);
}
