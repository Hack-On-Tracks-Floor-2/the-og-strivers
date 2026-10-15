import type { Request, RequestHandler } from 'express';
import type { Database } from '../database/index.js';
import { UserSchema, type User, type Role } from '@proofpatch/shared';
import { sessionDigest } from '../services/auth.js';
import { HttpError } from '../utils/errors.js';
export type AuthRequest = Request & { user?: User };
export const authenticate =
  (db: Database): RequestHandler =>
  async (req: AuthRequest, _res, next) => {
    const token = req.cookies?.pp_session;
    if (typeof token !== 'string' || token.length > 128)
      throw new HttpError(401, 'UNAUTHENTICATED', 'Log in to continue.');
    const rows = await db.query<{ document: User }>(
      'SELECT u.document FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',
      [sessionDigest(token)],
    );
    if (!rows.rows.length)
      throw new HttpError(401, 'UNAUTHENTICATED', 'Your session has expired. Log in again.');
    req.user = UserSchema.parse(rows.rows[0].document);
    next();
  };
export const requireRole =
  (role: Role): RequestHandler =>
  (req: AuthRequest, _res, next) => {
    if (req.user?.role !== role)
      throw new HttpError(403, 'FORBIDDEN', 'This action is not available for your role.');
    next();
  };
export function currentUser(req: Request): User {
  return (req as AuthRequest).user!;
}
