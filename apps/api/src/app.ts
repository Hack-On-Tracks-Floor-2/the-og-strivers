import express, { type ErrorRequestHandler } from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { ZodError } from 'zod';
import { API_VERSION } from '@proofpatch/shared';
import type { Database } from './database/index.js';
import { apiRouter } from './routes/index.js';
import { HttpError } from './utils/errors.js';
import type { Pipeline } from './pipeline/orchestrator.js';
export async function createApp(
  db: Database,
  options: { origin: string; production?: boolean; pipeline?: Pipeline },
) {
  // In development, 127.0.0.1 and localhost are the same machine: accept both spellings.
  const allowed = new Set([options.origin]);
  if (!options.production) {
    allowed.add(options.origin.replace('://127.0.0.1', '://localhost'));
    allowed.add(options.origin.replace('://localhost', '://127.0.0.1'));
  }
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(express.json({ limit: '32kb' }));
  app.use(cookieParser());
  app.use('/api', (req, _res, next) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !allowed.has(req.get('origin') ?? ''))
      throw new HttpError(403, 'ORIGIN_REJECTED', 'Request origin is not allowed.');
    next();
  });
  app.use('/api', await apiRouter(db, !!options.production, options.pipeline));
  app.use((_req, _res) => {
    throw new HttpError(404, 'NOT_FOUND', 'API endpoint not found.');
  });
  const errors: ErrorRequestHandler = (error, _req, res, _next) => {
    if (error instanceof ZodError) {
      res
        .status(400)
        .json({
          error: {
            code: 'VALIDATION_ERROR',
            message: error.issues[0]?.message ?? 'Invalid input.',
            issues: error.flatten(),
          },
          version: API_VERSION,
        });
      return;
    }
    if (error instanceof HttpError) {
      res
        .status(error.status)
        .json({ error: { code: error.code, message: error.message }, version: API_VERSION });
      return;
    }
    if (error.type === 'entity.parse.failed' || error.type === 'entity.too.large') {
      res
        .status(error.type === 'entity.too.large' ? 413 : 400)
        .json({
          error: { code: 'INVALID_BODY', message: 'Request body is invalid or too large.' },
          version: API_VERSION,
        });
      return;
    }
    console.error('Unhandled API error:', error instanceof Error ? error.message : 'Unknown error');
    res
      .status(500)
      .json({
        error: { code: 'INTERNAL_ERROR', message: 'Something went wrong. Please retry.' },
        version: API_VERSION,
      });
  };
  app.use(errors);
  return app;
}
