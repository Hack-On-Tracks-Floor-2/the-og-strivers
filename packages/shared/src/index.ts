import { z } from 'zod';

export const API_VERSION = 'v1' as const;
export const Id = z.string().uuid();
export const Timestamp = z.string().datetime();
export const RoleSchema = z.enum(['developer', 'reviewer']);
export const UserSchema = z.object({
  id: Id,
  name: z.string(),
  email: z.string().email(),
  role: RoleSchema,
  createdAt: Timestamp,
});
export const RegisterSchema = z
  .object({
    name: z.string().trim().min(2).max(80),
    email: z
      .string()
      .trim()
      .email()
      .max(254)
      .transform((v) => v.toLowerCase()),
    password: z.string().min(12).max(128),
  })
  .strict();
export const LoginSchema = z
  .object({
    email: z
      .string()
      .trim()
      .email()
      .max(254)
      .transform((v) => v.toLowerCase()),
    password: z.string().min(1).max(128),
    role: RoleSchema,
  })
  .strict();
export const GitHubUrlSchema = z
  .string()
  .trim()
  .max(300)
  .regex(
    /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/,
    'Use https://github.com/owner/repository without query parameters or subpaths.',
  )
  .refine((v) => {
    const repo = v
      .replace(/\/$/, '')
      .split('/')
      .pop()!
      .replace(/\.git$/, '');
    return repo !== '.' && repo !== '..' && repo.length <= 100;
  }, 'Invalid repository name.')
  .transform((v) => v.replace(/\/$/, '').replace(/\.git$/, ''));
export const RepositoryInputSchema = z.object({ url: GitHubUrlSchema }).strict();
export const RepositorySchema = z.object({
  id: Id,
  ownerId: Id,
  url: z.string().url(),
  name: z.string(),
  owner: z.string(),
  language: z.string().nullable(),
  framework: z.string().nullable(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export const RunStatusSchema = z.enum([
  'received',
  'queued',
  'mapping',
  'analyzing',
  'patching',
  'verifying',
  'needs_review',
  'verified',
  'failed',
  'not_configured',
]);
export const AnalysisInputSchema = z.object({ repositoryId: Id }).strict();
export const AnalysisRunSchema = z.object({
  id: Id,
  repositoryId: Id,
  ownerId: Id,
  status: RunStatusSchema,
  capability: z.enum(['not_configured', 'available']),
  error: z.string().nullable(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export const FindingSchema = z.object({
  id: Id,
  runId: Id,
  ownerId: Id,
  category: z.string(),
  severity: SeveritySchema,
  confidence: z.number().min(0).max(1),
  file: z.string(),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  rootCause: z.string(),
  evidence: z.array(z.string()),
  recommendation: z.string(),
  createdAt: Timestamp,
});
export const PatchSchema = z.object({
  id: Id,
  runId: Id,
  findingId: Id,
  ownerId: Id,
  status: z.enum(['proposed', 'applied', 'needs_review', 'approved', 'rejected']),
  files: z.array(z.object({ path: z.string(), original: z.string(), proposed: z.string() })),
  unifiedDiff: z.string(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export const VerificationRunSchema = z.object({
  id: Id,
  runId: Id,
  patchId: Id,
  ownerId: Id,
  stage: z.enum([
    'baseline',
    'reproduction',
    'patch_application',
    'security_retest',
    'regression',
    'final_decision',
  ]),
  status: z.enum(['pending', 'running', 'passed', 'failed', 'not_configured']),
  exitCode: z.number().int().nullable(),
  command: z.array(z.string()),
  logs: z.string(),
  artifactId: z.string().nullable(),
  createdAt: Timestamp,
  completedAt: Timestamp.nullable(),
});
export const RunEventSchema = z.object({
  id: Id,
  runId: Id,
  ownerId: Id,
  kind: z.enum([
    'job_received',
    'capability_unavailable',
    'stage_started',
    'stage_completed',
    'error',
    'review_decision',
  ]),
  message: z.string(),
  artifactId: z.string().nullable(),
  createdAt: Timestamp,
});
export const DecisionInputSchema = z
  .object({
    decision: z.enum(['approved', 'rejected']),
    reason: z.string().trim().min(10).max(4000),
  })
  .strict();
export const ReviewDecisionSchema = z.object({
  id: Id,
  runId: Id,
  patchId: Id,
  reviewerId: Id,
  decision: z.enum(['approved', 'rejected']),
  reason: z.string(),
  createdAt: Timestamp,
});
export const OverviewSchema = z.object({
  repositories: z.number(),
  runs: z.number(),
  findings: z.number(),
  verified: z.number(),
  patches: z.number(),
  awaitingReview: z.number(),
});
export const CapabilitySchema = z.object({
  code: z.literal('CAPABILITY_UNAVAILABLE'),
  state: z.enum(['not_configured', 'not_implemented']),
  message: z.string(),
});
export const ApiErrorSchema = z.object({
  error: z.object({ code: z.string(), message: z.string(), issues: z.unknown().optional() }),
  version: z.literal(API_VERSION),
});
export const envelope = <T extends z.ZodTypeAny>(schema: T) =>
  z.object({ data: schema, version: z.literal(API_VERSION) });
export type User = z.infer<typeof UserSchema>;
export type Role = z.infer<typeof RoleSchema>;
export type Repository = z.infer<typeof RepositorySchema>;
export type AnalysisRun = z.infer<typeof AnalysisRunSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type Patch = z.infer<typeof PatchSchema>;
export type VerificationRun = z.infer<typeof VerificationRunSchema>;
export type RunEvent = z.infer<typeof RunEventSchema>;
export type ReviewDecision = z.infer<typeof ReviewDecisionSchema>;
export type Overview = z.infer<typeof OverviewSchema>;
export type Unavailable = z.infer<typeof CapabilitySchema>;
