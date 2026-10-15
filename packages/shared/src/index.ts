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
/** What a developer sees about their submitted repository: a single status, never findings or patches. */
export const SubmissionStatusSchema = z.enum(['submitted', 'scanning', 'in_review', 'approved', 'merging', 'fix_branch_ready', 'rejected', 'scan_failed']);
export const SubmissionSchema = z.object({
  repositoryId: Id,
  url: z.string(),
  owner: z.string(),
  name: z.string(),
  status: SubmissionStatusSchema,
  /** The fix branch and pull request, once a reviewer has merged an approved fix. */
  branch: z.string().nullable().default(null),
  pullRequestUrl: z.string().nullable().default(null),
  submittedAt: Timestamp,
  updatedAt: Timestamp,
});
export type Submission = z.infer<typeof SubmissionSchema>;
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
  // CWE identifier (e.g. "CWE-89") and which stage of the search funnel produced it.
  cwe: z.string().nullable().default(null),
  source: z.enum(['scanner', 'ai', 'scanner+ai']).default('ai'),
  createdAt: Timestamp,
});
export const SecurityTestSchema = z.object({ path: z.string(), content: z.string() });
/**
 * Merging an approved fix onto the repository's latest code. A clean merge whose proofs pass is
 * published as a GitHub branch + pull request. An AI-resolved conflict stops at awaiting_review
 * until a reviewer confirms. If the proofs fail on the latest code, the fix goes back to patching.
 */
export const MergeCheckSchema = z.object({
  stage: z.enum(['apply', 'baseline', 'reproduction', 'security_retest', 'regression', 'publish']),
  passed: z.boolean(),
  summary: z.string(),
});
export const MergeSchema = z.object({
  status: z.enum(['merging', 'awaiting_review', 'merged', 'sent_back', 'already_fixed', 'failed']),
  baseBranch: z.string().nullable(),
  baseSha: z.string().nullable(),
  branch: z.string().nullable(),
  pullRequestUrl: z.string().nullable(),
  resolvedByAi: z.array(z.string()).default([]),
  mergedDiff: z.string().default(''),
  /** Full merged files, kept only while an AI-resolved merge awaits reviewer confirmation. */
  files: z.array(z.object({ path: z.string(), content: z.string() })).default([]),
  checks: z.array(MergeCheckSchema).default([]),
  message: z.string(),
  sentBackRunId: Id.nullable().default(null),
  updatedAt: Timestamp,
});
export type Merge = z.infer<typeof MergeSchema>;
export type MergeCheck = z.infer<typeof MergeCheckSchema>;
export const PatchSchema = z.object({
  id: Id,
  runId: Id,
  findingId: Id,
  ownerId: Id,
  status: z.enum(['proposed', 'applied', 'needs_review', 'approved', 'rejected']),
  files: z.array(z.object({ path: z.string(), original: z.string(), proposed: z.string() })),
  unifiedDiff: z.string(),
  // Generated exploit test: must fail on the original code and pass on the patch.
  securityTest: SecurityTestSchema.nullable().default(null),
  attempt: z.number().int().min(1).default(1),
  explanation: z.string().default(''),
  merge: MergeSchema.nullable().default(null),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export const TestCaseSchema = z.object({
  id: z.string(),
  outcome: z.enum(['passed', 'failed', 'error', 'skipped']),
});
export const TestSummarySchema = z.object({
  total: z.number().int().nonnegative(),
  passed: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  errors: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
  cases: z.array(TestCaseSchema),
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
  // Parsed per-test results (pytest JUnit XML) when the stage ran a test suite.
  tests: TestSummarySchema.nullable().default(null),
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
    'stage_failed',
    'ai_usage',
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
  state: z.enum(['not_configured', 'not_implemented', 'failed']),
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
export type TestSummary = z.infer<typeof TestSummarySchema>;
export type SecurityTest = z.infer<typeof SecurityTestSchema>;
export const ArtifactSchema = z.object({
  id: z.string(),
  runId: Id,
  kind: z.enum(['log', 'junit', 'diff', 'security_test', 'report']),
  sha256: z.string(),
  bytes: z.number().int().nonnegative(),
  createdAt: Timestamp,
});
export type Artifact = z.infer<typeof ArtifactSchema>;
export const HealthSchema = z.object({
  status: z.literal('ok'),
  database: z.literal('ready'),
  analysis: z.enum(['available', 'not_configured']),
  sandbox: z.enum(['docker', 'not_configured']).optional(),
  ai: z.array(z.string()).optional(),
  reason: z.string().optional(),
});
export * from './owasp.js';
