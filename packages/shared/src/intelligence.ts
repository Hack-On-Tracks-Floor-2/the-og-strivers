import { z } from 'zod';

export const ClassifyInputSchema = z
  .object({
    code: z.string().min(1).max(20000),
    language: z.string().trim().min(1).max(30).default('java'),
    filePath: z.string().trim().min(1).max(500).refine((value) => !value.includes('\0'), 'Invalid source path.').optional(),
  })
  .strict();
export const MLExampleSchema = z.object({
  code: z.string(),
  exampleId: z.string(),
  expectedLabel: z.string(),
  source: z.string(),
});
export const MLPredictionSchema = z.object({
  status: z.enum(['predicted', 'unknown', 'unsupported']),
  predicted_category: z.string().nullable(),
  cwe: z.string().nullable(),
  probability: z.number().min(0).max(1).nullable(),
  language: z.string(),
  supported_cwes: z.array(z.string()),
  scope: z.string(),
  reason: z.string().optional(),
  note: z.string().optional(),
  modelVersion: z.string(),
  filePath: z.string().optional(),
  probabilityKind: z.literal('uncalibrated').optional(),
  confirmed: z.literal(false).optional(),
});
export const MLModelInfoSchema = z.object({
  availability: z.enum(['available', 'unavailable']),
  reason: z.string().optional(),
  modelVersion: z.string(),
  model: z.string(),
  language: z.enum(['java', 'python', 'javascript', 'typescript']),
  supportedCwes: z.array(z.string()),
  trainedAt: z.string(),
  dataset: z.object({
    repository: z.string(),
    version: z.string(),
    commit: z.string(),
    license: z.string(),
  }),
  training: z.object({
    trainSamples: z.number().int(),
    testSamples: z.number().int(),
    sharedGroups: z.number().int(),
  }),
  metrics: z.object({
    precisionMacro: z.number(),
    recallMacro: z.number(),
    f1Macro: z.number(),
    negativeRecall: z.number(),
    negativeFalsePositiveRate: z.number().optional(),
  }),
  rejectionThreshold: z.number(),
  limitations: z.array(z.string()),
  activation: z.object({ enabled: z.boolean(), reason: z.string() }).optional(),
});
export const MLModelCatalogSchema = z.object({
  models: z.array(z.object({
    language: z.enum(['java', 'python', 'javascript', 'typescript']),
    status: z.enum(['available', 'unavailable', 'unsupported', 'disabled']),
    reason: z.string().optional(),
    info: MLModelInfoSchema.optional(),
  })),
});
export type MLModelCatalog = z.infer<typeof MLModelCatalogSchema>;
/** A sidecar for one normalized finding. ML never changes the original scanner record. */
export const FindingMLSchema = z.object({
  findingId: z.string().uuid(),
  runId: z.string().uuid(),
  repositoryId: z.string().uuid(),
  ownerId: z.string().uuid(),
  repositoryUrl: z.string().url(),
  commitSha: z.string().regex(/^[0-9a-f]{40,64}$/i),
  file: z.string().min(1).max(500),
  language: z.string(),
  findingRange: z.object({ startLine: z.number().int().positive(), endLine: z.number().int().positive() }),
  sourceSha256: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  snippet: z.object({
    startLine: z.number().int().positive(),
    endLine: z.number().int().positive(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    characters: z.number().int().max(20000),
    transformation: z.enum(['verbatim', 'dedent']),
  }).optional(),
  status: z.enum(['predicted', 'unknown', 'unsupported', 'invalid_input', 'unavailable']),
  scannerCwe: z.string().nullable(),
  comparison: z.enum(['agrees', 'disagrees', 'not_comparable']),
  prediction: MLPredictionSchema.optional(),
  reason: z.string().optional(),
  createdAt: z.string().datetime(),
});
export type FindingML = z.infer<typeof FindingMLSchema>;
const SuiteSummary = z.object({
  total: z.number(),
  passed: z.number(),
  failed: z.number(),
  errors: z.number(),
  skipped: z.number(),
});
export const RegressionEvidenceSchema = z.object({
  runId: z.string().uuid(),
  createdAt: z.string(),
  verdict: z.enum(['VERIFIED', 'FAILED']),
  scenario: z.string(),
  patchSource: z.string(),
  aiReason: z.string(),
  execution: z.string(),
  unifiedDiff: z.string(),
  integrity: z.object({
    fixtureSourceUnchanged: z.boolean(),
    functionalTestsUnchanged: z.boolean(),
    securityTestsIdentical: z.boolean(),
  }),
  comparison: z.object({
    ok: z.boolean(),
    broken: z.array(z.unknown()),
    fixed: z.array(z.unknown()),
  }),
  stages: z.array(
    z.object({
      stage: z.string(),
      argv: z.array(z.string()),
      startedAt: z.string(),
      durationMs: z.number(),
      exitCode: z.number().nullable(),
      error: z.string().nullable(),
      stdout: z.string(),
      stderr: z.string(),
      summary: SuiteSummary,
    }),
  ),
  sourceFiles: z
    .array(z.object({ path: z.string(), original: z.string(), proposed: z.string() }))
    .optional(),
});
export type MLPrediction = z.infer<typeof MLPredictionSchema>;
export type MLModelInfo = z.infer<typeof MLModelInfoSchema>;
export type RegressionEvidence = z.infer<typeof RegressionEvidenceSchema>;
