import { z } from 'zod';

export const ClassifyInputSchema = z
  .object({
    code: z.string().min(1).max(20000),
    language: z.string().trim().min(1).max(30).default('java'),
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
});
export const MLModelInfoSchema = z.object({
  availability: z.enum(['available', 'unavailable']),
  reason: z.string().optional(),
  modelVersion: z.string(),
  model: z.string(),
  language: z.literal('java'),
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
  }),
  rejectionThreshold: z.number(),
  limitations: z.array(z.string()),
});
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
