import { describe, expect, it, vi } from 'vitest';
import type { MLPrediction } from '@proofpatch/shared';
import type { classifySource } from '../apps/api/src/services/mini-ml.js';
import { enrichScannerFinding } from '../apps/api/src/services/ml-enrichment.js';

// Test-only interface fixtures; these are never used for training or evaluation metrics.
const code = 'def example(value):\n    return value\n';
const finding = { file: 'src/example.py', startLine: 2, cwe: 'CWE-79', severity: 'high', confidence: 0.9 };
const prediction = (overrides: Partial<MLPrediction> = {}): MLPrediction => ({
  status: 'predicted',
  predicted_category: 'CWE-79',
  cwe: 'CWE-79',
  probability: 0.75,
  language: 'python',
  supported_cwes: ['CWE-79'],
  scope: 'Test-only predictor contract',
  modelVersion: 'test-only-model',
  ...overrides,
});

describe('optional scanner finding ML adapter', () => {
  it('preserves the exact original finding without changing scanner evidence', async () => {
    const original = Object.freeze({ ...finding });
    const predict = vi.fn<typeof classifySource>(async () => prediction());
    const result = await enrichScannerFinding(original, code, { predict });
    expect(result.finding).toBe(original);
    expect(result.finding).toEqual(finding);
    expect(result.ml.comparison).toBe('agrees');
    expect(result.ml.prediction?.modelVersion).toBe('test-only-model');
    expect(predict).toHaveBeenCalledWith({ code, language: 'python', filePath: finding.file });
  });

  it('makes disagreements visible and normalizes CWE formatting for comparison only', async () => {
    const original = { ...finding, cwe: 'cwe-079' };
    const agreed = await enrichScannerFinding(original, code, {
      predict: async () => prediction(),
    });
    expect(agreed.ml.scannerCwe).toBe('CWE-79');
    expect(agreed.ml.comparison).toBe('agrees');
    expect(agreed.finding.cwe).toBe('cwe-079');
    const disagreed = await enrichScannerFinding(original, code, {
      predict: async () => prediction({ cwe: 'CWE-89', predicted_category: 'CWE-89' }),
    });
    expect(disagreed.ml.comparison).toBe('disagrees');
    expect(disagreed.finding).toBe(original);
  });

  it('treats a benchmark-negative prediction as disagreement, never as scanner clearance', async () => {
    const result = await enrichScannerFinding(finding, code, {
      predict: async () => prediction({ predicted_category: 'BENCHMARK_NEGATIVE', cwe: null }),
    });
    expect(result.ml.comparison).toBe('disagrees');
    expect(result.finding.cwe).toBe('CWE-79');
    expect(result.finding.severity).toBe('high');
  });

  it.each(['unknown', 'unsupported'] as const)('preserves a %s result without comparing CWEs', async (status) => {
    const result = await enrichScannerFinding(finding, code, {
      predict: async () => prediction({ status, cwe: null, predicted_category: null, probability: null }),
    });
    expect(result.ml.status).toBe(status);
    expect(result.ml.comparison).toBe('not_comparable');
  });

  it.each([
    ['src/file.java', 'java'],
    ['src/file.jsx', 'javascript'],
    ['src/file.js', 'javascript'],
    ['src/file.ts', 'typescript'],
    ['src/file.tsx', 'typescript'],
    ['src/file.PY', 'python'],
  ])('infers %s only as metadata and never opens it', async (file, language) => {
    const predict = vi.fn<typeof classifySource>(async () => prediction({ language }));
    await enrichScannerFinding({ ...finding, file }, code, { predict });
    expect(predict.mock.calls[0]?.[0]).toMatchObject({ language, filePath: file, code });
  });

  it('uses explicit language over an extension and never reads the source path', async () => {
    const predict = vi.fn<typeof classifySource>(async () => prediction());
    const file = 'C:\\nonexistent-qa-location\\source.java';
    await enrichScannerFinding({ ...finding, file, language: ' PY ' }, code, { predict });
    expect(predict.mock.calls[0]?.[0]).toMatchObject({ code, language: 'python', filePath: file });
  });

  it('does not guess an unsupported explicit language from a supported extension', async () => {
    const predict = vi.fn<typeof classifySource>(async () => prediction());
    const result = await enrichScannerFinding({ ...finding, language: 'ruby' }, code, { predict });
    expect(result.ml.status).toBe('unsupported');
    expect(predict).not.toHaveBeenCalled();
  });

  it.each(['constructor', '__proto__', 'toString'])(
    'rejects prototype property %s as either a language or an extension',
    async (property) => {
      const predict = vi.fn<typeof classifySource>(async () => prediction());
      const explicit = await enrichScannerFinding({ ...finding, language: property }, code, {
        predict,
      });
      const extension = await enrichScannerFinding(
        { ...finding, file: `src/example.${property}` },
        code,
        { predict },
      );
      expect(explicit.ml.status).toBe('unsupported');
      expect(extension.ml.status).toBe('unsupported');
      expect(predict).not.toHaveBeenCalled();
    },
  );

  it.each([
    { startLine: 0 },
    { startLine: -1 },
    { startLine: 1.5 },
    { startLine: Number.NaN },
    { startLine: 2, endLine: 1 },
    { startLine: 4 },
    { startLine: 1, endLine: 4 },
  ])('rejects invalid or out-of-range coordinates: %j', async (coordinates) => {
    const predict = vi.fn<typeof classifySource>(async () => prediction());
    const result = await enrichScannerFinding({ ...finding, ...coordinates }, code, { predict });
    expect(result.ml.status).toBe('invalid_input');
    expect(predict).not.toHaveBeenCalled();
  });

  it('bounds context by both characters and lines while retaining the finding lines', async () => {
    const lines = Array.from({ length: 200 }, (_, index) => `${index + 1}: ${'x'.repeat(1000)}`);
    const predict = vi.fn<typeof classifySource>(async () => prediction());
    const result = await enrichScannerFinding(
      { ...finding, startLine: 100, endLine: 102 },
      lines.join('\n'),
      { predict },
    );
    const input = predict.mock.calls[0]?.[0];
    expect(input?.code.length).toBeLessThanOrEqual(20_000);
    expect(input?.code.split('\n').length).toBeLessThanOrEqual(80);
    expect(input?.code).toContain(lines[99]);
    expect(input?.code).toContain(lines[101]);
    expect(result.ml.sourceRange?.startLine).toBeLessThanOrEqual(100);
    expect(result.ml.sourceRange?.endLine).toBeGreaterThanOrEqual(102);
  });

  it('does not silently truncate a finding that itself exceeds the context limit', async () => {
    const predict = vi.fn<typeof classifySource>(async () => prediction());
    const oversized = await enrichScannerFinding(
      { ...finding, startLine: 1 },
      'x'.repeat(20_001),
      { predict },
    );
    const tooManyLines = await enrichScannerFinding(
      { ...finding, startLine: 1, endLine: 81 },
      Array(81).fill('x').join('\n'),
      { predict },
    );
    expect(oversized.ml.status).toBe('unknown');
    expect(tooManyLines.ml.status).toBe('unknown');
    expect(predict).not.toHaveBeenCalled();
  });

  it('catches runtime, model and timeout failures without leaking their details', async () => {
    const result = await enrichScannerFinding(finding, code, {
      predict: async () => { throw new Error('ML_TIMEOUT: internal private runtime details'); },
    });
    expect(result.finding).toBe(finding);
    expect(result.ml.status).toBe('unavailable');
    expect(result.ml.comparison).toBe('not_comparable');
    expect(result.ml.reason).not.toContain('private runtime');
  });

  it('does not compare a prediction when the scanner has no usable CWE', async () => {
    const result = await enrichScannerFinding({ ...finding, cwe: null }, code, {
      predict: async () => prediction(),
    });
    expect(result.ml.scannerCwe).toBeNull();
    expect(result.ml.comparison).toBe('not_comparable');
  });

  it('treats a malformed runtime CWE as incomparable while preserving the original finding', async () => {
    const original = { ...finding, cwe: { id: 'CWE-79' } as unknown as string };
    const result = await enrichScannerFinding(original, code, {
      predict: async () => prediction(),
    });
    expect(result.finding).toBe(original);
    expect(result.ml.scannerCwe).toBeNull();
    expect(result.ml.comparison).toBe('not_comparable');
  });
});
