import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import type { AiClient, AiUsage, TokenBudget } from '../ai/client.js';
import type { DetectedIssue } from '../agents/detection.js';
import { importLines } from '../scanners/funnel.js';
import { jsImportLines } from '../scanners/javascript.js';
import { genericImportLines } from '../scanners/spans.js';
import { pythonToolchain, type Toolchain } from '../agents/toolchain.js';
import { applyEdits, changedLineCount, EditError, unifiedDiff, type Edit, type FileChange } from './edits.js';

export const PATCH_LIMITS = { maxFiles: 2, maxChangedLines: 40 } as const;

export interface GeneratedPatch {
  changes: FileChange[];
  unifiedDiff: string;
  securityTest: { path: string; content: string };
  explanation: string;
}
interface AiPatch {
  edits: Edit[];
  securityTest: { filename: string; content: string };
  explanation: string;
}
const SCHEMA = {
  type: 'object',
  properties: {
    edits: {
      type: 'array',
      items: {
        type: 'object',
        properties: { file: { type: 'string' }, search: { type: 'string' }, replace: { type: 'string' } },
        required: ['file', 'search', 'replace'],
      },
    },
    securityTest: {
      type: 'object',
      properties: { filename: { type: 'string' }, content: { type: 'string' } },
      required: ['filename', 'content'],
    },
    explanation: { type: 'string' },
  },
  required: ['edits', 'securityTest', 'explanation'],
};

export const SECURITY_TEST_DIR = 'tests/proofpatch_security';

function safeRead(root: string) {
  const base = resolve(root);
  return (path: string) => {
    const full = resolve(join(base, path));
    if (!full.startsWith(base + sep) || !existsSync(full)) return null;
    return readFileSync(full, 'utf8');
  };
}

/**
 * Funnel step 4/5: the patch prompt contains only the confirmed function, the file's imports,
 * a list of existing test files, and (on retry) the last lines of the failure.
 */
export async function generatePatch(input: {
  root: string;
  issue: DetectedIssue;
  testFiles: string[];
  ai: AiClient;
  budget: TokenBudget;
  signal: AbortSignal;
  previousFailure?: string;
  attempt?: number;
  /** How tests run in this repository (defaults to Python + pytest). */
  toolchain?: Toolchain;
  onUsage?: (usage: AiUsage, note: string) => void | Promise<void>;
}): Promise<GeneratedPatch> {
  const read = safeRead(input.root);
  const tc = input.toolchain ?? pythonToolchain();
  const imports = tc.runtime === 'python' ? importLines : tc.runtime === 'node' ? jsImportLines : genericImportLines;
  const { candidate } = input.issue;
  const fileText = read(candidate.file) ?? '';
  const data = [
    `FILE ${candidate.file} — imports:`,
    imports(fileText.split(/\r?\n/)) || '(none)',
    `\nFILE ${candidate.file} — vulnerable region (${input.issue.cwe}, ${candidate.category}):`,
    candidate.snippet,
    `\nExisting test files (for import style): ${input.testFiles.slice(0, 15).join(', ') || '(none)'}`,
    input.previousFailure ? `\nPREVIOUS ATTEMPT FAILED — fix this:\n${input.previousFailure.slice(-1500)}` : '',
  ].join('\n');
  const { value, usage } = await input.ai.completeJSON<AiPatch>(
    {
      task: 'patch',
      instructions:
        `Fix this vulnerability: ${input.issue.rootCause}\n` +
        'Rules: (1) Return the SMALLEST possible fix as exact search/replace edits. "search" must be copied verbatim from the ' +
        'region shown (WITHOUT the line-number prefix "NNNN| "), must be unique in the file, and should include 1–3 lines. ' +
        `(2) Change at most ${PATCH_LIMITS.maxFiles} files and ${PATCH_LIMITS.maxChangedLines} lines; preserve behaviour for valid input; ` +
        `never edit existing tests. (3) Write ONE security test file ("securityTest") for ${tc.label} with 1–3 tests that ATTACK the bug: ` +
        `they must FAIL on the vulnerable code and PASS after your fix. ${tc.testGuidance} It will be saved as ` +
        `${tc.securityTestPath(candidate.file, '<filename>')}. No network, no sleeps, no external services. Make the attack WORK against the vulnerable line exactly as ` +
        'written: account for any text that follows the injection point (e.g. end shell payloads with " #" so the rest of the ' +
        'command is ignored, close quotes in SQL, use absolute tmp_path paths). The test must PASS on a correct fix: a safe implementation may ' +
        'reject malicious input by raising an exception, so assert only that the attack had no effect (e.g. no file created, ' +
        'no data leaked), catching expected exceptions. Keep explanation under 80 words.' +
        (input.attempt && input.attempt > 1 ? ` This is attempt ${input.attempt}; do not repeat a previous answer.` : ''),
      data,
      schema: SCHEMA,
      maxOutputTokens: 2_500,
    },
    input.budget,
    input.signal,
  );
  await input.onUsage?.(usage, `Patch proposal for ${candidate.file}:${candidate.line}`);
  const edits = (value.edits ?? []).filter((e) => !/(^|\/)(tests?|testing)\//.test(e.file));
  if (!edits.length) throw new EditError('The AI proposed no source edits.');
  const changes = applyEdits(edits, read);
  if (!changes.length) throw new EditError('The proposed edits do not change any code.');
  if (changes.length > PATCH_LIMITS.maxFiles)
    throw new EditError(`Patch touches ${changes.length} files; the limit is ${PATCH_LIMITS.maxFiles}.`);
  const diff = changes.map((c) => unifiedDiff(c.path, c.original, c.proposed)).join('\n');
  const changed = changedLineCount(diff);
  if (changed > PATCH_LIMITS.maxChangedLines)
    throw new EditError(`Patch changes ${changed} lines; the minimal-diff limit is ${PATCH_LIMITS.maxChangedLines}.`);
  const name = (value.securityTest?.filename ?? '').split(/[\\/]/).pop()!.replace(/[^A-Za-z0-9_.]/g, '_');
  const filename = tc.securityTestName.test(name) ? name : tc.defaultSecurityTestName;
  const content = value.securityTest?.content ?? '';
  const hasTest = {
    python: /def test_/,
    node: /\b(test|it)\s*\(/,
    go: /func\s+TestProofPatch\w*\s*\(\s*\w+\s+\*testing\.T\s*\)/,
    php: /function\s+test\w*\s*\(/,
  }[tc.runtime];
  if (!hasTest.test(content))
    throw new EditError(`The security test contains no ${tc.framework} test.`);
  return {
    changes,
    unifiedDiff: diff,
    securityTest: { path: tc.securityTestPath(candidate.file, filename), content },
    explanation: String(value.explanation ?? '').slice(0, 1500),
  };
}
