import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAiClient, TokenBudget, type AiUsage } from '../ai/client.js';
import { applyEdits, changedLineCount, unifiedDiff, type Edit } from '../patching/edits.js';
import { parseJUnit, compareSuites } from './junit.js';
import type { TestSummary } from '@proofpatch/shared';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
// Also resolve correctly in the API's existing dist/apps/api/src output layout.
const projectRoot = existsSync(join(sourceRoot, 'package.json')) ? sourceRoot : resolve(sourceRoot, '../../..');
interface ExecutionEvidence {
  stage: string; executable: string; argv: string[]; cwd: string; startedAt: string; durationMs: number;
  exitCode: number | null; signal: NodeJS.Signals | null; error: string | null;
  stdout: string; stderr: string; summary: TestSummary;
}
export const defaultRegressionEvidence = () => resolve(process.env.REGRESSION_EVIDENCE_DIR || join(projectRoot, 'evidence/regression-demo'));
const sourceFile = 'src/reports.cjs';
const functionalFile = 'test/functional.test.cjs';
const securityFile = 'test/security.test.cjs';
const vulnerable = "  return readFileSync(join(root, name), 'utf8');";
const safe = [
  "  const { realpathSync } = require('node:fs');",
  "  const { relative, isAbsolute, sep } = require('node:path');",
  '  const base = realpathSync(root);',
  '  const target = realpathSync(join(base, name));',
  '  const within = relative(base, target);',
  "  if (within === '..' || within.startsWith('..' + sep) || isAbsolute(within)) {",
  "    throw Object.assign(new Error('Report path escapes its root'), { code: 'EACCES' });",
  '  }',
  "  return readFileSync(target, 'utf8');",
].join('\n');
const hash = (text: string) => createHash('sha256').update(text).digest('hex');

/** Only executes the authored fixture below. Never accepts a repository, command, or test from a caller. */
export async function runRegressionDemo(options: { outputDir?: string; env?: NodeJS.ProcessEnv } = {}) {
  const outputDir = resolve(options.outputDir || defaultRegressionEvidence());
  await mkdir(outputDir, { recursive: true });
  const runId = randomUUID();
  const runDir = join(outputDir, runId);
  const before = join(runDir, 'vulnerable');
  const after = join(runDir, 'patched');
  await mkdir(runDir);
  await cp(join(projectRoot, 'tests/regression/fixtures/report-reader'), before, { recursive: true });
  const original = await readFile(join(before, sourceFile), 'utf8');
  const functional = await readFile(join(before, functionalFile), 'utf8');
  const security = await readFile(join(projectRoot, 'tests/regression/security.test.cjs'), 'utf8');
  const stages: ExecutionEvidence[] = [];

  async function execute(stage: string, cwd: string, testFile: string): Promise<ExecutionEvidence> {
    const xmlPath = join(runDir, `${stage}.junit.xml`);
    const argv = ['--test', '--test-reporter=tap', '--test-reporter=junit', '--test-reporter-destination=stdout', `--test-reporter-destination=${xmlPath}`, testFile];
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const result = spawnSync(process.execPath, argv, { cwd, encoding: 'utf8', shell: false, timeout: 30_000, maxBuffer: 1024 * 1024 });
    const xml = await readFile(xmlPath, 'utf8').catch(() => '');
    const record = {
      stage, executable: process.execPath, argv, cwd, startedAt, durationMs: Date.now() - start,
      exitCode: result.status, signal: result.signal, error: result.error?.message ?? null,
      stdout: result.stdout || '', stderr: result.stderr || '', summary: parseJUnit(xml),
    };
    await writeFile(join(runDir, `${stage}.json`), JSON.stringify(record, null, 2) + '\n');
    await writeFile(join(runDir, `${stage}.txt`), `${JSON.stringify([record.executable, ...argv])}\nCWD: ${cwd}\nExit: ${record.exitCode}\n${record.stdout}\nSTDERR:\n${record.stderr}`);
    stages.push(record);
    return record;
  }

  const baseline = await execute('baseline', before, functionalFile);
  // Security test is introduced only after the unchanged functional baseline ran.
  await writeFile(join(before, securityFile), security);
  const reproduction = await execute('security-before', before, securityFile);

  const env = options.env ?? process.env;
  const ai = createAiClient({ ...env, AI_PROVIDER_ORDER: 'groq', AI_TIMEOUT_MS: '12000', AI_RETRY_DELAY_MS: '0' });
  let edits: Edit[] = [{ file: sourceFile, search: vulnerable, replace: safe }];
  let patchSource = 'deterministic';
  let aiReason = 'GROQ_API_KEY is not configured; used the explicitly labeled deterministic patch.';
  let aiUsage: AiUsage | null = null;
  if (ai) {
    try {
      const proposal = await ai.completeJSON<{ edits: Edit[] }>({
        task: 'patch',
        instructions: 'Fix CWE-22 in this controlled Node.js CommonJS fixture with minimal exact search/replace edits. Edit only src/reports.cjs. Preserve valid reads and ENOENT for missing files. Resolve real paths, reject parent traversal, sibling-prefix escapes and symlink escapes with error.code EACCES. Never change tests. Return {"edits":[{"file":"src/reports.cjs","search":"exact source","replace":"replacement"}]}.',
        data: original,
        schema: { type: 'object', properties: { edits: { type: 'array', items: { type: 'object', properties: { file: { type: 'string' }, search: { type: 'string' }, replace: { type: 'string' } }, required: ['file', 'search', 'replace'] } } }, required: ['edits'] },
        maxOutputTokens: 1800,
      }, new TokenBudget(8000), new AbortController().signal);
      if (!Array.isArray(proposal.value.edits) || !proposal.value.edits.length || proposal.value.edits.some(e => e.file !== sourceFile)) throw new Error('Proposal must edit only the fixture source.');
      const proposed = applyEdits(proposal.value.edits, p => p === sourceFile ? original : null);
      if (proposed.length !== 1 || changedLineCount(unifiedDiff(sourceFile, original, proposed[0].proposed)) > 40) throw new Error('Proposal is empty or exceeds the minimal patch limit.');
      edits = proposal.value.edits;
      patchSource = 'groq';
      aiReason = 'Patch generated by the existing Groq client; test outcomes below determine acceptance.';
      aiUsage = proposal.usage;
    } catch (error) {
      aiReason = `Groq unavailable or invalid proposal: ${error instanceof Error ? error.message : 'unknown error'}. Used deterministic patch.`;
    }
  }
  // Fresh copy of the trusted source fixture; source and original tests are not edited in place.
  await cp(join(projectRoot, 'tests/regression/fixtures/report-reader'), after, { recursive: true });
  await writeFile(join(after, securityFile), security);
  const [change] = applyEdits(edits, p => p === sourceFile ? original : null);
  if (!change) throw new Error('Patch did not change source.');
  const diff = unifiedDiff(change.path, change.original, change.proposed) + '\n';
  await writeFile(join(runDir, 'patch.diff'), diff);
  await writeFile(join(runDir, 'patch-provenance.json'), JSON.stringify({ patchSource, aiReason, aiUsage, edits }, null, 2) + '\n');
  await writeFile(join(after, change.path), change.proposed);
  const securityAfter = await execute('security-after', after, securityFile);
  const regression = await execute('regression', after, functionalFile);
  const comparison = compareSuites(baseline.summary, regression.summary);
  const integrity = {
    fixtureSourceUnchanged: hash(await readFile(join(before, sourceFile), 'utf8')) === hash(original),
    functionalTestsUnchanged: [await readFile(join(before, functionalFile), 'utf8'), await readFile(join(after, functionalFile), 'utf8')].every(t => hash(t) === hash(functional)),
    securityTestsIdentical: hash(await readFile(join(after, securityFile), 'utf8')) === hash(await readFile(join(before, securityFile), 'utf8')),
    functionalTestSha256: hash(functional), securityTestSha256: hash(security),
  };
  const passed = (s: typeof baseline, count: number) => s.exitCode === 0 && !s.error && s.summary.total === count && s.summary.passed === count;
  const reproduced = reproduction.exitCode === 1 && !reproduction.error && reproduction.summary.total === 3 && reproduction.summary.failed === 3 && reproduction.stdout.includes('ERR_ASSERTION');
  const verdict = passed(baseline, 5) && reproduced && passed(securityAfter, 3) && passed(regression, 5) && comparison.ok && integrity.fixtureSourceUnchanged && integrity.functionalTestsUnchanged && integrity.securityTestsIdentical ? 'VERIFIED' : 'FAILED';
  const report = {
    runId, createdAt: new Date().toISOString(), verdict, scenario: 'CWE-22 path traversal', patchSource, aiReason, aiUsage,
    execution: 'Real Node.js subprocesses on an authored, trusted local fixture; this is not a Docker sandbox for downloaded repositories.',
    nodeVersion: process.version, runDir, unifiedDiff: diff, integrity, comparison,
    stages,
  };
  await writeFile(join(runDir, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  await writeFile(join(outputDir, 'latest.json'), JSON.stringify(report, null, 2) + '\n');
  return report;
}
