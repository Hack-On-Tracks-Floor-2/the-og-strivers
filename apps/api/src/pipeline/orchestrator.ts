import { createHash, randomUUID } from 'node:crypto';
import { cp, mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
  FindingSchema,
  PatchSchema,
  VerificationRunSchema,
  type AnalysisRun,
  type Finding,
  type Patch,
  type Repository,
  type TestSummary,
  type VerificationRun,
} from '@proofpatch/shared';
import type { Database } from '../database/index.js';
import type { RepositoryIngestionService } from '../repositories/ingestion.js';
import type { WorkspaceStore } from '../repositories/clone.js';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
import { inspectRepository, listSourceFiles } from '../agents/intelligence.js';
import { detectVulnerabilities, type DetectedIssue } from '../agents/detection.js';
import { generatePatch, type GeneratedPatch } from '../patching/generator.js';
import { EditError } from '../patching/edits.js';
import { AiError, TokenBudget, type AiClient, type AiUsage } from '../ai/client.js';
import { evidenceService } from '../services/evidence.js';
import { compareSuites, parseJUnit } from '../verification/junit.js';
import type { ExecutionRequest } from '../verification/sandbox.js';
import type { SandboxRun } from '../verification/docker.js';
import type { ExternalHit } from '../scanners/funnel.js';

export interface PipelineSandbox {
  ready(): Promise<string | null>;
  prepare(workspace: WorkspaceHandle, signal: AbortSignal): Promise<{ exitCode: number; stdout: string; stderr: string; timedOut: boolean }>;
  executeWith(request: ExecutionRequest, depsId: string, signal: AbortSignal): Promise<CapabilityResult<SandboxRun>>;
  cleanup(workspaceId: string): Promise<void>;
}
export interface PipelineOptions {
  db: Database;
  ingestion: RepositoryIngestionService;
  store: WorkspaceStore;
  sandbox: PipelineSandbox;
  ai: AiClient | null;
  tokenBudget?: number;
  maxAttempts?: number;
  testTimeoutMs?: number;
}
export interface Pipeline {
  status(): Promise<{ available: boolean; reason: string | null; ai: string[] }>;
  start(run: AnalysisRun): void;
  cancel(runId: string): boolean;
  idle(): Promise<void>;
  shutdown(): Promise<void>;
}

const tail = (text: string, n = 20_000) => (text.length > n ? `…(truncated)\n${text.slice(-n)}` : text);
/** The useful part of a pytest failure: error lines ("E …"), failing test lines and the summary. */
export function pytestEssence(logs: string, max = 1_400) {
  const lines = logs.split(/\r?\n/);
  const keep = lines.filter((l) => /^(E\s|FAILED\s|ERROR\s|>\s)/.test(l) || /Error:|Exception:|assert /.test(l));
  const text = (keep.length ? keep : lines.slice(-25)).join('\n');
  return text.length > max ? text.slice(-max) : text;
}
const summarize = (t: TestSummary) =>
  `${t.passed} passed, ${t.failed} failed, ${t.errors} errors, ${t.skipped} skipped (${t.total} tests)`;

class StageFailure extends Error {}

export function createPipeline(options: PipelineOptions): Pipeline {
  const { db, store, sandbox } = options;
  const evidence = evidenceService(db);
  const maxAttempts = options.maxAttempts ?? 3;
  const testTimeoutMs = options.testTimeoutMs ?? 300_000;
  const controllers = new Map<string, AbortController>();
  let chain: Promise<void> = Promise.resolve();

  async function setRun(run: AnalysisRun, patch: Partial<AnalysisRun>) {
    Object.assign(run, patch, { updatedAt: new Date().toISOString() });
    await db.query('UPDATE runs SET document=$1 WHERE id=$2', [run, run.id]);
  }
  const event = (run: AnalysisRun, kind: Parameters<typeof evidence.recordEvent>[0]['kind'], message: string, artifactId: string | null = null) =>
    evidence.recordEvent({ runId: run.id, ownerId: run.ownerId, kind, message, artifactId });

  async function artifact(run: AnalysisRun, kind: 'log' | 'junit' | 'diff' | 'security_test' | 'report', content: string) {
    const sha256 = createHash('sha256').update(content).digest('hex');
    const id = createHash('sha256').update(`${run.id}:${kind}:${sha256}`).digest('hex').slice(0, 40);
    const doc = { id, runId: run.id, kind, sha256, bytes: Buffer.byteLength(content), createdAt: new Date().toISOString() };
    await db.query(
      'INSERT INTO artifacts(id,run_id,owner_id,document,content) VALUES($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING',
      [id, run.id, run.ownerId, doc, content],
    );
    return id;
  }

  async function copyWorkspace(from: WorkspaceHandle, files: Record<string, string>): Promise<WorkspaceHandle> {
    const id = randomUUID();
    await cp(store.path(from.id), store.path(id), { recursive: true });
    for (const [path, content] of Object.entries(files)) {
      const full = join(store.path(id), path);
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, content);
    }
    return { ...from, id };
  }

  async function execute(workspace: WorkspaceHandle, depsId: string, argv: string[], signal: AbortSignal) {
    const result = await sandbox.executeWith(
      {
        workspace,
        argv,
        timeoutMs: testTimeoutMs,
        memoryMb: 1024,
        cpuLimit: 1,
        network: 'none',
        readOnlyRoot: true,
        maxOutputBytes: 200_000,
      },
      depsId,
      signal,
    );
    if (result.state !== 'completed') throw new StageFailure(result.message);
    return result.data;
  }

  async function runSuite(workspace: WorkspaceHandle, depsId: string, argv: string[], signal: AbortSignal) {
    const out = await execute(workspace, depsId, [...argv, '--junitxml=/out/junit.xml'], signal);
    const tests = out.files['junit.xml'] ? parseJUnit(out.files['junit.xml']) : null;
    return { out, tests, logs: tail(`${out.stdout}\n${out.stderr}`) };
  }

  async function record(run: AnalysisRun, patchId: string, stage: VerificationRun['stage'], passed: boolean, data: {
    exitCode: number | null;
    command: string[];
    logs: string;
    tests?: TestSummary | null;
    junit?: string;
  }) {
    const now = new Date().toISOString();
    const artifactId = await artifact(run, 'log', data.logs || '(no output)');
    if (data.junit) await artifact(run, 'junit', data.junit);
    const doc = VerificationRunSchema.parse({
      id: randomUUID(),
      runId: run.id,
      patchId,
      ownerId: run.ownerId,
      stage,
      status: passed ? 'passed' : 'failed',
      exitCode: data.exitCode,
      command: data.command,
      logs: data.logs || '(no output)',
      artifactId,
      tests: data.tests ?? null,
      createdAt: now,
      completedAt: now,
    });
    await db.query('INSERT INTO verifications(id,run_id,patch_id,owner_id,document) VALUES($1,$2,$3,$4,$5)', [
      doc.id, run.id, patchId, run.ownerId, doc,
    ]);
    return doc;
  }

  async function saveFinding(run: AnalysisRun, issue: DetectedIssue) {
    const finding: Finding = FindingSchema.parse({
      id: randomUUID(),
      runId: run.id,
      ownerId: run.ownerId,
      category: issue.candidate.category,
      severity: issue.severity,
      confidence: issue.confidence,
      file: issue.candidate.file,
      startLine: issue.candidate.startLine,
      endLine: issue.candidate.endLine,
      rootCause: issue.rootCause,
      evidence: [`Scanner rule ${issue.candidate.rule} at line ${issue.candidate.line}`, ...issue.evidence],
      recommendation: issue.recommendation,
      cwe: issue.cwe,
      source: issue.source,
      createdAt: new Date().toISOString(),
    });
    await db.query('INSERT INTO findings(id,run_id,owner_id,document) VALUES($1,$2,$3,$4)', [finding.id, run.id, run.ownerId, finding]);
    return finding;
  }

  async function savePatch(run: AnalysisRun, finding: Finding, generated: GeneratedPatch, attempt: number) {
    const now = new Date().toISOString();
    const patch: Patch = PatchSchema.parse({
      id: randomUUID(),
      runId: run.id,
      findingId: finding.id,
      ownerId: run.ownerId,
      status: 'proposed',
      files: generated.changes.map(({ path, original, proposed }) => ({ path, original, proposed })),
      unifiedDiff: generated.unifiedDiff,
      securityTest: generated.securityTest,
      attempt,
      explanation: generated.explanation,
      createdAt: now,
      updatedAt: now,
    });
    await db.query('INSERT INTO patches(id,run_id,finding_id,owner_id,document) VALUES($1,$2,$3,$4,$5)', [
      patch.id, run.id, finding.id, run.ownerId, patch,
    ]);
    await artifact(run, 'diff', patch.unifiedDiff);
    await artifact(run, 'security_test', generated.securityTest.content);
    return patch;
  }
  async function setPatchStatus(patch: Patch, status: Patch['status']) {
    Object.assign(patch, { status, updatedAt: new Date().toISOString() });
    await db.query('UPDATE patches SET document=$1 WHERE id=$2', [patch, patch.id]);
  }

  async function process(run: AnalysisRun, signal: AbortSignal) {
    const repoRow = await db.query<{ document: Repository }>('SELECT document FROM repositories WHERE id=$1', [run.repositoryId]);
    const repository = repoRow.rows[0]?.document;
    if (!repository) throw new StageFailure('Repository record not found.');
    if (!options.ai) throw new StageFailure('No AI provider is configured (set GEMINI_API_KEY and/or GROQ_API_KEY).');
    const ai = options.ai;
    const budget = new TokenBudget(options.tokenBudget ?? 30_000);
    const onUsage = async (usage: AiUsage, note: string) => {
      await event(
        run,
        'ai_usage',
        `${note}: ${usage.provider} ${usage.model}, ${usage.inputTokens} in + ${usage.outputTokens} out tokens${usage.cached ? ' (cached, not charged)' : ''}${usage.redacted ? `, ${usage.redacted} secret(s) redacted before sending` : ''}. Run total ${budget.used}/${budget.limit}.`,
      );
    };
    const workspaces: string[] = [];
    try {
      // 1. Clone at a pinned commit.
      await setRun(run, { status: 'mapping' });
      await event(run, 'stage_started', `Cloning ${repository.owner}/${repository.name} (shallow, no submodules/LFS/symlinks).`);
      const ingested = await options.ingestion.ingest(repository, signal);
      if (ingested.state !== 'completed') throw new StageFailure(ingested.message);
      const original = ingested.data;
      workspaces.push(original.id);
      await event(run, 'stage_completed', `Cloned at commit ${original.commitSha}.`);

      // 2. Map the repository without executing it.
      const map = await inspectRepository(store.path(original.id));
      if (!map.testCommands.length)
        throw new StageFailure(`No supported test suite found (languages: ${map.languages.join(', ') || 'none'}). Supported: Python + pytest.`);
      const testArgv = map.testCommands[0];
      await event(run, 'stage_completed', `Mapped: ${map.languages.join(', ')}${map.frameworks.length ? ` · ${map.frameworks.join(', ')}` : ''} · test command ${JSON.stringify(testArgv)}.`);

      // 3. Install dependencies in the isolated preparation stage (only stage with network).
      await event(run, 'stage_started', 'Installing declared dependencies in the sandbox preparation stage.');
      const prepared = await sandbox.prepare(original, signal);
      if (prepared.exitCode !== 0)
        throw new StageFailure(`Dependency installation failed (exit ${prepared.exitCode}${prepared.timedOut ? ', timed out' : ''}): ${tail(prepared.stderr, 600)}`);
      await event(run, 'stage_completed', 'Dependencies installed. All further execution runs with network disabled.');

      // 4. Baseline: the original test suite, before any change.
      await setRun(run, { status: 'analyzing' });
      await event(run, 'stage_started', 'Running the original test suite (baseline, network=none).');
      const baseline = await runSuite(original, original.id, testArgv, signal);
      if (!baseline.tests || baseline.tests.total === 0)
        throw new StageFailure(`Baseline test run produced no test results (exit ${baseline.out.exitCode}${baseline.out.timedOut ? ', timed out' : ''}).`);
      await event(run, 'stage_completed', `Baseline: ${summarize(baseline.tests)}.`);

      // 5. Local scanner (Bandit, in the sandbox) + sink search + one AI confirmation call.
      let external: ExternalHit[] = [];
      try {
        const scan = await execute(original, original.id, ['bandit', '-r', '.', '-f', 'json', '-o', '/out/bandit.json', '-q', '-x', './tests,./test'], signal);
        const report = JSON.parse(scan.files['bandit.json'] ?? '{"results":[]}') as {
          results: { filename: string; line_number: number; test_id: string; issue_text: string; issue_cwe?: { id?: number } }[];
        };
        external = report.results.map((r) => ({
          file: r.filename.replace(/^\.\//, ''),
          line: r.line_number,
          cwe: r.issue_cwe?.id ? `CWE-${r.issue_cwe.id}` : 'CWE-20',
          category: r.issue_text.slice(0, 80),
          rule: `bandit:${r.test_id}`,
        }));
      } catch {
        external = [];
      }
      const detection = await detectVulnerabilities({ root: store.path(original.id), ai, budget, signal, external, onUsage });
      await event(
        run,
        'stage_completed',
        `Search funnel: ${detection.filesScanned} source files → ${detection.hits} scanner hits (Bandit ${external.length}) → ${detection.candidates.length} snippets sent to AI → ${detection.issues.length} confirmed.`,
      );
      if (!detection.issues.length)
        throw new StageFailure('No exploitable vulnerability was confirmed among the scanner candidates.');
      const findings: { issue: DetectedIssue; finding: Finding }[] = [];
      for (const issue of detection.issues.slice(0, 3)) findings.push({ issue, finding: await saveFinding(run, issue) });

      // 6–8. Patch → reproduce (red) → retest (green) → regression, with feedback retries.
      const testFiles = (await listSourceFiles(store.path(original.id))).filter((f) => f.isTest).map((f) => f.path);
      for (const { issue, finding } of findings) {
        let previousFailure: string | undefined;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
          await setRun(run, { status: 'patching' });
          await event(run, 'stage_started', `Generating patch for ${finding.file}:${finding.startLine} (${finding.cwe}), attempt ${attempt}/${maxAttempts}.`);
          let generated: GeneratedPatch;
          try {
            generated = await generatePatch({ root: store.path(original.id), issue, testFiles, ai, budget, signal, previousFailure, attempt, onUsage });
          } catch (error) {
            if (!(error instanceof EditError)) throw error;
            previousFailure = `Your edits could not be applied: ${error.message}`;
            await event(run, 'stage_failed', `Attempt ${attempt}: ${error.message}`);
            continue;
          }
          const patch = await savePatch(run, finding, generated, attempt);
          await setRun(run, { status: 'verifying' });
          const testPath = generated.securityTest.path;
          const withTest = await copyWorkspace(original, { [testPath]: generated.securityTest.content });
          workspaces.push(withTest.id);
          const patched = await copyWorkspace(original, {
            [testPath]: generated.securityTest.content,
            ...Object.fromEntries(generated.changes.map((c) => [c.path, c.proposed])),
          });
          workspaces.push(patched.id);
          // -rP prints captured output of passing tests too, so a no-effect attack shows its shell/DB errors.
          const securityArgv = [...testArgv, '--tb=short', '-rP', testPath];
          const baselineRecord = await record(run, patch.id, 'baseline', true, {
            exitCode: baseline.out.exitCode, command: [...testArgv, '--junitxml=/out/junit.xml'], logs: baseline.logs,
            tests: baseline.tests, junit: baseline.out.files['junit.xml'],
          });
          void baselineRecord;

          // Reproduction: the generated exploit test must FAIL on the original code.
          const repro = await runSuite(withTest, original.id, securityArgv, signal);
          const reproduced = repro.out.exitCode === 1 && !!repro.tests && repro.tests.failed > 0;
          await record(run, patch.id, 'reproduction', reproduced, {
            exitCode: repro.out.exitCode, command: securityArgv, logs: repro.logs, tests: repro.tests, junit: repro.out.files['junit.xml'],
          });
          if (!reproduced) {
            previousFailure = repro.out.exitCode === 0
              ? 'Your security test PASSED on the vulnerable code, so your attack had no effect there and does not reproduce the bug. ' +
                'Look at what the vulnerable line does with your payload (e.g. text appended after the injection point) and make the ' +
                `attack actually succeed on the original code. Output of your test on the original code:\n${tail(repro.logs, 1200)}`
              : `Your security test could not run on the original code (exit ${repro.out.exitCode}). Errors:\n${pytestEssence(repro.logs)}`;
            await setPatchStatus(patch, 'rejected');
            await event(run, 'stage_failed', `Attempt ${attempt}: the security test did not reproduce the vulnerability (exit ${repro.out.exitCode}).`);
            continue;
          }
          await event(run, 'stage_completed', `Reproduced: security test fails on the original code (${summarize(repro.tests!)}).`);

          await record(run, patch.id, 'patch_application', true, {
            exitCode: 0,
            command: ['proofpatch', 'apply', ...generated.changes.map((c) => c.path)],
            logs: `Applied ${generated.changes.length} file change(s) to a fresh copy of commit ${original.commitSha}.\n\n${generated.unifiedDiff}`,
          });
          await setPatchStatus(patch, 'applied');

          // Security retest: the same exploit test must PASS on the patched code.
          const retest = await runSuite(patched, original.id, securityArgv, signal);
          const secure = retest.out.exitCode === 0 && !!retest.tests && retest.tests.failed + retest.tests.errors === 0;
          await record(run, patch.id, 'security_retest', secure, {
            exitCode: retest.out.exitCode, command: securityArgv, logs: retest.logs, tests: retest.tests, junit: retest.out.files['junit.xml'],
          });
          if (!secure) {
            previousFailure =
              `After your patch the security test still fails (exit ${retest.out.exitCode}). Decide which is wrong: ` +
              'if the patch is a correct fix, KEEP THE SAME EDITS and rewrite only the test (a safe implementation may reject or ' +
              'fail on malicious input; assert only that the attack had no effect, wrapping the call in try/except or ' +
              `pytest.raises). Errors:\n${pytestEssence(retest.logs)}`;
            await setPatchStatus(patch, 'rejected');
            await event(run, 'stage_failed', `Attempt ${attempt}: security test still fails on the patched code.`);
            continue;
          }
          await event(run, 'stage_completed', 'Security retest: the exploit test now passes on the patched code.');

          // Regression: every test that passed before must still pass.
          const after = await runSuite(patched, original.id, testArgv, signal);
          const gate = after.tests ? compareSuites(baseline.tests, after.tests) : null;
          const regressionOk = !!gate?.ok;
          await record(run, patch.id, 'regression', regressionOk, {
            exitCode: after.out.exitCode,
            command: testArgv,
            logs: `${gate ? (gate.ok ? 'All tests that passed before still pass.' : `Broken: ${gate.broken.map((b) => `${b.id} (${b.after})`).join(', ')}`) : 'No test results.'}\n\n${after.logs}`,
            tests: after.tests,
            junit: after.out.files['junit.xml'],
          });
          if (!regressionOk) {
            previousFailure = `Your patch broke existing tests: ${gate?.broken.slice(0, 5).map((b) => b.id).join(', ') ?? 'suite did not run'}. Output tail:\n${tail(after.logs, 1200)}`;
            await setPatchStatus(patch, 'rejected');
            await event(run, 'stage_failed', `Attempt ${attempt}: ${gate?.broken.length ?? 'unknown'} previously passing test(s) broke.`);
            continue;
          }
          await event(run, 'stage_completed', `Regression: ${summarize(after.tests!)} — no previously passing test broke.`);

          const report = [
            `Finding: ${finding.cwe} ${finding.category} at ${finding.file}:${finding.startLine}-${finding.endLine}`,
            `Commit: ${original.commitSha}`,
            `Baseline: ${summarize(baseline.tests)}`,
            `Exploit test on original: FAILED as expected (vulnerability reproduced)`,
            `Exploit test on patch: PASSED`,
            `Regression after patch: ${summarize(after.tests!)}; broken: 0`,
            `Patch: ${generated.changes.length} file(s), attempt ${attempt}/${maxAttempts}`,
            `AI tokens used: ${budget.used}/${budget.limit}`,
          ].join('\n');
          await record(run, patch.id, 'final_decision', true, { exitCode: 0, command: ['proofpatch', 'decide'], logs: report });
          await artifact(run, 'report', report);
          await setPatchStatus(patch, 'needs_review');
          await setRun(run, { status: 'needs_review', error: null });
          await event(run, 'stage_completed', `Proof complete on attempt ${attempt}: vulnerability reproduced, fixed, and the existing suite is intact. Awaiting human review.`);
          return;
        }
      }
      throw new StageFailure(`No patch passed all proofs within ${maxAttempts} attempts per finding.`);
    } finally {
      for (const id of workspaces) {
        await store.remove(id).catch(() => {});
        await sandbox.cleanup(id).catch(() => {});
      }
    }
  }

  async function runOne(run: AnalysisRun) {
    const controller = new AbortController();
    controllers.set(run.id, controller);
    try {
      await process(run, controller.signal);
    } catch (error) {
      const message =
        controller.signal.aborted
          ? 'Run cancelled.'
          : error instanceof StageFailure || error instanceof AiError
            ? error.message
            : `Unexpected pipeline error: ${error instanceof Error ? error.message : 'unknown'}`;
      await event(run, 'stage_failed', message).catch(() => {});
      await setRun(run, { status: 'failed', error: message.slice(0, 2000) }).catch(() => {});
    } finally {
      controllers.delete(run.id);
    }
  }

  return {
    async status() {
      const reason = !options.ai ? 'No AI provider configured (GEMINI_API_KEY / GROQ_API_KEY).' : await sandbox.ready();
      return { available: !reason, reason, ai: options.ai?.providers ?? [] };
    },
    start(run) {
      // One run at a time: container execution is CPU/memory heavy.
      chain = chain.then(() => runOne(run));
    },
    cancel(runId) {
      const controller = controllers.get(runId);
      controller?.abort();
      return !!controller;
    },
    idle: () => chain,
    async shutdown() {
      for (const c of controllers.values()) c.abort();
      await chain;
    },
  };
}
