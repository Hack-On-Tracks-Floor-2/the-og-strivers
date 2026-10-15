import { createHash, randomUUID } from 'node:crypto';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
  FindingSchema,
  MergeSchema,
  PatchSchema,
  VerificationRunSchema,
  type AnalysisRun,
  type Finding,
  type Merge,
  type MergeCheck,
  type Patch,
  type Repository,
  type TestSummary,
  type User,
  type VerificationRun,
} from '@proofpatch/shared';
import type { Database } from '../database/index.js';
import type { RepositoryIngestionService } from '../repositories/ingestion.js';
import type { WorkspaceStore } from '../repositories/clone.js';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
import { inspectRepository, listSourceFiles } from '../agents/intelligence.js';
import { detectToolchain, type Language, type Toolchain } from '../agents/toolchain.js';
import { auditSummary, parseAudit } from '../verification/audit.js';
import { detectVulnerabilities, type DetectedIssue } from '../agents/detection.js';
import { generatePatch, type GeneratedPatch } from '../patching/generator.js';
import { EditError, unifiedDiff } from '../patching/edits.js';
import { createAnalysisRun } from '../scanners/service.js';
import type { GitHubPublisher } from '../merging/github.js';
import { mergeFile } from '../merging/three-way.js';
import { resolveConflict } from '../merging/resolver.js';
import { AiError, TokenBudget, type AiClient, type AiUsage } from '../ai/client.js';
import { evidenceService } from '../services/evidence.js';
import { compareSuites, parseJUnit } from '../verification/junit.js';
import type { ExecutionRequest } from '../verification/sandbox.js';
import type { SandboxRun } from '../verification/docker.js';
import type { ExternalHit, ModelSummary } from '../scanners/funnel.js';
import type { Locator } from '../scanners/locator.js';

export interface PipelineSandbox {
  ready(): Promise<string | null>;
  prepare(workspace: WorkspaceHandle, signal: AbortSignal, language?: Language): Promise<{ exitCode: number; stdout: string; stderr: string; timedOut: boolean; audit?: string }>;
  executeWith(request: ExecutionRequest, depsId: string, signal: AbortSignal): Promise<CapabilityResult<SandboxRun>>;
  cleanup(workspaceId: string): Promise<void>;
}
export interface PipelineOptions {
  db: Database;
  ingestion: RepositoryIngestionService;
  store: WorkspaceStore;
  sandbox: PipelineSandbox;
  ai: AiClient | null;
  /** Optional trained vulnerability locator (see ml/). */
  locator?: Locator | null;
  /** Clones the latest code and publishes merged fixes as GitHub branches + pull requests. */
  github?: GitHubPublisher;
  tokenBudget?: number;
  maxAttempts?: number;
  testTimeoutMs?: number;
}
export interface Pipeline {
  status(): Promise<{ available: boolean; reason: string | null; ai: string[] }>;
  start(run: AnalysisRun): void;
  cancel(runId: string): boolean;
  /** Merge an approved patch onto the latest code (queued like analysis runs). */
  merge(patchId: string): void;
  /** Publish an AI-resolved merge after a reviewer confirmed it. */
  confirmMerge(patchId: string): void;
  idle(): Promise<void>;
  shutdown(): Promise<void>;
}

const tail = (text: string, n = 20_000) => (text.length > n ? `…(truncated)\n${text.slice(-n)}` : text);
/** The useful part of a pytest failure: error lines ("E …"), failing test lines and the summary. */
function modelNote(model?: ModelSummary) {
  if (!model) return '';
  if (model.error) return ` · trained model unavailable (${model.error.slice(0, 80)})`;
  return ` · trained model scored ${model.functionsScored} functions, flagged ${model.flagged} (${model.modelOnly} missed by rules)`;
}

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

  const languageOf = new Map<string, Language>();
  async function prepareDeps(workspace: WorkspaceHandle, tc: Toolchain, signal: AbortSignal) {
    languageOf.set(workspace.id, tc.language);
    return sandbox.prepare(workspace, signal, tc.language);
  }
  async function toolchainFor(root: string) {
    const map = await inspectRepository(root);
    const tc = await detectToolchain(root, map);
    if ('unsupported' in tc) throw new StageFailure(`Unsupported repository: ${tc.unsupported}`);
    return { map, tc };
  }

  async function execute(workspace: WorkspaceHandle, depsId: string, argv: string[], signal: AbortSignal) {
    const result = await sandbox.executeWith(
      {
        workspace,
        argv,
        language: languageOf.get(depsId) ?? 'python',
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
    const out = await execute(workspace, depsId, argv, signal); // toolchain argv already writes /out/junit.xml
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
      const { map, tc } = await toolchainFor(store.path(original.id));
      const testArgv = tc.suite;
      await event(run, 'stage_completed', `Mapped: ${map.languages.join(', ')}${map.frameworks.length ? ` · ${map.frameworks.join(', ')}` : ''} · ${tc.label} · test command ${JSON.stringify(testArgv)}.`);

      // 3. Install dependencies in the isolated preparation stage (only stage with network).
      await event(run, 'stage_started', 'Installing declared dependencies in the sandbox preparation stage.');
      const prepared = await prepareDeps(original, tc, signal);
      if (prepared.exitCode !== 0)
        throw new StageFailure(`Dependency installation failed (exit ${prepared.exitCode}${prepared.timedOut ? ', timed out' : ''}): ${tail(prepared.stderr, 600)}`);
      await event(run, 'stage_completed', 'Dependencies installed. All further execution runs with network disabled.');
      const advisories = parseAudit(tc.language, prepared.audit);
      if (advisories) {
        const summary = auditSummary(advisories);
        await event(run, 'stage_completed', summary, await artifact(run, 'report', `${summary}\n\n${JSON.stringify(advisories, null, 2)}`));
      }

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
        if (tc.language !== 'python') throw new Error('Bandit is Python-only.');
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
      const detection = await detectVulnerabilities({ root: store.path(original.id), ai, budget, signal, external, locator: options.locator, language: tc.language, onUsage });
      await event(
        run,
        'stage_completed',
        `Search funnel: ${detection.filesScanned} source files → ${detection.hits} scanner hits (Bandit ${external.length})${modelNote(detection.model)} → ${detection.candidates.length} snippets sent to AI → ${detection.issues.length} confirmed.`,
      );
      if (!detection.issues.length)
        throw new StageFailure('No exploitable vulnerability was confirmed among the scanner candidates.');
      const findings: { issue: DetectedIssue; finding: Finding }[] = [];
      for (const issue of detection.issues.slice(0, 3)) findings.push({ issue, finding: await saveFinding(run, issue) });

      // 6–8. Patch → reproduce (red) → retest (green) → regression, with feedback retries.
      const testFiles = (await listSourceFiles(store.path(original.id))).filter((f) => f.isTest).map((f) => f.path);
      // Every confirmed finding (up to 3) gets its own proven patch; each lands in the review queue.
      let proven = 0;
      for (const { issue, finding } of findings) {
        let previousFailure: string | undefined;
        try {
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
          await setRun(run, { status: 'patching' });
          await event(run, 'stage_started', `Generating patch for ${finding.file}:${finding.startLine} (${finding.cwe}), attempt ${attempt}/${maxAttempts}.`);
          let generated: GeneratedPatch;
          try {
            generated = await generatePatch({ root: store.path(original.id), issue, testFiles, ai, budget, signal, previousFailure, attempt, toolchain: tc, onUsage });
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
          const securityArgv = tc.only(testPath);
          const baselineRecord = await record(run, patch.id, 'baseline', true, {
            exitCode: baseline.out.exitCode, command: testArgv, logs: baseline.logs,
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
          await event(run, 'stage_completed', `Proof complete for ${finding.cwe} at ${finding.file}:${finding.startLine} on attempt ${attempt}: vulnerability reproduced, fixed, and the existing suite is intact.`);
          proven += 1;
          break;
        }
        } catch (error) {
          // Out of AI budget after at least one proven fix: keep what is proven instead of failing the run.
          if (!(error instanceof AiError) || proven === 0) throw error;
          await event(run, 'stage_failed', `Stopped after ${proven} proven fix(es): ${error.message}`);
          break;
        }
      }
      if (!proven) throw new StageFailure(`No patch passed all proofs within ${maxAttempts} attempts per finding.`);
      await setRun(run, { status: 'needs_review', error: null });
      await event(run, 'stage_completed', `${proven} of ${findings.length} confirmed vulnerabilit${findings.length === 1 ? 'y' : 'ies'} fixed and proven. Awaiting human review.`);
    } finally {
      for (const id of workspaces) {
        await store.remove(id).catch(() => {});
        await sandbox.cleanup(id).catch(() => {});
        languageOf.delete(id);
      }
    }
  }

  // ---- Merge: approved fix → latest code → re-prove → GitHub branch + PR (or back to patching) ----
  async function setMerge(patch: Patch, update: Partial<Merge>) {
    const now = new Date().toISOString();
    patch.merge = MergeSchema.parse({
      status: 'merging', baseBranch: null, baseSha: null, branch: null, pullRequestUrl: null, message: '',
      ...patch.merge, ...update, updatedAt: now,
    });
    patch.updatedAt = now;
    await db.query('UPDATE patches SET document=$1 WHERE id=$2', [patch, patch.id]);
  }
  async function loadMergeContext(patchId: string) {
    const patch = (await db.query<{ document: Patch }>('SELECT document FROM patches WHERE id=$1', [patchId])).rows[0]?.document;
    if (!patch) throw new StageFailure('Patch not found.');
    const run = (await db.query<{ document: AnalysisRun }>('SELECT document FROM runs WHERE id=$1', [patch.runId])).rows[0]!.document;
    const repository = (await db.query<{ document: Repository }>('SELECT document FROM repositories WHERE id=$1', [run.repositoryId])).rows[0]!.document;
    const finding = (await db.query<{ document: Finding }>('SELECT document FROM findings WHERE id=$1', [patch.findingId])).rows[0]?.document;
    return { patch: PatchSchema.parse(patch), run, repository, finding };
  }
  async function publishFix(ctx: Awaited<ReturnType<typeof loadMergeContext>>, dir: string, signal: AbortSignal) {
    const { patch, repository, finding } = ctx;
    const github = options.github!;
    const branch = `proofpatch/fix-${patch.id.slice(0, 8)}`;
    const title = `Security fix: ${finding ? `${finding.cwe ?? ''} ${finding.category} in ${finding.file}`.trim() : 'ProofPatch fix'}`;
    const body = [
      'Opened by ProofPatch after a security reviewer approved this fix.',
      '',
      ...(patch.merge?.checks ?? []).map((c) => `- ${c.passed ? '✅' : '❌'} **${c.stage}**: ${c.summary}`),
      ...(patch.merge?.resolvedByAi.length ? ['', `Merge conflicts in ${patch.merge.resolvedByAi.join(', ')} were resolved by AI and confirmed by a reviewer.`] : []),
      '',
      'Please review and merge this pull request yourself; ProofPatch never merges it automatically.',
    ].join('\n');
    if (!github.canPublish) {
      await setMerge(patch, { status: 'failed', message: 'All proofs passed on the latest code, but GITHUB_TOKEN is not configured on the server, so the branch could not be pushed.' });
      return;
    }
    const { pullRequestUrl } = await github.publish({ repository, dir, branch, baseBranch: patch.merge!.baseBranch!, title, body, signal });
    await setMerge(patch, {
      status: 'merged', branch, pullRequestUrl,
      checks: [...(patch.merge?.checks ?? []), { stage: 'publish', passed: true, summary: `Pushed ${branch} and opened ${pullRequestUrl}` }],
      message: `Fix branch ${branch} pushed and pull request opened for the developer.`,
    });
    await event(ctx.run, 'stage_completed', `Merged: branch ${branch} pushed, pull request ${pullRequestUrl}.`);
  }

  async function mergeOne(patchId: string, signal: AbortSignal) {
    const ctx = await loadMergeContext(patchId);
    const { patch, run, repository } = ctx;
    const workspaces: string[] = [];
    const checks: MergeCheck[] = [];
    try {
      if (!options.github) throw new StageFailure('Merging is not configured on this server.');
      await setMerge(patch, { status: 'merging', message: 'Merging the approved fix onto the latest code.', checks: [], resolvedByAi: [], sentBackRunId: null });
      await event(run, 'stage_started', `Merging the approved fix onto the latest ${repository.owner}/${repository.name}.`);
      // 1. Latest default branch, with git history so the fix can be pushed as a branch.
      const repoId = randomUUID();
      workspaces.push(repoId);
      await mkdir(store.root, { recursive: true });
      const { baseBranch, baseSha } = await options.github.cloneLatest(repository, store.path(repoId), signal);
      await setMerge(patch, { baseBranch, baseSha });

      // 2. Lay the fix on top: unchanged files take the fix; changed files get a 3-way merge; conflicts go to the AI.
      const files: Record<string, string> = {};
      const resolvedByAi: string[] = [];
      for (const file of patch.files) {
        const latest = await readFile(join(store.path(repoId), file.path), 'utf8').catch(() => null);
        if (latest === null) return await sendBack(ctx, checks, `${file.path} no longer exists on ${baseBranch}.`);
        const merged = await mergeFile(file.original, latest, file.proposed);
        if (merged.conflicts) {
          if (!options.ai) throw new StageFailure('Merge conflict and no AI provider is configured to resolve it.');
          const resolved = await resolveConflict({
            path: file.path, conflicted: merged.text, fixDiff: patch.unifiedDiff, ai: options.ai,
            budget: new TokenBudget(options.tokenBudget ?? 30_000), signal,
            onUsage: async (usage, note) => {
              await event(run, 'ai_usage', `${note}: ${usage.provider} ${usage.model}, ${usage.inputTokens} in + ${usage.outputTokens} out tokens.`);
            },
          });
          files[file.path] = merged.restore(resolved.content);
          resolvedByAi.push(file.path);
        } else files[file.path] = merged.text;
      }
      if (patch.securityTest) files[patch.securityTest.path] = patch.securityTest.content;
      const mergedDiff = (
        await Promise.all(
          Object.entries(files).map(async ([path, content]) =>
            unifiedDiff(path, (await readFile(join(store.path(repoId), path), 'utf8').catch(() => '')), content),
          ),
        )
      ).join('\n');
      checks.push({
        stage: 'apply', passed: true,
        summary: resolvedByAi.length
          ? `Upstream changed the same lines; AI resolved conflicts in ${resolvedByAi.join(', ')}.`
          : `Fix applied cleanly on ${baseBranch} @ ${baseSha.slice(0, 7)}.`,
      });
      await setMerge(patch, { resolvedByAi, mergedDiff, checks: [...checks] });

      // 3. Re-prove on the latest code: baseline → attack still works there → fix blocks it → nothing breaks.
      const latest = await copyWorkspace({ id: repoId, repositoryId: repository.id, commitSha: baseSha }, {});
      workspaces.push(latest.id);
      await rm(join(store.path(latest.id), '.git'), { recursive: true, force: true });
      const { tc } = await toolchainFor(store.path(latest.id));
      const testArgv = tc.suite;
      const prepared = await prepareDeps(latest, tc, signal);
      if (prepared.exitCode !== 0) throw new StageFailure(`Dependency installation failed on the latest code (exit ${prepared.exitCode}).`);
      const baseline = await runSuite(latest, latest.id, testArgv, signal);
      if (!baseline.tests?.total) throw new StageFailure('The latest code produced no test results.');
      checks.push({ stage: 'baseline', passed: true, summary: `Latest code: ${summarize(baseline.tests)}.` });
      if (!patch.securityTest) throw new StageFailure('The approved patch has no security test to re-prove it.');
      const securityArgv = tc.only(patch.securityTest.path);
      const withTest = await copyWorkspace(latest, { [patch.securityTest.path]: patch.securityTest.content });
      workspaces.push(withTest.id);
      const repro = await runSuite(withTest, latest.id, securityArgv, signal);
      if (repro.out.exitCode === 0) {
        checks.push({ stage: 'reproduction', passed: false, summary: 'The attack no longer works on the latest code: it was already fixed upstream.' });
        await setMerge(patch, { status: 'already_fixed', checks: [...checks], message: 'The latest code already blocks this attack, so no branch was created.' });
        await event(run, 'stage_completed', 'Merge: the vulnerability is already fixed on the latest code; nothing to merge.');
        return;
      }
      checks.push({ stage: 'reproduction', passed: true, summary: 'The attack still works on the latest code (bug present).' });
      const merged = await copyWorkspace(latest, files);
      workspaces.push(merged.id);
      const retest = await runSuite(merged, latest.id, securityArgv, signal);
      const secure = retest.out.exitCode === 0 && !!retest.tests && retest.tests.failed + retest.tests.errors === 0;
      checks.push({ stage: 'security_retest', passed: secure, summary: secure ? 'The merged fix blocks the attack.' : 'The attack still works after merging the fix.' });
      if (!secure) return await sendBack(ctx, checks, 'After merging onto the latest code the attack still works.');
      const after = await runSuite(merged, latest.id, testArgv, signal);
      const gate = after.tests ? compareSuites(baseline.tests, after.tests) : null;
      checks.push({
        stage: 'regression', passed: !!gate?.ok,
        summary: gate?.ok ? `${summarize(after.tests!)}; no previously passing test broke.` : `Broken: ${gate?.broken.slice(0, 5).map((b) => b.id).join(', ') ?? 'suite did not run'}.`,
      });
      if (!gate?.ok) return await sendBack(ctx, checks, 'Merging onto the latest code broke existing tests.');

      // 4. AI-resolved merges wait for a reviewer; clean merges are published straight away.
      if (resolvedByAi.length) {
        await setMerge(patch, {
          status: 'awaiting_review', checks: [...checks],
          files: Object.entries(files).map(([path, content]) => ({ path, content })),
          message: `AI resolved merge conflicts in ${resolvedByAi.join(', ')}. All proofs pass on the latest code; confirm to create the branch.`,
        });
        await event(run, 'stage_completed', 'Merge: AI-resolved conflicts pass every proof and await reviewer confirmation.');
        return;
      }
      await setMerge(patch, { checks: [...checks] });
      for (const [path, content] of Object.entries(files)) {
        await mkdir(dirname(join(store.path(repoId), path)), { recursive: true });
        await writeFile(join(store.path(repoId), path), content);
      }
      await publishFix(ctx, store.path(repoId), signal);
    } catch (error) {
      const message = signal.aborted ? 'Merge cancelled.' : error instanceof Error ? error.message : 'Merge failed.';
      await setMerge(patch, { status: 'failed', checks: [...checks], message: message.slice(0, 1000) }).catch(() => {});
      await event(run, 'stage_failed', `Merge failed: ${message.slice(0, 300)}`).catch(() => {});
    } finally {
      for (const id of workspaces) {
        await store.remove(id).catch(() => {});
        await sandbox.cleanup(id).catch(() => {});
        languageOf.delete(id);
      }
    }
  }

  /** A real bug on the latest code: the fix goes back to patching as a fresh analysis of the latest code. */
  async function sendBack(ctx: Awaited<ReturnType<typeof loadMergeContext>>, checks: MergeCheck[], reason: string) {
    const next = await createAnalysisRun(db, { id: ctx.run.ownerId } as User, ctx.run.repositoryId, true);
    await setMerge(ctx.patch, { status: 'sent_back', checks: [...checks], sentBackRunId: next.id, message: `${reason} Sent back for patching on the latest code.` });
    await event(ctx.run, 'stage_failed', `Merge: ${reason} Sent back for patching (new analysis ${next.id.slice(0, 8)}).`);
    chain = chain.then(() => runOne(next));
  }

  /** Reviewer confirmed an AI-resolved merge: push exactly what was proven, if the branch has not moved. */
  async function confirmOne(patchId: string, signal: AbortSignal) {
    const ctx = await loadMergeContext(patchId);
    const { patch } = ctx;
    const dirId = randomUUID();
    try {
      if (patch.merge?.status !== 'awaiting_review') throw new StageFailure('This merge is not awaiting confirmation.');
      await setMerge(patch, { status: 'merging', message: 'Reviewer confirmed; publishing the fix branch.' });
      await mkdir(store.root, { recursive: true });
      const latest = await options.github!.cloneLatest(ctx.repository, store.path(dirId), signal);
      if (latest.baseSha !== patch.merge.baseSha) {
        await store.remove(dirId).catch(() => {});
        await event(ctx.run, 'stage_started', 'Merge: the branch moved since the proofs ran; merging and proving again.');
        return await mergeOne(patchId, signal);
      }
      for (const { path, content } of patch.merge.files) {
        await mkdir(dirname(join(store.path(dirId), path)), { recursive: true });
        await writeFile(join(store.path(dirId), path), content);
      }
      await publishFix(ctx, store.path(dirId), signal);
    } catch (error) {
      await setMerge(patch, { status: 'failed', message: (error instanceof Error ? error.message : 'Publishing failed.').slice(0, 1000) }).catch(() => {});
    } finally {
      await store.remove(dirId).catch(() => {});
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
    merge(patchId) {
      chain = chain.then(() => mergeOne(patchId, new AbortController().signal));
    },
    confirmMerge(patchId) {
      chain = chain.then(() => confirmOne(patchId, new AbortController().signal));
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
