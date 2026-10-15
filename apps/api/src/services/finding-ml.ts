import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { FindingMLSchema, type AnalysisRun, type Finding, type FindingML, type Repository } from '@proofpatch/shared';
import type { Database } from '../database/index.js';
import type { WorkspaceHandle } from '../agents/contracts.js';
import { classifySource } from './mini-ml.js';
import { enrichScannerFinding, findingLanguage, type MLEnrichment } from './ml-enrichment.js';

const sourceLimit = 1024 * 1024;
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

/** Read only a bounded plain file below the already-audited, pinned workspace. No source execution. */
async function sourceAt(root: string, file: string): Promise<Buffer> {
  const parts = file.replaceAll('\\', '/').split('/');
  if (!file || file.length > 500 || file.includes('\0') || isAbsolute(file) || /^[A-Za-z]:/.test(file) ||
      parts.some((part) => !part || part === '.' || part === '..' || part.toLowerCase() === '.git')) throw new Error('Unsafe source path');
  const base = await realpath(root);
  let target = base;
  for (const part of parts) {
    target = join(target, part);
    if ((await lstat(target)).isSymbolicLink()) throw new Error('Symlink source');
  }
  const canonical = await realpath(target);
  const path = relative(base, canonical);
  if (!path || path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path)) throw new Error('Source outside workspace');
  const handle = await open(resolve(canonical), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > sourceLimit) throw new Error('Source is not a bounded plain file');
    const buffer = Buffer.alloc(sourceLimit + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset > sourceLimit) throw new Error('Source too large');
    return buffer.subarray(0, offset);
  } finally { await handle.close(); }
}

/** One sidecar per saved finding, before patches or workspace cleanup. Failures never reject the scan. */
export async function recordFindingML(
  db: Database,
  input: { run: AnalysisRun; repository: Repository; workspace: WorkspaceHandle; root: string; finding: Finding },
  options: { predict?: typeof classifySource; timeoutMs?: number } = {},
): Promise<{ record: FindingML | null; persisted: boolean }> {
  const { run, repository, workspace, finding } = input;
  // Callers cannot associate a finding with another repository, run or owner.
  if (finding.runId !== run.id || finding.ownerId !== run.ownerId || run.repositoryId !== repository.id ||
      workspace.repositoryId !== repository.id || repository.ownerId !== run.ownerId || !/^[0-9a-f]{40,64}$/i.test(workspace.commitSha)) {
    return { record: null, persisted: false };
  }
  const language = findingLanguage(finding) ?? 'unknown';
  let ml: MLEnrichment = { status: 'unsupported', comparison: 'not_comparable', scannerCwe: finding.cwe,
    reason: 'No trained classifier supports this source language. The original finding is retained.' };
  let sourceSha256: string | null = null;
  let snippet: FindingML['snippet'];
  if (language === 'java' || language === 'python') {
    try {
      const bytes = await sourceAt(input.root, finding.file);
      sourceSha256 = digest(bytes);
      const source = bytes.toString('utf8');
      let captured: { code: string } | undefined;
      const classify = enrichScannerFinding(finding, source, {
        preferFindingRange: true,
        predict: async (request) => {
          captured = { code: request.code };
          return (options.predict ?? classifySource)(request);
        },
      });
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const outcome = await Promise.race([
          classify,
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => reject(new Error('ML deadline')), options.timeoutMs ?? 15_000);
            timer.unref();
          }),
        ]);
        ml = outcome.ml;
        if (captured && ml.sourceRange) {
          const original = source.split(/\r\n|\n|\r/).slice(ml.sourceRange.startLine - 1, ml.sourceRange.endLine).join('\n');
          snippet = { ...ml.sourceRange, sha256: digest(captured.code), characters: captured.code.length,
            transformation: captured.code === original ? 'verbatim' : 'dedent' };
        }
      } finally { if (timer) clearTimeout(timer); }
    } catch {
      ml = { status: 'unavailable', comparison: 'not_comparable', scannerCwe: finding.cwe,
        reason: 'Source extraction or ML inference is unavailable. The scanner finding is unchanged.' };
    }
  }
  const parsed = FindingMLSchema.safeParse({
    findingId: finding.id, runId: run.id, repositoryId: repository.id, ownerId: run.ownerId,
    repositoryUrl: repository.url, commitSha: workspace.commitSha, file: finding.file, language,
    findingRange: { startLine: finding.startLine, endLine: finding.endLine }, sourceSha256, snippet,
    status: ml.status, scannerCwe: ml.scannerCwe, comparison: ml.comparison,
    ...(ml.prediction ? { prediction: ml.prediction } : {}), ...(ml.reason ? { reason: ml.reason } : {}),
    createdAt: new Date().toISOString(),
  });
  if (!parsed.success) return { record: null, persisted: false };
  try {
    // Idempotent: an already-recorded prediction remains tied to its original source/model snapshot.
    await db.query('INSERT INTO finding_ml(finding_id,run_id,repository_id,owner_id,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT (finding_id) DO NOTHING',
      [finding.id, run.id, repository.id, run.ownerId, parsed.data]);
    return { record: parsed.data, persisted: true };
  } catch { return { record: parsed.data, persisted: false }; }
}
