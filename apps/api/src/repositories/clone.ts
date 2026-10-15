import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readdir, rm, realpath } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type { Repository } from '@proofpatch/shared';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
import { ingestionLimits, type RepositoryIngestionService } from './ingestion.js';

/** Root folder for cloned workspaces. Each workspace is an opaque UUID folder. */
export class WorkspaceStore {
  constructor(public readonly root: string) {}
  path(id: string) {
    if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error('Invalid workspace id.');
    return join(this.root, id);
  }
  async remove(id: string) {
    await rm(this.path(id), { recursive: true, force: true });
  }
}

export interface GitRunner {
  (args: string[], options: { cwd?: string; timeoutMs: number; signal: AbortSignal }): Promise<string>;
}

/** Git with interactive prompts, hooks, submodules and LFS smudging disabled. No shell. */
export const runGit: GitRunner = (args, { cwd, timeoutMs, signal }) =>
  new Promise((resolvePromise, reject) => {
    const child = spawn('git', args, {
      cwd,
      signal,
      timeout: timeoutMs,
      windowsHide: true,
      env: {
        PATH: process.env.PATH,
        SYSTEMROOT: process.env.SYSTEMROOT,
        HOME: process.env.HOME ?? process.env.USERPROFILE,
        GIT_TERMINAL_PROMPT: '0',
        GIT_LFS_SKIP_SMUDGE: '1',
        GIT_CONFIG_NOSYSTEM: '1',
      },
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err = (err + d).slice(-2000)));
    child.on('error', reject);
    child.on('close', (code) =>
      code === 0 ? resolvePromise(out.trim()) : reject(new Error(err.trim() || `git exited ${code}`)),
    );
  });

const fail = (message: string): CapabilityResult<never> => ({
  code: 'CAPABILITY_UNAVAILABLE',
  state: 'failed',
  message,
});

export function githubIngestion(
  store: WorkspaceStore,
  options: { git?: GitRunner; fetchImpl?: typeof fetch } = {},
): RepositoryIngestionService {
  const git = options.git ?? runGit;
  const fetchImpl = options.fetchImpl ?? fetch;
  return {
    async ingest(repository: Repository, signal: AbortSignal) {
      // 1. Confirm the repository is public and within the size limit before cloning.
      const meta = await fetchImpl(
        `https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.name)}`,
        { signal, headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'proofpatch-ai' } },
      ).catch(() => null);
      if (!meta || !meta.ok)
        return fail(
          meta?.status === 404
            ? 'Repository not found or not public on GitHub.'
            : 'Could not verify the repository with GitHub. Retry shortly.',
        );
      const info = (await meta.json()) as { private?: boolean; size?: number };
      if (info.private) return fail('Private repositories are not supported.');
      if ((info.size ?? 0) * 1024 > ingestionLimits.maxBytes)
        return fail(`Repository is larger than ${ingestionLimits.maxBytes / 1024 / 1024} MiB.`);

      // 2. Shallow clone with symlinks, hooks and submodules disabled.
      const id = randomUUID();
      const dir = store.path(id);
      await mkdir(store.root, { recursive: true });
      try {
        // Retry transient network failures (connection reset, early EOF) on flaky Wi-Fi.
        for (let attempt = 1; ; attempt++) {
          try {
            await git(
              [
                '-c', 'core.symlinks=false',
                '-c', 'core.hooksPath=/dev/null',
                '-c', 'protocol.file.allow=never',
                '-c', 'http.postBuffer=524288000',
                'clone', '--depth', '1', '--single-branch', '--no-tags', '--no-recurse-submodules',
                `https://github.com/${repository.owner}/${repository.name}.git`,
                dir,
              ],
              { timeoutMs: ingestionLimits.cloneTimeoutMs, signal },
            );
            break;
          } catch (error) {
            const transient = error instanceof Error && /RPC failed|early EOF|Connection was reset|unexpected disconnect|Could not resolve host|timed out|SSL/i.test(error.message);
            await rm(dir, { recursive: true, force: true });
            if (!transient || attempt >= 3 || signal.aborted) throw error;
            await new Promise((resolve) => setTimeout(resolve, attempt * 2_000));
          }
        }
        const commitSha = await git(['rev-parse', 'HEAD'], { cwd: dir, timeoutMs: 10_000, signal });
        // 3. Enforce file/size limits and reject anything that is not a plain file or folder.
        const problem = await auditTree(dir);
        if (problem) {
          await store.remove(id);
          return fail(problem);
        }
        await rm(join(dir, '.git'), { recursive: true, force: true });
        const handle: WorkspaceHandle = { id, repositoryId: repository.id, commitSha };
        return { state: 'completed', data: handle };
      } catch (error) {
        await store.remove(id);
        return fail(
          signal.aborted
            ? 'Clone cancelled.'
            : `Clone failed: ${error instanceof Error ? error.message.slice(0, 300) : 'unknown error'}`,
        );
      }
    },
  };
}

async function auditTree(root: string) {
  const base = await realpath(root);
  let files = 0;
  let bytes = 0;
  const stack = [base];
  while (stack.length) {
    const dir = stack.pop()!;
    for (const entry of await readdir(dir)) {
      if (dir === base && entry === '.git') continue;
      const full = join(dir, entry);
      const info = await lstat(full);
      if (info.isSymbolicLink()) return `Symbolic links are not allowed (${full.slice(base.length + 1)}).`;
      if (info.isDirectory()) stack.push(full);
      else if (info.isFile()) {
        files += 1;
        bytes += info.size;
      } else return 'Special files are not allowed.';
      if (!resolve(full).startsWith(base + sep)) return 'Path escapes the workspace.';
      if (files > ingestionLimits.maxFiles) return `Repository has more than ${ingestionLimits.maxFiles} files.`;
      if (bytes > ingestionLimits.maxBytes) return 'Repository exceeds the size limit.';
    }
  }
  return null;
}
