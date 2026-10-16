import { spawn } from 'node:child_process';
import type { Repository } from '@proofpatch/shared';

/**
 * Clones a repository's latest default branch (keeping .git) and publishes a fix as a branch + pull
 * request. The token is only passed to git through environment config (never on a command line,
 * never logged); without a token, cloning still works and publishing reports that it is not configured.
 */
export interface GitHubPublisher {
  canPublish: boolean;
  cloneLatest(repository: Repository, dir: string, signal: AbortSignal): Promise<{ baseBranch: string; baseSha: string }>;
  publish(input: {
    repository: Repository;
    dir: string;
    branch: string;
    baseBranch: string;
    title: string;
    body: string;
    signal: AbortSignal;
  }): Promise<{ pullRequestUrl: string }>;
}

function git(args: string[], cwd: string | undefined, signal: AbortSignal, token?: string) {
  return new Promise<string>((resolve, reject) => {
    const auth = token
      ? {
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
          GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`,
        }
      : {};
    const child = spawn('git', args, {
      cwd,
      signal,
      timeout: 120_000,
      windowsHide: true,
      env: {
        PATH: process.env.PATH,
        SYSTEMROOT: process.env.SYSTEMROOT,
        HOME: process.env.HOME ?? process.env.USERPROFILE,
        GIT_TERMINAL_PROMPT: '0',
        GIT_LFS_SKIP_SMUDGE: '1',
        GIT_CONFIG_NOSYSTEM: '1',
        ...auth,
      },
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err = (err + d).slice(-2000)));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) return resolve(out.trim());
      const message = (err.trim() || `git exited ${code}`).split(token || '\u0000').join('***');
      reject(new Error(message));
    });
  });
}

export function githubPublisher(token = process.env.GITHUB_TOKEN?.trim() || '', fetchImpl: typeof fetch = fetch): GitHubPublisher {
  const api = async (path: string, init: RequestInit & { signal: AbortSignal }) => {
    const res = await fetchImpl(`https://api.github.com${path}`, {
      ...init,
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'proofpatch-ai',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      },
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new Error(`GitHub ${res.status}: ${String(body.message ?? 'request failed').slice(0, 200)}`);
    return body;
  };
  return {
    canPublish: !!token,
    async cloneLatest(repository, dir, signal) {
      const meta = await api(`/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.name)}`, { signal });
      const baseBranch = String(meta.default_branch ?? 'main');
      await git(
        ['-c', 'core.symlinks=false', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never',
          'clone', '--depth', '1', '--branch', baseBranch, '--single-branch', '--no-tags', '--no-recurse-submodules',
          `https://github.com/${repository.owner}/${repository.name}.git`, dir],
        undefined,
        signal,
      );
      return { baseBranch, baseSha: await git(['rev-parse', 'HEAD'], dir, signal) };
    },
    async publish({ repository, dir, branch, baseBranch, title, body, signal }) {
      if (!token) throw new Error('GITHUB_TOKEN is not configured on the server, so the fix branch cannot be pushed.');
      const ident = ['-c', 'user.name=Proof Patch', '-c', 'user.email=proofpatch@users.noreply.github.com', '-c', 'core.hooksPath=/dev/null'];
      await git(['checkout', '-b', branch], dir, signal);
      await git(['add', '-A'], dir, signal);
      await git([...ident, 'commit', '-m', title, '-m', body], dir, signal);
      await git(['push', `https://github.com/${repository.owner}/${repository.name}.git`, `HEAD:refs/heads/${branch}`], dir, signal, token);
      const pr = await api(`/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.name)}/pulls`, {
        method: 'POST',
        signal,
        body: JSON.stringify({ title, body, head: branch, base: baseBranch, maintainer_can_modify: true }),
      });
      return { pullRequestUrl: String(pr.html_url) };
    },
  };
}
