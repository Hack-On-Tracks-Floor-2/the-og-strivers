import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
import type { ExecutionRequest, ExecutionResult, SandboxExecutionAdapter } from './sandbox.js';

export interface DockerOptions {
  image: string;
  /** Runner image for JavaScript repositories (node:test / Jest / Mocha). */
  nodeImage?: string;
  workspacePath: (id: string) => string;
  scratchRoot: string; // per-execution output folders and dependency folders
  docker?: string;
  spawnImpl?: typeof spawn;
}
export interface SandboxRun extends ExecutionResult {
  timedOut: boolean;
  files: Record<string, string>; // files the run wrote to /out (e.g. junit.xml)
}

/** Fixed hardening flags shared by every container (SECURITY.md "future Docker adapter"). */
export function hardeningArgs(memoryMb: number, cpus: number) {
  return [
    '--read-only',
    '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=768m',
    '--user', '10001:10001',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '256',
    '--memory', `${memoryMb}m`,
    '--memory-swap', `${memoryMb}m`,
    '--cpus', String(cpus),
    '--ulimit', 'nofile=1024:1024',
    '-e', 'HOME=/tmp',
    '-e', 'PYTHONDONTWRITEBYTECODE=1',
    '-e', 'PYTHONPATH=/tmp/work:/tmp/work/src:/deps',
    '-e', 'PIP_DISABLE_PIP_VERSION_CHECK=1',
  ];
}

const bind = (source: string, target: string, readonly: boolean) => [
  '--mount',
  `type=bind,source=${source},target=${target}${readonly ? ',readonly' : ''}`,
];

export class DockerSandbox implements SandboxExecutionAdapter {
  constructor(private options: DockerOptions) {}

  private run(args: string[], timeoutMs: number, maxOutputBytes: number, signal: AbortSignal) {
    const docker = this.options.docker ?? 'docker';
    const spawnImpl = this.options.spawnImpl ?? spawn;
    return new Promise<{ exitCode: number; stdout: string; stderr: string; timedOut: boolean; durationMs: number }>(
      (resolve, reject) => {
        const name = `pp-${randomUUID()}`;
        const started = Date.now();
        const child = spawnImpl(docker, ['run', '--rm', '--name', name, ...args], { windowsHide: true });
        let stdout = '';
        let stderr = '';
        let timedOut = false;
        const cap = (buf: string, d: Buffer) => (buf.length < maxOutputBytes ? (buf + d).slice(0, maxOutputBytes) : buf);
        child.stdout?.on('data', (d: Buffer) => (stdout = cap(stdout, d)));
        child.stderr?.on('data', (d: Buffer) => (stderr = cap(stderr, d)));
        const kill = () => spawnImpl(docker, ['kill', name], { windowsHide: true }).on('error', () => {});
        const timer = setTimeout(() => {
          timedOut = true;
          kill();
        }, timeoutMs);
        const onAbort = () => kill();
        signal.addEventListener('abort', onAbort, { once: true });
        child.on('error', (e) => {
          clearTimeout(timer);
          reject(e);
        });
        child.on('close', (code) => {
          clearTimeout(timer);
          signal.removeEventListener('abort', onAbort);
          resolve({ exitCode: code ?? -1, stdout, stderr, timedOut, durationMs: Date.now() - started });
        });
      },
    );
  }

  /** True when the Docker CLI responds and the runner image exists. */
  async ready(): Promise<string | null> {
    const docker = this.options.docker ?? 'docker';
    return new Promise((resolve) => {
      const child = (this.options.spawnImpl ?? spawn)(
        docker,
        ['image', 'inspect', '--format', '{{.Id}}', this.options.image],
        { windowsHide: true },
      );
      child.on('error', () => resolve('Docker is not installed or not running.'));
      child.on('close', (code) =>
        resolve(code === 0 ? null : `Docker image ${this.options.image} is missing. Build it: docker build -t ${this.options.image} docker/runner`),
      );
    });
  }

  private imageFor(language: 'python' | 'javascript' = 'python') {
    return language === 'javascript' ? (this.options.nodeImage ?? 'proofpatch-runner:node22') : this.options.image;
  }

  depsPath(workspaceId: string) {
    return join(this.options.scratchRoot, 'deps', workspaceId);
  }

  /**
   * Isolated preparation stage: installs the repository's declared dependencies into a
   * dependency folder. This is the ONLY stage with network access; it still runs as a
   * non-root user with no capabilities and resource limits. Tests later mount it read-only.
   */
  async prepare(workspace: WorkspaceHandle, signal: AbortSignal, language: 'python' | 'javascript' = 'python') {
    const deps = this.depsPath(workspace.id);
    await mkdir(deps, { recursive: true });
    await chmod(deps, 0o777); // container runs as uid 10001
    // npm runs with install scripts disabled: a repository's postinstall never executes, even here.
    const nodeScript = [
      'set -e',
      'cp package.json /deps/package.json',
      'if [ -f package-lock.json ]; then cp package-lock.json /deps/; fi',
      'cd /deps',
      'if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund --loglevel=error;',
      'else npm install --ignore-scripts --no-audit --no-fund --loglevel=error; fi',
      'if grep -q \'"jest"\' package.json; then npm install --no-save --ignore-scripts --no-audit --no-fund --loglevel=error jest-junit; fi',
      // OWASP A06: known-vulnerable runtime dependencies (best effort; never fails the stage).
      'timeout 90 npm audit --json --omit=dev > /deps/audit.json 2>/dev/null || true',
      'echo prepared',
    ].join('\n');
    const pythonScript = [
      'set -e',
      'for f in requirements.txt requirements-dev.txt requirements-test.txt test-requirements.txt requirements/test.txt requirements/dev.txt; do',
      '  if [ -f "$f" ]; then pip install --no-cache-dir --quiet --target /deps -r "$f"; fi',
      'done',
      'if [ -f pyproject.toml ] || [ -f setup.py ]; then',
      '  pip install --no-cache-dir --quiet --target /deps ".[test]" 2>/dev/null || pip install --no-cache-dir --quiet --target /deps . || true',
      'fi',
      // OWASP A06: known-vulnerable installed packages (best effort; never fails the stage).
      'if command -v pip-audit >/dev/null; then PYTHONPATH= timeout 120 pip-audit --path /deps -f json -o /deps/audit.json --progress-spinner off >/dev/null 2>&1 || true; fi',
      'echo prepared',
    ].join('\n');
    const result = await this.run(
      [
        '--network', 'bridge',
        ...hardeningArgs(1536, 2),
        ...bind(this.options.workspacePath(workspace.id), '/src', true),
        ...bind(deps, '/deps', false),
        this.imageFor(language), 'sh', '-c', language === 'javascript' ? nodeScript : pythonScript,
      ],
      300_000,
      200_000,
      signal,
    );
    const audit = await readFile(join(deps, 'audit.json'), 'utf8').catch(() => undefined);
    return { ...result, depsId: workspace.id, audit };
  }

  async execute(request: ExecutionRequest, signal: AbortSignal): Promise<CapabilityResult<SandboxRun>> {
    return this.executeWith(request, request.workspace.id, signal);
  }

  /** Runs argv with network=none. `depsId` selects which prepared dependency folder to mount. */
  async executeWith(request: ExecutionRequest, depsId: string, signal: AbortSignal): Promise<CapabilityResult<SandboxRun>> {
    const out = join(this.options.scratchRoot, 'out', randomUUID());
    await mkdir(out, { recursive: true });
    await chmod(out, 0o777); // container runs as uid 10001
    const deps = this.depsPath(depsId);
    await mkdir(deps, { recursive: true });
    try {
      const result = await this.run(
        [
          '--network', 'none',
          ...hardeningArgs(request.memoryMb, request.cpuLimit),
          ...bind(this.options.workspacePath(request.workspace.id), '/src', true),
          ...bind(deps, '/deps', true),
          ...bind(out, '/out', false),
          this.imageFor(request.language),
          ...request.argv,
        ],
        request.timeoutMs,
        request.maxOutputBytes,
        signal,
      );
      const files: Record<string, string> = {};
      for (const name of ['junit.xml', 'bandit.json'])
        if (existsSync(join(out, name))) files[name] = (await readFile(join(out, name), 'utf8')).slice(0, 2_000_000);
      return {
        state: 'completed',
        data: { ...result, artifactId: '', files },
      };
    } catch (error) {
      return {
        code: 'CAPABILITY_UNAVAILABLE',
        state: 'failed',
        message: `Sandbox execution failed: ${error instanceof Error ? error.message : 'unknown error'}`,
      };
    } finally {
      await rm(out, { recursive: true, force: true });
    }
  }

  async cleanup(workspaceId: string) {
    await rm(this.depsPath(workspaceId), { recursive: true, force: true });
  }
}
