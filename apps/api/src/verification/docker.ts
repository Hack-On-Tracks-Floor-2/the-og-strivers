import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
import type { ExecutionRequest, ExecutionResult, SandboxExecutionAdapter } from './sandbox.js';
import type { Runtime } from '../agents/toolchain.js';

export interface DockerOptions {
  image: string;
  /** Runner images for the other runtimes (defaults: proofpatch-runner:node22 / go122 / php83). */
  nodeImage?: string;
  goImage?: string;
  phpImage?: string;
  javaImage?: string;
  dotnetImage?: string;
  rubyImage?: string;
  rustImage?: string;
  cImage?: string;
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

  private imageFor(runtime: Runtime = 'python') {
    return {
      python: this.options.image,
      node: this.options.nodeImage ?? 'proofpatch-runner:node22',
      go: this.options.goImage ?? 'proofpatch-runner:go122',
      php: this.options.phpImage ?? 'proofpatch-runner:php83',
      java: this.options.javaImage ?? 'proofpatch-runner:java21',
      dotnet: this.options.dotnetImage ?? 'proofpatch-runner:dotnet8',
      ruby: this.options.rubyImage ?? 'proofpatch-runner:ruby33',
      rust: this.options.rustImage ?? 'proofpatch-runner:rust180',
      c: this.options.cImage ?? 'proofpatch-runner:c13',
    }[runtime];
  }

  depsPath(workspaceId: string) {
    return join(this.options.scratchRoot, 'deps', workspaceId);
  }

  /**
   * Isolated preparation stage: installs the repository's declared dependencies into a
   * dependency folder. This is the ONLY stage with network access; it still runs as a
   * non-root user with no capabilities and resource limits. Tests later mount it read-only.
   */
  async prepare(workspace: WorkspaceHandle, signal: AbortSignal, runtime: Runtime = 'python') {
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
    // Go modules land in /deps/gomod (GOMODCACHE in the image); tests later run with GOPROXY=off.
    const goScript = [
      'set -e',
      'GOPROXY=https://proxy.golang.org,direct go mod download',
      'echo prepared',
    ].join('\n');
    // Composer with scripts and plugins disabled; the autoloader is regenerated per test run.
    const phpScript = [
      'set -e',
      'cp composer.json /deps/composer.json',
      'if [ -f composer.lock ]; then cp composer.lock /deps/; fi',
      'cd /deps',
      'composer install --no-scripts --no-plugins --no-interaction --prefer-dist --no-progress --no-autoloader -q',
      // OWASP A06: known-vulnerable packages (best effort; never fails the stage).
      'timeout 90 composer audit --format=json --no-interaction > /deps/audit.json 2>/dev/null || true',
      'echo prepared',
    ].join('\n');
    // Maven: download every dependency and plugin, then compile and resolve the Surefire runner with a
    // test filter that matches nothing, so no repository test code runs while the network is on.
    const javaScript = [
      'set -e',
      'mvn -B -q -Dmaven.repo.local=/deps/m2 dependency:go-offline || true',
      // Surefire downloads its JUnit provider only when it runs a test: run an empty probe test that
      // exists only in this private copy (never the repository's own tests).
      'mkdir -p src/test/java',
      'if grep -q "junit-jupiter\\|junit-bom" pom.xml || ! grep -q "<artifactId>junit</artifactId>" pom.xml; then',
      '  printf "public class ProofPatchProbeTest { @org.junit.jupiter.api.Test void probe() {} }\\n" > src/test/java/ProofPatchProbeTest.java',
      'else',
      '  printf "public class ProofPatchProbeTest { @org.junit.Test public void probe() {} }\\n" > src/test/java/ProofPatchProbeTest.java',
      'fi',
      'mvn -B -q -Dmaven.repo.local=/deps/m2 test -Dtest=ProofPatchProbeTest -Dsurefire.failIfNoSpecifiedTests=false',
      'echo prepared',
    ].join('\n');
    // NuGet packages for every project land in /deps/nuget (NUGET_PACKAGES); tests restore offline from it.
    const dotnetScript = [
      'set -e',
      'for p in $(find . -name "*.csproj" -not -path "*/bin/*" -not -path "*/obj/*"); do dotnet restore "$p" --packages /deps/nuget --verbosity quiet; done',
      'echo prepared',
    ].join('\n');
    // Bundler installs into /deps/bundle; the resolved lockfile is kept so tests resolve offline.
    const rubyScript = [
      'set -e',
      'BUNDLE_PATH=/deps/bundle bundle install --jobs 4 --quiet',
      'cp Gemfile.lock /deps/Gemfile.lock',
      'echo prepared',
    ].join('\n');
    // Cargo registry and crates go to /deps/cargo; the lockfile is kept for offline builds.
    const rustScript = [
      'set -e',
      'CARGO_HOME=/deps/cargo CARGO_NET_OFFLINE=false cargo fetch',
      'cp Cargo.lock /deps/Cargo.lock',
      'echo prepared',
    ].join('\n');
    // C/C++ has no package manager: only CMake FetchContent sources are downloaded (configure step, no build).
    const cScript = [
      'set -e',
      'if [ -f CMakeLists.txt ]; then cmake -S . -B /tmp/prepare-build -DFETCHCONTENT_BASE_DIR=/deps/fetch > /dev/null; fi',
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
        this.imageFor(runtime), 'sh', '-c', { python: pythonScript, node: nodeScript, go: goScript, php: phpScript, java: javaScript, dotnet: dotnetScript, ruby: rubyScript, rust: rustScript, c: cScript }[runtime],
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
