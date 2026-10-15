import { readFile, readdir, stat } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';
import type { CapabilityResult, RepositoryIntelligenceAgent, RepositoryMap, WorkspaceHandle } from './contracts.js';

/** Folders never worth reading for vulnerability search (saves tokens and time). */
export const IGNORED_DIRS = new Set([
  '.git', 'node_modules', 'vendor', 'third_party', 'dist', 'build', '.venv', 'venv', 'env',
  '__pycache__', '.tox', '.mypy_cache', '.pytest_cache', 'site-packages', 'docs', 'doc',
  'examples', 'migrations', '.github', 'coverage', 'htmlcov', 'static', 'assets',
]);
const LANGUAGES: Record<string, string> = {
  '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.go': 'Go', '.java': 'Java',
  '.rb': 'Ruby', '.php': 'PHP', '.rs': 'Rust', '.c': 'C', '.cpp': 'C++',
};
const FRAMEWORKS: [RegExp, string][] = [
  [/\bflask\b/i, 'Flask'], [/\bdjango\b/i, 'Django'], [/\bfastapi\b/i, 'FastAPI'],
  [/\bstarlette\b/i, 'Starlette'], [/\btornado\b/i, 'Tornado'], [/\bexpress\b/i, 'Express'],
];

export interface SourceFile {
  path: string; // relative, forward slashes
  bytes: number;
  isTest: boolean;
}
export const isTestPath = (p: string) =>
  /(^|\/)(tests?|testing)\//.test(p) || /(^|\/)(test_[^/]+|[^/]+_test)\.py$/.test(p) || /conftest\.py$/.test(p);

/** Lists source files, skipping vendored/generated folders and anything over 200 KB. */
export async function listSourceFiles(root: string): Promise<SourceFile[]> {
  const out: SourceFile[] = [];
  const walk = async (dir: string) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) await walk(join(dir, entry.name));
      } else if (entry.isFile() && LANGUAGES[extname(entry.name)]) {
        const full = join(dir, entry.name);
        const size = (await stat(full)).size;
        if (size > 200_000 || /\.min\.js$/.test(entry.name)) continue;
        const path = relative(root, full).split('\\').join('/');
        out.push({ path, bytes: size, isTest: isTestPath(path) });
      }
    }
  };
  await walk(root);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

async function readIfExists(path: string) {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

export async function inspectRepository(root: string): Promise<RepositoryMap> {
  const files = await listSourceFiles(root);
  const counts = new Map<string, number>();
  for (const f of files) {
    const lang = LANGUAGES[extname(f.path)];
    counts.set(lang, (counts.get(lang) ?? 0) + 1);
  }
  const languages = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([l]) => l);
  const manifests = (
    await Promise.all(
      ['requirements.txt', 'requirements-dev.txt', 'pyproject.toml', 'setup.py', 'setup.cfg', 'package.json'].map(
        (m) => readIfExists(join(root, m)),
      ),
    )
  ).join('\n');
  const frameworks = FRAMEWORKS.filter(([re]) => re.test(manifests)).map(([, name]) => name);
  const entryPoints = files
    .filter((f) => !f.isTest && /(^|\/)(app|main|server|wsgi|asgi|views|routes|api)\.py$/.test(f.path))
    .map((f) => f.path)
    .slice(0, 20);
  const testCommands: string[][] = [];
  const hasPyTests = files.some((f) => f.isTest && f.path.endsWith('.py'));
  if (languages[0] === 'Python' && hasPyTests)
    testCommands.push(['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider']);
  return { languages, frameworks, entryPoints, testCommands };
}

export function repositoryIntelligence(workspacePath: (id: string) => string): RepositoryIntelligenceAgent {
  return {
    async inspect(workspace: WorkspaceHandle): Promise<CapabilityResult<RepositoryMap>> {
      const map = await inspectRepository(workspacePath(workspace.id));
      if (!map.testCommands.length)
        return {
          code: 'CAPABILITY_UNAVAILABLE',
          state: 'not_implemented',
          message: `No supported test suite found (languages: ${map.languages.join(', ') || 'none'}). This version supports Python repositories with a pytest suite.`,
        };
      return { state: 'completed', data: map };
    },
  };
}
