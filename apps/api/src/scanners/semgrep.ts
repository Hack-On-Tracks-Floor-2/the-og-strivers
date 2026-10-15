import type { ExternalHit } from './funnel.js';

/**
 * Semgrep adapter. The scanner runs in its own sandbox image (proofpatch-semgrep) with a pinned CLI and
 * pinned, trusted security rules baked in (see docker/runner-semgrep). It never reads a repository's own
 * Semgrep config and never applies autofixes. Results become external hits for the search funnel, next
 * to Bandit and ProofPatch's own rules, so every finding keeps the scanners that reported it.
 */
export const SEMGREP_VERSION = '1.178.0';
export const SEMGREP_RULES_COMMIT = '9bbf021d0acffa3095fcffd17b2bc7787eb4796d';

/** Rule folders baked into the image, by repository language (as named in the repository map). */
const RULE_DIRS: Record<string, string[]> = {
  Python: ['python'], JavaScript: ['javascript'], TypeScript: ['typescript', 'javascript'], Java: ['java'],
  Kotlin: ['kotlin', 'java'], Go: ['go'], PHP: ['php'], Ruby: ['ruby'], 'C#': ['csharp'], Rust: ['rust'], C: ['c'], 'C++': ['c'],
};

/** Rule folders for every detected language (mixed-language repositories are scanned for all of them). */
export function semgrepRuleDirs(languages: string[]) {
  return [...new Set(languages.flatMap((l) => RULE_DIRS[l] ?? []))];
}

/** Semgrep command line: pinned rule folders only, JSON to /out, bounded time and file size. */
export function semgrepArgv(ruleDirs: string[]) {
  return [
    'semgrep', 'scan',
    ...ruleDirs.flatMap((d) => ['--config', `/rules/${d}`]),
    '--json', '--output', '/out/semgrep.json',
    '--metrics=off', '--disable-version-check',
    '--timeout', '20', '--timeout-threshold', '3', '--max-target-bytes', '500000', '--jobs', '1',
    ...['tests', 'test', 'spec', '__tests__', 'node_modules', 'vendor', 'dist', 'build', 'target'].flatMap((d) => ['--exclude', d]),
    '.',
  ];
}

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: { message?: string; severity?: string; metadata?: { cwe?: string | string[]; owasp?: string | string[]; confidence?: string } };
}
export interface SemgrepHit extends ExternalHit {
  severity: string;
  column: number;
}

/** Parses `semgrep --json`. Returns null when the report is missing or not JSON (scanner failure). */
export function parseSemgrep(text: string | undefined): { hits: SemgrepHit[]; errors: number } | null {
  if (!text?.trim()) return null;
  let json: { results?: SemgrepResult[]; errors?: unknown[] };
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  const hits = (json.results ?? []).map((r) => {
    const cwes = ([] as string[]).concat(r.extra.metadata?.cwe ?? []);
    const cwe = /CWE-\d+/.exec(cwes[0] ?? '')?.[0] ?? 'CWE-20';
    return {
      file: r.path.replace(/^\.\//, ''),
      line: r.start.line,
      column: r.start.col,
      cwe,
      category: (r.extra.message ?? r.check_id).replace(/\s+/g, ' ').slice(0, 120),
      rule: `semgrep:${r.check_id.split('.').slice(-1)[0]}`,
      severity: r.extra.severity ?? 'INFO',
    };
  });
  return { hits, errors: (json.errors ?? []).length };
}

/** Which scanners contributed to a candidate, from its joined rule ids ("semgrep:x+bandit:B602+shell-true"). */
export function scannersOf(rule: string): string[] {
  const names = rule.split('+').map((id) =>
    id.startsWith('semgrep:') ? 'Semgrep' : id.startsWith('bandit:') ? 'Bandit' : id === 'trained-model' ? 'Trained model' : 'ProofPatch rules',
  );
  return [...new Set(names)];
}
