import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { listSourceFiles } from '../agents/intelligence.js';

/**
 * Token-efficient code search. Steps 1–2 of the funnel run locally with zero AI tokens:
 *   1. skip vendored/test/generated files, match dangerous "sinks" per vulnerability class
 *   2. score candidates (sink weight + user input nearby + scanner agreement), keep the top N,
 *      and cut each one down to its enclosing function using Python's ast module (parse only).
 * Only these small snippets are ever sent to the AI.
 */
export interface SinkRule {
  id: string;
  cwe: string;
  category: string;
  weight: number;
  pattern: RegExp;
}
export const PYTHON_SINKS: SinkRule[] = [
  { id: 'sql-format', cwe: 'CWE-89', category: 'SQL injection', weight: 9,
    pattern: /\.(execute|executemany|raw|executescript)\s*\(\s*(f["']|("[^"]*"|'[^']*')\s*(%|\+|\.format))/ },
  { id: 'sql-concat', cwe: 'CWE-89', category: 'SQL injection', weight: 7,
    pattern: /("(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"|'(SELECT|INSERT|UPDATE|DELETE)\b[^']*')\s*(\+|%|\.format)|f["'](SELECT|INSERT|UPDATE|DELETE)\b/i },
  { id: 'shell-true', cwe: 'CWE-78', category: 'Command injection', weight: 9,
    pattern: /subprocess\.\w+\([^)]*shell\s*=\s*True|os\.(system|popen)\s*\(/ },
  { id: 'eval-exec', cwe: 'CWE-95', category: 'Code injection', weight: 9, pattern: /(^|[^.\w])(eval|exec)\s*\(/ },
  { id: 'pickle', cwe: 'CWE-502', category: 'Unsafe deserialization', weight: 8,
    pattern: /\b(pickle|cPickle|dill|marshal)\.loads?\s*\(|\bshelve\.open\s*\(/ },
  { id: 'yaml-load', cwe: 'CWE-502', category: 'Unsafe deserialization', weight: 8,
    pattern: /yaml\.(load|load_all)\s*\((?![^)]*SafeLoader)/ },
  { id: 'path-join', cwe: 'CWE-22', category: 'Path traversal', weight: 6,
    pattern: /(open|send_file|send_from_directory|os\.path\.join|Path)\s*\([^)]*(request|filename|name|path|param|arg)/i },
  { id: 'tar-extract', cwe: 'CWE-22', category: 'Path traversal (archive)', weight: 7,
    pattern: /\.(extractall|extract)\s*\((?![^)]*filter\s*=)/ },
  { id: 'template-string', cwe: 'CWE-1336', category: 'Template injection', weight: 8,
    pattern: /render_template_string\s*\(|Template\s*\([^)]*request/ },
  { id: 'ssrf', cwe: 'CWE-918', category: 'Server-side request forgery', weight: 5,
    pattern: /(requests|httpx|urllib\.request)\.(get|post|urlopen|request)\s*\([^)]*(url|request|param)/i },
  { id: 'redirect', cwe: 'CWE-601', category: 'Open redirect', weight: 4, pattern: /redirect\s*\(\s*request\./ },
  { id: 'xxe', cwe: 'CWE-611', category: 'XML external entities', weight: 6,
    pattern: /(etree\.parse|etree\.fromstring|xml\.dom\.minidom\.parse|XMLParser\()/ },
  { id: 'weak-hash', cwe: 'CWE-328', category: 'Weak hashing', weight: 3, pattern: /hashlib\.(md5|sha1)\s*\(/ },
  { id: 'insecure-random', cwe: 'CWE-338', category: 'Insecure randomness', weight: 3,
    pattern: /random\.(random|randint|choice)\s*\([^)]*\).*(token|secret|password|key)/i },
  { id: 'tls-off', cwe: 'CWE-295', category: 'TLS verification disabled', weight: 5, pattern: /verify\s*=\s*False/ },
  { id: 'secret', cwe: 'CWE-798', category: 'Hardcoded credential', weight: 4,
    pattern: /(password|secret|api_key|token)\s*=\s*["'][^"']{8,}["']/i },
  { id: 'debug', cwe: 'CWE-489', category: 'Debug mode enabled', weight: 2, pattern: /\.run\([^)]*debug\s*=\s*True/ },
];
const USER_INPUT = /\brequest\.(args|form|values|json|files|cookies|headers|data|GET|POST|get_json|query_params|path_params)|\binput\(|sys\.argv|environ\[/;

export interface Candidate {
  id: string;
  file: string;
  line: number;
  startLine: number;
  endLine: number;
  cwe: string;
  category: string;
  rule: string;
  score: number;
  source: 'scanner' | 'scanner+ai' | 'ai';
  snippet: string;
}
export interface ExternalHit {
  file: string;
  line: number;
  cwe: string;
  category: string;
  rule: string;
}

/** Python helper: for each (file, line) return the enclosing def/class span. Parses, never executes. */
const SPAN_SCRIPT = `
import ast, json, sys
req = json.load(sys.stdin)
out = {}
for path, lines in req.items():
    try:
        tree = ast.parse(open(path, encoding='utf-8', errors='replace').read())
    except Exception:
        continue
    nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    spans = {}
    for line in lines:
        best = None
        for n in nodes:
            end = getattr(n, 'end_lineno', n.lineno)
            start = min([d.lineno for d in n.decorator_list] + [n.lineno])
            if start <= line <= end and (best is None or end - start < best[1] - best[0]):
                best = (start, end)
        if best: spans[str(line)] = best
    out[path] = spans
print(json.dumps(out))
`;
export async function functionSpans(
  root: string,
  wanted: Map<string, number[]>,
  python = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3'),
): Promise<Record<string, Record<string, [number, number]>>> {
  const request = Object.fromEntries([...wanted].map(([file, lines]) => [join(root, file), lines]));
  return new Promise((resolve) => {
    const child = spawn(python, ['-I', '-c', SPAN_SCRIPT], { windowsHide: true, timeout: 20_000 });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.on('error', () => resolve({}));
    child.on('close', () => {
      try {
        const raw = JSON.parse(out) as Record<string, Record<string, [number, number]>>;
        resolve(
          Object.fromEntries(
            Object.entries(raw).map(([full, spans]) => [
              full.slice(root.length + 1).split('\\').join('/'),
              spans,
            ]),
          ),
        );
      } catch {
        resolve({});
      }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

export function numbered(lines: string[], start: number, end: number) {
  return lines
    .slice(start - 1, end)
    .map((text, i) => `${String(start + i).padStart(4)}| ${text}`)
    .join('\n');
}

export async function findCandidates(
  root: string,
  options: { maxCandidates?: number; maxSnippetLines?: number; external?: ExternalHit[] } = {},
): Promise<{ candidates: Candidate[]; filesScanned: number; hits: number }> {
  const maxCandidates = options.maxCandidates ?? 6;
  const maxSnippetLines = options.maxSnippetLines ?? 45;
  const files = (await listSourceFiles(root)).filter((f) => !f.isTest && f.path.endsWith('.py'));
  const contents = new Map<string, string[]>();
  type Hit = Omit<Candidate, 'id' | 'startLine' | 'endLine' | 'snippet' | 'source'> & { external: boolean };
  const hits: Hit[] = [];
  for (const file of files) {
    const lines = (await readFile(join(root, file.path), 'utf8')).split(/\r?\n/);
    contents.set(file.path, lines);
    lines.forEach((text, i) => {
      if (/^\s*#/.test(text)) return;
      for (const rule of PYTHON_SINKS)
        if (rule.pattern.test(text))
          hits.push({ file: file.path, line: i + 1, cwe: rule.cwe, category: rule.category, rule: rule.id,
            score: rule.weight, external: false });
    });
  }
  for (const ext of options.external ?? []) {
    if (!contents.has(ext.file)) continue;
    const same = hits.find((h) => h.file === ext.file && Math.abs(h.line - ext.line) <= 2 && h.cwe === ext.cwe);
    if (same) same.score += 4; // scanner agreement
    else hits.push({ ...ext, score: 5, external: true });
  }
  if (!hits.length) return { candidates: [], filesScanned: files.length, hits: 0 };

  // Function spans for every hit, in one python process.
  const wanted = new Map<string, number[]>();
  for (const h of hits) wanted.set(h.file, [...(wanted.get(h.file) ?? []), h.line]);
  const spans = await functionSpans(root, wanted);

  const scored = hits.map((h) => {
    const lines = contents.get(h.file)!;
    const span = spans[h.file]?.[String(h.line)];
    let [start, end] = span ?? [Math.max(1, h.line - 8), Math.min(lines.length, h.line + 8)];
    const body = lines.slice(start - 1, end).join('\n');
    let score = h.score;
    if (USER_INPUT.test(body)) score += 4; // user input reaches the same function
    if (/@\w+\.(route|get|post|put|delete)\(|def (get|post|put|delete)\(self, request/.test(body)) score += 2;
    if (end - start + 1 > maxSnippetLines) {
      start = Math.max(start, h.line - Math.floor(maxSnippetLines / 2));
      end = Math.min(end, start + maxSnippetLines - 1);
    }
    return { ...h, score, startLine: start, endLine: end };
  });
  // One candidate per function: keep the highest-scoring hit, sum evidence from the rest.
  const byFunction = new Map<string, (typeof scored)[number] & { rules: string[] }>();
  for (const h of scored) {
    const key = `${h.file}:${h.startLine}`;
    const prev = byFunction.get(key);
    if (!prev) byFunction.set(key, { ...h, rules: [h.rule] });
    else {
      prev.rules.push(h.rule);
      if (h.score > prev.score) Object.assign(prev, { ...h, rules: prev.rules, score: h.score + 1 });
      else prev.score += 1;
    }
  }
  const candidates = [...byFunction.values()]
    .sort((a, b) => b.score - a.score || a.file.localeCompare(b.file) || a.line - b.line)
    .slice(0, maxCandidates)
    .map((h, i) => ({
      id: `C${i + 1}`,
      file: h.file,
      line: h.line,
      startLine: h.startLine,
      endLine: h.endLine,
      cwe: h.cwe,
      category: h.category,
      rule: h.rules.join('+'),
      score: h.score,
      source: 'scanner' as const,
      snippet: numbered(contents.get(h.file)!, h.startLine, h.endLine),
    }));
  return { candidates, filesScanned: files.length, hits: hits.length };
}

/** Imports at the top of a file (needed so the AI can write a correct patch). */
export function importLines(lines: string[]) {
  return lines
    .map((text, i) => ({ text, n: i + 1 }))
    .filter((l) => /^(import |from \S+ import )/.test(l.text))
    .slice(0, 30)
    .map((l) => `${String(l.n).padStart(4)}| ${l.text}`)
    .join('\n');
}

export const contentHash = (text: string) => createHash('sha256').update(text).digest('hex');
