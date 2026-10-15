import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { listSourceFiles } from '../agents/intelligence.js';
import type { Locator } from './locator.js';
import { JS_ROUTE, JS_SINKS, JS_USER_INPUT, jsFunctionSpans } from './javascript.js';

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
  // OWASP Top 10 coverage beyond the classic sinks (category follows from the CWE, see owaspFor()).
  { id: 'cors-wildcard', cwe: 'CWE-942', category: 'Permissive CORS', weight: 3,
    pattern: /CORS\([^)]*(origins\s*=\s*["']\*|supports_credentials\s*=\s*True)|Access-Control-Allow-Origin["']?\s*[\]:,=]\s*["']\*/ },
  { id: 'temp-file', cwe: 'CWE-377', category: 'Insecure temporary file', weight: 3, pattern: /tempfile\.mktemp\s*\(/ },
  { id: 'weak-cipher', cwe: 'CWE-327', category: 'Broken cipher', weight: 5,
    pattern: /\b(DES|DES3|ARC4|Blowfish)\.new\s*\(|MODE_ECB|algorithms\.(TripleDES|ARC4|Blowfish)\b/ },
  { id: 'password-hash', cwe: 'CWE-916', category: 'Weak password hashing', weight: 5,
    pattern: /hashlib\.(md5|sha1|sha224|sha256)\s*\([^)]*(password|passwd|pwd)/i },
  { id: 'nosql', cwe: 'CWE-943', category: 'NoSQL injection', weight: 6,
    pattern: /["']\$where["']|\.(find|find_one|update_one|delete_one|aggregate)\s*\(\s*(request\.|json\.loads\s*\(\s*request)/ },
  { id: 'xss-markup', cwe: 'CWE-79', category: 'Cross-site scripting', weight: 6,
    pattern: /Markup\s*\(\s*(f["']|[^)]*(%|\+|\.format\())|autoescape\s*=\s*False|mark_safe\s*\(\s*(f["']|[^)]*request)|\|\s*safe\s*\}\}|make_response\s*\(\s*f["'][^"']*<[^"']*\{/ },
  { id: 'ldap-xpath', cwe: 'CWE-90', category: 'LDAP/XPath injection', weight: 6,
    pattern: /\.(search_s|search|xpath)\s*\([^)]*(f["'][^"']*\{|["']\s*%\s*|["']\s*\+)/ },
  { id: 'mass-assign', cwe: 'CWE-915', category: 'Mass assignment', weight: 4,
    pattern: /\*\*\s*request\.(json|form|args|get_json\s*\(\s*\))|__dict__\.update\s*\(\s*request\.|setattr\s*\([^)]*request\.(json|form)/ },
  { id: 'cookie-insecure', cwe: 'CWE-614', category: 'Insecure cookie', weight: 3,
    pattern: /set_cookie\s*\([^)]*(secure\s*=\s*False|httponly\s*=\s*False)|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False/ },
  { id: 'jwt-unverified', cwe: 'CWE-347', category: 'JWT signature not verified', weight: 7,
    pattern: /jwt\.decode\s*\([^)]*(verify\s*=\s*False|["']verify_signature["']\s*:\s*False|algorithms\s*=\s*\[[^\]]*["']none["'])/i },
  { id: 'log-secret', cwe: 'CWE-532', category: 'Secret written to logs', weight: 3,
    pattern: /(log(ger|ging)?\.(debug|info|warning|error|critical|exception)|print)\s*\([^)]*\b(password|passwd|secret|token|api_key|apikey)\b/i },
  { id: 'swallowed-error', cwe: 'CWE-390', category: 'Exception silently swallowed', weight: 2, pattern: /except(\s+[\w.]+(\s+as\s+\w+)?)?\s*:\s*pass\b/ },
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
  /** Trained-model risk for the enclosing function (0-1), when the model ran. */
  modelScore?: number;
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

/** Python helper: every def span in each file (outermost-first order irrelevant). Parses, never executes. */
const ALL_SPANS_SCRIPT = `
import ast, json, sys
out = {}
for path in json.load(sys.stdin):
    try:
        tree = ast.parse(open(path, encoding='utf-8', errors='replace').read())
    except Exception:
        continue
    out[path] = [[min([d.lineno for d in n.decorator_list] + [n.lineno]), getattr(n, 'end_lineno', n.lineno)]
                 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
print(json.dumps(out))
`;
async function allFunctionSpans(root: string, files: string[], python = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3')) {
  return new Promise<Record<string, [number, number][]>>((resolve) => {
    const child = spawn(python, ['-I', '-c', ALL_SPANS_SCRIPT], { windowsHide: true, timeout: 20_000 });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.on('error', () => resolve({}));
    child.on('close', () => {
      try {
        const raw = JSON.parse(out) as Record<string, [number, number][]>;
        resolve(Object.fromEntries(Object.entries(raw).map(([full, s]) => [full.slice(root.length + 1).split('\\').join('/'), s])));
      } catch {
        resolve({});
      }
    });
    child.stdin.end(JSON.stringify(files.map((f) => join(root, f))));
  });
}

interface ModelFunction {
  file: string;
  start: number;
  end: number;
  score: number;
  riskiestLine: number;
  riskiestScore: number;
}
/** Scores every function with the trained locator (the scorer converts source to its trained statement format). */
async function scoreFunctions(root: string, files: string[], contents: Map<string, string[]>, locator: Locator, maxFunctions = 600) {
  const spans = await allFunctionSpans(root, files);
  const fns: { id: string; file: string; start: number; end: number; source: string }[] = [];
  for (const [file, list] of Object.entries(spans)) {
    const lines = contents.get(file);
    if (!lines) continue;
    for (const [start, end] of list)
      fns.push({ id: String(fns.length), file, start, end, source: lines.slice(start - 1, end).join('\n') });
  }
  const batch = fns.slice(0, maxFunctions);
  const { scores, threshold } = await locator.score(batch.map((f) => ({ id: f.id, source: f.source, start: f.start })));
  const byId = new Map(batch.map((f) => [f.id, f]));
  const scored: ModelFunction[] = [];
  for (const s of scores) {
    const f = byId.get(s.id);
    if (!f || !s.lines.length) continue;
    const top = s.lines.indexOf(Math.max(...s.lines));
    scored.push({ file: f.file, start: f.start, end: f.end, score: s.score, riskiestLine: s.line_numbers?.[top] ?? f.start, riskiestScore: s.lines[top]! });
  }
  return { scored, threshold, total: fns.length };
}

export interface ModelSummary {
  functionsScored: number;
  functionsTotal: number;
  threshold: number;
  flagged: number;
  modelOnly: number;
  error?: string;
}

/** Appends a marker to the line the trained model rates riskiest, so the AI looks there first. */
function markRiskiest(snippet: string, m?: ModelFunction) {
  if (!m || m.riskiestScore < 0.2) return snippet;
  const tag = String(m.riskiestLine).padStart(4) + '| ';
  return snippet
    .split('\n')
    .map((l) => (l.startsWith(tag) ? `${l}  # <- trained model: riskiest line (${Math.round(m.riskiestScore * 100)}%)` : l))
    .join('\n');
}

export function numbered(lines: string[], start: number, end: number) {
  return lines
    .slice(start - 1, end)
    .map((text, i) => `${String(start + i).padStart(4)}| ${text}`)
    .join('\n');
}

export async function findCandidates(
  root: string,
  options: {
    maxCandidates?: number;
    maxSnippetLines?: number;
    external?: ExternalHit[];
    locator?: Locator | null;
    language?: 'python' | 'javascript';
  } = {},
): Promise<{ candidates: Candidate[]; filesScanned: number; hits: number; model?: ModelSummary }> {
  const maxCandidates = options.maxCandidates ?? 6;
  const maxSnippetLines = options.maxSnippetLines ?? 45;
  const js = options.language === 'javascript';
  const sinks = js ? JS_SINKS : PYTHON_SINKS;
  const files = (await listSourceFiles(root)).filter((f) => !f.isTest && (js ? /\.[cm]?js$/.test(f.path) : f.path.endsWith('.py')));
  const contents = new Map<string, string[]>();
  type Hit = Omit<Candidate, 'id' | 'startLine' | 'endLine' | 'snippet' | 'source'> & { external: boolean };
  const hits: Hit[] = [];
  for (const file of files) {
    const lines = (await readFile(join(root, file.path), 'utf8')).split(/\r?\n/);
    contents.set(file.path, lines);
    lines.forEach((text, i) => {
      if (js ? /^\s*(\/\/|\*|\/\*)/.test(text) : /^\s*#/.test(text)) return;
      for (const rule of sinks)
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
  // Trained model: scores every function, so it can rank regex hits and surface code the rules miss.
  let modelFns: ModelFunction[] = [];
  let model: ModelSummary | undefined;
  if (options.locator && !js) {
    try {
      const r = await scoreFunctions(root, files.map((f) => f.path), contents, options.locator);
      modelFns = r.scored;
      model = { functionsScored: r.scored.length, functionsTotal: r.total, threshold: r.threshold,
        flagged: r.scored.filter((f) => f.score >= r.threshold).length, modelOnly: 0 };
    } catch (error) {
      model = { functionsScored: 0, functionsTotal: 0, threshold: 0, flagged: 0, modelOnly: 0,
        error: error instanceof Error ? error.message.slice(0, 200) : 'locator failed' };
    }
  }
  const threshold = model?.threshold || 1;
  const modelFor = (file: string, line: number) =>
    modelFns
      .filter((f) => f.file === file && f.start <= line && line <= f.end)
      .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
  if (!hits.length && !modelFns.some((f) => f.score >= threshold))
    return { candidates: [], filesScanned: files.length, hits: 0, model };

  // Function spans for every hit, in one python process.
  const wanted = new Map<string, number[]>();
  for (const h of hits) wanted.set(h.file, [...(wanted.get(h.file) ?? []), h.line]);
  const spans = js ? await jsFunctionSpans(root, wanted) : await functionSpans(root, wanted);

  const scored = hits.map((h) => {
    const lines = contents.get(h.file)!;
    const span = spans[h.file]?.[String(h.line)];
    let [start, end] = span ?? [Math.max(1, h.line - 8), Math.min(lines.length, h.line + 8)];
    const body = lines.slice(start - 1, end).join('\n');
    let score = h.score;
    if ((js ? JS_USER_INPUT : USER_INPUT).test(body)) score += 4; // user input reaches the same function
    if (js ? JS_ROUTE.test(body) : /@\w+\.(route|get|post|put|delete)\(|def (get|post|put|delete)\(self, request/.test(body)) score += 2;
    const m = modelFor(h.file, h.line);
    if (m) score += Math.round(m.score * 10); // trained model agrees this function is risky
    if (end - start + 1 > maxSnippetLines) {
      start = Math.max(start, h.line - Math.floor(maxSnippetLines / 2));
      end = Math.min(end, start + maxSnippetLines - 1);
    }
    return { ...h, score, startLine: start, endLine: end, model: m };
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
  // Functions only the model flags (no regex hit): its strongest few become candidates too.
  const covered = new Set([...byFunction.values()].map((h) => h.model));
  const modelOnly = modelFns
    .filter((f) => f.score >= threshold && !covered.has(f))
    .sort((a, b) => b.score - a.score)
    .slice(0, 4);
  if (model) model.modelOnly = modelOnly.length;
  for (const f of modelOnly) {
    let [start, end] = [f.start, f.end];
    if (end - start + 1 > maxSnippetLines) {
      start = Math.max(start, f.riskiestLine - Math.floor(maxSnippetLines / 2));
      end = Math.min(end, start + maxSnippetLines - 1);
    }
    byFunction.set(`${f.file}:${start}`, { file: f.file, line: f.riskiestLine, cwe: 'CWE-noinfo',
      category: 'Flagged by trained model', rule: 'trained-model', score: Math.round(f.score * 10) + 2,
      external: false, startLine: start, endLine: end, model: f, rules: ['trained-model'] });
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
      snippet: markRiskiest(numbered(contents.get(h.file)!, h.startLine, h.endLine), h.model),
      ...(h.model ? { modelScore: Math.round(h.model.score * 100) / 100 } : {}),
    }));
  return { candidates, filesScanned: files.length, hits: hits.length, model };
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
