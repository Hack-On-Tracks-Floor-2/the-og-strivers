import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import ts from 'typescript';
import type { SinkRule } from './funnel.js';

/**
 * JavaScript/Node rules for the local search funnel (zero AI tokens). Same idea as the Python sinks:
 * dangerous calls, scored higher when user input (req.query/params/body…) reaches the same function.
 */
export const JS_SINKS: SinkRule[] = [
  { id: 'js-sql-template', cwe: 'CWE-89', category: 'SQL injection', weight: 9,
    pattern: /\.(query|execute|raw|all|get|run|prepare|exec)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+)/ },
  { id: 'js-sql-concat', cwe: 'CWE-89', category: 'SQL injection', weight: 7,
    pattern: /(["'`]\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*["'`]?\s*\+|`\s*(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{)/i },
  { id: 'js-exec', cwe: 'CWE-78', category: 'Command injection', weight: 9,
    pattern: /\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_$][\w$.]*\s*[,)])/ },
  { id: 'js-spawn-shell', cwe: 'CWE-78', category: 'Command injection', weight: 8,
    pattern: /\b(spawn|spawnSync|execFile|execFileSync)\s*\([^)]*shell\s*:\s*true/ },
  { id: 'js-eval', cwe: 'CWE-95', category: 'Code injection', weight: 9,
    pattern: /(^|[^.\w$])(eval\s*\(|new\s+Function\s*\(|vm\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\()/ },
  { id: 'js-path', cwe: 'CWE-22', category: 'Path traversal', weight: 6,
    pattern: /\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|sendFile|download|join|resolve)\s*\([^)]*\b(req\.|params|query|body|name|file|filename|path)\b/i },
  { id: 'js-deserialize', cwe: 'CWE-502', category: 'Unsafe deserialization', weight: 8,
    pattern: /\b(unserialize|deserialize)\s*\(|require\(\s*["']node-serialize["']\s*\)/ },
  { id: 'js-yaml-load', cwe: 'CWE-502', category: 'Unsafe deserialization', weight: 6, pattern: /yaml\.load\s*\((?![^)]*(JSON_SCHEMA|FAILSAFE|CORE)_?SCHEMA)/ },
  { id: 'js-redirect', cwe: 'CWE-601', category: 'Open redirect', weight: 5, pattern: /\.redirect\s*\(\s*(req\.|request\.)/ },
  { id: 'js-ssrf', cwe: 'CWE-918', category: 'Server-side request forgery', weight: 5,
    pattern: /\b(fetch|axios(\.(get|post|request))?|https?\.(get|request)|got|request)\s*\(\s*(req\.|request\.|url\b|[`"'][^`"']*\$\{)/ },
  { id: 'js-xss', cwe: 'CWE-79', category: 'Cross-site scripting', weight: 6,
    pattern: /(res\.(send|write|end)\s*\(\s*`[^`]*<[^`]*\$\{|\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()/ },
  { id: 'js-proto', cwe: 'CWE-1321', category: 'Prototype pollution', weight: 5, pattern: /\[\s*(key|k|prop|name)\s*\]\s*=(?!=)/ },
  { id: 'js-regex', cwe: 'CWE-1333', category: 'Regular expression from input', weight: 4, pattern: /new\s+RegExp\s*\(\s*(req\.|request\.)/ },
  { id: 'js-weak-hash', cwe: 'CWE-328', category: 'Weak hashing', weight: 3, pattern: /createHash\s*\(\s*["'](md5|sha1)["']/ },
  { id: 'js-insecure-random', cwe: 'CWE-338', category: 'Insecure randomness', weight: 3, pattern: /Math\.random\s*\(\).*(token|secret|password|key|session)/i },
  { id: 'js-tls-off', cwe: 'CWE-295', category: 'TLS verification disabled', weight: 5,
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/ },
  { id: 'js-secret', cwe: 'CWE-798', category: 'Hardcoded credential', weight: 4,
    pattern: /(password|secret|api_?key|token)\s*[:=]\s*["'][^"']{8,}["']/i },
];
export const JS_USER_INPUT = /\b(req|request|ctx\.request)\.(query|params|body|headers|cookies|files|url)\b|process\.argv|\bctx\.(query|params)\b/;
export const JS_ROUTE = /\b(app|router|server)\.(get|post|put|patch|delete|all|use)\s*\(/;

/** Enclosing function span for each (file, line), parsed with the TypeScript parser. Parses only, never runs. */
export async function jsFunctionSpans(root: string, wanted: Map<string, number[]>) {
  const out: Record<string, Record<string, [number, number]>> = {};
  for (const [file, lines] of wanted) {
    const text = await readFile(join(root, file), 'utf8').catch(() => null);
    if (text === null) continue;
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    const spans: [number, number][] = [];
    const visit = (node: ts.Node) => {
      if (
        ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node) || ts.isGetAccessor(node) || ts.isSetAccessor(node)
      ) {
        // Include a route registration around an inline handler: app.get('/x', (req, res) => {...})
        let target: ts.Node = node;
        if (ts.isCallExpression(node.parent) && ts.isExpressionStatement(node.parent.parent)) target = node.parent.parent;
        else if (ts.isVariableDeclaration(node.parent)) target = node.parent.parent.parent ?? node.parent;
        const start = source.getLineAndCharacterOfPosition(target.getStart(source)).line + 1;
        const end = source.getLineAndCharacterOfPosition(target.getEnd()).line + 1;
        spans.push([start, end]);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
    out[file] = {};
    for (const line of lines) {
      const best = spans
        .filter(([s, e]) => s <= line && line <= e)
        .sort((a, b) => a[1] - a[0] - (b[1] - b[0]))[0];
      if (best) out[file][String(line)] = best;
    }
  }
  return out;
}

/** require()/import lines at the top of a JavaScript file (so the AI can write a correct patch). */
export function jsImportLines(lines: string[]) {
  return lines
    .map((text, i) => ({ text, n: i + 1 }))
    .filter((l) => /^\s*(import\s.+from\s|import\s+["']|(const|let|var)\s.+=\s*require\()/.test(l.text))
    .slice(0, 30)
    .map((l) => `${String(l.n).padStart(4)}| ${l.text}`)
    .join('\n');
}
