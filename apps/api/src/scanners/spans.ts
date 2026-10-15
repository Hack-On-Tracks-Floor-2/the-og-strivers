import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { SIGNATURE } from './languages.js';

/** Removes string/char literals and line comments so braces inside them do not count. */
function codeOnly(line: string) {
  return line
    .replace(/\\./g, '')
    .replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '""')
    .replace(/\/\/.*$|#(?!\[).*$/, '');
}

/** Function spans for brace languages: a signature line, then the block until its braces balance. */
function braceSpans(lines: string[], signature: RegExp): [number, number][] {
  const spans: [number, number][] = [];
  let inBlockComment = false;
  const clean = lines.map((raw) => {
    let line = raw;
    if (inBlockComment) {
      const end = line.indexOf('*/');
      if (end < 0) return '';
      line = line.slice(end + 2);
      inBlockComment = false;
    }
    line = line.replace(/\/\*.*?\*\//g, '');
    const start = line.indexOf('/*');
    if (start >= 0) {
      inBlockComment = true;
      line = line.slice(0, start);
    }
    return codeOnly(line);
  });
  for (let i = 0; i < lines.length; i++) {
    if (!signature.test(lines[i])) continue;
    // The body must open within the signature or the next 3 lines (multi-line parameter lists).
    let depth = 0;
    let opened = false;
    let end = -1;
    for (let j = i; j < lines.length; j++) {
      if (!opened && j > i + 3) break;
      if (!opened && j > i && /;\s*$/.test(clean[j - 1])) break; // a declaration, not a definition
      for (const ch of clean[j]) {
        if (ch === '{') {
          depth += 1;
          opened = true;
        } else if (ch === '}') depth -= 1;
      }
      if (opened && depth <= 0) {
        end = j;
        break;
      }
    }
    if (end >= 0) spans.push([i + 1, end + 1]);
  }
  return spans;
}

/** Ruby: "def" until the "end" at the same indentation. */
function rubySpans(lines: string[]): [number, number][] {
  const spans: [number, number][] = [];
  lines.forEach((line, i) => {
    const m = /^(\s*)def\s+/.exec(line);
    if (!m) return;
    if (/\bend\s*$/.test(line) || /=\s*[^=]/.test(line.replace(/^\s*def\s+[\w.?!]+(\([^)]*\))?/, ''))) {
      spans.push([i + 1, i + 1]); // one-line or endless method
      return;
    }
    for (let j = i + 1; j < lines.length; j++)
      if (new RegExp(`^${m[1]}end\\b`).test(lines[j])) {
        spans.push([i + 1, j + 1]);
        return;
      }
  });
  return spans;
}

const familyOf = (language: string) =>
  ({ csharp: 'java', c: 'java', cpp: 'java', kotlin: 'kotlin', go: 'go', rust: 'rust', php: 'php', ruby: 'ruby', java: 'java' })[language] ?? 'java';

/** Enclosing function span for each (file, line), for the brace languages and Ruby. Parses text only. */
export async function textFunctionSpans(root: string, wanted: Map<string, number[]>, language: string) {
  const out: Record<string, Record<string, [number, number]>> = {};
  const family = familyOf(language);
  for (const [file, lines] of wanted) {
    const text = await readFile(join(root, file), 'utf8').catch(() => null);
    if (text === null) continue;
    const all = text.split(/\r?\n/);
    const spans = family === 'ruby' ? rubySpans(all) : braceSpans(all, SIGNATURE[family]);
    out[file] = {};
    for (const line of lines) {
      const best = spans.filter(([s, e]) => s <= line && line <= e).sort((a, b) => a[1] - a[0] - (b[1] - b[0]))[0];
      if (best) out[file][String(line)] = best;
    }
  }
  return out;
}

/** Import/use lines at the top of a file, for the patch prompt (any language). */
export function genericImportLines(lines: string[]) {
  return lines
    .map((text, i) => ({ text, n: i + 1 }))
    .filter((l) => /^\s*(import\b|from\s+\S+\s+import|package\s|using\s+[\w.]+;|#include\b|use\s+[\w:{}, *]+;|require(_relative|_once)?\b|include(_once)?\b|namespace\s)/.test(l.text))
    .slice(0, 30)
    .map((l) => `${String(l.n).padStart(4)}| ${l.text}`)
    .join('\n');
}
