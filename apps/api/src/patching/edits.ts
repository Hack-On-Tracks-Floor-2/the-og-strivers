/** Exact search/replace edits (token-cheap and unambiguous) plus a local unified-diff generator. */
export interface Edit {
  file: string;
  search: string;
  replace: string;
}
export interface FileChange {
  path: string;
  original: string;
  proposed: string;
}

export class EditError extends Error {}

const normalize = (text: string) => text.replace(/\r\n/g, '\n');

/** Applies edits in memory. Each search block must occur exactly once in its file. */
export function applyEdits(edits: Edit[], read: (path: string) => string | null): FileChange[] {
  const changes = new Map<string, FileChange>();
  for (const edit of edits) {
    const path = edit.file.replace(/^\.?\//, '');
    if (path.includes('..') || path.startsWith('/') || /^[a-z]:/i.test(path))
      throw new EditError(`Edit targets an unsafe path: ${edit.file}`);
    const current = changes.get(path)?.proposed ?? (() => {
      const text = read(path);
      if (text === null) throw new EditError(`Edit targets a file that does not exist: ${path}`);
      return normalize(text);
    })();
    let search = normalize(edit.search);
    let replace = normalize(edit.replace);
    if (!search.trim()) throw new EditError(`Empty search block for ${path}.`);
    let first = current.indexOf(search);
    if (first < 0) {
      // Models sometimes re-indent the block or escape template backticks; match line by line instead.
      const loose = looseFind(current, search);
      if (!loose) throw new EditError(`Search text not found in ${path}. Copy it exactly from the snippet (without line numbers).`);
      if (loose === 'ambiguous') throw new EditError(`Search text is not unique in ${path}; include more surrounding lines.`);
      const indent = (s: string) => /^[ \t]*/.exec(s.split('\n').find((l) => l.trim()) ?? '')![0];
      const fileIndent = indent(loose.search);
      const modelIndent = indent(search);
      replace = replace
        .replace(/\\`/g, '`')
        .split('\n')
        .map((l) => (l.trim() && l.startsWith(modelIndent) ? fileIndent + l.slice(modelIndent.length) : l))
        .join('\n');
      ({ first, search } = loose);
    } else if (current.indexOf(search, first + 1) >= 0)
      throw new EditError(`Search text is not unique in ${path}; include more surrounding lines.`);
    const proposed = current.slice(0, first) + replace + current.slice(first + search.length);
    const original = changes.get(path)?.original ?? normalize(read(path)!);
    changes.set(path, { path, original, proposed });
  }
  return [...changes.values()].filter((c) => c.original !== c.proposed);
}

/**
 * Finds the search block ignoring indentation, trailing spaces and escaped backticks. Returns the exact
 * matching text from the file, so the edit still replaces precisely those lines, or 'ambiguous'.
 */
function looseFind(text: string, search: string): { first: number; search: string } | 'ambiguous' | null {
  const clean = (line: string) => line.replace(/\\`/g, '`').trim();
  const want = search.split('\n').map(clean);
  while (want.length && !want[0]) want.shift();
  while (want.length && !want[want.length - 1]) want.pop();
  if (!want.length) return null;
  const lines = text.split('\n');
  const offsets: number[] = [];
  let pos = 0;
  for (const line of lines) {
    offsets.push(pos);
    pos += line.length + 1;
  }
  const hits: number[] = [];
  for (let i = 0; i + want.length <= lines.length; i++)
    if (want.every((w, k) => clean(lines[i + k]) === w)) hits.push(i);
  if (hits.length > 1) return 'ambiguous';
  if (!hits.length) return null;
  const start = hits[0];
  const end = start + want.length - 1;
  return { first: offsets[start], search: text.slice(offsets[start], offsets[end] + lines[end].length) };
}

/** Line-level unified diff (3 lines of context) between two texts. */
export function unifiedDiff(path: string, before: string, after: string, context = 3): string {
  const a = normalize(before).split('\n');
  const b = normalize(after).split('\n');
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const am = a.slice(pre, a.length - suf);
  const bm = b.slice(pre, b.length - suf);
  // LCS on the changed middle only (small after trimming).
  const dp: number[][] = Array.from({ length: am.length + 1 }, () => new Array(bm.length + 1).fill(0));
  for (let i = am.length - 1; i >= 0; i--)
    for (let j = bm.length - 1; j >= 0; j--)
      dp[i][j] = am[i] === bm[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  type Op = { t: ' ' | '-' | '+'; text: string; ai: number; bi: number };
  const ops: Op[] = [];
  for (let k = 0; k < pre; k++) ops.push({ t: ' ', text: a[k], ai: k, bi: k });
  let i = 0;
  let j = 0;
  while (i < am.length || j < bm.length) {
    if (i < am.length && j < bm.length && am[i] === bm[j]) {
      ops.push({ t: ' ', text: am[i], ai: pre + i, bi: pre + j });
      i++;
      j++;
    } else if (i < am.length && (j >= bm.length || dp[i + 1][j] >= dp[i][j + 1])) {
      // Prefer deletions first so each hunk reads "- old" then "+ new".
      ops.push({ t: '-', text: am[i], ai: pre + i, bi: pre + j });
      i++;
    } else {
      ops.push({ t: '+', text: bm[j], ai: pre + i, bi: pre + j });
      j++;
    }
  }
  for (let k = 0; k < suf; k++)
    ops.push({ t: ' ', text: a[a.length - suf + k], ai: a.length - suf + k, bi: b.length - suf + k });
  const changed = ops.map((o, idx) => (o.t === ' ' ? -1 : idx)).filter((x) => x >= 0);
  if (!changed.length) return '';
  const hunks: [number, number][] = [];
  for (const idx of changed) {
    const lo = Math.max(0, idx - context);
    const hi = Math.min(ops.length - 1, idx + context);
    const last = hunks[hunks.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else hunks.push([lo, hi]);
  }
  const out = [`--- a/${path}`, `+++ b/${path}`];
  for (const [lo, hi] of hunks) {
    const slice = ops.slice(lo, hi + 1);
    const aStart = slice.find((o) => o.t !== '+')?.ai ?? slice[0].ai;
    const bStart = slice.find((o) => o.t !== '-')?.bi ?? slice[0].bi;
    const aLen = slice.filter((o) => o.t !== '+').length;
    const bLen = slice.filter((o) => o.t !== '-').length;
    out.push(`@@ -${aStart + 1},${aLen} +${bStart + 1},${bLen} @@`);
    for (const o of slice) out.push(`${o.t}${o.text}`);
  }
  return out.join('\n');
}

export function changedLineCount(diff: string) {
  return diff.split('\n').filter((l) => /^[+-]/.test(l) && !/^(\+\+\+|---) /.test(l)).length;
}
