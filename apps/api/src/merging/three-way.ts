import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Three-way merge of one file, the same way git does it:
 *   base = the file when the fix was written, ours = the file on the latest branch, theirs = the fix.
 * Returns the merged text, or the text with conflict markers when both sides changed the same lines.
 */
export async function mergeFile(base: string, ours: string, theirs: string) {
  // Compare on LF and give the result the latest file's line endings, so CRLF checkouts don't look like conflicts.
  const crlf = ours.includes('\r\n');
  const lf = (text: string) => text.replace(/\r\n/g, '\n');
  const result = await mergeLf(lf(base), lf(ours), lf(theirs));
  // Conflicted text stays LF (it goes to the resolver); restore() gives any final text the file's endings.
  const restore = (text: string) => (crlf ? lf(text).replace(/\n/g, '\r\n') : text);
  return { ...result, text: result.conflicts ? result.text : restore(result.text), restore };
}

async function mergeLf(base: string, ours: string, theirs: string) {
  if (ours === base) return { text: theirs, conflicts: 0 };
  if (ours === theirs) return { text: ours, conflicts: 0 };
  const dir = await mkdtemp(join(tmpdir(), 'pp-merge-'));
  try {
    await writeFile(join(dir, 'base'), base);
    await writeFile(join(dir, 'ours'), ours);
    await writeFile(join(dir, 'theirs'), theirs);
    const code = await new Promise<number>((resolve, reject) => {
      const child = spawn(
        'git',
        ['merge-file', '-L', 'latest', '-L', 'scanned', '-L', 'fix', join(dir, 'ours'), join(dir, 'base'), join(dir, 'theirs')],
        { windowsHide: true, env: { PATH: process.env.PATH, SYSTEMROOT: process.env.SYSTEMROOT, GIT_CONFIG_NOSYSTEM: '1' } },
      );
      child.on('error', reject);
      child.on('close', (c) => resolve(c ?? -1));
    });
    if (code < 0) throw new Error('git merge-file failed');
    return { text: await readFile(join(dir, 'ours'), 'utf8'), conflicts: code };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export const hasConflictMarkers = (text: string) => /^(<{7}|={7}|>{7})( |$)/m.test(text);
