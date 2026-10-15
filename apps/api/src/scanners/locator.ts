import { spawn } from 'node:child_process';
import { join } from 'node:path';

/**
 * Trained vulnerability locator (UniXcoder fine-tuned on real Python CVE fixes).
 * Runs locally: scores every function and every line, so the funnel can rank code the
 * regex rules miss and tell the AI which lines look risky. Source text only; nothing executes.
 */
export interface FunctionScore {
  id: string;
  score: number;
  lines: number[];
  /** Source line number of each scored statement (when scored from source). */
  line_numbers?: number[];
}
export interface Locator {
  score(functions: ({ id: string; lines: string[] } | { id: string; source: string; start: number })[]): Promise<{ scores: FunctionScore[]; threshold: number }>;
}

export function createLocator(env: NodeJS.ProcessEnv): Locator | null {
  const python = env.DETECTOR_PYTHON?.trim();
  const dir = env.DETECTOR_DIR?.trim();
  if (!python || !dir) return null;
  return {
    score(functions) {
      return new Promise((resolve, reject) => {
        const child = spawn(python, [join(dir, 'score.py')], {
          cwd: dir,
          windowsHide: true,
          timeout: 120_000,
          env: { ...process.env, HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1', HF_HOME: env.HF_HOME ?? process.env.HF_HOME },
        });
        let out = '';
        let err = '';
        child.stdout.on('data', (d) => (out += d));
        child.stderr.on('data', (d) => (err = (err + d).slice(-2000)));
        child.on('error', reject);
        child.on('close', (code) => {
          if (code !== 0) return reject(new Error(`locator exited ${code}: ${err.slice(-300)}`));
          try {
            resolve(JSON.parse(out));
          } catch {
            reject(new Error('locator returned invalid output'));
          }
        });
        child.stdin.end(JSON.stringify({ functions }));
      });
    },
  };
}
