import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MLModelInfoSchema,
  MLPredictionSchema,
  type MLModelInfo,
  type MLPrediction,
} from '@proofpatch/shared';
import { HttpError } from '../utils/errors.js';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const root = existsSync(join(sourceRoot, 'package.json'))
  ? sourceRoot
  : resolve(sourceRoot, '../../..');
const folder = join(root, 'ml/mini_classifier');
const artifacts = join(folder, 'artifacts');
function pythonPath(): string | null {
  if (process.env.MINI_ML_PYTHON?.trim()) return process.env.MINI_ML_PYTHON.trim();
  const bundled = join(
    homedir(),
    '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe',
  );
  if (process.platform === 'win32' && existsSync(bundled)) return bundled;
  for (const directory of (process.env.PATH ?? '').split(delimiter)) {
    if (/WindowsApps/i.test(directory)) continue;
    const candidate = join(directory, process.platform === 'win32' ? 'python.exe' : 'python3');
    if (existsSync(candidate)) return candidate;
  }
  return null;
}
const jsonFile = async (name: string) => JSON.parse(await readFile(join(artifacts, name), 'utf8'));
export async function heldoutExample() {
  const [code, evidence] = await Promise.all([
    readFile(join(artifacts, 'heldout-example.java'), 'utf8'),
    jsonFile('heldout-inference.json'),
  ]);
  return {
    code,
    exampleId: evidence.example_id,
    expectedLabel: evidence.expected_label,
    source: 'Official OWASP Benchmark held-out test example; not user repository analysis.',
  };
}
export async function modelInfo(): Promise<MLModelInfo> {
  try {
    const [report, metadata, integrity] = await Promise.all([
      jsonFile('evaluation.json'),
      jsonFile('metadata.json'),
      jsonFile('integrity.json'),
    ]);
    const modelVersion = `owasp-java-${report.dataset.version}-${integrity['model.joblib'].slice(0, 12)}`;
    let reason: string | undefined;
    for (const name of ['model.joblib', 'vectorizer.joblib']) {
      const hash = createHash('sha256')
        .update(await readFile(join(artifacts, name)))
        .digest('hex');
      if (hash !== integrity[name])
        reason = 'Saved model integrity check failed. Restore the trusted committed artifacts.';
    }
    if (!pythonPath())
      reason =
        'Python is not configured on this backend. Set MINI_ML_PYTHON and install the classifier requirements.';
    return MLModelInfoSchema.parse({
      availability: reason ? 'unavailable' : 'available',
      ...(reason ? { reason } : {}),
      modelVersion,
      model: report.model,
      language: 'java',
      supportedCwes: metadata.supported_cwes,
      trainedAt: report.trained_at,
      dataset: report.dataset,
      training: {
        trainSamples: report.split.train_samples,
        testSamples: report.split.test_samples,
        sharedGroups: report.split.shared_groups,
      },
      metrics: {
        precisionMacro: report.evaluation.precision_macro,
        recallMacro: report.evaluation.recall_macro,
        f1Macro: report.evaluation.f1_macro,
        negativeRecall: report.evaluation.per_class.BENCHMARK_NEGATIVE.recall,
      },
      rejectionThreshold: metadata.rejection_threshold,
      limitations: report.limitations,
    });
  } catch {
    throw new HttpError(
      503,
      'ML_NOT_CONFIGURED',
      'The saved classifier artifacts or evaluation report are unavailable on this backend.',
    );
  }
}

let worker: ChildProcessWithoutNullStreams | undefined;
let ready: Promise<void> | undefined;
let buffer = '';
let busy = false;
let pending:
  { id: string; resolve: (value: unknown) => void; reject: (error: Error) => void } | undefined;
export function closeMLWorker() {
  worker?.kill();
  worker = undefined;
  ready = undefined;
  buffer = '';
}
function startWorker(): Promise<void> {
  if (ready) return ready;
  const python = pythonPath();
  if (!python)
    throw new HttpError(503, 'ML_NOT_CONFIGURED', 'Configure MINI_ML_PYTHON on the backend.');
  ready = new Promise<void>((resolveReady, rejectReady) => {
    const child = spawn(python, ['-u', join(folder, 'serve.py')], {
      cwd: folder,
      shell: false,
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONUTF8: '1',
        PYTHONUNBUFFERED: '1',
        PYTHONDONTWRITEBYTECODE: '1',
        OMP_NUM_THREADS: '1',
        OPENBLAS_NUM_THREADS: '1',
        MKL_NUM_THREADS: '1',
        NUMEXPR_NUM_THREADS: '1',
      },
    });
    worker = child;
    buffer = '';
    let initialized = false;
    let stderr = '';
    const startup = setTimeout(() => {
      rejectReady(new HttpError(504, 'ML_TIMEOUT', 'Model initialization timed out.'));
      closeMLWorker();
    }, 60_000);
    startup.unref();
    child.stderr.on('data', (data) => {
      stderr = (stderr + String(data)).slice(-1000);
    });
    child.stdout.on('data', (data) => {
      buffer += String(data);
      if (buffer.length > 100_000) {
        child.kill();
        return;
      }
      let newline: number;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        try {
          const message = JSON.parse(line);
          if (message.ready) {
            initialized = true;
            clearTimeout(startup);
            resolveReady();
          } else if (pending && message.id === pending.id) {
            const request = pending;
            pending = undefined;
            if (message.error)
              request.reject(
                new HttpError(
                  503,
                  'ML_INFERENCE_FAILED',
                  'The classifier could not process this source.',
                ),
              );
            else request.resolve(message.result);
          }
        } catch {
          child.kill();
        }
      }
    });
    const fail = () => {
      clearTimeout(startup);
      const error = new HttpError(
        503,
        'ML_UNAVAILABLE',
        stderr.includes('ModuleNotFoundError')
          ? 'Install ml/mini_classifier/requirements.txt on the backend Python runtime.'
          : 'The Python classifier is unavailable. Check its runtime and trusted artifacts.',
      );
      if (!initialized) rejectReady(error);
      pending?.reject(error);
      pending = undefined;
      if (worker === child) {
        worker = undefined;
        ready = undefined;
        buffer = '';
      }
    };
    child.on('error', fail);
    child.on('close', fail);
    child.stdin.on('error', () => {
      child.kill();
    });
  });
  return ready;
}
export async function classifySource(input: {
  code: string;
  language: string;
}): Promise<MLPrediction> {
  const info = await modelInfo();
  const language = input.language.toLowerCase();
  if (language !== 'java')
    return MLPredictionSchema.parse({
      status: 'unsupported',
      predicted_category: null,
      cwe: null,
      probability: null,
      language,
      supported_cwes: info.supportedCwes,
      scope: 'OWASP Benchmark Java only',
      reason: 'Unsupported language; only Java was trained and evaluated.',
      modelVersion: info.modelVersion,
    });
  if (info.availability !== 'available')
    throw new HttpError(503, 'ML_NOT_CONFIGURED', info.reason ?? 'ML inference is unavailable.');
  if (busy)
    throw new HttpError(
      429,
      'ML_BUSY',
      'The classifier is processing another request. Please retry shortly.',
    );
  busy = true;
  try {
    await startWorker();
    const result = await new Promise<unknown>((resolveResult, reject) => {
      const id = randomUUID();
      const timer = setTimeout(() => {
        pending = undefined;
        reject(new HttpError(504, 'ML_TIMEOUT', 'Classification timed out.'));
        closeMLWorker();
      }, 30_000);
      timer.unref();
      pending = {
        id,
        resolve: (value) => {
          clearTimeout(timer);
          resolveResult(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      worker!.stdin.write(JSON.stringify({ id, code: input.code, language }) + '\n');
    });
    return MLPredictionSchema.parse({
      ...(result as Record<string, unknown>),
      modelVersion: info.modelVersion,
    });
  } finally {
    busy = false;
  }
}
process.once('exit', closeMLWorker);
