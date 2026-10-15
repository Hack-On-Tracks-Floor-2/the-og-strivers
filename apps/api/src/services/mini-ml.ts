import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MLModelInfoSchema,
  MLModelCatalogSchema,
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
const workerFolder = join(root, 'ml/multilang_classifier');
const folders = new Map([['java', artifacts], ['python', join(workerFolder, 'artifacts/python')]]);
const unsupportedReasons = new Map([
  ['javascript', 'No evaluated JavaScript model: source-level labels, upstream licenses and repository-held-out samples still require curation.'],
  ['typescript', 'No evaluated TypeScript model: credible per-CWE labeled samples are insufficient.'],
]);
const normalizeLanguage = (language: string) => language.trim().toLowerCase();
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
const jsonFile = async (name: string, directory = artifacts) => JSON.parse(await readFile(join(directory, name), 'utf8'));
export async function heldoutExample(language = 'java') {
  language = normalizeLanguage(language);
  const directory = folders.get(language);
  if (!directory) throw new HttpError(404, 'ML_UNSUPPORTED', unsupportedReasons.get(language) ?? 'Unsupported language.');
  const [code, evidence] = await Promise.all([
    readFile(join(directory, `heldout-example.${language === 'java' ? 'java' : 'py'}`), 'utf8'),
    jsonFile('heldout-inference.json', directory),
  ]);
  return {
    code,
    exampleId: evidence.example_id,
    expectedLabel: evidence.expected_label,
    source: 'Official OWASP Benchmark held-out test example; not user repository analysis.',
  };
}
export async function modelInfo(language = 'java'): Promise<MLModelInfo> {
  language = normalizeLanguage(language);
  const directory = folders.get(language);
  if (!directory) throw new HttpError(404, 'ML_UNSUPPORTED', unsupportedReasons.get(language) ?? 'Unsupported language.');
  try {
    const [report, metadata, integrity] = await Promise.all([
      jsonFile('evaluation.json', directory),
      jsonFile('metadata.json', directory),
      jsonFile('integrity.json', directory),
    ]);
    const modelVersion = `owasp-${language}-${report.dataset.version}-${integrity['model.joblib'].slice(0, 12)}`;
    const activation = { enabled: language === 'java' || metadata.enabled === true, reason: language === 'java' ? 'Existing experimental Java baseline preserved; review its negative-example recall.' : metadata.activation_reason ?? metadata.reason ?? 'Activation requires a passing recorded grouped hold-out quality gate.' };
    let reason: string | undefined;
    for (const name of ['model.joblib', 'vectorizer.joblib']) {
      const hash = createHash('sha256')
        .update(await readFile(join(directory, name)))
        .digest('hex');
      if (hash !== integrity[name])
        reason = 'Saved model integrity check failed. Restore the trusted committed artifacts.';
    }
    if (!pythonPath())
      reason =
        'Python is not configured on this backend. Set MINI_ML_PYTHON and install the classifier requirements.';
    if (!activation.enabled) reason = activation.reason;
    return MLModelInfoSchema.parse({
      availability: reason ? 'unavailable' : 'available',
      ...(reason ? { reason } : {}),
      modelVersion,
      model: report.model,
      language,
      activation,
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
        negativeFalsePositiveRate: 1 - report.evaluation.per_class.BENCHMARK_NEGATIVE.recall,
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

export async function modelCatalog() {
  const models = await Promise.all(['java', 'python', 'javascript', 'typescript'].map(async (language) => {
    if (!folders.has(language)) return { language, status: 'unsupported', reason: unsupportedReasons.get(language) };
    try {
      const info = await modelInfo(language);
      return { language, status: info.activation?.enabled === false ? 'disabled' : info.availability, reason: info.reason, info };
    } catch {
      return { language, status: 'unavailable', reason: 'Evaluated model artifacts are not installed or failed integrity validation. No prediction is available.' };
    }
  }));
  return MLModelCatalogSchema.parse({ models });
}

let worker: ChildProcessWithoutNullStreams | undefined;
let ready: Promise<void> | undefined;
let buffer = '';
let busy = false;
let pending:
  { id: string; resolve: (value: unknown) => void; reject: (error: Error) => void } | undefined;
let rejectStartup: ((error: Error) => void) | undefined;
export function closeMLWorker() {
  const child = worker;
  worker = undefined;
  ready = undefined;
  buffer = '';
  const error = new HttpError(503, 'ML_UNAVAILABLE', 'The classifier worker was stopped.');
  const request = pending;
  pending = undefined;
  request?.reject(error);
  rejectStartup?.(error);
  rejectStartup = undefined;
  child?.kill();
}
function startWorker(): Promise<void> {
  if (ready) return ready;
  const python = pythonPath();
  if (!python)
    throw new HttpError(503, 'ML_NOT_CONFIGURED', 'Configure MINI_ML_PYTHON on the backend.');
  ready = new Promise<void>((resolveReady, rejectReady) => {
    rejectStartup = rejectReady;
    const child = spawn(python, ['-u', join(workerFolder, 'worker.py')], {
      cwd: workerFolder,
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
      if (worker !== child) return;
      rejectReady(new HttpError(504, 'ML_TIMEOUT', 'Model initialization timed out.'));
      closeMLWorker();
    }, 60_000);
    startup.unref();
    child.stderr.on('data', (data) => {
      stderr = (stderr + String(data)).slice(-1000);
    });
    child.stdout.on('data', (data) => {
      if (worker !== child) return;
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
            rejectStartup = undefined;
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
      if (worker !== child) return;
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
        rejectStartup = undefined;
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
  filePath?: string;
}): Promise<MLPrediction> {
  const language = normalizeLanguage(input.language);
  const unknown = (status: 'unknown' | 'unsupported', reason: string, info?: MLModelInfo) => MLPredictionSchema.parse({
    status, predicted_category: null, cwe: null, probability: null, language,
    supported_cwes: info?.supportedCwes ?? [], scope: 'Experimental language-specific benchmark classification; not a confirmed vulnerability.',
    reason, modelVersion: info?.modelVersion ?? 'unavailable', filePath: input.filePath, confirmed: false,
  });
  if (!folders.has(language)) return unknown('unsupported', unsupportedReasons.get(language) ?? 'Unsupported language; no evaluated model is registered.');
  let info: MLModelInfo;
  try { info = await modelInfo(language); }
  catch { return unknown('unknown', 'The selected model artifacts are unavailable or failed integrity validation.'); }
  if (info.availability !== 'available') return unknown('unknown', info.reason ?? 'ML inference is unavailable.', info);
  if (busy)
    throw new HttpError(
      429,
      'ML_BUSY',
      'The classifier is processing another request. Please retry shortly.',
    );
  busy = true;
  try {
    await startWorker();
    const child = worker;
    if (!child) return unknown('unknown', 'The classifier worker is unavailable.', info);
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
      child.stdin.write(JSON.stringify({ id, code: input.code, language }) + '\n');
    });
    return MLPredictionSchema.parse({
      ...(result as Record<string, unknown>),
      modelVersion: (result as Record<string, unknown>).modelVersion ?? info.modelVersion,
      filePath: input.filePath,
      confirmed: false,
      ...((result as Record<string, unknown>).probability !== null ? { probabilityKind: 'uncalibrated' } : {}),
    });
  } catch (error) {
    return unknown('unknown', error instanceof HttpError ? error.message : 'The classifier could not process this source.', info);
  } finally {
    busy = false;
  }
}
process.once('exit', closeMLWorker);
