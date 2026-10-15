import type { MLPrediction } from '@proofpatch/shared';
import { classifySource } from './mini-ml.js';

type ScannerFinding = {
  file: string;
  startLine: number;
  endLine?: number;
  cwe?: string | null;
  language?: string;
};

export type MLEnrichment = {
  status: MLPrediction['status'] | 'invalid_input' | 'unavailable';
  prediction?: MLPrediction;
  comparison: 'agrees' | 'disagrees' | 'not_comparable';
  scannerCwe: string | null;
  sourceRange?: { startLine: number; endLine: number };
  reason?: string;
};

const maxLines = 80;
const maxCharacters = 20_000;

function normalizeCwe(value: string | null | undefined): string | null {
  const match = /^CWE-(\d+)$/i.exec(typeof value === 'string' ? value.trim() : '');
  return match ? `CWE-${Number(match[1])}` : null;
}

function findingLanguage(finding: ScannerFinding): string | null {
  const aliases: Record<string, string> = {
    python: 'python',
    py: 'python',
    javascript: 'javascript',
    js: 'javascript',
    jsx: 'javascript',
    typescript: 'typescript',
    ts: 'typescript',
    tsx: 'typescript',
    java: 'java',
  };
  if (finding.language?.trim()) {
    const language = finding.language.trim().toLowerCase();
    return Object.hasOwn(aliases, language) ? aliases[language] : null;
  }
  const extension = /\.([^.\\/]+)$/.exec(finding.file)?.[1].toLowerCase();
  return extension && Object.hasOwn(aliases, extension) ? aliases[extension] : null;
}

/** Optional adapter: callers supply source text. This function never opens the finding's path. */
export async function enrichScannerFinding<T extends ScannerFinding>(
  finding: T,
  sourceText: string,
  options: { predict?: typeof classifySource } = {},
): Promise<{ finding: T; ml: MLEnrichment }> {
  const scannerCwe = normalizeCwe(finding.cwe);
  const result = (ml: Omit<MLEnrichment, 'scannerCwe'>) => ({
    finding,
    ml: { ...ml, scannerCwe },
  });
  if (
    typeof sourceText !== 'string' ||
    typeof finding.file !== 'string' ||
    !finding.file.trim() ||
    finding.file.length > 500 ||
    finding.file.includes('\0')
  ) {
    return result({
      status: 'invalid_input',
      comparison: 'not_comparable',
      reason: 'Source text and a valid source path are required.',
    });
  }
  const lines = sourceText.split(/\r\n|\n|\r/);
  const lastFindingLine = finding.endLine ?? finding.startLine;
  if (
    !Number.isSafeInteger(finding.startLine) ||
    !Number.isSafeInteger(lastFindingLine) ||
    finding.startLine < 1 ||
    lastFindingLine < finding.startLine ||
    lastFindingLine > lines.length
  ) {
    return result({
      status: 'invalid_input',
      comparison: 'not_comparable',
      reason: 'Finding coordinates must refer to existing source lines.',
    });
  }
  const language = findingLanguage(finding);
  if (!language) {
    return result({
      status: 'unsupported',
      comparison: 'not_comparable',
      reason: 'The finding language is not supported by the classifier router.',
    });
  }
  const findingStart = finding.startLine - 1;
  const findingEnd = lastFindingLine;
  const findingLength = findingEnd - findingStart;
  const findingCode = lines.slice(findingStart, findingEnd).join('\n');
  if (findingLength > maxLines || findingCode.length > maxCharacters || !findingCode.trim()) {
    return result({
      status: 'unknown',
      comparison: 'not_comparable',
      reason: 'The finding cannot fit inside a nonempty bounded classification snippet.',
    });
  }
  const contextBudget = maxLines - findingLength;
  const before = Math.min(20, Math.floor(contextBudget / 2));
  const after = Math.min(20, contextBudget - before);
  let start = Math.max(0, findingStart - before);
  let end = Math.min(lines.length, findingEnd + after);
  let code = lines.slice(start, end).join('\n');
  while (code.length > maxCharacters && start < findingStart) {
    start++;
    code = lines.slice(start, end).join('\n');
  }
  while (code.length > maxCharacters && end > findingEnd) {
    end--;
    code = lines.slice(start, end).join('\n');
  }
  const sourceRange = { startLine: start + 1, endLine: end };
  try {
    const prediction = await (options.predict ?? classifySource)({
      code,
      language,
      filePath: finding.file,
    });
    let comparison: MLEnrichment['comparison'] = 'not_comparable';
    if (prediction.status === 'predicted' && scannerCwe) {
      const predictedCwe = normalizeCwe(prediction.cwe);
      if (prediction.predicted_category === 'BENCHMARK_NEGATIVE') comparison = 'disagrees';
      else if (predictedCwe) comparison = predictedCwe === scannerCwe ? 'agrees' : 'disagrees';
    }
    return result({
      status: prediction.status,
      prediction,
      comparison,
      sourceRange,
      ...(prediction.reason ? { reason: prediction.reason } : {}),
    });
  } catch {
    return result({
      status: 'unavailable',
      comparison: 'not_comparable',
      sourceRange,
      reason: 'ML enrichment is unavailable. Preserve the scanner finding and continue normally.',
    });
  }
}
