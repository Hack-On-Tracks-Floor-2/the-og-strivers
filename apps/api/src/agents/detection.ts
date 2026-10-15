import type { Severity } from './types.js';
import type { AiClient, AiUsage, TokenBudget } from '../ai/client.js';
import { findCandidates, type Candidate, type ExternalHit, type ModelSummary } from '../scanners/funnel.js';
import type { Locator } from '../scanners/locator.js';

export interface DetectedIssue {
  candidate: Candidate;
  cwe: string;
  severity: Severity;
  confidence: number;
  rootCause: string;
  evidence: string[];
  recommendation: string;
  source: 'scanner+ai' | 'ai';
}
interface AiVerdict {
  verdicts: {
    candidateId: string;
    vulnerable: boolean;
    confidence: number;
    cwe: string;
    severity: Severity;
    rootCause: string;
    evidence: string[];
    recommendation: string;
  }[];
}
const SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          candidateId: { type: 'string' },
          vulnerable: { type: 'boolean' },
          confidence: { type: 'number' },
          cwe: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          rootCause: { type: 'string' },
          evidence: { type: 'array', items: { type: 'string' } },
          recommendation: { type: 'string' },
        },
        required: ['candidateId', 'vulnerable', 'confidence', 'cwe', 'severity', 'rootCause', 'evidence', 'recommendation'],
      },
    },
  },
  required: ['verdicts'],
};

/**
 * Funnel step 3: one compact AI call over the pre-ranked snippets (never whole files).
 * Returns confirmed issues, most confident first.
 */
export async function detectVulnerabilities(input: {
  root: string;
  ai: AiClient;
  budget: TokenBudget;
  signal: AbortSignal;
  external?: ExternalHit[];
  locator?: Locator | null;
  language?: 'python' | 'javascript';
  onUsage?: (usage: AiUsage, note: string) => void | Promise<void>;
}): Promise<{ issues: DetectedIssue[]; candidates: Candidate[]; filesScanned: number; hits: number; model?: ModelSummary }> {
  const search = await findCandidates(input.root, { external: input.external, locator: input.locator, language: input.language });
  if (!search.candidates.length) return { issues: [], ...search };
  const data = search.candidates
    .map((c) => `### ${c.id} ${c.file}:${c.startLine}-${c.endLine} (${c.rule === 'trained-model' ? 'trained model' : 'scanner'}: ${c.category}, ${c.cwe}${c.modelScore !== undefined ? `, model risk ${Math.round(c.modelScore * 100)}%` : ''})\n${c.snippet}`)
    .join('\n\n');
  const { value, usage } = await input.ai.completeJSON<AiVerdict>(
    {
      task: 'detect',
      instructions:
        'Each block is a code region flagged by a static scanner and/or a vulnerability model trained on real CVE fixes ' +
        '(a "# <- trained model" comment marks the line it rates riskiest; it is a hint, not proof). ' +
        'Decide which are REAL, exploitable security vulnerabilities ' +
        '(attacker-controlled input reaches the dangerous call without adequate validation). Reject false positives. ' +
        'For model-only blocks, name the precise CWE yourself. Return one verdict per candidate id. Use the exact line numbers shown. Keep rootCause and recommendation under 60 words each.',
      data,
      schema: SCHEMA,
      maxOutputTokens: 1_500,
    },
    input.budget,
    input.signal,
  );
  await input.onUsage?.(usage, `Detection reviewed ${search.candidates.length} snippets from ${search.filesScanned} files`);
  const byId = new Map(search.candidates.map((c) => [c.id, c]));
  const issues = (value.verdicts ?? [])
    .filter((v) => v.vulnerable && byId.has(v.candidateId))
    .map((v) => ({
      candidate: byId.get(v.candidateId)!,
      cwe: /^CWE-\d+$/.test(v.cwe) ? v.cwe : byId.get(v.candidateId)!.cwe,
      severity: v.severity,
      confidence: Math.max(0, Math.min(1, v.confidence)),
      rootCause: String(v.rootCause).slice(0, 1000),
      evidence: (v.evidence ?? []).map(String).slice(0, 6),
      recommendation: String(v.recommendation).slice(0, 1000),
      source: 'scanner+ai' as const,
    }))
    .sort((a, b) => b.confidence - a.confidence || b.candidate.score - a.candidate.score);
  return { issues, ...search };
}
