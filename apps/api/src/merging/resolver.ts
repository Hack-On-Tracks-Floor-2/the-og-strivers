import type { AiClient, AiUsage, TokenBudget } from '../ai/client.js';
import { hasConflictMarkers } from './three-way.js';

const SCHEMA = {
  type: 'object',
  properties: { content: { type: 'string' }, explanation: { type: 'string' } },
  required: ['content', 'explanation'],
};

/**
 * Asks the AI to resolve git conflict markers in one file: keep every upstream change from "latest"
 * and re-apply the security fix from "fix". The result is only used after the merged code passes the
 * sandbox proofs again and a reviewer confirms it.
 */
export async function resolveConflict(input: {
  path: string;
  conflicted: string;
  fixDiff: string;
  ai: AiClient;
  budget: TokenBudget;
  signal: AbortSignal;
  onUsage?: (usage: AiUsage, note: string) => void | Promise<void>;
}) {
  const lines = input.conflicted.split('\n').length;
  if (lines > 800) throw new Error(`${input.path} is too large (${lines} lines) for automatic conflict resolution.`);
  const { value, usage } = await input.ai.completeJSON<{ content: string; explanation: string }>(
    {
      task: 'merge',
      instructions:
        `Resolve the git merge conflicts in ${input.path}. Sections between "<<<<<<< latest" and "=======" are the ` +
        'current upstream code; sections between "=======" and ">>>>>>> fix" are a reviewed security fix written against an ' +
        'older version. Produce the full file that keeps every upstream change AND still applies the security fix exactly. ' +
        'Do not add features, do not reformat unrelated code, and remove all conflict markers. Return the complete file content ' +
        'and a one-sentence explanation.',
      data: `### Security fix (diff against the older version)\n${input.fixDiff.slice(0, 6000)}\n\n### ${input.path} with conflicts\n${input.conflicted}`,
      schema: SCHEMA,
      maxOutputTokens: Math.min(6_000, 400 + lines * 30),
    },
    input.budget,
    input.signal,
  );
  await input.onUsage?.(usage, `AI resolved merge conflicts in ${input.path}`);
  if (!value.content || hasConflictMarkers(value.content))
    throw new Error(`The AI left conflict markers in ${input.path}.`);
  return { content: value.content.endsWith('\n') || !input.conflicted.endsWith('\n') ? value.content : `${value.content}\n`, explanation: value.explanation };
}
