import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { z } from 'zod';
import { ArrowUpRight, GitMerge, GitPullRequest } from 'lucide-react';
import { PatchSchema, type Patch } from '@proofpatch/shared';
import { api } from '../../lib/api';
import { Eyebrow, ErrorBox } from '../ui';

const LABELS: Record<NonNullable<Patch['merge']>['status'], string> = {
  merging: 'Merging and re-proving on the latest code…',
  awaiting_review: 'AI resolved a merge conflict — your confirmation is needed',
  merged: 'Fix branch pushed and pull request opened',
  sent_back: 'Bug on the latest code — sent back for patching',
  already_fixed: 'Already fixed on the latest code',
  failed: 'Merge failed',
};

/**
 * Reviewer-only: merge an approved fix onto the repository's latest code. Clean merges that pass every
 * proof become a GitHub branch + pull request for the developer. AI-resolved conflicts wait here for
 * the reviewer to confirm. Failing proofs send the fix back for patching.
 */
export function MergePanel({ patch: initial, base }: { patch: Patch; base: string }) {
  const [patch, setPatch] = useState(initial);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const merge = patch.merge;
  const working = busy || merge?.status === 'merging';

  useEffect(() => setPatch(initial), [initial]);
  useEffect(() => {
    if (!working) return;
    const timer = setInterval(async () => {
      const patches = await api(`/runs/${patch.runId}/patches`, z.array(PatchSchema)).catch(() => null);
      const fresh = patches?.find((p) => p.id === patch.id);
      if (fresh) {
        setPatch(fresh);
        if (fresh.merge && fresh.merge.status !== 'merging') setBusy(false);
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [working, patch.id, patch.runId]);

  async function post(path: string) {
    setError('');
    setBusy(true);
    try {
      await api(path, z.object({ queued: z.boolean() }), {});
      setPatch((p) => ({ ...p, merge: { ...(p.merge ?? emptyMerge()), status: 'merging', message: 'Queued…' } }));
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }

  return (
    <section className="panel merge-panel">
      <Eyebrow>MERGE INTO THE DEVELOPER&apos;S REPOSITORY</Eyebrow>
      <h3>
        <GitMerge size={18} /> {merge ? LABELS[merge.status] : 'Approved — ready to merge'}
      </h3>
      <p>
        {merge?.message ||
          'ProofPatch lays this fix onto the latest code, re-runs the attack test and the full suite, then pushes a branch and opens a pull request for the developer. If the latest code breaks the fix, it goes back for patching.'}
      </p>
      {merge?.checks.length ? (
        <ul className="merge-checks">
          {merge.checks.map((c, i) => (
            <li key={i} className={c.passed ? 'passed' : 'failed'}>
              <strong>{c.passed ? '✓' : '✗'} {c.stage.replace('_', ' ')}</strong> — {c.summary}
            </li>
          ))}
        </ul>
      ) : null}
      {merge?.status === 'awaiting_review' && merge.mergedDiff && (
        <>
          <Eyebrow>AI-RESOLVED MERGE — REVIEW BEFORE PUBLISHING</Eyebrow>
          <pre className="code-block execution-log">{merge.mergedDiff}</pre>
        </>
      )}
      {merge?.pullRequestUrl && (
        <p>
          Branch <code>{merge.branch}</code> ·{' '}
          <a className="lime-text" href={merge.pullRequestUrl} target="_blank" rel="noreferrer">
            Open pull request <GitPullRequest size={14} />
          </a>
        </p>
      )}
      {merge?.sentBackRunId && (
        <Link className="button secondary small-button" to={`${base}/scanner?run=${merge.sentBackRunId}`}>
          Follow the new patching run <ArrowUpRight size={14} />
        </Link>
      )}
      {error && <ErrorBox message={error} />}
      <div className="patch-action-bar">
        {(!merge || merge.status === 'failed') && (
          <button className="button primary small-button" disabled={working} onClick={() => post(`/reviews/${patch.id}/merge`)}>
            {working ? 'Merging…' : merge ? 'Retry merge' : 'Merge fix'} <GitMerge size={14} />
          </button>
        )}
        {merge?.status === 'awaiting_review' && (
          <button className="button primary small-button" disabled={working} onClick={() => post(`/reviews/${patch.id}/merge/confirm`)}>
            Confirm &amp; create branch <GitPullRequest size={14} />
          </button>
        )}
      </div>
    </section>
  );
}

function emptyMerge(): NonNullable<Patch['merge']> {
  return {
    status: 'merging', baseBranch: null, baseSha: null, branch: null, pullRequestUrl: null, resolvedByAi: [],
    mergedDiff: '', files: [], checks: [], message: '', sentBackRunId: null, updatedAt: new Date().toISOString(),
  };
}
