import { useEffect, useState, type FormEvent } from 'react';
import { z } from 'zod';
import { ArrowUpRight, FolderGit2, GitPullRequest } from 'lucide-react';
import { RepositorySchema, RepositoryInputSchema, SubmissionSchema, type Submission } from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, EmptyState, ErrorBox, Loading, date } from '../components/ui';

/** Plain-language status. Developers never see findings, patches or evidence; reviewers do. */
const LABELS: Record<Submission['status'], string> = {
  submitted: 'Submitted',
  scanning: 'Security scan running',
  in_review: 'With security reviewer',
  approved: 'Fix approved',
  merging: 'Fix being merged',
  fix_branch_ready: 'Fix branch ready',
  rejected: 'Reviewed — no fix approved',
  scan_failed: 'Scan could not complete',
};

/** The developer workspace: submit a repository for security review and follow its status. */
export function SubmissionsPage() {
  const state = useResource(() => api('/submissions', z.array(SubmissionSchema)));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState('');
  const active = state.data?.some((s) => ['submitted', 'scanning', 'merging'].includes(s.status));
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(state.reload, 5000);
    return () => clearInterval(timer);
  }, [active, state.reload]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError('');
    const parsed = RepositoryInputSchema.safeParse({ url });
    if (!parsed.success) {
      setError(parsed.error.issues[0].message);
      return;
    }
    setBusy(true);
    try {
      await api('/repositories', RepositorySchema, parsed.data);
      setUrl('');
      state.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageTitle
        eyebrow="01 / SUBMIT FOR SECURITY REVIEW"
        title="REPOSITORIES"
      />
      <section className="panel repository-form">
        <h2>Add a repository</h2>
        <p>Paste a public GitHub repository. The security scan starts automatically.</p>
        <form onSubmit={submit}>
          <label htmlFor="repo-url" className="sr-only">
            GitHub repository URL
          </label>
          <div className="repo-input">
            <FolderGit2 size={18} />
            <input
              id="repo-url"
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
            />
          </div>
          <button className="button primary" disabled={busy}>
            {busy ? 'Submitting…' : 'Add repository'}
            <ArrowUpRight size={17} />
          </button>
        </form>
        {error && <ErrorBox message={error} />}
        <span className="field-help mono">HTTPS / GITHUB.COM / PUBLIC REPOSITORIES</span>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Your submissions <span className="count">{state.data?.length ?? 0}</span>
          </h2>
        </div>
        {state.loading && !state.data ? (
          <Loading />
        ) : state.error ? (
          <ErrorBox message={state.error} retry={state.reload} />
        ) : !state.data?.length ? (
          <EmptyState
            title="Nothing submitted yet."
            description="Add a GitHub URL above. Findings and patches go to the security reviewer."
          />
        ) : (
          <div className="record-list">
            {state.data.map((s) => (
              <div className="record-row" key={s.repositoryId}>
                <FolderGit2 size={22} />
                <div>
                  <strong>
                    {s.owner} / {s.name}
                  </strong>
                  <span>
                    {s.url} · Submitted {date(s.submittedAt)}
                  </span>
                </div>
                <span className={`mono submission-status ${s.status}`}>
                  {LABELS[s.status]}
                  {s.pullRequestUrl && (
                    <>
                      {' · '}
                      <a className="lime-text" href={s.pullRequestUrl} target="_blank" rel="noreferrer">
                        {s.branch} <GitPullRequest size={13} />
                      </a>
                    </>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
