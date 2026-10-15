import { useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import { z } from 'zod';
import { ArrowUpRight, FolderGit2, ArrowLeft } from 'lucide-react';
import { RepositorySchema, RepositoryInputSchema, AnalysisRunSchema } from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, Eyebrow, EmptyState, ErrorBox, Loading, Status, date } from '../components/ui';
export function RepositoriesPage() {
  const state = useResource(() => api('/repositories', z.array(RepositorySchema)));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState('');
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
        eyebrow="01 / SOURCE CONTROL"
        title="REPOSITORIES"
        description="Give your code a place in the security workflow."
      />
      <section className="panel repository-form">
        <Eyebrow>REGISTER A REPOSITORY</Eyebrow>
        <h2>Start with your source.</h2>
        <p>
          Add a public GitHub repository. Registration saves its URL; source inspection begins when
          the agent is connected.
        </p>
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
            {busy ? 'Registering…' : 'Add repository'}
            <ArrowUpRight size={17} />
          </button>
        </form>
        {error && <ErrorBox message={error} />}
        <span className="field-help mono">HTTPS / GITHUB.COM / PUBLIC REPOSITORIES</span>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Your repositories <span className="count">{state.data?.length ?? 0}</span>
          </h2>
          <span className="mono muted">PERSISTED LOCALLY</span>
        </div>
        {state.loading ? (
          <Loading />
        ) : state.error ? (
          <ErrorBox message={state.error} retry={state.reload} />
        ) : !state.data?.length ? (
          <EmptyState
            title="A clean slate for your code."
            description="Registered repositories will appear here. Add a GitHub URL above to get started."
          />
        ) : (
          <div className="record-list">
            {state.data.map((repo) => (
              <Link
                className="record-row"
                to={`/developer/app/repositories/${repo.id}`}
                key={repo.id}
              >
                <FolderGit2 size={22} />
                <div>
                  <strong>
                    {repo.owner} / {repo.name}
                  </strong>
                  <span>
                    {repo.url} · Added {date(repo.createdAt)}
                  </span>
                </div>
                <span className="mono muted">LANGUAGE UNKNOWN</span>
                <ArrowUpRight size={18} />
              </Link>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
export function RepositoryDetailPage() {
  const { id } = useParams();
  const state = useResource(
    async () => ({
      repo: await api(`/repositories/${id}`, RepositorySchema),
      runs: (await api('/runs', z.array(AnalysisRunSchema))).filter((r) => r.repositoryId === id),
    }),
    [id],
  );
  if (state.loading) return <Loading />;
  if (state.error) return <ErrorBox message={state.error} retry={state.reload} />;
  const { repo, runs } = state.data!;
  return (
    <>
      <Link to="/developer/app/repositories" className="back-link">
        <ArrowLeft size={15} /> Repositories
      </Link>
      <PageTitle
        eyebrow={repo.owner}
        title={repo.name}
        description={repo.url}
        action={
          <Link className="button primary" to={`/developer/app/scanner?repository=${repo.id}`}>
            Create analysis job <ArrowUpRight size={17} />
          </Link>
        }
      />
      <div className="detail-grid">
        <div className="panel details">
          <Eyebrow>REPOSITORY DETAILS</Eyebrow>
          <dl>
            <dt>Language</dt>
            <dd>{repo.language ?? 'Unknown — not inspected'}</dd>
            <dt>Framework</dt>
            <dd>{repo.framework ?? 'Unknown — not inspected'}</dd>
            <dt>Registered</dt>
            <dd>{date(repo.createdAt)}</dd>
            <dt>Repository ID</dt>
            <dd className="mono">{repo.id}</dd>
          </dl>
        </div>
        <div className="panel details">
          <Eyebrow>INGESTION STATUS</Eyebrow>
          <h2>Ready for integration.</h2>
          <p>
            The URL is registered. Existence, public visibility, source files, and test commands
            have not been inspected.
          </p>
          <Status value="not_configured" />
        </div>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Analysis history</h2>
        </div>
        {runs.length ? (
          runs.map((run) => (
            <Link className="record-row" key={run.id} to={`/developer/app/scanner?run=${run.id}`}>
              <div>
                <strong>{run.id.slice(0, 8)}</strong>
                <span>{date(run.createdAt)}</span>
              </div>
              <Status value={run.status} />
            </Link>
          ))
        ) : (
          <EmptyState
            title="No analysis requests yet."
            description="Create a job to record the request. Agent execution is pending integration."
          />
        )}
      </section>
    </>
  );
}
