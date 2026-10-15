import { Link, useParams } from 'react-router-dom';
import { z } from 'zod';
import { ArrowUpRight, FolderGit2, ArrowLeft } from 'lucide-react';
import { RepositorySchema, AnalysisRunSchema } from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, Eyebrow, EmptyState, ErrorBox, Loading, Status, date } from '../components/ui';
import { SecurityIntelligence } from '../features/intelligence/SecurityIntelligence';
/** Reviewer view of every repository developers have submitted. */
export function RepositoriesPage() {
  const state = useResource(() => api('/repositories', z.array(RepositorySchema)));
  return (
    <>
      <PageTitle
        eyebrow="01 / SUBMITTED SOURCE"
        title="REPOSITORIES"
      />
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Submitted repositories <span className="count">{state.data?.length ?? 0}</span>
          </h2>
        </div>
        {state.loading ? (
          <Loading />
        ) : state.error ? (
          <ErrorBox message={state.error} retry={state.reload} />
        ) : !state.data?.length ? (
          <EmptyState
            title="Nothing submitted yet."
            description="Repositories appear here when a developer submits them. Their scans start automatically."
          />
        ) : (
          <div className="record-list">
            {state.data.map((repo) => (
              <Link className="record-row" to={`/reviewer/app/repositories/${repo.id}`} key={repo.id}>
                <FolderGit2 size={22} />
                <div>
                  <strong>
                    {repo.owner} / {repo.name}
                  </strong>
                  <span>
                    {repo.url} · Submitted {date(repo.createdAt)}
                  </span>
                </div>
                <span className="mono muted">{repo.language ?? 'Language not recorded'}</span>
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
      <Link to="/reviewer/app/repositories" className="back-link">
        <ArrowLeft size={15} /> Repositories
      </Link>
      <PageTitle
        eyebrow={repo.owner}
        title={repo.name}
        description={repo.url}
        action={
          <Link className="button primary" to={`/reviewer/app/scanner?repository=${repo.id}`}>
            Rescan repository <ArrowUpRight size={17} />
          </Link>
        }
      />
      <SecurityIntelligence
        runs={runs}
        repositories={[repo]}
        repositoryId={repo.id}
        onRefresh={state.reload}
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
          <h2>Latest analysis</h2>
          <p>
            {runs.length
              ? 'The latest run status comes from the backend. Inspect its events and execution evidence to understand what completed.'
              : 'Create an analysis job to begin repository mapping and security investigation.'}
          </p>
          {runs[0] && <Status value={runs[0].status} />}
        </div>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Analysis history</h2>
        </div>
        {runs.length ? (
          runs.map((run) => (
            <Link className="record-row" key={run.id} to={`/reviewer/app/scanner?run=${run.id}`}>
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
            description="Create a job to begin collecting real security findings and execution evidence."
          />
        )}
      </section>
    </>
  );
}
