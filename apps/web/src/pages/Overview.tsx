import { Link } from 'react-router-dom';
import {
  ArrowUpRight,
  FolderGit2,
  ScanLine,
  ShieldAlert,
  CheckCheck,
  GitPullRequest,
  ArrowRight,
  Circle,
} from 'lucide-react';
import { z } from 'zod';
import { OverviewSchema, AnalysisRunSchema, RepositorySchema } from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { useAuth } from '../features/auth';
import { PageTitle, Eyebrow, EmptyState, Loading, ErrorBox, Status, date } from '../components/ui';
export function OverviewPage() {
  const { user } = useAuth();
  const reviewer = user!.role === 'reviewer';
  const base = `/${user!.role}/app`;
  const state = useResource(
    async () => ({
      stats: await api('/overview', OverviewSchema),
      runs: await api('/runs', z.array(AnalysisRunSchema)),
      repos: reviewer ? [] : await api('/repositories', z.array(RepositorySchema)),
    }),
    [reviewer],
  );
  return (
    <>
      <PageTitle
        eyebrow="YOUR SECURITY WORKSPACE"
        title={reviewer ? 'REVIEW OVERVIEW' : 'WORKSPACE OVERVIEW'}
        description={
          reviewer
            ? 'Follow the evidence. Make a confident decision.'
            : 'A clear view of your code, your risks, and what happens next.'
        }
        action={
          <Link to={`${base}/${reviewer ? 'queue' : 'repositories'}`} className="button primary">
            {reviewer ? 'Open review queue' : 'Add repository'}
            <ArrowUpRight size={17} />
          </Link>
        }
      />
      {state.loading ? (
        <Loading />
      ) : state.error ? (
        <ErrorBox message={state.error} retry={state.reload} />
      ) : (
        state.data && (
          <>
            <div className="stat-grid">
              {[
                [
                  reviewer ? 'Reviewable runs' : 'Repositories',
                  reviewer ? state.data.stats.runs : state.data.stats.repositories,
                  FolderGit2,
                ],
                [
                  reviewer ? 'Awaiting review' : 'Analysis jobs',
                  reviewer ? state.data.stats.awaitingReview : state.data.stats.runs,
                  ScanLine,
                ],
                ['Security findings', state.data.stats.findings, ShieldAlert],
                ['Verified runs', state.data.stats.verified, CheckCheck],
              ].map(([label, value, Icon]) => {
                const Symbol = Icon as typeof FolderGit2;
                return (
                  <div className="stat-card" key={String(label)}>
                    <div>
                      <span>{String(label)}</span>
                      <Symbol size={17} />
                    </div>
                    <strong>{String(value).padStart(2, '0')}</strong>
                    <span className="stat-caption">
                      {Number(value) === 0 ? 'No records yet' : 'Persisted records'}
                    </span>
                  </div>
                );
              })}
            </div>
            <section className="workflow-strip">
              <div>
                <Eyebrow>THE PROOFPATCH PROCESS</Eyebrow>
                <span>From source code to a supported decision.</span>
              </div>
              <div className="workflow-steps">
                {['Detect', 'Prove', 'Patch', 'Verify'].map((step, i) => (
                  <span key={step}>
                    <i>{String(i + 1).padStart(2, '0')}</i>
                    {step}
                    {i < 3 && <ArrowRight size={14} />}
                  </span>
                ))}
              </div>
            </section>
            <div className="overview-grid">
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <Eyebrow>ACTIVITY</Eyebrow>
                    <h2>Recent analysis jobs</h2>
                  </div>
                  <Link to={`${base}/${reviewer ? 'queue' : 'scanner'}`} className="text-button">
                    View all <ArrowUpRight size={15} />
                  </Link>
                </div>
                {state.data.runs.length === 0 ? (
                  <EmptyState
                    title={
                      reviewer ? 'The review queue is clear.' : 'Your first signal starts here.'
                    }
                    description={
                      reviewer
                        ? 'Submitted patches and their recorded evidence will appear here when they are ready for review.'
                        : 'Register a repository to create your first analysis request. Every result will be backed by recorded evidence.'
                    }
                    action={
                      <Link
                        className="button secondary"
                        to={`${base}/${reviewer ? 'queue' : 'repositories'}`}
                      >
                        {reviewer ? 'View review queue' : 'Connect a repository'}
                        <ArrowRight size={16} />
                      </Link>
                    }
                  />
                ) : (
                  <div className="record-list">
                    {state.data.runs.slice(0, 5).map((run) => (
                      <Link
                        key={run.id}
                        className="record-row"
                        to={`${base}/${reviewer ? 'queue' : 'scanner'}?run=${run.id}`}
                      >
                        <ScanLine size={19} />
                        <div>
                          <strong>
                            {state.data!.repos.find((r) => r.id === run.repositoryId)?.name ??
                              `Analysis ${run.id.slice(0, 8)}`}
                          </strong>
                          <span>{date(run.createdAt)}</span>
                        </div>
                        <Status value={run.status} />
                        <ArrowUpRight size={16} />
                      </Link>
                    ))}
                  </div>
                )}
              </section>
              <aside className="panel getting-started">
                <Eyebrow>WORKSPACE CHECKLIST</Eyebrow>
                <h2>A stronger starting point.</h2>
                <div className="checklist-item">
                  <span className="check-circle">✓</span>
                  <div>
                    <strong>Workspace created</strong>
                    <p>Your account and session are ready.</p>
                  </div>
                </div>
                <div className="checklist-item">
                  <span className={state.data.stats.repositories ? 'check-circle' : 'step-circle'}>
                    {state.data.stats.repositories ? '✓' : '02'}
                  </span>
                  <div>
                    <strong>{reviewer ? 'Inspect submitted work' : 'Register a repository'}</strong>
                    <p>
                      {reviewer
                        ? 'Open the queue to inspect real patches.'
                        : 'Start with a public GitHub URL.'}
                    </p>
                  </div>
                </div>
                <div className="checklist-item">
                  <span className="step-circle">03</span>
                  <div>
                    <strong>Connect the agent pipeline</strong>
                    <p>
                      Intelligence, patching, and verification adapters are awaiting integration.
                    </p>
                  </div>
                </div>
                <div className="phase-note">
                  <span className="integration-dot" />
                  <span>FOUNDATION PHASE / NO AUTOMATED EXECUTION</span>
                </div>
              </aside>
            </div>
            <div className="evidence-note">
              <ShieldAlert size={17} />
              <span>
                A patch is only as strong as its proof. Verification requires actual test logs and
                recorded exit codes.
              </span>
              <span className="mono">EVIDENCE BY DESIGN</span>
            </div>
          </>
        )
      )}
    </>
  );
}
