import { Link } from 'react-router-dom';
import { ArrowUpRight, ScanLine } from 'lucide-react';
import { HealthSchema, OverviewSchema } from '@proofpatch/shared';
import { useAuth } from '../features/auth';
import { useWorkspaceIndex } from '../hooks/useSecurityData';
import { useResource } from '../hooks/useResource';
import { api } from '../lib/api';
import { repositoryLabel } from '../lib/security-data';
import { PageTitle, ErrorBox, Status, date } from '../components/ui';
import {
  IntelligenceSkeleton,
  SecurityIntelligence,
} from '../features/intelligence/SecurityIntelligence';

export function OverviewPage() {
  const { user } = useAuth();
  const reviewer = user!.role === 'reviewer';
  const base = `/${user!.role}/app`;
  const index = useWorkspaceIndex();
  const summary = useResource(async () => {
    const [stats, health] = await Promise.all([
      api('/overview', OverviewSchema),
      api('/health', HealthSchema),
    ]);
    return { stats, health };
  }, [user!.id]);
  return (
    <>
      <PageTitle
        eyebrow="EVIDENCE-DRIVEN SECURITY"
        title={reviewer ? 'REVIEW INTELLIGENCE' : 'SECURITY INTELLIGENCE'}
        action={
          <Link className="button primary" to={`${base}/${reviewer ? 'queue' : 'repositories'}`}>
            {reviewer ? 'Open review queue' : 'Add repository'}
            <ArrowUpRight size={17} />
          </Link>
        }
      />
      {summary.error && <ErrorBox message={summary.error} retry={summary.reload} />}{' '}
      {summary.data && (
        <>
          <div className="workspace-totals" aria-label="Workspace totals">
            {[
              [
                reviewer ? 'Submitted runs' : 'Repositories',
                reviewer ? summary.data.stats.runs : summary.data.stats.repositories,
              ],
              ['Analysis runs', summary.data.stats.runs],
              ['Patch records', summary.data.stats.patches],
              ['Awaiting review', summary.data.stats.awaitingReview],
            ].map(([label, count]) => (
              <div key={label}>
                <span>{label}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
          <div className="pipeline-availability">
            <span
              className={`availability-dot ${summary.data.health.analysis === 'available' ? 'available' : ''}`}
            />
            <strong>
              {summary.data.health.analysis === 'available'
                ? 'Agent pipeline available'
                : 'Agent pipeline not configured'}
            </strong>
            <span>
              {summary.data.health.reason ??
                (summary.data.health.sandbox === 'docker'
                  ? 'Execution adapter: Docker'
                  : 'Availability is reported by the API.')}
            </span>
          </div>
        </>
      )}
      {index.error ? (
        <ErrorBox message={index.error} retry={index.reload} />
      ) : !index.data ? (
        <IntelligenceSkeleton />
      ) : (
        <>
          <SecurityIntelligence
            runs={index.data.runs}
            repositories={index.data.repositories}
            onRefresh={() => {
              index.reload();
              summary.reload();
            }}
          />
          {index.data.runs.length > 0 && (
            <section className="panel recent-run-panel">
              <div className="panel-heading">
                <div>
                  <h2>Recent analysis runs</h2>
                </div>
              </div>
              {index.data.runs.slice(0, 5).map((run) => (
                <Link
                  className="record-row"
                  key={run.id}
                  to={`${base}/${reviewer ? 'patches' : 'scanner'}?run=${run.id}`}
                >
                  <ScanLine size={18} />
                  <div>
                    <strong>{repositoryLabel(run, index.data!.repositories)}</strong>
                    <span>
                      {date(run.createdAt)} · Run {run.id.slice(0, 8)}
                    </span>
                  </div>
                  <Status value={run.status} />
                  <ArrowUpRight size={16} />
                </Link>
              ))}
            </section>
          )}
        </>
      )}
    </>
  );
}
