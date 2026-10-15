import { lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { AnalysisRun, Repository } from '@proofpatch/shared';
import { useAuth } from '../auth';
import { useRunBundle } from '../../hooks/useSecurityData';
import {
  distinctFindings,
  latestStages,
  recordedMetadata,
  verificationState,
} from '../../lib/security-data';
import { RunScope } from '../../components/RunScope';
import { EmptyState, ErrorBox, Eyebrow, Status, date } from '../../components/ui';
const IntelligenceCharts = lazy(() => import('./IntelligenceCharts'));
export function IntelligenceSkeleton() {
  return (
    <div className="intelligence-skeleton" role="status" aria-label="Loading security intelligence">
      <div />
      <div />
      <div />
      <div />
    </div>
  );
}
export function SecurityIntelligence({
  runs,
  repositories,
  repositoryId: lockedRepository,
  onRefresh,
}: {
  runs: AnalysisRun[];
  repositories: Repository[];
  repositoryId?: string;
  onRefresh?: () => void;
}) {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const requestedRun = runs.find((run) => run.id === params.get('run'));
  const repositoryId =
    lockedRepository ??
    requestedRun?.repositoryId ??
    params.get('repository') ??
    repositories[0]?.id ??
    runs[0]?.repositoryId ??
    '';
  const scopedRuns = runs.filter((run) => run.repositoryId === repositoryId);
  const selected = scopedRuns.find((run) => run.id === params.get('run')) ?? scopedRuns[0];
  const bundle = useRunBundle(selected?.id);
  const repository = repositories.find((repo) => repo.id === repositoryId);
  const selectRepository = (id: string) => {
    const next = new URLSearchParams(params);
    next.set('repository', id);
    next.delete('run');
    setParams(next);
  };
  const selectRun = (id: string) => {
    const next = new URLSearchParams(params);
    next.set('run', id);
    next.set('repository', repositoryId);
    setParams(next);
  };
  const data = bundle.data;
  const findings = distinctFindings(data?.findings ?? []);
  const metadata = recordedMetadata(data?.events ?? [], repository);
  const latestCompleted = scopedRuns
    .filter((run) => ['needs_review', 'verified'].includes(run.status))
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
  const failedRegression = (data?.patches ?? []).filter((patch) =>
    latestStages((data?.verification ?? []).filter((record) => record.patchId === patch.id)).some(
      (record) => record.stage === 'regression' && record.status === 'failed',
    ),
  ).length;
  return (
    <section className="security-intelligence">
      <div className="intelligence-heading">
        <div>
          <Eyebrow>REPOSITORY INTELLIGENCE</Eyebrow>
          <h2>Evidence in context.</h2>
        </div>
        {data && <Status value={data.run.status} />}
      </div>
      <RunScope
        runs={runs}
        repositories={repositories}
        repositoryId={repositoryId}
        runId={selected?.id ?? ''}
        onRepository={selectRepository}
        onRun={selectRun}
        refresh={() => {
          bundle.reload();
          onRefresh?.();
        }}
        lockedRepository={!!lockedRepository}
      />
      {bundle.error && <ErrorBox message={bundle.error} retry={bundle.reload} />}
      {!selected ? (
        <section className="panel">
          <EmptyState
            title="No analysis selected."
            description={
              repositoryId
                ? 'This repository has no analysis runs yet. Create an analysis request to start collecting security intelligence.'
                : 'Register a repository or receive a submitted patch to explore its analysis records.'
            }
          />
        </section>
      ) : !data ? (
        bundle.error ? null : (
          <IntelligenceSkeleton />
        )
      ) : (
        <>
          {data.run.status === 'not_configured' && (
            <div className="analysis-notice">
              <strong>Execution is not configured for this run.</strong>
              <span>
                Empty results represent missing analysis evidence, not a clean security assessment.
              </span>
            </div>
          )}
          <div className="repository-metrics">
            {[
              { label: 'Total findings', value: findings.length, detail: 'Distinct finding IDs' },
              {
                label: 'Critical / High',
                value: findings.filter((finding) => ['critical', 'high'].includes(finding.severity))
                  .length,
                detail: 'Backend severity values',
              },
              {
                label: 'Files analyzed',
                value: metadata.filesAnalyzed ?? 'Not recorded',
                detail: 'Recorded source-search coverage',
              },
              {
                label: 'Patch attempts',
                value: data.patches.length,
                detail: 'Persisted patch records',
              },
              {
                label: 'Checks verified',
                value: data.patches.filter(
                  (patch) => verificationState(patch, data.verification) === 'checks_passed',
                ).length,
                detail: 'Evidence-backed execution decisions',
              },
              {
                label: 'Regression failures',
                value: failedRegression,
                detail: 'Failed regression stages',
              },
              {
                label: 'Languages detected',
                value: metadata.languages.length || 'Not recorded',
                detail: metadata.languages.join(', ') || 'No language metadata supplied',
              },
              {
                label: 'Latest completed analysis',
                value: latestCompleted ? date(latestCompleted.updatedAt) : 'Not recorded',
                detail: 'Analysis ready for review or verified',
              },
            ].map((metric) => (
              <div className="repository-metric" key={metric.label}>
                <span>{metric.label}</span>
                <strong className={typeof metric.value === 'number' ? '' : 'text-metric'}>
                  {metric.value}
                </strong>
                <small>{metric.detail}</small>
              </div>
            ))}
          </div>
          <Suspense fallback={<IntelligenceSkeleton />}>
            <IntelligenceCharts
              findings={findings}
              bundle={data}
              runs={scopedRuns}
              base={`/${user?.role ?? 'developer'}/app`}
            />
          </Suspense>
          <section className="panel technology-panel">
            <div>
              <Eyebrow>DETECTED TECHNOLOGY</Eyebrow>
              <h2>Repository stack</h2>
              <p>Source metadata from the repository record and recorded mapping events.</p>
            </div>
            <dl>
              <dt>Languages</dt>
              <dd>
                {metadata.languages.length
                  ? metadata.languages.map((language) => (
                      <span className="technology-tag" key={language}>
                        {language}
                      </span>
                    ))
                  : 'Not recorded'}
              </dd>
              <dt>Frameworks</dt>
              <dd>
                {metadata.frameworks.length
                  ? metadata.frameworks.map((framework) => (
                      <span className="technology-tag" key={framework}>
                        {framework}
                      </span>
                    ))
                  : 'Not recorded'}
              </dd>
              <dt>Commit</dt>
              <dd>
                <code>{metadata.commitSha ?? 'No commit reference supplied'}</code>
              </dd>
            </dl>
            <p className="chart-footnote">
              Language byte counts are not supplied by the API, so language percentages are not
              displayed.
            </p>
          </section>
        </>
      )}
    </section>
  );
}
