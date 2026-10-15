import { Link, useSearchParams } from 'react-router-dom';
import { RegressionEvidenceSchema } from '@proofpatch/shared';
import { useAuth } from '../features/auth';
import { useResource } from '../hooks/useResource';
import { api, ApiError } from '../lib/api';
import { PageTitle, ErrorBox, Loading, Status, date } from '../components/ui';
import { ArtifactsPage } from './Artifacts';
import { DiffViewer } from '../components/code/DiffViewer';

const labels: Record<string, string> = {
  baseline: 'Original baseline tests',
  'security-before': 'Vulnerability reproduction',
  'security-after': 'Post-patch security tests',
  regression: 'Original regression suite',
};
export function ReferenceRegression({ comparison = false }: { comparison?: boolean }) {
  const { user } = useAuth();
  const base = `/${user!.role}/app`;
  const evidence = useResource(async () => {
    try {
      return await api('/regression-demo/evidence', RegressionEvidenceSchema);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  });
  if (evidence.loading) return <Loading />;
  if (evidence.error) return <ErrorBox message={evidence.error} retry={evidence.reload} />;
  const report = evidence.data;
  if (!report)
    return (
      <section className="panel details">
        <h2>Not executed</h2>
        <p>
          No regression reference evidence is recorded on this backend. Verification is incomplete.
        </p>
      </section>
    );
  const complete =
    report.verdict === 'VERIFIED' &&
    report.stages.length >= 4 &&
    report.integrity.fixtureSourceUnchanged &&
    report.integrity.functionalTestsUnchanged &&
    report.integrity.securityTestsIdentical &&
    report.comparison.ok;
  return (
    <section className="panel details">
      <div className="section-header">
        <div>
          <span className="eyebrow">EXECUTED REFERENCE SCENARIO</span>
          <h2>{report.scenario}</h2>
        </div>
        <Status
          value={complete ? 'verified' : report.verdict === 'FAILED' ? 'failed' : 'not_available'}
        />
      </div>
      <p>{report.execution}</p>
      <p className="scope-explanation">
        This is genuine execution evidence for the project's authored reference fixture. It does not
        verify a different repository patch or an ML prediction.
      </p>
      <div className="patch-metadata">
        <span>
          Run <code>{report.runId}</code>
        </span>
        <span>{date(report.createdAt)}</span>
        <span>Patch source: {report.patchSource}</span>
      </div>
      {comparison ? (
        report.sourceFiles?.length ? (
          <DiffViewer
            patch={{
              id: report.runId,
              files: report.sourceFiles,
              unifiedDiff: report.unifiedDiff,
              securityTest: null,
            }}
          />
        ) : (
          <div>
            <p>
              Source snapshots are unavailable on this backend. The recorded unified diff is
              available.
            </p>
            <pre className="code-block">{report.unifiedDiff}</pre>
          </div>
        )
      ) : (
        <>
          <div className="verification-stage-grid">
            {report.stages.map((stage) => {
              const reproduction = stage.stage === 'security-before';
              const skipped =
                stage.summary.total === 0 || stage.summary.skipped === stage.summary.total;
              const passed =
                !stage.error &&
                !skipped &&
                (reproduction
                  ? stage.exitCode === 1 && stage.summary.failed > 0 && stage.summary.errors === 0
                  : stage.exitCode === 0 &&
                    stage.summary.passed > 0 &&
                    stage.summary.failed === 0 &&
                    stage.summary.errors === 0);
              return (
                <div className="verification-stage" key={stage.stage}>
                  <span>{labels[stage.stage] ?? stage.stage}</span>
                  <Status value={skipped ? 'skipped' : passed ? 'passed' : 'failed'} />
                  <small>
                    {stage.summary.passed} passed · {stage.summary.failed} failed ·{' '}
                    {stage.summary.skipped} skipped
                  </small>
                  <small>
                    Exit {stage.exitCode ?? 'not recorded'} · {(stage.durationMs / 1000).toFixed(2)}{' '}
                    s
                  </small>
                  {reproduction && (
                    <small>Expected failure on current source demonstrates reproduction.</small>
                  )}
                </div>
              );
            })}
            <div className="verification-stage">
              <span>Patch application</span>
              <Status
                value={
                  report.unifiedDiff && report.integrity.fixtureSourceUnchanged
                    ? 'applied'
                    : 'not_available'
                }
              />
              <small>Recorded diff and unchanged original fixture</small>
            </div>
            <div className="verification-stage">
              <span>Final verification verdict</span>
              <Status
                value={
                  complete ? 'verified' : report.verdict === 'FAILED' ? 'failed' : 'not_available'
                }
              />
              <small>Functional and security test integrity recorded</small>
            </div>
          </div>
          <div className="reference-logs">
            {report.stages.map((stage) => (
              <details className="supporting-evidence" key={stage.stage}>
                <summary>{labels[stage.stage] ?? stage.stage} · execution log</summary>
                <p>
                  {date(stage.startedAt)} · {stage.durationMs} ms · exit{' '}
                  {stage.exitCode ?? 'not recorded'}
                </p>
                <pre className="code-block">
                  {stage.argv.map((value) => JSON.stringify(value)).join(' ')}
                </pre>
                <pre className="code-block execution-log">
                  {stage.stdout || 'No standard output recorded.'}
                  {stage.stderr ? `\n${stage.stderr}` : ''}
                  {stage.error ? `\n${stage.error}` : ''}
                </pre>
              </details>
            ))}
          </div>
          <p>{report.aiReason}</p>
        </>
      )}
      {user!.role === 'reviewer' && (
        <div className="patch-action-bar">
          <Link
            className="button secondary small-button"
            to={`${base}/${comparison ? 'regression' : 'patches?reference=regression'}`}
          >
            {comparison ? 'Open Regression Verification' : 'Inspect recorded source revision'}
          </Link>
          <Link className="button secondary small-button" to={`${base}/findings`}>
            Security Findings
          </Link>
        </div>
      )}
    </section>
  );
}
export function RegressionVerificationPage() {
  const { user } = useAuth();
  const [params] = useSearchParams();
  const scoped = user!.role === 'reviewer' && !!params.get('run');
  return (
    <>
      <PageTitle
        eyebrow="EXECUTED CHECKS / RECORDED EVIDENCE"
        title="REGRESSION VERIFICATION"
        description="Inspect baseline, reproduction, security retest, and regression outcomes. Missing execution remains incomplete."
      />
      {scoped ? (
        <>
          <ArtifactsPage kind="evidence" embedded />
          <details className="panel details">
            <summary>Independent reference-fixture evidence</summary>
            <ReferenceRegression />
          </details>
        </>
      ) : (
        <>
          <ReferenceRegression />
          {user!.role === 'reviewer' ? (
            <>
              <h2>Repository and patch evidence</h2>
              <ArtifactsPage kind="evidence" embedded />
            </>
          ) : (
            <p className="scope-explanation">
              Repository patch verification and merge proofs are managed in the Security Reviewer
              workspace.
            </p>
          )}
        </>
      )}
    </>
  );
}
export function PatchStudioPage() {
  const [params] = useSearchParams();
  return params.get('reference') === 'regression' ? (
    <>
      <PageTitle
        eyebrow="RECORDED REGRESSION REFERENCE"
        title="PATCH STUDIO"
        description="Current source and proposed revision from the executed reference fixture. This comparison does not create a repository finding."
      />
      <ReferenceRegression comparison />
    </>
  ) : (
    <ArtifactsPage kind="patches" />
  );
}
