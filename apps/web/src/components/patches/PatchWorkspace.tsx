import { Link } from 'react-router-dom';
import { ArrowUpRight, GitCommitHorizontal, GitPullRequest } from 'lucide-react';
import type { Patch, Repository } from '@proofpatch/shared';
import { useAuth } from '../../features/auth';
import {
  diffStatistics,
  formatDuration,
  durationMs,
  owaspLabel,
  patchEvidence,
  recordedMetadata,
  repositoryLabel,
  requiredStages,
  stageLabels,
  verificationState,
  type RunBundle,
} from '../../lib/security-data';
import { Eyebrow, Status, date } from '../ui';
import { DiffViewer } from '../code/DiffViewer';
import { MergePanel } from './MergePanel';
import { RegressionTable } from './RegressionTable';

export function PatchWorkspace({
  patch,
  bundle,
  repositories = [],
}: {
  patch: Patch;
  bundle?: RunBundle;
  repositories?: Repository[];
}) {
  const { user } = useAuth();
  const base = `/${user?.role ?? 'developer'}/app`;
  const finding = bundle?.findings.find((item) => item.id === patch.findingId);
  const stats = diffStatistics(patch.unifiedDiff);
  const repository = repositories.find((item) => item.id === bundle?.run.repositoryId);
  const metadata = recordedMetadata(bundle?.events ?? [], repository);
  const outcome = verificationState(patch, bundle?.verification ?? []);
  const stages = patchEvidence(patch, bundle?.verification ?? []);
  return (
    <article className="patch-workspace" id={`patch-${patch.id}`}>
      <div className="patch-context-header">
        <div>
          <Eyebrow>
            PATCH / {patch.id.slice(0, 8)} · ATTEMPT {patch.attempt}
            {owaspLabel(finding?.cwe) ? ` · ${owaspLabel(finding?.cwe)}` : ''}
          </Eyebrow>
          <h2>
            {finding
              ? `${finding.cwe ? `${finding.cwe} · ` : ''}${finding.category}`
              : 'Patch inspection'}
          </h2>
          <p>{repositoryLabel(bundle?.run, repositories)}</p>
        </div>
        <div className="patch-status-stack">
          <span>
            Review state <Status value={patch.status} />
          </span>
          <span>
            Verification <Status value={outcome} />
          </span>
        </div>
      </div>
      <div className="patch-metadata">
        <span>
          <GitCommitHorizontal size={14} />
          {metadata.commitSha ? (
            <code title={metadata.commitSha}>{metadata.commitSha.slice(0, 12)}</code>
          ) : (
            'Commit not recorded'
          )}
        </span>
        <span>
          <GitPullRequest size={14} />
          {patch.files.length} changed {patch.files.length === 1 ? 'file' : 'files'}
        </span>
        <span>
          <b className="addition">+{stats.added}</b> <b className="deletion">−{stats.removed}</b>{' '}
          lines
        </span>
        <span>
          Finding <code title={patch.findingId}>{patch.findingId.slice(0, 8)}</code>
        </span>
        <span>{date(patch.createdAt)}</span>
      </div>
      <DiffViewer key={patch.id} patch={patch} />
      <div className="patch-explanations">
        <section>
          <h3>What creates the risk</h3>
          <p>{finding?.rootCause || 'Root-cause analysis was not supplied with this patch.'}</p>
          {finding && (
            <p className="source-reference">
              <code>
                {finding.file}:{finding.startLine}–{finding.endLine}
              </code>
              <Status value={finding.severity} />
            </p>
          )}
        </section>
        <section>
          <h3>Why this revision was proposed</h3>
          <p>
            {patch.explanation ||
              finding?.recommendation ||
              'The backend has not provided a patch rationale.'}
          </p>
        </section>
      </div>
      <RegressionTable stages={stages} />
      <section className="patch-verification">
        <div className="section-header">
          <div>
            <h3>Verification summary</h3>
          </div>
          <Link
            className="text-button"
            to={`${base}/evidence?run=${patch.runId}&patch=${patch.id}`}
          >
            Open Evidence Rail <ArrowUpRight size={15} />
          </Link>
        </div>
        <div className="verification-stage-grid">
          {[...requiredStages, 'final_decision' as const].map((name) => {
            const record = stages.find((item) => item.stage === name);
            const label =
              record?.tests && record.tests.total > 0 && record.tests.skipped === record.tests.total
                ? 'skipped'
                : (record?.status ?? 'not_available');
            return (
              <div className="verification-stage" key={name}>
                <span>{stageLabels[name]}</span>
                <Status value={label} />
                <small>
                  {record
                    ? `${record.exitCode === null ? 'Exit not recorded' : `Exit ${record.exitCode}`}${(durationMs(record.createdAt, record.completedAt) ?? 0) > 0 ? ` · ${formatDuration(durationMs(record.createdAt, record.completedAt))}` : ''}`
                    : 'No execution record'}
                </small>
                {record?.tests && (
                  <small>
                    {record.tests.passed} passed · {record.tests.failed} failed ·{' '}
                    {record.tests.skipped} skipped
                  </small>
                )}
              </div>
            );
          })}
        </div>
      </section>
      {user?.role === 'reviewer' && patch.status === 'approved' && <MergePanel patch={patch} base={base} />}
      <div className="patch-action-bar">
        <Link
          className="button secondary small-button"
          to={`${base}/regression?run=${patch.runId}&patch=${patch.id}`}
        >
          Regression Verification <ArrowUpRight size={14} />
        </Link>
        <Link
          className="button secondary small-button"
          to={`${base}/findings?run=${patch.runId}&finding=${patch.findingId}`}
        >
          View finding <ArrowUpRight size={14} />
        </Link>
        <Link
          className="button secondary small-button"
          to={`${base}/evidence?run=${patch.runId}&patch=${patch.id}`}
        >
          Verification evidence <ArrowUpRight size={14} />
        </Link>
        {user?.role === 'reviewer' && patch.status === 'needs_review' && (
          <Link className="button primary small-button" to={`${base}/queue?patch=${patch.id}`}>
            Review this patch <ArrowUpRight size={14} />
          </Link>
        )}
      </div>
    </article>
  );
}
