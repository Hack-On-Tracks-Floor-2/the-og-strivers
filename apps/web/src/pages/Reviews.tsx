import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowUpRight, Search, RefreshCw, X } from 'lucide-react';
import { PatchSchema, ReviewDecisionSchema, DecisionInputSchema } from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { loadRunBundle } from '../hooks/useSecurityData';
import {
  normalizeCategory,
  normalizeSeverity,
  owaspLabel,
  repositoryLabel,
  severityOrder,
  verificationState,
} from '../lib/security-data';
import { PageTitle, EmptyState, ErrorBox, Loading, Status, date } from '../components/ui';
import { EvidenceTimeline, FindingCard } from '../components/artifacts';
import { PatchWorkspace } from '../components/patches/PatchWorkspace';

export function ReviewsPage({ decisions = false }: { decisions?: boolean }) {
  const [params, setParams] = useSearchParams();
  const queue = useResource(() => api('/reviews/queue', z.array(PatchSchema)));
  const history = useResource(() => api('/reviews/decisions', z.array(ReviewDecisionSchema)));
  const runIds = [...new Set((queue.data ?? []).map((patch) => patch.runId))].sort();
  const contexts = useResource(async () => {
    const results = await Promise.allSettled(runIds.map(loadRunBundle));
    return {
      bundles: results.flatMap((result) => (result.status === 'fulfilled' ? [result.value] : [])),
      failures: results.flatMap((result, index) =>
        result.status === 'rejected'
          ? [
              `Run ${runIds[index].slice(0, 8)}: ${result.reason instanceof Error ? result.reason.message : 'Evidence could not be loaded.'}`,
            ]
          : [],
      ),
    };
  }, [runIds.join(',')]);
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<'approved' | 'rejected' | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const detail = useRef<HTMLDivElement>(null);
  const selected = queue.data?.find((patch) => patch.id === params.get('patch'));
  const bundle = contexts.data?.bundles.find((item) => item.run.id === selected?.runId);
  useEffect(() => {
    setReason('');
    setError('');
    if (selected)
      detail.current?.scrollIntoView({
        behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
        block: 'start',
      });
  }, [selected?.id]);
  useEffect(() => {
    if (confirmation && !dialog.current?.open) dialog.current?.showModal();
    else if (!confirmation && dialog.current?.open) dialog.current.close();
  }, [confirmation]);
  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: key === 'q' });
  }
  const query = (params.get('q') ?? '').trim().toLowerCase();
  const severity = params.get('severity') ?? '';
  const category = params.get('category') ?? '';
  const repository = params.get('repository') ?? '';
  const status = params.get('status') ?? '';
  const sort = params.get('sort') ?? 'newest';
  const rows = (queue.data ?? []).map((patch) => {
    const context = contexts.data?.bundles.find((item) => item.run.id === patch.runId);
    const finding = context?.findings.find((item) => item.id === patch.findingId);
    return {
      patch,
      context,
      finding,
      repository: repositoryLabel(context?.run, []),
      verification: context ? verificationState(patch, context.verification) : 'not_available',
    };
  });
  const filtered = rows
    .filter(
      (row) =>
        (!severity ||
          (row.finding ? normalizeSeverity(row.finding.severity) : 'unknown') === severity) &&
        (!category || (row.finding && normalizeCategory(row.finding) === category)) &&
        (!repository || row.context?.run.repositoryId === repository) &&
        (!status || row.verification === status) &&
        (!query ||
          `${row.repository} ${row.context?.run.repositoryId ?? ''} ${row.patch.id} ${row.patch.findingId} ${row.patch.files.map((file) => file.path).join(' ')} ${row.finding?.rootCause ?? ''} ${row.finding?.category ?? ''} ${row.finding?.cwe ?? ''}`
            .toLowerCase()
            .includes(query)),
    )
    .sort((a, b) =>
      sort === 'severity'
        ? (a.finding ? severityOrder.indexOf(normalizeSeverity(a.finding.severity)) : 5) -
            (b.finding ? severityOrder.indexOf(normalizeSeverity(b.finding.severity)) : 5) ||
          b.patch.updatedAt.localeCompare(a.patch.updatedAt)
        : sort === 'oldest'
          ? a.patch.updatedAt.localeCompare(b.patch.updatedAt)
          : b.patch.updatedAt.localeCompare(a.patch.updatedAt),
    );
  function prepare(decision: 'approved' | 'rejected') {
    const result = DecisionInputSchema.safeParse({ decision, reason });
    setError(result.success ? '' : result.error.issues[0].message);
    if (result.success) setConfirmation(decision);
  }
  async function decide() {
    if (!selected || !confirmation || busy) return;
    setBusy(true);
    setError('');
    try {
      await api(`/reviews/${selected.id}/decision`, ReviewDecisionSchema, {
        decision: confirmation,
        reason,
      });
      setSuccess(
        `Patch ${selected.id.slice(0, 8)} ${confirmation}. Your rationale has been recorded.`,
      );
      setConfirmation(null);
      update('patch', '');
      queue.reload();
      history.reload();
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const refresh = () => {
    queue.reload();
    history.reload();
    contexts.reload();
  };
  const historyRows = (history.data ?? [])
    .filter(
      (record) =>
        !query ||
        `${record.patchId} ${record.runId} ${record.reviewerId} ${record.reason} ${record.decision}`
          .toLowerCase()
          .includes(query),
    )
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return (
    <>
      <PageTitle
        eyebrow={decisions ? 'RECORDED HUMAN JUDGMENT' : 'SECURITY REVIEW WORKSPACE'}
        title={decisions ? 'REVIEW DECISIONS' : 'REVIEW QUEUE'}
        description={
          decisions
            ? 'Trace each decision to its rationale, reviewer, and underlying patch.'
            : 'Prioritize submitted patches, inspect the source revision, and weigh the execution evidence.'
        }
        action={
          <button className="button secondary" onClick={refresh}>
            <RefreshCw size={15} /> Refresh
          </button>
        }
      />
      {success && (
        <div className="review-success" role="status">
          {success}
        </div>
      )}
      {decisions ? (
        <>
          <label className="search-field history-search">
            <Search size={16} />
            <input
              aria-label="Search review history"
              placeholder="Search rationale, patch, run, or reviewer…"
              value={params.get('q') ?? ''}
              onChange={(event) => update('q', event.target.value)}
            />
          </label>
          {history.loading ? (
            <Loading />
          ) : history.error ? (
            <ErrorBox message={history.error} retry={history.reload} />
          ) : historyRows.length ? (
            historyRows.map((record) => (
              <article className="panel details review-history-card" key={record.id}>
                <div className="artifact-heading">
                  <h2>Patch {record.patchId.slice(0, 8)}</h2>
                  <Status value={record.decision} />
                </div>
                <p>{record.reason}</p>
                <div className="review-audit-meta">
                  <time>{date(record.createdAt)}</time>
                  <span>
                    Reviewer <code>{record.reviewerId}</code>
                  </span>
                  <span>
                    Run <code>{record.runId}</code>
                  </span>
                </div>
                <Link
                  className="text-button"
                  to={`/reviewer/app/patches?run=${record.runId}&patch=${record.patchId}`}
                >
                  Inspect this patch and its evidence <ArrowUpRight size={14} />
                </Link>
              </article>
            ))
          ) : (
            <section className="panel">
              <EmptyState
                title={query ? 'No decisions match your search.' : 'No decisions on record.'}
                description="Recorded approvals and rejections appear here with their rationale and reviewer attribution."
              />
            </section>
          )}
        </>
      ) : queue.loading ? (
        <Loading />
      ) : queue.error ? (
        <ErrorBox message={queue.error} retry={queue.reload} />
      ) : !queue.data?.length ? (
        <section className="panel">
          <EmptyState
            title="Nothing awaiting your verdict."
            description="Only actual patches submitted for review appear here. Findings, source revisions, and execution evidence remain linked throughout the review."
          />
        </section>
      ) : (
        <>
          {contexts.loading && (
            <p className="scope-explanation" role="status">
              Loading finding context and verification records…
            </p>
          )}
          {contexts.error && <ErrorBox message={contexts.error} retry={contexts.reload} />}{' '}
          {contexts.data?.failures.map((message) => (
            <ErrorBox key={message} message={message} retry={contexts.reload} />
          ))}
          <div className="review-filters">
            <label className="search-field">
              <Search size={16} />
              <input
                aria-label="Search review queue"
                placeholder="Search file, finding, or repository…"
                value={params.get('q') ?? ''}
                onChange={(event) => update('q', event.target.value)}
              />
            </label>
            <label>
              Severity
              <select value={severity} onChange={(event) => update('severity', event.target.value)}>
                <option value="">All severities</option>
                {[...severityOrder, 'unknown'].map((value) => (
                  <option value={value} key={value}>
                    {value === 'info'
                      ? 'Informational / Unknown'
                      : value === 'unknown'
                        ? 'Context unavailable'
                        : value}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Category
              <select value={category} onChange={(event) => update('category', event.target.value)}>
                <option value="">All categories</option>
                {[
                  ...new Set(
                    rows.flatMap((row) => (row.finding ? [normalizeCategory(row.finding)] : [])),
                  ),
                ].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <label>
              Repository
              <select
                value={repository}
                onChange={(event) => update('repository', event.target.value)}
              >
                <option value="">All repositories</option>
                {[
                  ...new Set(
                    rows.flatMap((row) => (row.context ? [row.context.run.repositoryId] : [])),
                  ),
                ].map((id) => (
                  <option key={id} value={id}>
                    Repository {id.slice(0, 8)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Verification
              <select value={status} onChange={(event) => update('status', event.target.value)}>
                <option value="">All outcomes</option>
                <option value="checks_passed">Checks passed</option>
                <option value="failed">Failed</option>
                <option value="running">Running</option>
                <option value="pending">Pending</option>
                <option value="not_available">Not available</option>
              </select>
            </label>
            <label>
              Sort by
              <select value={sort} onChange={(event) => update('sort', event.target.value)}>
                <option value="newest">Recently updated</option>
                <option value="oldest">Oldest update</option>
                <option value="severity">Highest severity</option>
              </select>
            </label>
          </div>
          <div className="result-summary">
            <span>
              {filtered.length} of {rows.length} submitted patches
            </span>
            <button
              className="text-button"
              onClick={() => {
                const next = new URLSearchParams();
                if (selected) next.set('patch', selected.id);
                setParams(next);
              }}
            >
              Clear filters
            </button>
          </div>
          <div className="review-table-wrap panel">
            <table className="review-table">
              <thead>
                <tr>
                  <th scope="col">Repository / Finding</th>
                  <th scope="col">Risk</th>
                  <th scope="col">Review state</th>
                  <th scope="col">Verification</th>
                  <th scope="col">Last updated</th>
                  <th scope="col">
                    <span className="sr-only">Review action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((row) => (
                  <tr
                    key={row.patch.id}
                    className={selected?.id === row.patch.id ? 'is-selected' : ''}
                  >
                    <td>
                      <strong>{row.repository}</strong>
                      <span>
                        {row.finding?.cwe ? `${row.finding.cwe} · ` : ''}
                        {owaspLabel(row.finding?.cwe) ? `${owaspLabel(row.finding?.cwe).replace('OWASP ', '')} · ` : ''}
                        {row.finding?.category ?? `Finding ${row.patch.findingId.slice(0, 8)}`}
                      </span>
                      <code title={row.patch.files.map((file) => file.path).join(', ')}>
                        {row.patch.files[0]?.path ?? 'No source snapshots'}
                        {row.patch.files.length > 1 ? ` +${row.patch.files.length - 1} files` : ''}
                      </code>
                    </td>
                    <td>
                      {row.finding ? (
                        <Status value={row.finding.severity} />
                      ) : (
                        <span className="muted">Unavailable</span>
                      )}
                    </td>
                    <td>
                      <Status value={row.patch.status} />
                      <small>Attempt {row.patch.attempt}</small>
                    </td>
                    <td>
                      <Status value={row.verification} />
                    </td>
                    <td>
                      <time
                        dateTime={row.patch.updatedAt}
                        title={`Patch created ${date(row.patch.createdAt)}`}
                      >
                        {date(row.patch.updatedAt)}
                      </time>
                    </td>
                    <td>
                      <button
                        className="button secondary small-button"
                        aria-expanded={selected?.id === row.patch.id}
                        onClick={() =>
                          update('patch', selected?.id === row.patch.id ? '' : row.patch.id)
                        }
                      >
                        {selected?.id === row.patch.id ? 'Close' : 'Inspect'}
                        <ArrowUpRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!filtered.length && (
              <EmptyState
                title="No patches match these filters."
                description="Broaden the search or clear a filter to inspect the remaining submissions."
              />
            )}
          </div>
          <p className="chart-footnote">
            Repository names and reviewer assignments are not exposed by the reviewer API.
            Repository IDs are shown as recorded references.
          </p>
          {selected && (
            <div ref={detail} className="review-detail" tabIndex={-1}>
              <div className="review-detail-heading">
                <div>
                  <span className="eyebrow">REVIEW IN CONTEXT</span>
                  <h2>Finding → Revision → Evidence → Decision</h2>
                </div>
                <button className="icon-label" onClick={() => update('patch', '')}>
                  <X size={16} /> Close inspection
                </button>
              </div>
              {bundle ? (
                <>
                  {bundle.findings.find((finding) => finding.id === selected.findingId) && (
                    <FindingCard
                      finding={bundle.findings.find(
                        (finding) => finding.id === selected.findingId,
                      )!}
                    />
                  )}
                  <PatchWorkspace patch={selected} bundle={bundle} />
                  <details className="panel inline-evidence">
                    <summary>
                      Inspect execution logs and test details{' '}
                      <span>
                        {
                          bundle.verification.filter((record) => record.patchId === selected.id)
                            .length
                        }{' '}
                        recorded stages
                      </span>
                    </summary>
                    <EvidenceTimeline
                      events={[]}
                      verification={bundle.verification.filter(
                        (record) => record.patchId === selected.id,
                      )}
                    />
                  </details>
                </>
              ) : contexts.loading ? (
                <Loading />
              ) : (
                <ErrorBox
                  message="Finding and verification context is unavailable. Reload it before reviewing this patch."
                  retry={contexts.reload}
                />
              )}
              <section className="panel details review-decision">
                <div className="section-header">
                  <div>
                    <span className="eyebrow">HUMAN REVIEW</span>
                    <h2>Record your judgment</h2>
                  </div>
                  <Status value={selected.status} />
                </div>
                <p>
                  Approval requires the backend’s baseline, reproduction, patch application,
                  security retest, and regression evidence. Your review records a separate human
                  decision.
                </p>
                <label>
                  Review rationale
                  <textarea
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    minLength={10}
                    maxLength={4000}
                    rows={4}
                    placeholder="Explain your decision with references to the source revision and execution evidence."
                  />
                </label>
                <div className="rationale-count">
                  {reason.length} / 4000 characters · minimum 10
                </div>
                {error && !confirmation && <ErrorBox message={error} />}
                <div className="hero-actions">
                  <button
                    disabled={
                      busy ||
                      !bundle ||
                      verificationState(selected, bundle.verification) !== 'checks_passed'
                    }
                    className="button primary"
                    onClick={() => prepare('approved')}
                  >
                    Approve patch
                  </button>
                  <button
                    disabled={busy || !bundle}
                    className="button secondary reject-action"
                    onClick={() => prepare('rejected')}
                  >
                    Reject patch
                  </button>
                </div>
                {bundle && verificationState(selected, bundle.verification) !== 'checks_passed' && (
                  <p className="field-help">
                    Approval is unavailable until the required execution stages and verification
                    decision have complete passing evidence. Inspect the Evidence Rail for missing,
                    skipped, or failed checks.
                  </p>
                )}
              </section>
              <section className="panel details">
                <h2>Review history for this patch</h2>
                {history.error ? (
                  <ErrorBox message={history.error} retry={history.reload} />
                ) : history.loading ? (
                  <Loading />
                ) : (
                  (history.data ?? [])
                    .filter((record) => record.patchId === selected.id)
                    .map((record) => (
                      <article className="review-history-entry" key={record.id}>
                        <Status value={record.decision} />
                        <p>{record.reason}</p>
                        <small>
                          {date(record.createdAt)} · Reviewer {record.reviewerId}
                        </small>
                      </article>
                    ))
                )}
                {!history.loading &&
                  !history.error &&
                  !history.data?.some((record) => record.patchId === selected.id) && (
                    <p>No review decision has been recorded for this patch.</p>
                  )}
              </section>
            </div>
          )}
          {params.get('patch') && !selected && !queue.loading && !success && (
            <ErrorBox message="This patch is no longer in the review queue. Open Review Decisions to inspect completed reviews." />
          )}
        </>
      )}
      <dialog
        ref={dialog}
        className="review-confirmation"
        onCancel={(event) => {
          event.preventDefault();
          if (!busy) setConfirmation(null);
        }}
        aria-labelledby="decision-confirm-title"
      >
        <span className="eyebrow">CONFIRM REVIEW DECISION</span>
        <h2 id="decision-confirm-title">
          {confirmation === 'approved' ? 'Approve this patch?' : 'Reject this patch?'}
        </h2>
        <p>
          Patch {selected?.id.slice(0, 8)} · Attempt {selected?.attempt}. This decision and the
          rationale below will be recorded against your reviewer account.
        </p>
        <blockquote>{reason}</blockquote>
        {error && <ErrorBox message={error} />}
        <div className="hero-actions">
          <button
            autoFocus
            className="button secondary"
            disabled={busy}
            onClick={() => setConfirmation(null)}
          >
            Continue inspecting
          </button>
          <button
            className={`button ${confirmation === 'approved' ? 'primary' : 'secondary reject-action'}`}
            disabled={busy}
            onClick={decide}
          >
            {busy
              ? 'Recording decision…'
              : confirmation === 'approved'
                ? 'Confirm approval'
                : 'Confirm rejection'}
          </button>
        </div>
      </dialog>
    </>
  );
}
