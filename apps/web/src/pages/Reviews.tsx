import { Fragment, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { Link } from 'react-router-dom';
import {
  PatchSchema,
  ReviewDecisionSchema,
  DecisionInputSchema,
  VerificationRunSchema,
  FindingSchema,
  type Patch,
} from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, EmptyState, ErrorBox, Loading, Status, date } from '../components/ui';
import { PatchViewer } from '../components/artifacts';
export function ReviewsPage({ decisions = false }: { decisions?: boolean }) {
  const queue = useResource(() => api('/reviews/queue', z.array(PatchSchema)));
  const history = useResource(() => api('/reviews/decisions', z.array(ReviewDecisionSchema)));
  const [selected, setSelected] = useState<Patch>();
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const detailRef = useRef<HTMLDivElement>(null);
  const evidence = useResource(
    async () =>
      selected
        ? {
            verification: (
              await api(`/runs/${selected.runId}/verification`, z.array(VerificationRunSchema))
            ).filter((v) => v.patchId === selected.id),
            finding: (await api(`/runs/${selected.runId}/findings`, z.array(FindingSchema))).find(
              (f) => f.id === selected.findingId,
            ),
          }
        : null,
    [selected?.id],
  );
  useEffect(() => {
    if (selected) detailRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [selected?.id]);
  async function decide(decision: 'approved' | 'rejected') {
    if (!selected) return;
    setError('');
    const parsed = DecisionInputSchema.safeParse({ decision, reason });
    if (!parsed.success) {
      setError(parsed.error.issues[0].message);
      return;
    }
    setBusy(true);
    try {
      await api(`/reviews/${selected.id}/decision`, ReviewDecisionSchema, parsed.data);
      setSelected(undefined);
      setReason('');
      queue.reload();
      history.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const state = decisions ? history : queue;
  return (
    <>
      <PageTitle
        eyebrow={decisions ? '06 / HUMAN JUDGMENT' : '01 / AWAITING YOUR REVIEW'}
        title={decisions ? 'REVIEW DECISIONS' : 'REVIEW QUEUE'}
        description={
          decisions
            ? 'A recorded trail of security review decisions and their rationale.'
            : 'Inspect submitted patches and test evidence before making the final call.'
        }
      />
      {error && <ErrorBox message={error} />}{' '}
      {state.loading ? (
        <Loading />
      ) : state.error ? (
        <ErrorBox message={state.error} retry={state.reload} />
      ) : decisions ? (
        history.data?.length ? (
          history.data.map((record) => (
            <article className="panel details" key={record.id}>
              <div className="artifact-heading">
                <strong>Patch {record.patchId.slice(0, 8)}</strong>
                <Status value={record.decision} />
              </div>
              <p>{record.reason}</p>
              <code>
                {date(record.createdAt)} · REVIEWER / {record.reviewerId}
                <br />
                RUN / {record.runId}
              </code>
            </article>
          ))
        ) : (
          <section className="panel">
            <EmptyState
              title="No decisions on record."
              description="Approved and rejected patch reviews will appear here with their reason, reviewer, and timestamp."
            />
          </section>
        )
      ) : queue.data?.length ? (
        <div>
          {queue.data.map((patch) => (
            <Fragment key={patch.id}>
              <button
                className={`panel record-row w-full ${selected?.id === patch.id ? 'selected' : ''}`}
                style={
                  selected?.id === patch.id ? { borderColor: 'var(--lime, #d4ff3f)' } : undefined
                }
                onClick={() => {
                  setSelected(selected?.id === patch.id ? undefined : patch);
                  setReason('');
                  setError('');
                }}
              >
                <div>
                  <strong>
                    {patch.files.map((f) => f.path).join(', ') || `Patch ${patch.id.slice(0, 8)}`}
                  </strong>
                  <span>
                    {date(patch.createdAt)} · Run {patch.runId.slice(0, 8)} · attempt{' '}
                    {patch.attempt} ·{' '}
                    {selected?.id === patch.id ? 'click to close' : 'click to review'}
                  </span>
                </div>
                <Status value={patch.status} />
              </button>
              {selected?.id === patch.id && (
                <div ref={detailRef}>
                  {evidence.data?.finding && (
                    <section className="panel details">
                      <h2>
                        {evidence.data.finding.cwe} · {evidence.data.finding.category}
                      </h2>
                      <p>
                        {evidence.data.finding.file}:{evidence.data.finding.startLine}–
                        {evidence.data.finding.endLine} · severity {evidence.data.finding.severity}{' '}
                        · confidence {Math.round(evidence.data.finding.confidence * 100)}%
                      </p>
                      <p>{evidence.data.finding.rootCause}</p>
                    </section>
                  )}
                  {evidence.data && (
                    <section className="panel details">
                      <h2>Recorded evidence</h2>
                      {evidence.data.verification.map((v) => (
                        <div className="record-row" key={v.id}>
                          <div>
                            <strong>{v.stage.replaceAll('_', ' ')}</strong>
                            <span>
                              exit {v.exitCode ?? '—'}
                              {v.tests
                                ? ` · ${v.tests.passed} passed / ${v.tests.failed} failed / ${v.tests.total} tests`
                                : ''}
                              {v.stage === 'reproduction'
                                ? ' · exploit test fails on original = bug proven'
                                : ''}
                            </span>
                          </div>
                          <Status value={v.status} />
                        </div>
                      ))}
                    </section>
                  )}
                  <PatchViewer patch={selected} />
                  <section className="panel details">
                    <h2>Record your decision</h2>
                    <p>
                      Approval requires passing baseline, reproduction, patch application, security
                      retest and regression evidence.
                    </p>
                    <Link
                      className="text-button lime-text"
                      to={`/reviewer/app/evidence?run=${selected.runId}`}
                    >
                      Inspect recorded evidence ↗
                    </Link>
                    <label>
                      Review rationale
                      <textarea
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        minLength={10}
                        maxLength={4000}
                        rows={4}
                        placeholder="Explain your decision with reference to the evidence."
                      />
                    </label>
                    <div className="hero-actions">
                      <button
                        disabled={busy}
                        className="button primary"
                        onClick={() => decide('approved')}
                      >
                        Approve patch
                      </button>
                      <button
                        disabled={busy}
                        className="button secondary"
                        onClick={() => decide('rejected')}
                      >
                        Reject patch
                      </button>
                    </div>
                  </section>
                </div>
              )}
            </Fragment>
          ))}
        </div>
      ) : (
        <section className="panel">
          <EmptyState
            title="Nothing awaiting your verdict."
            description="Only actual patches submitted for review appear here. Their findings, diffs, and test evidence will be available before you decide."
          />
        </section>
      )}
    </>
  );
}
