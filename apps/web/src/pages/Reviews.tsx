import { useState } from 'react';
import { z } from 'zod';
import { Link } from 'react-router-dom';
import {
  PatchSchema,
  ReviewDecisionSchema,
  DecisionInputSchema,
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
            <button
              className="panel record-row w-full"
              key={patch.id}
              onClick={() => {
                setSelected(patch);
                setError('');
              }}
            >
              <div>
                <strong>Patch {patch.id.slice(0, 8)}</strong>
                <span>
                  {date(patch.createdAt)} · Run {patch.runId.slice(0, 8)}
                </span>
              </div>
              <Status value={patch.status} />
            </button>
          ))}
          {selected && (
            <>
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
            </>
          )}
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
