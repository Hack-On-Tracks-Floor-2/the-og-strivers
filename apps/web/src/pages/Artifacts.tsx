import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { z } from 'zod';
import {
  AnalysisRunSchema,
  FindingSchema,
  PatchSchema,
  VerificationRunSchema,
  RunEventSchema,
} from '@proofpatch/shared';
import { useResource } from '../hooks/useResource';
import { api } from '../lib/api';
import { PageTitle, EmptyState, ErrorBox, Loading } from '../components/ui';
import { FindingCard, PatchViewer, EvidenceTimeline } from '../components/artifacts';
import { useAuth } from '../features/auth';
const content = {
  findings: {
    eyebrow: '03 / SECURITY INTELLIGENCE',
    title: 'SECURITY FINDINGS',
    description: 'Root causes, exact locations, and the evidence behind each finding.',
    empty: 'No findings without an investigation.',
    body: 'Recorded vulnerability findings will appear here after a real detection adapter runs.',
  },
  patches: {
    eyebrow: '04 / MINIMAL CHANGES',
    title: 'PATCH STUDIO',
    description: 'Inspect source changes and actual unified diffs in one place.',
    empty: 'A clean canvas for the next fix.',
    body: 'Generated patches will appear here with original code, proposed changes, and their review status.',
  },
  evidence: {
    eyebrow: '05 / TRACEABLE PROOF',
    title: 'EVIDENCE RAIL',
    description: 'Every execution, every result, every decision. On the record.',
    empty: 'Evidence starts with execution.',
    body: 'Baseline tests, vulnerability reproduction, patch application, security retests, and regression results will appear only when recorded.',
  },
};
export function ArtifactsPage({ kind }: { kind: keyof typeof content }) {
  const { user } = useAuth();
  const copy = content[kind];
  const [params] = useSearchParams();
  const [selection, setSelection] = useState(params.get('run') ?? '');
  const runs = useResource(() => api('/runs', z.array(AnalysisRunSchema)));
  const selected = selection || runs.data?.[0]?.id;
  const state = useResource(async () => {
    if (!selected) return { findings: [], patches: [], events: [], verification: [] };
    const [findings, patches, events, verification] = await Promise.all([
      api(`/runs/${selected}/findings`, z.array(FindingSchema)),
      api(`/runs/${selected}/patches`, z.array(PatchSchema)),
      api(`/runs/${selected}/events`, z.array(RunEventSchema)),
      api(`/runs/${selected}/verification`, z.array(VerificationRunSchema)),
    ]);
    return { findings, patches, events, verification };
  }, [selected, kind]);
  const empty =
    kind === 'evidence'
      ? !state.data?.events.length && !state.data?.verification.length
      : !state.data?.[kind].length;
  return (
    <>
      <PageTitle
        eyebrow={copy.eyebrow}
        title={kind === 'patches' && user?.role === 'reviewer' ? 'PATCH INSPECTION' : copy.title}
        description={copy.description}
      />
      {!!runs.data?.length && (
        <label className="run-selector">
          Analysis run
          <select value={selected ?? ''} onChange={(e) => setSelection(e.target.value)}>
            {runs.data.map((run) => (
              <option key={run.id} value={run.id}>
                {run.id.slice(0, 8)} / {run.status.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </label>
      )}
      {runs.error ? (
        <ErrorBox message={runs.error} retry={runs.reload} />
      ) : state.error ? (
        <ErrorBox message={state.error} retry={state.reload} />
      ) : runs.loading || state.loading ? (
        <Loading />
      ) : empty ? (
        <section className="panel">
          <EmptyState title={copy.empty} description={copy.body} />
        </section>
      ) : kind === 'findings' ? (
        state.data!.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)
      ) : kind === 'patches' ? (
        state.data!.patches.map((patch) => <PatchViewer key={patch.id} patch={patch} />)
      ) : (
        <EvidenceTimeline events={state.data!.events} verification={state.data!.verification} />
      )}
    </>
  );
}
