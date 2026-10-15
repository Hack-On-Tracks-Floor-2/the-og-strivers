import { Link, useSearchParams } from 'react-router-dom';
import { ArrowUpRight, Search } from 'lucide-react';
import { useWorkspaceIndex, useRunBundle } from '../hooks/useSecurityData';
import {
  distinctFindings,
  findingState,
  findingStateLabels,
  normalizeCategory,
  normalizeSeverity,
  severityOrder,
} from '../lib/security-data';
import { PageTitle, EmptyState, ErrorBox } from '../components/ui';
import { FindingCard, EvidenceTimeline } from '../components/artifacts';
import { PatchWorkspace } from '../components/patches/PatchWorkspace';
import { IntelligenceSkeleton } from '../features/intelligence/SecurityIntelligence';
import { RunScope } from '../components/RunScope';
import { useAuth } from '../features/auth';

const content = {
  findings: {
    eyebrow: 'SECURITY INVESTIGATION',
    title: 'SECURITY FINDINGS',
    description:
      'Inspect the root cause, affected source, and supporting evidence for each finding.',
    empty: 'No findings recorded.',
    body: 'Confirmed findings appear here when the selected analysis produces detection evidence.',
  },
  patches: {
    eyebrow: 'SOURCE REVISION WORKSPACE',
    title: 'PATCH STUDIO',
    description:
      'Compare current source with the proposed revision, then inspect its verification evidence.',
    empty: 'No source revisions recorded.',
    body: 'The selected analysis has not produced a patch. No source changes or test outcomes are inferred.',
  },
  evidence: {
    eyebrow: 'TRACEABLE EXECUTION',
    title: 'EVIDENCE RAIL',
    description:
      'Follow the recorded execution trail, inspect test outcomes, and open the underlying logs.',
    empty: 'No execution evidence recorded.',
    body: 'Test stages and activity appear here only when the backend records them.',
  },
};
export function ArtifactsPage({ kind }: { kind: keyof typeof content }) {
  const { user } = useAuth();
  const base = `/${user!.role}/app`;
  const copy = content[kind];
  const [params, setParams] = useSearchParams();
  const index = useWorkspaceIndex();
  const requested = index.data?.runs.find((run) => run.id === params.get('run'));
  const repositoryId =
    requested?.repositoryId ??
    params.get('repository') ??
    index.data?.repositories[0]?.id ??
    index.data?.runs[0]?.repositoryId ??
    '';
  const scopedRuns = index.data?.runs.filter((run) => run.repositoryId === repositoryId) ?? [];
  const selected = scopedRuns.find((run) => run.id === params.get('run')) ?? scopedRuns[0];
  const state = useRunBundle(selected?.id);
  const data = state.data;
  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key === 'repository') {
      next.delete('run');
      next.delete('patch');
      next.delete('finding');
    }
    if (key === 'run') {
      next.delete('patch');
      next.delete('finding');
    }
    setParams(next);
  }
  const allFindings = distinctFindings(data?.findings ?? []);
  const category = params.get('category') ?? '';
  const severity = params.get('severity') ?? '';
  const status = params.get('status') ?? '';
  const query = (params.get('q') ?? '').toLowerCase();
  const findings = allFindings.filter(
    (finding) =>
      (!category || normalizeCategory(finding) === category) &&
      (!severity || normalizeSeverity(finding.severity) === severity) &&
      (!status ||
        findingState(finding, data?.patches ?? [], data?.verification ?? []) === status) &&
      (!params.get('finding') || finding.id === params.get('finding')) &&
      (!query ||
        `${finding.id} ${finding.file} ${finding.category} ${finding.cwe ?? ''} ${finding.rootCause}`
          .toLowerCase()
          .includes(query)),
  );
  const patches = (data?.patches ?? [])
    .filter((patch) => !params.get('finding') || patch.findingId === params.get('finding'))
    .sort((a, b) => b.attempt - a.attempt || b.createdAt.localeCompare(a.createdAt));
  const patchId = params.get('patch') ?? patches[0]?.id;
  const patch = patches.find((item) => item.id === patchId);
  const evidence =
    data?.verification.filter(
      (record) => !params.get('patch') || record.patchId === params.get('patch'),
    ) ?? [];
  const resetFilters = () => {
    const next = new URLSearchParams(params);
    for (const key of ['category', 'severity', 'status', 'q', 'finding']) next.delete(key);
    setParams(next);
  };
  return (
    <>
      <PageTitle
        eyebrow={copy.eyebrow}
        title={kind === 'patches' && user!.role === 'reviewer' ? 'PATCH INSPECTION' : copy.title}
        description={copy.description}
        action={kind === 'patches' ? <Link className="button secondary small-button" to={`${base}/verification`}>Regression Verification <ArrowUpRight size={15} /></Link> : undefined}
      />
      {index.data && (
        <RunScope
          runs={index.data.runs}
          repositories={index.data.repositories}
          repositoryId={repositoryId}
          runId={selected?.id ?? ''}
          onRepository={(id) => update('repository', id)}
          onRun={(id) => update('run', id)}
          refresh={() => {
            state.reload();
            index.reload();
          }}
        />
      )}
      {index.error ? (
        <ErrorBox message={index.error} retry={index.reload} />
      ) : state.error ? (
        <ErrorBox message={state.error} retry={state.reload} />
      ) : index.loading || (selected && !data) ? (
        <IntelligenceSkeleton />
      ) : !data ? (
        <section className="panel">
          <EmptyState
            title="Choose an analysis to inspect."
            description="This repository has no recorded analysis runs. Select another repository or create an analysis request."
            action={
              user!.role === 'developer' ? (
                <Link to={`${base}/scanner`} className="button secondary">
                  Open Security Scanner <ArrowUpRight size={15} />
                </Link>
              ) : undefined
            }
          />
        </section>
      ) : (
        <>
          {kind === 'findings' && (
            <>
              <div className="finding-filters">
                <label className="search-field">
                  <Search size={16} />
                  <input
                    aria-label="Search findings"
                    placeholder="Search file, finding, CWE, or explanation…"
                    value={params.get('q') ?? ''}
                    onChange={(event) => update('q', event.target.value)}
                  />
                </label>
                <label>
                  Severity
                  <select
                    value={severity}
                    onChange={(event) => update('severity', event.target.value)}
                  >
                    <option value="">All severities</option>
                    {severityOrder.map((value) => (
                      <option key={value} value={value}>
                        {value === 'info' ? 'Informational / Unknown' : value}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Category
                  <select
                    value={category}
                    onChange={(event) => update('category', event.target.value)}
                  >
                    <option value="">All categories</option>
                    {[...new Set(allFindings.map(normalizeCategory))].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Workflow
                  <select value={status} onChange={(event) => update('status', event.target.value)}>
                    <option value="">All states</option>
                    {Object.entries(findingStateLabels).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="result-summary">
                <span>
                  {findings.length} of {allFindings.length} distinct findings
                </span>
                <button className="text-button" onClick={resetFilters}>
                  Clear filters
                </button>
              </div>
              {findings.length ? (
                findings.map((finding) => (
                  <div key={finding.id}>
                    <FindingCard finding={finding} />
                    <div className="finding-actions">
                      <Link
                        className="text-button"
                        to={`${base}/patches?run=${finding.runId}&finding=${finding.id}`}
                      >
                        Inspect proposed revisions <ArrowUpRight size={14} />
                      </Link>
                      <Link className="text-button" to={`${base}/evidence?run=${finding.runId}`}>
                        Open recorded evidence <ArrowUpRight size={14} />
                      </Link>
                    </div>
                  </div>
                ))
              ) : (
                <section className="panel">
                  <EmptyState
                    title={allFindings.length ? 'No findings match these filters.' : copy.empty}
                    description={
                      allFindings.length
                        ? 'Clear a filter or broaden the search to inspect the remaining findings.'
                        : copy.body
                    }
                  />
                </section>
              )}
            </>
          )}
          {kind === 'patches' &&
            (patches.length ? (
              <>
                <label className="patch-selector">
                  Patch attempt
                  <select
                    value={patchId ?? ''}
                    onChange={(event) => update('patch', event.target.value)}
                  >
                    {patches.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.files[0]?.path ?? 'Source snapshots unavailable'} · Attempt{' '}
                        {item.attempt} · {item.id.slice(0, 8)} · {item.status.replaceAll('_', ' ')}
                      </option>
                    ))}
                  </select>
                </label>
                {patch ? (
                  <PatchWorkspace
                    patch={patch}
                    bundle={data}
                    repositories={index.data?.repositories}
                  />
                ) : (
                  <ErrorBox message="The requested patch is not part of this analysis. Choose an available patch attempt." />
                )}
              </>
            ) : (
              <section className="panel">
                <EmptyState title={copy.empty} description={copy.body} />
              </section>
            ))}
          {kind === 'evidence' && (
            <>
              {data.patches.length > 0 && (
                <label className="patch-selector">
                  Execution scope
                  <select
                    value={params.get('patch') ?? ''}
                    onChange={(event) => update('patch', event.target.value)}
                  >
                    <option value="">All patches in this run</option>
                    {data.patches.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.id.slice(0, 8)} · Attempt {item.attempt} ·{' '}
                        {item.files[0]?.path ?? 'No file snapshots'}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {params.get('patch') && (
                <p className="scope-explanation">
                  Execution records are filtered to the selected patch. Run-level activity is
                  retained for context.
                </p>
              )}
              {data.events.length || evidence.length ? (
                <EvidenceTimeline events={data.events} verification={evidence} />
              ) : (
                <section className="panel">
                  <EmptyState title={copy.empty} description={copy.body} />
                </section>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}
