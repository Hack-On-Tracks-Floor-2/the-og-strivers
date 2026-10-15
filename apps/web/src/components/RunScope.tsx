import { RefreshCw } from 'lucide-react';
import type { AnalysisRun, Repository } from '@proofpatch/shared';
import { date } from './ui';
export function RunScope({
  runs,
  repositories,
  repositoryId,
  runId,
  onRepository,
  onRun,
  refresh,
  lockedRepository = false,
}: {
  runs: AnalysisRun[];
  repositories: Repository[];
  repositoryId: string;
  runId: string;
  onRepository: (id: string) => void;
  onRun: (id: string) => void;
  refresh: () => void;
  lockedRepository?: boolean;
}) {
  const repositoryIds = [
    ...new Set([...repositories.map((repo) => repo.id), ...runs.map((run) => run.repositoryId)]),
  ];
  const scoped = runs.filter((run) => run.repositoryId === repositoryId);
  return (
    <div className="scope-bar">
      <div className="scope-fields">
        {!lockedRepository && (
          <label>
            Repository
            <select
              value={repositoryId}
              onChange={(event) => onRepository(event.target.value)}
              disabled={!repositoryIds.length}
            >
              <option value="" disabled>
                Select a repository
              </option>
              {repositoryIds.map((id) => {
                const repo = repositories.find((item) => item.id === id);
                return (
                  <option key={id} value={id}>
                    {repo ? `${repo.owner}/${repo.name}` : `Repository ${id.slice(0, 8)}`}
                  </option>
                );
              })}
            </select>
          </label>
        )}
        <label>
          Analysis run
          <select
            value={runId}
            onChange={(event) => onRun(event.target.value)}
            disabled={!scoped.length}
          >
            <option value="" disabled>
              {scoped.length ? 'Select an analysis' : 'No analysis recorded'}
            </option>
            {scoped.map((run) => (
              <option value={run.id} key={run.id}>
                {date(run.createdAt)} · {run.id.slice(0, 8)} · {run.status.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </label>
      </div>
      <button
        className="button secondary small-button"
        onClick={refresh}
        aria-label="Refresh analysis data"
      >
        <RefreshCw size={15} /> Refresh
      </button>
    </div>
  );
}
