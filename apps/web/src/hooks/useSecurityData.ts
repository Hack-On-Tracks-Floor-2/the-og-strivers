import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';
import {
  AnalysisRunSchema,
  FindingSchema,
  PatchSchema,
  RepositorySchema,
  RunEventSchema,
  VerificationRunSchema,
} from '@proofpatch/shared';
import { api } from '../lib/api';
import { useAuth } from '../features/auth';
import { useResource } from './useResource';
import { ACTIVE_RUNS, type RunBundle } from '../lib/security-data';

export function useWorkspaceIndex() {
  const { user } = useAuth();
  return useResource(async () => {
    const [runs, repositories] = await Promise.all([
      api('/runs', z.array(AnalysisRunSchema)),
      api('/repositories', z.array(RepositorySchema)),
    ]);
    return { runs, repositories };
  }, [user?.id, user?.role]);
}
export async function loadRunBundle(id: string): Promise<RunBundle> {
  const [run, findings, patches, verification, events] = await Promise.all([
    api(`/runs/${id}`, AnalysisRunSchema),
    api(`/runs/${id}/findings`, z.array(FindingSchema)),
    api(`/runs/${id}/patches`, z.array(PatchSchema)),
    api(`/runs/${id}/verification`, z.array(VerificationRunSchema)),
    api(`/runs/${id}/events`, z.array(RunEventSchema)),
  ]);
  return { run, findings, patches, verification, events };
}
export function useRunBundle(id: string | undefined) {
  const [data, setData] = useState<RunBundle>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    let alive = true;
    setData((current) => (current?.run.id === id ? current : undefined));
    setError('');
    if (!id) {
      setData(undefined);
      setLoading(false);
      return;
    }
    setLoading(true);
    loadRunBundle(id)
      .then((bundle) => {
        if (alive) setData(bundle);
      })
      .catch((reason) => {
        if (alive)
          setError(reason instanceof Error ? reason.message : 'Unable to load run evidence.');
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [id, revision]);
  useEffect(() => {
    if (!data || !ACTIVE_RUNS.has(data.run.status)) return;
    const timer = setTimeout(reload, 5000);
    return () => clearTimeout(timer);
  }, [data, reload]);
  return { data: data?.run.id === id ? data : undefined, error, loading, reload };
}
