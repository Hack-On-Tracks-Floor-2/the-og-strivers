import { useCallback, useEffect, useState } from 'react';
export function useResource<T>(loader: () => Promise<T>, keys: unknown[] = []) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');
    setData(undefined);
    loader()
      .then((value) => {
        if (alive) setData(value);
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : 'Unable to load data.');
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [...keys, revision]);
  const reload = useCallback(() => setRevision((n) => n + 1), []);
  return { data, error, loading, reload };
}
