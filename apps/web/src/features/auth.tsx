import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { UserSchema, type User } from '@proofpatch/shared';
import { api, ApiError } from '../lib/api';
type Auth = {
  user: User | null;
  loading: boolean;
  error: string;
  setUser: (user: User | null) => void;
  refresh: () => void;
};
const AuthContext = createContext<Auth>(null!);
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [rev, setRev] = useState(0);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError('');
    api('/auth/me', UserSchema)
      .then((u) => {
        if (alive) setUser(u);
      })
      .catch((e) => {
        if (alive && (!(e instanceof ApiError) || e.status !== 401)) setError(e.message);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [rev]);
  return (
    <AuthContext.Provider
      value={{ user, loading, error, setUser, refresh: () => setRev((n) => n + 1) }}
    >
      {children}
    </AuthContext.Provider>
  );
}
export const useAuth = () => useContext(AuthContext);
