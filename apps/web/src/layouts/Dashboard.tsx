import { useEffect, useState } from 'react';
import { NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderGit2,
  ScanLine,
  ShieldAlert,
  GitPullRequest,
  Layers,
  Settings,
  LogOut,
  Menu,
  X,
  ChevronRight,
  ClipboardCheck,
  ListChecks,
  BrainCircuit,
  FlaskConical,
} from 'lucide-react';
import { z } from 'zod';
import { Brand, Loading, ErrorBox } from '../components/ui';
import { useAuth } from '../features/auth';
import { api } from '../lib/api';
import { HealthSchema } from '@proofpatch/shared';
const developerNav = [['', 'Repositories', FolderGit2]] as const;
const reviewerNav = [
  ['', 'Review Overview', LayoutDashboard],
  ['repositories', 'Repositories', FolderGit2],
  ['scanner', 'Security Scanner', ScanLine],
  ['queue', 'Review Queue', ListChecks],
  ['findings', 'Security Findings', ShieldAlert],
  ['ml', 'ML Intelligence', BrainCircuit],
  ['patches', 'Patch Inspection', GitPullRequest],
  ['evidence', 'Evidence Rail', Layers],
  ['decisions', 'Review Decisions', ClipboardCheck],
  ['regression', 'Regression Verification', FlaskConical],
  ['settings', 'Settings', Settings],
] as const;
/** Information-only pages, listed apart at the bottom of the sidebar. */
const FOOTER_PATHS: readonly string[] = ['regression', 'settings'];
export function Dashboard({ role }: { role: 'developer' | 'reviewer' }) {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [pipelineReady, setPipelineReady] = useState(false);
  useEffect(() => {
    api('/health', HealthSchema)
      .then((h) => setPipelineReady(h.analysis === 'available'))
      .catch(() => setPipelineReady(false));
  }, []);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  if (auth.loading) return <Loading />;
  if (auth.error) return <ErrorBox message={auth.error} retry={auth.refresh} />;
  if (!auth.user) return <Navigate to={`/${role}/login`} replace />;
  if (auth.user.role !== role) return <Navigate to={`/${auth.user.role}/app`} replace />;
  const nav = role === 'developer' ? developerNav : reviewerNav;
  const base = `/${role}/app`;
  const current =
    nav.find(([path]) =>
      path ? location.pathname.startsWith(`${base}/${path}`) : location.pathname === base,
    )?.[1] ?? 'Repository details';
  async function logout() {
    try {
      await api('/auth/logout', z.object({ loggedOut: z.boolean() }), {});
      auth.setUser(null);
      navigate(`/${role}`);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <div className="dashboard">
      <aside className={`sidebar ${open ? 'is-open' : ''}`}>
        <div className="sidebar-brand">
          <Brand compact />
          <button
            className="mobile-only icon-button"
            aria-label="Close navigation"
            onClick={() => setOpen(false)}
          >
            <X size={20} />
          </button>
        </div>
        <nav>
          {nav.filter(([path]) => !FOOTER_PATHS.includes(path)).map(([path, label, Icon]) => (
            <NavLink
              end={!path}
              onClick={() => setOpen(false)}
              to={path ? `${base}/${path}` : base}
              key={label}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
          <div className="nav-footer-group">
            {nav.filter(([path]) => FOOTER_PATHS.includes(path)).map(([path, label, Icon]) => (
              <NavLink
                onClick={() => setOpen(false)}
                to={`${base}/${path}`}
                key={label}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon size={18} />
                {label}
              </NavLink>
            ))}
          </div>
        </nav>
        <div className="sidebar-bottom">
          <div className="integration-card">
            <span className="integration-dot" />
            <strong>{pipelineReady ? 'Pipeline ready' : 'Pipeline offline'}</strong>
          </div>
          <div className="account">
            <span className="account-avatar">{auth.user.name.slice(0, 2).toUpperCase()}</span>
            <div>
              <strong>{auth.user.name}</strong>
              <span>{role === 'developer' ? 'Developer' : 'Security reviewer'}</span>
            </div>
            <button className="icon-button" aria-label="Log out" onClick={logout}>
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="workspace-main">
        <header className="workspace-header">
          <div className="breadcrumbs">
            <button
              className="mobile-only icon-button"
              aria-label="Open navigation"
              onClick={() => setOpen(true)}
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{current}</strong>
          </div>
        </header>
        {error && <ErrorBox message={error} />}
        <main className="workspace-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
