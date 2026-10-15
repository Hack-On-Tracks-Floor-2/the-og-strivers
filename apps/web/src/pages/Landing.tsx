import { ArrowLeft, ArrowUpRight, Code2, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Brand, Eyebrow } from '../components/ui';

type PortalRole = 'developer' | 'reviewer';
const portals = {
  developer: {
    eyebrow: 'BUILD WITH CONFIDENCE',
    title: 'DEVELOPERS',
    description: 'Submit your repository for a security review and follow its status.',
    footer: '01 / SUBMIT & TRACK',
  },
  reviewer: {
    eyebrow: 'TURN RISK INTO EVIDENCE',
    title: 'SECURITY REVIEWERS',
    description: 'Run scans. Investigate findings. Review AI-generated patches and their test evidence.',
    footer: '02 / INVESTIGATE & REVIEW',
  },
} as const;

function PortalPanel({ role, single = false }: { role: PortalRole; single?: boolean }) {
  const portal = portals[role];
  const Heading = single ? 'h1' : 'h2';
  return (
    <section className={`portal-panel portal-panel--${role}`} aria-labelledby={`${role}-heading`}>
      <div className="portal-content">
        <Eyebrow>{portal.eyebrow}</Eyebrow>
        <Heading id={`${role}-heading`} className="portal-heading">
          {role === 'reviewer' ? (
            <>
              <span>SECURITY</span> <span>REVIEWERS</span>
            </>
          ) : (
            portal.title
          )}
        </Heading>
        <p className="portal-description">{portal.description}</p>
        <div className="portal-actions">
          <Link
            className="button primary"
            to={`/${role}/login`}
            aria-label={`${role === 'developer' ? 'Developer' : 'Security reviewer'} Portal Login`}
          >
            Portal Login <ArrowUpRight size={17} aria-hidden="true" />
          </Link>
          {role === 'developer' && (
            <Link className="button secondary" to="/developer/register">
              Create Account
            </Link>
          )}
        </div>
      </div>
      <footer className="portal-panel-footer mono">
        <span>{portal.footer}</span>
        <span className="portal-footer-cross" aria-hidden="true">
          +
        </span>
      </footer>
    </section>
  );
}

export function Landing({ role }: { role?: PortalRole }) {
  return (
    <div className={`portal-landing ${role ? 'portal-landing--single' : ''}`}>
      <header className="portal-header">
        <Brand />
        {role ? (
          <Link to="/" className="portal-switch">
            <ArrowLeft size={14} aria-hidden="true" /> Switch portal
          </Link>
        ) : (
          <span className="portal-header-caption mono">DETECT. PROVE. PATCH. VERIFY.</span>
        )}
      </header>
      {role ? (
        <main className="single-portal">
          <PortalPanel role={role} single />
        </main>
      ) : (
        <main className="split-portals">
          <h1 className="sr-only">ProofPatch AI — developer and security reviewer portals</h1>
          <PortalPanel role="developer" />
          <PortalPanel role="reviewer" />
          <div className="portal-divider" aria-hidden="true">
            <span className="portal-divider-mark">
              <Shield size={28} strokeWidth={1.1} />
              <Code2 className="portal-divider-code" size={12} strokeWidth={1.5} />
            </span>
          </div>
        </main>
      )}
    </div>
  );
}
