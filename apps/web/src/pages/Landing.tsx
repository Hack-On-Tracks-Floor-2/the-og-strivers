import { ArrowRight, ArrowUpRight, Code2, ScanLine } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Brand, Eyebrow } from '../components/ui';
export function Landing({ role }: { role?: 'developer' | 'reviewer' }) {
  const developer = role === 'developer';
  return (
    <div className={`landing ${role ? 'role-landing' : ''}`}>
      <header className="landing-header">
        <Brand />
        <div className="header-right">
          <span className="live-indicator" />
          <span className="header-label">EVIDENCE-FIRST SECURITY</span>
          <span className="header-divider" />
          {role ? (
            <Link to="/">
              Switch portal <ArrowUpRight size={14} />
            </Link>
          ) : (
            <span className="mono">FOUNDATION / 01</span>
          )}
        </div>
      </header>
      <main className="landing-main">
        <div className="hero-index mono">
          {role
            ? developer
              ? '01 / DEVELOPER PORTAL'
              : '02 / REVIEWER PORTAL'
            : 'THE PROOFPATCH WORKSPACE'}
          <span className="tiny-cross">+</span>
        </div>
        <Eyebrow>
          <span className="lime-dash" />
          {role
            ? developer
              ? 'BUILD WITH CONFIDENCE'
              : 'TURN RISK INTO EVIDENCE'
            : 'SECURE CODE. VISIBLE PROOF.'}
        </Eyebrow>
        <h1 className="hero-heading">
          {!role ? (
            <>
              TRUST IS GOOD.
              <br />
              PROOF IS <span className="lime-text">BETTER.</span>
            </>
          ) : developer ? (
            'DEVELOPERS'
          ) : (
            <>
              SECURITY
              <br />
              REVIEWERS
            </>
          )}
        </h1>
        <div className="hero-bottom">
          <p className="hero-description">
            {role ? (
              developer ? (
                'Submit your code. Follow every finding, patch, and review.'
              ) : (
                'Investigate submissions. Review the fix. Make the final call.'
              )
            ) : (
              <>
                An evidence-first workspace for safer software.
                <br />
                From the first finding to the final verified fix.
              </>
            )}
          </p>
          {!role && (
            <div className="hero-principle mono">
              DETECT. PROVE.
              <br />
              PATCH. VERIFY.
            </div>
          )}
        </div>
        {role ? (
          <div className="hero-actions">
            <Link className="button primary" to={`/${role}/login`}>
              Portal login <ArrowUpRight size={18} />
            </Link>
            {developer && (
              <Link className="button secondary" to="/developer/register">
                Create account <ArrowRight size={17} />
              </Link>
            )}
          </div>
        ) : (
          <div className="portal-grid">
            <Link to="/developer" className="portal-card">
              <div className="portal-top">
                <span className="mono">01 / BUILD & SHIP</span>
                <Code2 size={20} />
              </div>
              <div className="portal-card-title">
                DEVELOPERS <ArrowUpRight size={26} />
              </div>
              <p>Submit your code. Track the fix. Ship with confidence.</p>
              <span className="portal-enter">
                Enter developer portal <ArrowRight size={16} />
              </span>
            </Link>
            <Link to="/reviewer" className="portal-card">
              <div className="portal-top">
                <span className="mono">02 / INVESTIGATE & REVIEW</span>
                <ScanLine size={20} />
              </div>
              <div className="portal-card-title">
                SECURITY REVIEWERS <ArrowUpRight size={26} />
              </div>
              <p>Inspect every finding. Follow the evidence. Make the call.</p>
              <span className="portal-enter">
                Enter reviewer portal <ArrowRight size={16} />
              </span>
            </Link>
          </div>
        )}
      </main>
      <footer className="landing-footer">
        <span className="mono">
          {role
            ? developer
              ? '01 / SUBMIT & TRACK'
              : '02 / INVESTIGATE & REVIEW'
            : 'DETECT. PROVE. PATCH. VERIFY.'}
        </span>
        <span className="footer-note">
          {role ? 'A clear path from risk to resolution.' : 'Built for code. Grounded in evidence.'}
        </span>
        <span className="mono">PROOFPATCH AI © {new Date().getFullYear()}</span>
      </footer>
    </div>
  );
}
