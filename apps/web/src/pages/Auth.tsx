import { useState, type FormEvent } from 'react';
import { z } from 'zod';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowUpRight, Eye, EyeOff, LockKeyhole, FlaskConical } from 'lucide-react';
import { UserSchema, LoginSchema, RegisterSchema } from '@proofpatch/shared';
import { Brand, Eyebrow, ErrorBox, Loading } from '../components/ui';
import { useAuth } from '../features/auth';
import { api } from '../lib/api';

const demoAccounts = import.meta.env.DEV || __PUBLIC_DEMO__
  ? { reviewer: __REVIEWER_DEMO__, developer: __DEVELOPER_DEMO__ }
  : { reviewer: null, developer: null };

export function AuthPage({
  role,
  register = false,
}: {
  role: 'developer' | 'reviewer';
  register?: boolean;
}) {
  const { user, setUser, loading } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [visible, setVisible] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [demoFilled, setDemoFilled] = useState(false);
  if (loading) return <Loading />;
  if (user && user.role === role) return <Navigate to={`/${user.role}/app`} replace />;
  if (user) {
    // Signed in with the other role: say so instead of silently redirecting.
    const other = user.role === 'reviewer' ? 'security reviewer' : 'developer';
    const signOut = async () => {
      setBusy(true);
      try {
        await api('/auth/logout', z.object({ loggedOut: z.boolean() }), {});
        setUser(null);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setBusy(false);
      }
    };
    return (
      <main className="auth-page">
        <section className="auth-card switch-account">
          <Eyebrow>ALREADY SIGNED IN</Eyebrow>
          <h1>You're signed in as a {other}.</h1>
          <p>
            {user.email} is using this browser. Sign out to continue to the{' '}
            {role === 'reviewer' ? 'security reviewer' : 'developer'} portal, or go back to your
            workspace.
          </p>
          {error && <ErrorBox message={error} />}
          <div className="switch-actions">
            <button className="button primary" disabled={busy} onClick={signOut}>
              {busy ? 'Signing out…' : 'Sign out and continue'}
            </button>
            <button className="button secondary" onClick={() => navigate(`/${user.role}/app`)}>
              Back to my {other} workspace
            </button>
          </div>
        </section>
      </main>
    );
  }
  function fillDemoCredentials() {
    const demo = demoAccounts[role];
    if (!demo || register) return;
    setEmail(demo.email);
    setPassword(demo.password);
    setVisible(true);
    setError('');
    setDemoFilled(true);
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    const form = new FormData(event.currentTarget);
    const body = {
      email: String(form.get('email')),
      password: String(form.get('password')),
      ...(register ? { name: String(form.get('name')) } : { role }),
    };
    const parsed = (register ? RegisterSchema : LoginSchema).safeParse(body);
    if (!parsed.success) {
      setError(parsed.error.issues[0].message);
      return;
    }
    setBusy(true);
    try {
      const account = await api(
        `/auth/${register ? 'register' : 'login'}`,
        UserSchema,
        parsed.data,
      );
      setUser(account);
      navigate(`/${account.role}/app`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-page">
      <header className="landing-header">
        <Brand />
        <Link to={`/${role}`} className="back-link">
          <ArrowLeft size={15} /> Back to portal
        </Link>
      </header>
      <main className="auth-main">
        <div className="auth-intro">
          <Eyebrow>
            {role === 'developer' ? '01 / DEVELOPER ACCESS' : '02 / REVIEWER ACCESS'}
          </Eyebrow>
          <h1>
            {register ? (
              <>
                YOUR CODE.
                <br />
                OUR{' '}
                <span className="lime-text">
                  SHARED
                  <br />
                  CONFIDENCE.
                </span>
              </>
            ) : (
              <>
                PICK UP
                <br />
                WHERE YOU
                <br />
                <span className="lime-text">LEFT OFF.</span>
              </>
            )}
          </h1>
          <p>
            {role === 'developer'
              ? 'Submit your repositories for security review and follow their status. Findings and fixes are handled by the security reviewer.'
              : 'A deliberate workspace for independent security review. Every decision starts with evidence.'}
          </p>
          <span className="auth-footnote mono">
            <LockKeyhole size={14} /> PRIVATE WORKSPACE / SECURE SESSION
          </span>
        </div>
        <form className="auth-form" onSubmit={submit}>
          <Eyebrow>PROOFPATCH / {register ? 'CREATE ACCOUNT' : 'PORTAL LOGIN'}</Eyebrow>
          <h2>{register ? 'Make it official.' : 'Welcome back.'}</h2>
          <p>
            {register
              ? 'Create your developer workspace.'
              : `Sign in to your ${role === 'reviewer' ? 'security reviewer' : 'developer'} workspace.`}
          </p>
          {!register && demoAccounts[role] && (
            <div className="demo-login">
              <button
                type="button"
                className="button secondary demo-fill-button"
                onClick={fillDemoCredentials}
                disabled={busy}
              >
                <FlaskConical size={16} aria-hidden="true" /> Fill demo credentials
              </button>
              <p role="status" aria-live="polite">
                {demoFilled
                  ? 'Demo credentials filled. Select Enter workspace to sign in.'
                  : `Use the local demo ${role === 'reviewer' ? 'reviewer' : 'developer'} account.`}
              </p>
            </div>
          )}
          {error && <ErrorBox message={error} />}{' '}
          {register && (
            <label>
              Full name
              <input
                name="name"
                autoComplete="name"
                required
                minLength={2}
                maxLength={80}
                placeholder="Your name"
              />
            </label>
          )}
          <label>
            Email address
            <input
              name="email"
              type="email"
              autoComplete="email"
              required
              maxLength={254}
              placeholder="you@company.com"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
                setDemoFilled(false);
              }}
            />
          </label>
          <label>
            Password
            <div className="password-input">
              <input
                name="password"
                type={visible ? 'text' : 'password'}
                autoComplete={register ? 'new-password' : 'current-password'}
                required
                minLength={register ? 12 : 1}
                maxLength={128}
                placeholder={register ? 'At least 12 characters' : 'Your password'}
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                  setDemoFilled(false);
                }}
              />
              <button
                type="button"
                aria-label={visible ? 'Hide password' : 'Show password'}
                onClick={() => setVisible(!visible)}
              >
                {visible ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>
          </label>
          <button className="button primary" disabled={busy}>
            {busy ? 'Please wait…' : register ? 'Create account' : 'Enter workspace'}
            <ArrowUpRight size={18} />
          </button>
          {role === 'developer' ? (
            <p className="form-bottom">
              {register ? 'Already have an account?' : 'New to ProofPatch?'}{' '}
              <Link to={`/developer/${register ? 'login' : 'register'}`}>
                {register ? 'Log in' : 'Create account'}
              </Link>
            </p>
          ) : (
            <p className="form-bottom">
              Reviewer access is provisioned by your workspace administrator.
            </p>
          )}
        </form>
      </main>
    </div>
  );
}
