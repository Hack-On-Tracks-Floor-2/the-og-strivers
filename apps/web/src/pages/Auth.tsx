import { useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowUpRight, Eye, EyeOff, LockKeyhole } from 'lucide-react';
import { UserSchema, LoginSchema, RegisterSchema } from '@proofpatch/shared';
import { Brand, Eyebrow, ErrorBox, Loading } from '../components/ui';
import { useAuth } from '../features/auth';
import { api } from '../lib/api';
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
  if (loading) return <Loading />;
  if (user) return <Navigate to={`/${user.role}/app`} replace />;
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
              ? 'One workspace for your repositories, security findings, patches, and the evidence behind them.'
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
