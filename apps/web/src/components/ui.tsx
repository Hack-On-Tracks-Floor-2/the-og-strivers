import { ArrowUpRight, Shield, Terminal, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link to="/" className="brand" aria-label="ProofPatch home">
      <span className="brand-mark">
        <Shield size={20} strokeWidth={2.5} />
      </span>
      <span>
        PROOFPATCH<span className="brand-ai"> AI</span>
      </span>
      {!compact && <span className="brand-version">V.01</span>}
    </Link>
  );
}
export function Eyebrow({ children }: { children: ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}
export function PageTitle({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-title">
      <div>
        <Eyebrow>{eyebrow}</Eyebrow>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Terminal size={24} />
      </span>
      <Eyebrow>AWAITING YOUR FIRST SIGNAL</Eyebrow>
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  );
}
export function Status({ value }: { value: string }) {
  return (
    <span className={`status status-${value}`}>
      <i />
      {value.replaceAll('_', ' ')}
    </span>
  );
}
export function ErrorBox({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="error-box" role="alert">
      <span>{message}</span>
      {retry && (
        <button className="text-button" onClick={retry}>
          <RefreshCw size={14} /> Retry
        </button>
      )}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span className="loading-square" /> Loading workspace…
    </div>
  );
}
export function Arrow() {
  return <ArrowUpRight size={18} />;
}
export const date = (value: string) =>
  new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
