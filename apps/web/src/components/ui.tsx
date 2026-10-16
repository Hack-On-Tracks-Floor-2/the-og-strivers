import { ArrowUpRight, Shield, Terminal, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link to="/" className="brand" aria-label="Proof Patch home">
      <span className="brand-mark">
        <Shield size={20} strokeWidth={2.5} />
      </span>
      <span>
        PROOF PATCH
      </span>
      {!compact && <span className="brand-version">V.01</span>}
    </Link>
  );
}
export function Eyebrow({ children }: { children: ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}
export function PageTitle({
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-title">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}
export function EmptyState({
  title,
  action,
}: {
  title: string;
  /** Kept for callers; empty states show the title only. */
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Terminal size={24} />
      </span>
      <h2>{title}</h2>
      {action}
    </div>
  );
}
export function Status({ value }: { value: string }) {
  const labels: Record<string, string> = {
    checks_passed: 'Checks passed',
    not_available: 'Not available',
    needs_review: 'Needs review',
    verified_checks: 'Verified by checks',
    under_verification: 'Under verification',
    patch_proposed: 'Patch proposed',
    failed_verification: 'Verification failed',
    info: 'Informational',
    not_configured: 'Not configured',
    passed: 'Passed',
    failed: 'Failed',
    running: 'Running',
    pending: 'Pending',
    skipped: 'Skipped',
    approved: 'Approved',
    rejected: 'Rejected',
    proposed: 'Proposed',
    applied: 'Applied',
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    received: 'Received',
    queued: 'Queued',
    mapping: 'Mapping',
    analyzing: 'Analyzing',
    patching: 'Generating patch',
    verifying: 'Verifying',
    verified: 'Verified',
    error: 'Error',
  };
  return (
    <span className={`status status-${value}`}>
      <i />
      {labels[value] ?? value.replaceAll('_', ' ')}
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
