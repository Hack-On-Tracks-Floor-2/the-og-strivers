import { HealthSchema } from '@proofpatch/shared';
import { PageTitle, Eyebrow, Status } from '../components/ui';
import { useAuth } from '../features/auth';
import { useResource } from '../hooks/useResource';
import { api } from '../lib/api';
export function SettingsPage() {
  const { user } = useAuth();
  const health = useResource(() => api('/health', HealthSchema));
  const ready = health.data?.analysis === 'available';
  const capabilities: [string, boolean, string?][] = [
    ['AI providers (in fallback order)', !!health.data?.ai?.length, health.data?.ai?.join(' → ')],
    ['Sandbox', health.data?.sandbox === 'docker', health.data?.sandbox === 'docker' ? 'Docker, network off' : undefined],
    ['Find, patch & prove', ready],
  ];
  return (
    <>
      <PageTitle title="SETTINGS" />
      <section className="panel details">
        <Eyebrow>YOUR ACCOUNT</Eyebrow>
        <dl>
          <dt>Name</dt>
          <dd>{user?.name}</dd>
          <dt>Email</dt>
          <dd>{user?.email}</dd>
          <dt>Role</dt>
          <dd>{user?.role}</dd>
        </dl>
      </section>
      <section className="panel details">
        <Eyebrow>AGENT CAPABILITIES</Eyebrow>
        {capabilities.map(([item, on, detail]) => (
          <div className="capability-row" key={item}>
            <span>
              {item}
              {detail && <small> · {detail}</small>}
            </span>
            <Status value={health.loading ? 'pending' : on ? 'available' : 'not_configured'} />
          </div>
        ))}
      </section>
    </>
  );
}
