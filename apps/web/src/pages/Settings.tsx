import { PageTitle, Eyebrow, Status } from '../components/ui';
import { useAuth } from '../features/auth';
export function SettingsPage() {
  const { user } = useAuth();
  return (
    <>
      <PageTitle
        eyebrow="07 / WORKSPACE PREFERENCES"
        title="SETTINGS"
        description="Your account and the capabilities available to this workspace."
      />
      <section className="panel details">
        <Eyebrow>YOUR ACCOUNT</Eyebrow>
        <dl>
          <dt>Name</dt>
          <dd>{user?.name}</dd>
          <dt>Email</dt>
          <dd>{user?.email}</dd>
          <dt>Role</dt>
          <dd>{user?.role}</dd>
          <dt>Authentication</dt>
          <dd>Server-side session / HTTP-only cookie</dd>
        </dl>
      </section>
      <section className="panel details">
        <Eyebrow>AGENT CAPABILITIES</Eyebrow>
        {[
          'Repository intelligence',
          'Vulnerability detection',
          'Patch generation',
          'Isolated verification',
        ].map((item) => (
          <div className="capability-row" key={item}>
            <span>{item}</span>
            <Status value="not_configured" />
          </div>
        ))}
        <p>
          Capabilities are configured on the server. API keys and reviewer credentials are never
          exposed to the frontend.
        </p>
      </section>
    </>
  );
}
