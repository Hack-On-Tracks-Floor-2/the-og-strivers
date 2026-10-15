import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
const auth = vi.hoisted(() => ({ role: 'developer' as 'developer' | 'reviewer' }));
vi.mock('../../apps/web/src/features/auth', () => ({
  useAuth: () => ({ user: { id: 'navigation-test', name: 'Navigation test', role: auth.role }, loading: false, error: '', refresh: () => {}, setUser: () => {} }),
}));
import { Dashboard } from '../../apps/web/src/layouts/Dashboard';
import { ArtifactsPage } from '../../apps/web/src/pages/Artifacts';
import { VerificationPage } from '../../apps/web/src/pages/Verification';
vi.mock('../../apps/web/src/hooks/useSecurityData', () => ({
  useWorkspaceIndex: () => ({ data: { runs: [], repositories: [] }, loading: false, error: '', reload: () => {} }),
  useRunBundle: () => ({ data: undefined, loading: false, error: '', reload: () => {} }),
}));
const render = (component: ReturnType<typeof createElement>, path: string) => renderToStaticMarkup(createElement(MemoryRouter, { initialEntries: [path] }, component));
describe('verification navigation and safe empty states', () => {
  it.each(['developer', 'reviewer'] as const)('renders the %s navigation link and retains Evidence Rail', role => {
    auth.role = role;
    const html = render(createElement(Dashboard, { role }), `/${role}/app/verification`);
    expect(html).toContain(`href="/${role}/app/verification"`);
    expect(html).toContain('Regression Verification');
    expect(html).toContain('Evidence Rail');
    expect(html).toContain('aria-current="page"');
  });
  it('provides a Patch Studio entry even when there are no saved patches', () => {
    auth.role = 'developer';
    const html = render(createElement(ArtifactsPage, { kind: 'patches' }), '/developer/app/patches');
    expect(html).toContain('href="/developer/app/verification"');
  });
  it('never marks missing backend records as verified', () => {
    const html = render(createElement(VerificationPage), '/developer/app/verification?source=records');
    expect(html).toContain('Verification incomplete');
    expect(html).toContain('Not yet executed');
    expect(html).not.toContain('Verified by saved execution records');
  });
});
