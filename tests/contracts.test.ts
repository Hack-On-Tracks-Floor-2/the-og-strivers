import { describe, it, expect } from 'vitest';
import { GitHubUrlSchema, RegisterSchema, RunStatusSchema } from '@proofpatch/shared';
describe('shared trust boundaries', () => {
  it('canonicalizes a supported repository URL', () =>
    expect(GitHubUrlSchema.parse('https://github.com/acme/app.git/')).toBe(
      'https://github.com/acme/app',
    ));
  it.each([
    'http://github.com/a/b',
    'https://github.com.evil.com/a/b',
    'https://github.com/a/b/tree/main',
    'https://github.com/a/..',
    'https://github.com/a/b?x=1',
    'https://user@github.com/a/b',
    'https://github.com/a/b#readme',
    'https://github.com/a/b;whoami',
    'file:///tmp/x',
  ])('rejects unsafe URL %s', (url) => expect(GitHubUrlSchema.safeParse(url).success).toBe(false));
  it('rejects role injection at developer registration', () =>
    expect(
      RegisterSchema.safeParse({
        name: 'User',
        email: 'a@example.com',
        password: 'very-strong-password',
        role: 'reviewer',
      }).success,
    ).toBe(false));
  it('rejects short passwords', () =>
    expect(
      RegisterSchema.safeParse({ name: 'User', email: 'a@example.com', password: 'short' }).success,
    ).toBe(false));
  it('represents unavailable execution explicitly', () =>
    expect(RunStatusSchema.parse('not_configured')).toBe('not_configured'));
});
