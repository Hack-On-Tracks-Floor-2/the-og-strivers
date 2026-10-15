import { defineConfig, loadEnv } from 'vite';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import react from '@vitejs/plugin-react';
import tailwind from '@tailwindcss/vite';
const projectRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, projectRoot, '');
  // Demo accounts are filled in for local dev, or for a public demo build when PUBLIC_DEMO=true
  // (hackathon only: the demo passwords then ship in the public bundle).
  const demoAllowed = command === 'serve' || env.PUBLIC_DEMO === 'true';
  const reviewerDemo =
    demoAllowed &&
    env.REVIEWER_DEMO_ENABLED === 'true' &&
    env.REVIEWER_EMAIL &&
    env.REVIEWER_PASSWORD
      ? { email: env.REVIEWER_EMAIL, password: env.REVIEWER_PASSWORD }
      : null;
  const developerDemo =
    demoAllowed &&
    env.REVIEWER_DEMO_ENABLED === 'true' &&
    env.DEVELOPER_DEMO_EMAIL &&
    env.DEVELOPER_DEMO_PASSWORD
      ? { email: env.DEVELOPER_DEMO_EMAIL, password: env.DEVELOPER_DEMO_PASSWORD }
      : null;

  return {
    plugins: [
      react(),
      tailwind(),
      {
        name: 'public-deployment-revision',
        generateBundle() {
          let commit = process.env.VERCEL_GIT_COMMIT_SHA ?? null;
          let workingTreeDirty: boolean | null = null;
          try {
            commit ??= execFileSync('git', ['rev-parse', 'HEAD'], {
              cwd: projectRoot,
              encoding: 'utf8',
            }).trim();
            workingTreeDirty = Boolean(
              execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
                cwd: projectRoot,
                encoding: 'utf8',
              }).trim(),
            );
          } catch {
            /* Git metadata can be unavailable in manually uploaded deployment bundles. */
          }
          this.emitFile({
            type: 'asset',
            fileName: 'deployment-info.json',
            source: JSON.stringify({ commit, workingTreeDirty, builtAt: new Date().toISOString() }),
          });
        },
      },
    ],
    envDir: projectRoot,
    define: {
      __REVIEWER_DEMO__: JSON.stringify(reviewerDemo),
      __DEVELOPER_DEMO__: JSON.stringify(developerDemo),
      __PUBLIC_DEMO__: JSON.stringify(env.PUBLIC_DEMO === 'true'),
    },
    server: { port: 5173, strictPort: true, proxy: { '/api': 'http://127.0.0.1:3001' } },
  };
});
