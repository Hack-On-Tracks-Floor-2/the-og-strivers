import { defineConfig, loadEnv } from 'vite';
import { fileURLToPath } from 'node:url';
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
    plugins: [react(), tailwind()],
    envDir: projectRoot,
    define: {
      __REVIEWER_DEMO__: JSON.stringify(reviewerDemo),
      __DEVELOPER_DEMO__: JSON.stringify(developerDemo),
      __PUBLIC_DEMO__: JSON.stringify(env.PUBLIC_DEMO === 'true'),
    },
    server: { port: 5173, strictPort: true, proxy: { '/api': 'http://127.0.0.1:3001' } },
  };
});
