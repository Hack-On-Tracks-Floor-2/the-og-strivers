import { defineConfig, loadEnv } from 'vite';
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import tailwind from '@tailwindcss/vite';
const projectRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, projectRoot, '');
  // This account is deliberately available for the explicitly enabled local demo.
  // Production builds always replace this value with null, without credentials.
  const reviewerDemo =
    command === 'serve' &&
    env.REVIEWER_DEMO_ENABLED === 'true' &&
    env.REVIEWER_EMAIL &&
    env.REVIEWER_PASSWORD
      ? { email: env.REVIEWER_EMAIL, password: env.REVIEWER_PASSWORD }
      : null;

  return {
    plugins: [react(), tailwind()],
    envDir: projectRoot,
    define: { __REVIEWER_DEMO__: JSON.stringify(reviewerDemo) },
    server: { port: 5173, strictPort: true, proxy: { '/api': 'http://127.0.0.1:3001' } },
  };
});
