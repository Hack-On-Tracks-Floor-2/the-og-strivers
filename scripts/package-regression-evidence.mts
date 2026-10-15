import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname, join } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const report = JSON.parse(await readFile(join(root, 'evidence/regression-demo/latest.json'), 'utf8'));
if (!/^[a-f0-9-]{36}$/.test(report.runId)) throw new Error('Invalid recorded run ID');
const run = join(root, 'evidence/regression-demo', report.runId);
const payload = {
  ...report,
  originalCode: await readFile(join(run, 'vulnerable/src/reports.cjs'), 'utf8'),
  proposedCode: await readFile(join(run, 'patched/src/reports.cjs'), 'utf8'),
  functionalTests: await readFile(join(run, 'vulnerable/test/functional.test.cjs'), 'utf8'),
  securityTest: await readFile(join(run, 'vulnerable/test/security.test.cjs'), 'utf8'),
  provenance: { commit: '676b811', reportPath: `evidence/regression-demo/${report.runId}/report.json` },
};
await mkdir(join(root, 'apps/web/public/evidence'), { recursive: true });
await writeFile(join(root, 'apps/web/public/evidence/regression-demo.json'), JSON.stringify(payload, null, 2) + '\n');
console.log(`Packaged existing recorded run ${report.runId}; no tests executed and no outcomes changed.`);
