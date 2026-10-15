import { config } from 'dotenv';
import { resolve } from 'node:path';
import { runRegressionDemo } from '../apps/api/src/verification/regression-demo.js';

config({ path: resolve(process.env.REGRESSION_ENV_FILE || '.env'), quiet: true });
const report = await runRegressionDemo({ outputDir: process.argv[2] });
console.log(`${report.verdict}: ${report.scenario}; patch source: ${report.patchSource}`);
console.log(report.aiReason);
for (const stage of report.stages) console.log(`${stage.stage}: exit=${stage.exitCode}; ${stage.summary.passed}/${stage.summary.total} passed, ${stage.summary.failed} failed`);
console.log(`Evidence: ${report.runDir}`);
process.exitCode = report.verdict === 'VERIFIED' ? 0 : 1;
