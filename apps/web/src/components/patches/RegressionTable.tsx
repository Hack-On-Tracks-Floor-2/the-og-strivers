import type { VerificationRun } from '@proofpatch/shared';
import { Eyebrow } from '../ui';

type Outcome = 'passed' | 'failed' | 'error' | 'skipped' | 'missing';
const label: Record<Outcome, string> = { passed: 'Pass', failed: 'Fail', error: 'Error', skipped: 'Skip', missing: '—' };

/**
 * The regression proof, test by test: every test of the repository's own suite before the patch
 * (baseline) and after it. A test that passed before and does not pass after is a regression.
 */
export function RegressionTable({ stages }: { stages: VerificationRun[] }) {
  const baseline = stages.find((s) => s.stage === 'baseline')?.tests;
  const after = stages.find((s) => s.stage === 'regression')?.tests;
  if (!baseline?.cases.length && !after?.cases.length) return null;
  const before = new Map((baseline?.cases ?? []).map((c) => [c.id, c.outcome as Outcome]));
  const now = new Map((after?.cases ?? []).map((c) => [c.id, c.outcome as Outcome]));
  const ids = [...new Set([...before.keys(), ...now.keys()])];
  const rows = ids.map((id) => {
    const b = before.get(id) ?? 'missing';
    const a = now.get(id) ?? 'missing';
    const verdict = b === 'passed' && a !== 'passed' ? 'broken' : b === 'missing' ? 'added' : b !== 'passed' && a === 'passed' ? 'fixed' : 'same';
    return { id, b, a, verdict };
  });
  const order = { broken: 0, added: 1, fixed: 2, same: 3 };
  rows.sort((x, y) => order[x.verdict as keyof typeof order] - order[y.verdict as keyof typeof order] || x.id.localeCompare(y.id));
  const broken = rows.filter((r) => r.verdict === 'broken').length;
  const kept = rows.filter((r) => r.b === 'passed' && r.a === 'passed').length;
  const short = (id: string) => id.replace(/^.*?::/, '').length > 70 ? `…${id.slice(-70)}` : id.replace(/^.*?::/, '');

  return (
    <section className="regression-table">
      <Eyebrow>REGRESSION GATE · TEST BY TEST</Eyebrow>
      <h3 className={broken ? 'failed' : 'passed'}>
        {broken
          ? `${broken} test${broken > 1 ? 's' : ''} that passed before the patch no longer pass`
          : `All ${kept} tests that passed before the patch still pass`}
      </h3>
      <p>
        The repository&apos;s own suite, run in the sandbox before the patch (baseline) and after it. A regression is any
        test that passed before and does not pass after. New tests are the generated security test.
      </p>
      <div className="regression-scroll">
        <table>
          <thead>
            <tr>
              <th>Test</th>
              <th>Before patch</th>
              <th>After patch</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className={r.verdict}>
                <td className="mono" title={r.id}>{short(r.id)}</td>
                <td className={`outcome ${r.b}`}>{label[r.b]}</td>
                <td className={`outcome ${r.a}`}>{label[r.a]}</td>
                <td>{{ broken: 'Regression', added: 'New test', fixed: 'Now passes', same: 'Unchanged' }[r.verdict]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
