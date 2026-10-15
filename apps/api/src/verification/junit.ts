import type { TestSummary } from '@proofpatch/shared';

const decode = (s: string) =>
  s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const attr = (tag: string, name: string) => decode(tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1] ?? '');

/** Parses pytest's JUnit XML into per-test outcomes (no XML library needed for this subset). */
export function parseJUnit(xml: string, maxCases = 3_000): TestSummary {
  const cases: TestSummary['cases'] = [];
  const re = /<testcase\b([^>]*?)(\/>|>([\s\S]*?)<\/testcase>)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    const tag = m[1];
    const body = m[3] ?? '';
    const cls = attr(tag, 'classname');
    const name = attr(tag, 'name');
    const outcome = /<error\b/.test(body)
      ? 'error'
      : /<failure\b/.test(body)
        ? 'failed'
        : /<skipped\b/.test(body)
          ? 'skipped'
          : 'passed';
    cases.push({ id: cls ? `${cls}::${name}` : name, outcome });
  }
  // .NET TRX (dotnet test --logger trx): <UnitTestResult testName="..." outcome="Passed|Failed|NotExecuted" />
  if (!cases.length && /<TestRun\b/.test(xml)) {
    const trx = /<UnitTestResult\b([^>]*?)(\/>|>)/g;
    while ((m = trx.exec(xml))) {
      const outcome = attr(m[1], 'outcome');
      cases.push({
        id: attr(m[1], 'testName'),
        outcome: outcome === 'Passed' ? 'passed' : outcome === 'Failed' ? 'failed' : outcome === 'Error' || outcome === 'Timeout' ? 'error' : 'skipped',
      });
    }
  }
  const count = (o: string) => cases.filter((c) => c.outcome === o).length;
  return {
    total: cases.length,
    passed: count('passed'),
    failed: count('failed'),
    errors: count('error'),
    skipped: count('skipped'),
    cases: cases.slice(0, maxCases),
  };
}

/**
 * Regression gate: every test that passed on the original code must still pass on the patched
 * code. New tests and previously-failing tests do not count against the patch.
 */
export function compareSuites(baseline: TestSummary, after: TestSummary) {
  const afterById = new Map(after.cases.map((c) => [c.id, c.outcome]));
  const broken = baseline.cases
    .filter((c) => c.outcome === 'passed' && afterById.get(c.id) !== 'passed')
    .map((c) => ({ id: c.id, after: afterById.get(c.id) ?? 'missing' }));
  const fixed = baseline.cases
    .filter((c) => (c.outcome === 'failed' || c.outcome === 'error') && afterById.get(c.id) === 'passed')
    .map((c) => c.id);
  return { broken, fixed, ok: broken.length === 0 };
}
