import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { EventEmitter } from 'node:events';
import { openDatabase, type Database } from '../../apps/api/src/database/index.js';
import { createApp } from '../../apps/api/src/app.js';
import { provisionReviewer } from '../../apps/api/src/services/auth.js';
import { WorkspaceStore } from '../../apps/api/src/repositories/clone.js';
import { createPipeline, type PipelineSandbox } from '../../apps/api/src/pipeline/orchestrator.js';
import { createAiClient, TokenBudget, type AiClient } from '../../apps/api/src/ai/client.js';
import { findCandidates, PYTHON_SINKS } from '../../apps/api/src/scanners/funnel.js';
import { JS_SINKS } from '../../apps/api/src/scanners/javascript.js';
import { auditSummary, parseAudit } from '../../apps/api/src/verification/audit.js';
import { parseSemgrep, scannersOf, semgrepArgv, semgrepRuleDirs } from '../../apps/api/src/scanners/semgrep.js';
import { OWASP_TOP_10, owaspFor } from '@proofpatch/shared';
import { applyEdits, unifiedDiff, changedLineCount, EditError } from '../../apps/api/src/patching/edits.js';
import { parseJUnit, compareSuites } from '../../apps/api/src/verification/junit.js';
import { DockerSandbox, hardeningArgs } from '../../apps/api/src/verification/docker.js';
import { inspectRepository } from '../../apps/api/src/agents/intelligence.js';
import { detectToolchain, type Language } from '../../apps/api/src/agents/toolchain.js';
import { randomUUID } from 'node:crypto';
import { closeMLWorker } from '../../apps/api/src/services/mini-ml.js';

const FIXTURE = join(__dirname, 'fixtures', 'vulnapp');
const VULN_LINE = `    rows = db.execute("SELECT id, name, email FROM users WHERE name = '%s'" % name).fetchall()`;
const SAFE_LINE = `    rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()`;
const SECURITY_TEST = `from vulnapp.store import connect, find_user


def test_injection_does_not_return_all_users():
    assert find_user(connect(), "x' OR '1'='1") == []
`;

describe('search funnel (local, zero AI tokens)', () => {
  it('maps the fixture as Python with a pytest command', async () => {
    const map = await inspectRepository(FIXTURE);
    expect(map.languages[0]).toBe('Python');
    expect(map.testCommands[0]).toEqual(['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider']);
  });
  it('ranks the SQL injection first and sends only the enclosing function', async () => {
    const { candidates, filesScanned } = await findCandidates(FIXTURE);
    expect(filesScanned).toBe(2); // tests/ excluded
    expect(candidates[0]).toMatchObject({ file: 'vulnapp/store.py', cwe: 'CWE-89', id: 'C1' });
    expect(candidates[0].snippet).toContain("WHERE name = '%s'");
    expect(candidates[0].snippet).toContain('def find_user');
    expect(candidates[0].snippet).not.toContain('def connect'); // function-level, not whole file
  });
  it('uses the trained locator to boost hits, mark the riskiest line and add model-only candidates', async () => {
    // Fake locator: every function gets 0.9, riskiest on its last line.
    const locator = {
      score: async (fns: { id: string; source: string; start: number }[]) => ({
        threshold: 0.5,
        scores: fns.map((f) => ({
          id: f.id,
          score: 0.9,
          lines: [0.05, 0.9],
          line_numbers: [f.start, f.start + f.source.split('\n').length - 1],
        })),
      }),
    };
    const { candidates, model } = await findCandidates(FIXTURE, { locator });
    expect(model).toMatchObject({ threshold: 0.5 });
    expect(model!.functionsScored).toBeGreaterThan(1);
    const sql = candidates.find((c) => c.cwe === 'CWE-89')!;
    expect(sql.modelScore).toBe(0.9);
    expect(sql.snippet).toContain('# <- trained model: riskiest line (90%)');
    expect(candidates.some((c) => c.rule === 'trained-model')).toBe(true); // e.g. connect(), no regex hit
  });
  it('falls back to rules only when the locator fails', async () => {
    const locator = { score: async () => { throw new Error('model offline'); } };
    const { candidates, model } = await findCandidates(FIXTURE, { locator });
    expect(model?.error).toContain('model offline');
    expect(candidates[0]).toMatchObject({ file: 'vulnapp/store.py', cwe: 'CWE-89' });
  });
});

describe('JavaScript support', () => {
  const JS_FIXTURE = join(__dirname, 'fixtures', 'vulnjs');
  it('maps a node:test repository to the JavaScript toolchain', async () => {
    const map = await inspectRepository(JS_FIXTURE);
    expect(map.languages[0]).toBe('JavaScript');
    const tc = await detectToolchain(JS_FIXTURE, map);
    expect(tc).toMatchObject({ language: 'javascript', framework: 'node:test' });
    if ('unsupported' in tc) throw new Error(tc.unsupported);
    expect(tc.suite).toContain('--test-reporter-destination=/out/junit.xml');
    expect(tc.only('test/proofpatch_security/x.test.js').at(-1)).toBe('test/proofpatch_security/x.test.js');
  });
  it('picks Jest or Mocha from package.json and rejects unsupported languages', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pp-tc-'));
    const map = { languages: ['JavaScript'], frameworks: [], entryPoints: [], testCommands: [], hasNodeTests: true };
    await writeFile(join(dir, 'package.json'), JSON.stringify({ devDependencies: { jest: '^29' }, type: 'module' }));
    const jest = await detectToolchain(dir, map);
    expect(jest).toMatchObject({ framework: 'jest', esm: true });
    if ('unsupported' in jest) throw new Error(jest.unsupported);
    const only = jest.only('test/proofpatch_security/a.test.js');
    // The path must not follow --reporters (Jest would read it as a reporter module).
    expect(only.indexOf('test/proofpatch_security/a.test.js')).toBeLessThan(only.indexOf('--reporters=default'));
    await writeFile(join(dir, 'package.json'), JSON.stringify({ scripts: { test: 'mocha' } }));
    expect(await detectToolchain(dir, map)).toMatchObject({ framework: 'mocha' });
    expect(await detectToolchain(dir, { ...map, languages: ['Go'] })).toHaveProperty('unsupported');
    await rm(dir, { recursive: true, force: true });
  });
  it('finds the command injection and sends only the enclosing function', async () => {
    const { candidates, filesScanned } = await findCandidates(JS_FIXTURE, { language: 'javascript' });
    expect(filesScanned).toBe(1); // test/ excluded
    expect(candidates[0]).toMatchObject({ file: 'src/greet.js', cwe: 'CWE-78', id: 'C1' });
    expect(candidates[0].snippet).toContain('function greet(name)');
    expect(candidates[0].snippet).toContain('execSync(`echo Hello ${name}`)');
    expect(candidates[0].snippet).not.toContain('function shout');
  });
});

describe('more languages: detection and toolchains', () => {
  // [language, file, source, vulnerable line text, CWE, other function that must not be in the snippet]
  const cases: [string, string, string, string, string, string][] = [
    ['go', 'store/store.go', 'package store\n\nimport (\n\t"database/sql"\n\t"fmt"\n)\n\nfunc Find(db *sql.DB, name string) (*sql.Rows, error) {\n\treturn db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = \'%s\'", name))\n}\n\nfunc Hello() string {\n\treturn "hi"\n}\n', 'db.Query(fmt.Sprintf', 'CWE-89', 'func Hello'],
    ['java', 'src/main/java/app/Files.java', 'package app;\n\nimport java.nio.file.*;\n\npublic class Files2 {\n    public String read(String name) throws Exception {\n        return new String(java.nio.file.Files.readAllBytes(Paths.get("/data", name)));\n    }\n\n    public int add(int a, int b) {\n        return a + b;\n    }\n}\n', 'Paths.get("/data", name)', 'CWE-22', 'public int add'],
    ['csharp', 'Api/Users.cs', 'using System.Data.SqlClient;\n\npublic class Users\n{\n    public void Find(SqlConnection c, string name)\n    {\n        var cmd = new SqlCommand("SELECT * FROM users WHERE name = \'" + name + "\'", c);\n    }\n\n    public int Count() { return 0; }\n}\n', 'new SqlCommand(', 'CWE-89', 'public int Count'],
    ['php', 'src/Report.php', '<?php\nfunction showReport($name) {\n    return file_get_contents("/reports/" . $name);\n}\n\nfunction title() {\n    return "Reports";\n}\n', 'file_get_contents("/reports/"', 'CWE-22', 'function title'],
    ['ruby', 'app/models/user.rb', 'class User\n  def self.search(name)\n    where("name = \'#{name}\'")\n  end\n\n  def greeting\n    "hi"\n  end\nend\n', 'where("name', 'CWE-89', 'def greeting'],
    ['rust', 'src/main.rs', 'use std::process::Command;\n\nfn run(cmd: &str) {\n    Command::new("sh").arg("-c").arg(cmd).output().unwrap();\n}\n\nfn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n', 'Command::new("sh")', 'CWE-78', 'fn add'],
    ['typescript', 'src/user.ts', 'import { execSync } from "node:child_process";\n\nexport function archive(name: string): string {\n  return execSync(`tar czf ${name}.tgz data`).toString();\n}\n\nexport function size(n: number): string {\n  return `${n} B`;\n}\n', 'execSync(`tar', 'CWE-78', 'function size'],
    ['c', 'src/main.c', '#include <string.h>\n\nvoid copy(char *dst, const char *src)\n{\n    strcpy(dst, src);\n}\n\nint add(int a, int b)\n{\n    return a + b;\n}\n', 'strcpy(dst, src)', 'CWE-120', 'int add'],
  ];
  it.each(cases)('%s: finds the planted bug and cuts out only its function', async (language, file, source, line, cwe, other) => {
    const dir = await mkdtemp(join(tmpdir(), `pp-${language}-`));
    await mkdir(join(dir, dirname(file)), { recursive: true });
    await writeFile(join(dir, file), source);
    const { candidates } = await findCandidates(dir, { language: language as Language });
    const hit = candidates.find((c) => c.cwe === cwe);
    expect(hit, JSON.stringify(candidates.map((c) => [c.cwe, c.rule]))).toBeTruthy();
    expect(hit!.snippet).toContain(line);
    expect(hit!.snippet).not.toContain(other);
    await rm(dir, { recursive: true, force: true });
  });
  it('picks proven toolchains for Go, PHP and TypeScript and detection-only for the rest', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pp-tc2-'));
    const map = (languages: string[]) => ({ languages, frameworks: [], entryPoints: [], testCommands: [], hasNodeTests: true });
    await writeFile(join(dir, 'go.mod'), 'module example.com/app\n\ngo 1.22\n');
    const go = await detectToolchain(dir, map(['Go']));
    expect(go).toMatchObject({ language: 'go', runtime: 'go', framework: 'go test' });
    if (!('only' in go)) throw new Error('go');
    expect(go.securityTestPath('store/store.go', 'x')).toBe('store/proofpatch_security_test.go');
    expect(go.only('store/proofpatch_security_test.go').slice(-3)).toEqual(['-run', '^TestProofPatch', './store']);
    await writeFile(join(dir, 'composer.json'), JSON.stringify({ 'require-dev': { 'phpunit/phpunit': '^11' } }));
    expect(await detectToolchain(dir, map(['PHP']))).toMatchObject({ language: 'php', runtime: 'php', framework: 'phpunit' });
    await writeFile(join(dir, 'package.json'), JSON.stringify({ devDependencies: { vitest: '^2' } }));
    expect(await detectToolchain(dir, map(['TypeScript']))).toMatchObject({ language: 'typescript', runtime: 'node', framework: 'vitest' });
    // Without their build files these are scanned only; C and C++ are always detection-only.
    for (const lang of ['Java', 'Kotlin', 'C#', 'Ruby', 'Rust', 'C', 'C++'])
      expect(await detectToolchain(dir, map([lang]))).toMatchObject({ detectOnly: true });
    expect(await detectToolchain(dir, map(['Haskell']))).toHaveProperty('unsupported');
    // With their build files they get full proofs.
    await writeFile(join(dir, 'pom.xml'), '<project><dependencies><dependency><artifactId>junit-jupiter</artifactId></dependency></dependencies></project>');
    const java = await detectToolchain(dir, map(['Java']));
    expect(java).toMatchObject({ runtime: 'java', label: 'Java · Maven + JUnit 5' });
    if (!('only' in java)) throw new Error('java');
    expect(java.securityTestPath('src/main/java/com/a/b/X.java', 'x')).toBe('src/test/java/com/a/b/ProofPatchSecurityTest.java');
    await mkdir(join(dir, 'App.Tests'), { recursive: true });
    await writeFile(join(dir, 'App.Tests', 'App.Tests.csproj'), '<Project><ItemGroup><PackageReference Include="Microsoft.NET.Test.Sdk" /><PackageReference Include="xunit" /></ItemGroup></Project>');
    const cs = await detectToolchain(dir, map(['C#']));
    expect(cs).toMatchObject({ runtime: 'dotnet', label: 'C# · dotnet test (xunit)' });
    if (!('only' in cs)) throw new Error('cs');
    expect(cs.securityTestPath('src/X.cs', 'x')).toBe('App.Tests/ProofPatchSecurityTests.cs');
    await writeFile(join(dir, 'Gemfile'), 'gem "rspec"\n');
    expect(await detectToolchain(dir, map(['Ruby']))).toMatchObject({ runtime: 'ruby', framework: 'rspec' });
    await writeFile(join(dir, 'Cargo.toml'), '[package]\nname = "my-crate"\n');
    await mkdir(join(dir, 'src'), { recursive: true });
    await writeFile(join(dir, 'src', 'lib.rs'), '');
    const rust = await detectToolchain(dir, map(['Rust']));
    expect(rust).toMatchObject({ runtime: 'rust', framework: 'cargo test' });
    if (!('only' in rust)) throw new Error('rust');
    expect(rust.testGuidance).toContain('use my_crate::');
    expect(await detectToolchain(dir, map(['C']))).toMatchObject({ detectOnly: true });
    // C/C++: CTest (or a "make test" target) gives full proofs; the attack test is a standalone ASan program.
    await writeFile(join(dir, 'CMakeLists.txt'), 'project(x C)\nenable_testing()\nadd_test(NAME a COMMAND a)\n');
    const c = await detectToolchain(dir, map(['C']));
    expect(c).toMatchObject({ runtime: 'c', framework: 'ctest', label: 'C · CMake + CTest + ASan' });
    if (!('only' in c)) throw new Error('c');
    expect(c.securityTestPath('src/parser.c', 'x')).toBe('proofpatch_security/proofpatch_security.c');
    expect(c.only('proofpatch_security/proofpatch_security.c')).toEqual(['c-security-test', 'proofpatch_security/proofpatch_security.c']);
    expect(await detectToolchain(dir, map(['C++']))).toMatchObject({ language: 'cpp', label: 'C++ · CMake + CTest + ASan' });
    await rm(dir, { recursive: true, force: true });
  });
});

describe('Semgrep adapter', () => {
  // Trimmed from a real `semgrep --json` run (1.178.0, pinned rules) on the invoice-tools demo.
  const REPORT = JSON.stringify({
    results: [
      { check_id: 'python.lang.security.audit.formatted-sql-query.formatted-sql-query', path: 'vulnapp/store.py', start: { line: 16, col: 12 }, end: { line: 16, col: 90 },
        extra: { message: 'Detected possible formatted SQL query. Use parameterized queries instead.', severity: 'WARNING', metadata: { cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"] } } },
      { check_id: 'python.lang.security.deserialization.pickle.avoid-pickle', path: './vulnapp/session.py', start: { line: 11, col: 12 }, end: { line: 11, col: 40 },
        extra: { message: 'Avoid using pickle.', severity: 'WARNING', metadata: { cwe: 'CWE-502: Deserialization of Untrusted Data' } } },
    ],
    errors: [{ type: 'Syntax error' }],
  });
  it('maps real Semgrep JSON to findings with file, line, column, CWE, severity and rule', () => {
    const parsed = parseSemgrep(REPORT)!;
    expect(parsed.errors).toBe(1);
    expect(parsed.hits).toEqual([
      expect.objectContaining({ file: 'vulnapp/store.py', line: 16, column: 12, cwe: 'CWE-89', severity: 'WARNING', rule: 'semgrep:formatted-sql-query' }),
      expect.objectContaining({ file: 'vulnapp/session.py', line: 11, cwe: 'CWE-502', rule: 'semgrep:avoid-pickle' }),
    ]);
    expect(parseSemgrep('')).toBeNull();
    expect(parseSemgrep('not json')).toBeNull();
  });
  it('only uses pinned rule folders, never repository configs or autofix', () => {
    expect(semgrepRuleDirs(['TypeScript', 'Java', 'Haskell'])).toEqual(['typescript', 'javascript', 'java']);
    const argv = semgrepArgv(['python']);
    expect(argv.filter((a, i) => argv[i - 1] === '--config')).toEqual(['/rules/python']);
    expect(argv).toContain('--metrics=off');
    expect(argv.join(' ')).not.toMatch(/autofix|--fix|auto/);
  });
  it('merges a Semgrep hit with ProofPatch rules on the same line and keeps both scanners', async () => {
    const { hits } = parseSemgrep(REPORT)!;
    const { candidates } = await findCandidates(FIXTURE, { external: hits });
    const sql = candidates.find((c) => c.cwe === 'CWE-89')!;
    expect(sql.rule).toContain('semgrep:formatted-sql-query');
    expect(scannersOf(sql.rule)).toEqual(expect.arrayContaining(['Semgrep', 'ProofPatch rules']));
  });
});

describe('OWASP Top 10 coverage', () => {
  it.each([
    ['Python', PYTHON_SINKS],
    ['JavaScript', JS_SINKS],
  ])('%s rules map to every code-detectable OWASP category', (_lang, rules) => {
    for (const rule of rules) expect(owaspFor(rule.cwe), `${rule.id} ${rule.cwe}`).not.toBeNull();
    const covered = new Set(rules.map((r) => owaspFor(r.cwe)!.id));
    // A06 (vulnerable components) is covered by the dependency audit, not by code rules.
    for (const c of OWASP_TOP_10.filter((c) => c.id !== 'A06')) expect(covered.has(c.id), c.id).toBe(true);
  });
  it('reads npm audit and pip-audit reports as A06 advisories', () => {
    const npm = parseAudit('javascript', JSON.stringify({ vulnerabilities: { lodash: { severity: 'high', range: '<4.17.21', via: [{ url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }], fixAvailable: { version: '4.17.21' } } } }));
    expect(npm).toEqual([{ name: 'lodash', version: '<4.17.21', severity: 'high', ids: ['GHSA-35jh-r3h4-6jhm'], fix: 'upgrade to 4.17.21' }]);
    const pip = parseAudit('python', JSON.stringify({ dependencies: [{ name: 'requests', version: '2.19.0', vulns: [{ id: 'PYSEC-2018-28', fix_versions: ['2.20.0'], aliases: ['CVE-2018-18074'] }] }, { name: 'six', version: '1.16.0', vulns: [] }] }));
    expect(pip).toEqual([{ name: 'requests', version: '2.19.0', severity: 'known CVE', ids: ['PYSEC-2018-28', 'CVE-2018-18074'], fix: 'upgrade to 2.20.0' }]);
    expect(auditSummary(pip!)).toMatch(/OWASP A06\): 1 vulnerable package — requests 2.19.0/);
    expect(parseAudit('python', 'not json')).toBeNull();
  });
});

describe('patch edits and diffs', () => {
  const read = (p: string) => (p === 'a.py' ? 'x = 1\ny = 2\nz = 3\n' : null);
  it('applies exact search/replace edits and emits a unified diff', () => {
    const [change] = applyEdits([{ file: 'a.py', search: 'y = 2', replace: 'y = 20' }], read);
    const diff = unifiedDiff(change.path, change.original, change.proposed);
    expect(diff).toContain('-y = 2');
    expect(diff).toContain('+y = 20');
    expect(changedLineCount(diff)).toBe(2);
  });
  it('rejects missing, ambiguous and unsafe edits', () => {
    expect(() => applyEdits([{ file: 'a.py', search: 'nope', replace: '' }], read)).toThrow(EditError);
    expect(() => applyEdits([{ file: '../etc/passwd', search: 'x', replace: '' }], read)).toThrow(EditError);
    expect(() =>
      applyEdits([{ file: 'a.py', search: ' = ', replace: '=' }], () => 'a = 1\nb = 2\n'),
    ).toThrow(/not unique/);
  });
  it('matches a re-indented search with escaped backticks and keeps the file indentation', () => {
    const file = 'function a(x) {\n  return run(`echo ${x}`);\n}\n';
    const [change] = applyEdits(
      [{ file: 'a.js', search: 'return run(\\`echo ${x}\\`);', replace: "return run('echo', [x]);\nif (!x) throw new Error('empty');" }],
      () => file,
    );
    expect(change.proposed).toBe("function a(x) {\n  return run('echo', [x]);\n  if (!x) throw new Error('empty');\n}\n");
  });
});

describe('JUnit parsing and the regression gate', () => {
  const xml = (cases: [string, string][]) =>
    `<testsuites><testsuite>${cases
      .map(([n, o]) => `<testcase classname="t" name="${n}">${o === 'failed' ? '<failure message="x"/>' : o === 'error' ? '<error/>' : o === 'skipped' ? '<skipped/>' : ''}</testcase>`)
      .join('')}</testsuite></testsuites>`;
  it('counts outcomes', () => {
    const s = parseJUnit(xml([['a', 'passed'], ['b', 'failed'], ['c', 'skipped'], ['d', 'error']]));
    expect([s.total, s.passed, s.failed, s.skipped, s.errors]).toEqual([4, 1, 1, 1, 1]);
  });
  it('reads .NET TRX results', () => {
    const trx = '<TestRun><Results><UnitTestResult testName="A.Ok" outcome="Passed" /><UnitTestResult testName="A.Bad" outcome="Failed"></UnitTestResult><UnitTestResult testName="A.Skip" outcome="NotExecuted" /></Results></TestRun>';
    expect(parseJUnit(trx)).toMatchObject({ total: 3, passed: 1, failed: 1, skipped: 1 });
  });
  it('fails only when a previously passing test stops passing', () => {
    const before = parseJUnit(xml([['a', 'passed'], ['b', 'failed']]));
    expect(compareSuites(before, parseJUnit(xml([['a', 'passed'], ['b', 'passed'], ['new', 'passed']]))).ok).toBe(true);
    const broken = compareSuites(before, parseJUnit(xml([['a', 'failed'], ['b', 'failed']])));
    expect(broken.ok).toBe(false);
    expect(broken.broken).toEqual([{ id: 't::a', after: 'failed' }]);
  });
});

describe('AI client', () => {
  const ok = (text: string) => new Response(JSON.stringify({ candidates: [{ finishReason: 'STOP', content: { parts: [{ text }] } }], usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 20 } }));
  const groqOk = (text: string) => new Response(JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: text } }], usage: { prompt_tokens: 90, completion_tokens: 10 } }));
  const req = { task: 't', instructions: 'i', data: 'd', schema: { type: 'object' }, maxOutputTokens: 200 };
  it('uses Groq first by default and Gemini as the fallback', async () => {
    const urls: string[] = [];
    const ai = createAiClient({ GEMINI_API_KEY: 'g', GROQ_API_KEY: 'q', AI_RETRY_DELAY_MS: '0' }, {
      fetchImpl: (async (url: string) => {
        urls.push(String(url));
        return String(url).includes('groq') ? new Response('', { status: 503 }) : ok('{"b":2}');
      }) as typeof fetch,
    })!;
    expect(ai.providers[0]).toMatch(/^Groq/);
    const result = await ai.completeJSON<{ b: number }>(req, new TokenBudget(10_000), new AbortController().signal);
    expect(result.usage.provider).toBe('Gemini');
    expect(urls[0]).toContain('api.groq.com');
  });
  it('redacts secrets before sending and restores them in the answer', async () => {
    let sent = '';
    const secret = 'sk-live-THIS_IS_A_FAKE_SECRET_123456';
    const ai = createAiClient({ GROQ_API_KEY: 'q' }, {
      fetchImpl: (async (_url: string, init: RequestInit) => {
        sent = String(init.body);
        const placeholder = sent.match(/«SECRET_\d+»/)![0];
        return groqOk(JSON.stringify({ search: `KEY = "${placeholder}"` }));
      }) as typeof fetch,
    })!;
    const result = await ai.completeJSON<{ search: string }>(
      { ...req, data: `KEY = "${secret}"
password = "hunter2-very-secret"` },
      new TokenBudget(10_000),
      new AbortController().signal,
    );
    expect(sent).not.toContain(secret);
    expect(sent).not.toContain('hunter2-very-secret');
    expect(result.value.search).toBe(`KEY = "${secret}"`);
    expect(result.usage.redacted).toBe(2);
  });
  it('falls back across providers, charges the budget and caches repeat prompts', async () => {
    let calls = 0;
    const ai = createAiClient({ GEMINI_API_KEY: 'g', GROQ_API_KEY: 'q', AI_PROVIDER_ORDER: 'gemini,groq', AI_RETRY_DELAY_MS: '0' }, {
      fetchImpl: (async (url: string) => {
        calls++;
        return String(url).includes('generativelanguage') ? new Response('', { status: 429 }) : groqOk('{"a":1}');
      }) as typeof fetch,
    })!;
    const budget = new TokenBudget(10_000);
    const first = await ai.completeJSON<{ a: number }>(req, budget, new AbortController().signal);
    expect(first.value.a).toBe(1);
    expect(first.usage.provider).toBe('Groq');
    expect(budget.used).toBe(100);
    const second = await ai.completeJSON(req, budget, new AbortController().signal);
    expect(second.usage.cached).toBe(true);
    expect(calls).toBe(3); // Gemini 429, one retry, then Groq; the repeat is served from cache
  });
  it('rotates to the next key of the same provider at once when a key is rate limited', async () => {
    const used: string[] = [];
    const ai = createAiClient(
      { GROQ_API_KEY: 'q1', GROQ_API_KEY_2: 'q2', GROQ_API_KEY_3: ' ', GROQ_API_KEY_4: 'q1', GEMINI_API_KEY: 'g', AI_RETRY_DELAY_MS: '60000' },
      {
        fetchImpl: (async (url: string, init: RequestInit) => {
          const key = String(url).includes('groq') ? (init.headers as Record<string, string>).Authorization : 'gemini';
          used.push(key);
          return key === 'Bearer q1' ? new Response('', { status: 429 }) : groqOk('{"a":1}');
        }) as typeof fetch,
      },
    )!;
    // Blank and duplicate keys are skipped.
    expect(ai.providers).toEqual(['Groq (openai/gpt-oss-120b)', 'Groq key 2 (openai/gpt-oss-120b)', 'Gemini (gemini-3.8-flash)']);
    const result = await ai.completeJSON<{ a: number }>(req, new TokenBudget(10_000), new AbortController().signal);
    expect(result.usage.provider).toBe('Groq key 2');
    expect(used).toEqual(['Bearer q1', 'Bearer q2']); // no 60 s wait before switching keys
  });
  it('refuses work that would exceed the run budget', async () => {
    const ai = createAiClient({ GEMINI_API_KEY: 'g' }, { fetchImpl: (async () => ok('{}')) as typeof fetch })!;
    await expect(ai.completeJSON(req, new TokenBudget(50), new AbortController().signal)).rejects.toThrow(/budget/i);
  });
});

describe('Docker sandbox hardening', () => {
  it('runs tests with no network, read-only root, non-root user and dropped capabilities', async () => {
    let args: string[] = [];
    const spawnImpl = ((_cmd: string, a: string[]) => {
      args = a;
      const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter };
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      setTimeout(() => child.emit('close', 0), 5);
      return child;
    }) as never;
    const folder = await mkdtemp(join(tmpdir(), 'pp-docker-'));
    const sandbox = new DockerSandbox({ image: 'img', workspacePath: () => folder, scratchRoot: folder, spawnImpl });
    const ws = { id: randomUUID(), repositoryId: randomUUID(), commitSha: 'abc' };
    const res = await sandbox.executeWith(
      { workspace: ws, argv: ['python', '-m', 'pytest'], timeoutMs: 5000, memoryMb: 512, cpuLimit: 1, network: 'none', readOnlyRoot: true, maxOutputBytes: 1000 },
      ws.id,
      new AbortController().signal,
    );
    expect(res.state).toBe('completed');
    for (const flag of ['--network', 'none', '--read-only', '--cap-drop', 'ALL', 'no-new-privileges', '--pids-limit'])
      expect(args).toContain(flag);
    expect(args.join(' ')).toMatch(/target=\/src,readonly/);
    expect(hardeningArgs(512, 1)).toContain('10001:10001');
    await rm(folder, { recursive: true, force: true });
  });
});

/* ---------------- end-to-end orchestration with fake AI + fake sandbox ---------------- */

/** Imitates pytest on the fixture by reading the workspace files (no real code execution). */
function fakeSandbox(store: WorkspaceStore, options: { breakSuite?: boolean; redBaseline?: boolean } = {}): PipelineSandbox & { calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    ready: async () => null,
    prepare: async () => ({ exitCode: 0, stdout: 'prepared', stderr: '', timedOut: false }),
    cleanup: async () => {},
    async executeWith(request) {
      calls.push(request.argv);
      const root = store.path(request.workspace.id);
      if (request.argv[0] === 'bandit')
        return { state: 'completed', data: { exitCode: 1, stdout: '', stderr: '', durationMs: 1, artifactId: '', timedOut: false, files: { 'bandit.json': JSON.stringify({ results: [{ filename: './vulnapp/store.py', line_number: 16, test_id: 'B608', issue_text: 'Possible SQL injection', issue_cwe: { id: 89 } }] }) } } };
      const store_ = await readFile(join(root, 'vulnapp', 'store.py'), 'utf8');
      const vulnerable = store_.includes("'%s'\" % name");
      const broken = options.breakSuite && !vulnerable;
      const secPath = request.argv.find((a) => a.includes('proofpatch_security'));
      const hasSec = existsSync(join(root, 'tests', 'proofpatch_security'));
      const cases: [string, boolean][] = secPath
        ? [['test_injection_does_not_return_all_users', !vulnerable]]
        : [
            ['test_finds_existing_user', !broken],
            ['test_unknown_user_is_empty', !options.redBaseline],
            ['test_checksum_is_stable', true],
            ...(hasSec ? ([['test_injection_does_not_return_all_users', !vulnerable]] as [string, boolean][]) : []),
          ];
      const xml = `<testsuites><testsuite>${cases.map(([n, p]) => `<testcase classname="tests" name="${n}">${p ? '' : '<failure message="assert"/>'}</testcase>`).join('')}</testsuite></testsuites>`;
      const failed = cases.some(([, p]) => !p);
      return { state: 'completed', data: { exitCode: failed ? 1 : 0, stdout: `${cases.length} tests`, stderr: '', durationMs: 5, artifactId: '', timedOut: false, files: { 'junit.xml': xml } } };
    },
  };
}

/** Fake GitHub: "latest" is the fixture, optionally edited upstream; publishing records the branch. */
function fakeGithub(upstream?: (storePy: string) => string) {
  const published: { branch: string; storePy: string }[] = [];
  return {
    published,
    canPublish: true,
    async cloneLatest(_repo: unknown, dir: string) {
      await cp(FIXTURE, dir, { recursive: true });
      if (upstream) {
        const file = join(dir, 'vulnapp', 'store.py');
        await writeFile(file, upstream(await readFile(file, 'utf8')));
      }
      return { baseBranch: 'main', baseSha: 'abc1234def' };
    },
    async publish(input: { dir: string; branch: string }) {
      published.push({ branch: input.branch, storePy: await readFile(join(input.dir, 'vulnapp', 'store.py'), 'utf8') });
      return { pullRequestUrl: `https://github.com/example/vulnapp/pull/${published.length}` };
    },
  };
}

function fakeAi(patchAttempts: string[][]): AiClient & { tasks: string[] } {
  const tasks: string[] = [];
  let patchCall = 0;
  return {
    tasks,
    providers: ['Fake (test)'],
    async completeJSON<T>(req: { task: string }, budget: TokenBudget) {
      tasks.push(req.task);
      budget.charge(500);
      const usage = { provider: 'Fake', model: 'test', inputTokens: 400, outputTokens: 100, cached: false, redacted: 0 };
      if (req.task === 'merge') {
        // Keep the upstream rename and apply the parameterized query.
        const conflicted = (req as unknown as { data: string }).data.split('with conflicts\n')[1];
        const content = conflicted.replace(
          /<<<<<<< latest\n[\s\S]*?=======\n[\s\S]*?>>>>>>> fix\n/,
          '    found = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()\n',
        );
        return { value: { content, explanation: 'Kept the rename, bound the parameter.' } as T, usage };
      }
      if (req.task === 'detect')
        return { value: { verdicts: [{ candidateId: 'C1', vulnerable: true, confidence: 0.95, cwe: 'CWE-89', severity: 'high', rootCause: 'User input is formatted into SQL.', evidence: ['name flows into execute'], recommendation: 'Use a parameterized query.' }] } as T, usage };
      const [search, replace] = patchAttempts[Math.min(patchCall++, patchAttempts.length - 1)];
      return { value: { edits: [{ file: 'vulnapp/store.py', search, replace }], securityTest: { filename: 'test_sqli.py', content: SECURITY_TEST }, explanation: 'Bind the name as a parameter.' } as T, usage };
    },
  };
}

describe.sequential('end-to-end pipeline', () => {
  const origin = 'http://127.0.0.1:5173';
  const password = 'correct-horse-battery-99';
  let folder: string;
  let db: Database;
  beforeAll(async () => {
    folder = await mkdtemp(join(tmpdir(), 'pp-e2e-'));
  });
  afterAll(async () => {
    closeMLWorker();
    await db?.close();
    await rm(folder, { recursive: true, force: true });
  });

  async function setup(ai: AiClient, sandboxOptions: { breakSuite?: boolean; redBaseline?: boolean } = {}, github = fakeGithub()) {
    await db?.close();
    db = await openDatabase(join(folder, randomUUID(), 'db'));
    await provisionReviewer(db, { email: 'reviewer@example.com', password, name: 'Reviewer' });
    const store = new WorkspaceStore(join(folder, 'ws'));
    const sandbox = fakeSandbox(store, sandboxOptions);
    const pipeline = createPipeline({
      db,
      store,
      sandbox,
      ai,
      github,
      ingestion: {
        async ingest(repository) {
          const id = randomUUID();
          await cp(FIXTURE, store.path(id), { recursive: true });
          return { state: 'completed', data: { id, repositoryId: repository.id, commitSha: 'f'.repeat(40) } };
        },
      },
    });
    const app = await createApp(db, { origin, pipeline });
    const developer = request.agent(app);
    await developer.post('/api/auth/register').set('Origin', origin).send({ name: 'Dev', email: 'dev@example.com', password });
    // Developer submits; the scan starts automatically. Results are read by the reviewer.
    const repo = await developer.post('/api/repositories').set('Origin', origin).send({ url: 'https://github.com/example/vulnapp' });
    expect(repo.status).toBe(201);
    await pipeline.idle();
    const dev = request.agent(app);
    await dev.post('/api/auth/login').set('Origin', origin).send({ email: 'reviewer@example.com', password, role: 'reviewer' });
    const [run] = (await dev.get('/api/runs')).body.data;
    expect(run.repositoryId).toBe(repo.body.data.id);
    expect((await developer.get(`/api/runs/${run.id}/patches`)).status).toBe(403);
    return { app, dev, developer, runId: run.id as string, sandbox, pipeline, github };
  }

  it('finds the bug, reproduces it, patches it, proves it, and lets a reviewer approve', async () => {
    const ai = fakeAi([[VULN_LINE, SAFE_LINE]]);
    const { app, dev, developer, runId, sandbox } = await setup(ai);
    const run = (await dev.get(`/api/runs/${runId}`)).body.data;
    expect(run.status).toBe('needs_review');
    expect((await developer.get('/api/submissions')).body.data[0].status).toBe('in_review');
    const findings = (await dev.get(`/api/runs/${runId}/findings`)).body.data;
    expect(findings[0]).toMatchObject({ cwe: 'CWE-89', source: 'scanner+ai', file: 'vulnapp/store.py' });
    const ml = (await dev.get(`/api/runs/${runId}/ml-findings`)).body.data;
    expect(ml[0].finding).toEqual(findings[0]);
    expect(ml[0].ml).toMatchObject({ findingId: findings[0].id, language: 'python', commitSha: 'f'.repeat(40), file: findings[0].file });
    expect(ml[0].ml.prediction.modelVersion).toBe('owasp-python-0.1-b20e1accbd58');
    expect(ml[0].ml.sourceSha256).toMatch(/^[0-9a-f]{64}$/);
    const [patch] = (await dev.get(`/api/runs/${runId}/patches`)).body.data;
    expect(patch.status).toBe('needs_review');
    expect(patch.unifiedDiff).toContain('+    rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()');
    expect(patch.securityTest.path).toBe('tests/proofpatch_security/test_sqli.py');
    const stages = (await dev.get(`/api/runs/${runId}/verification`)).body.data.map((v: { stage: string; status: string; exitCode: number }) => `${v.stage}:${v.status}:${v.exitCode}`);
    expect(stages).toEqual(['baseline:passed:0', 'reproduction:passed:1', 'patch_application:passed:0', 'security_retest:passed:0', 'regression:passed:0', 'final_decision:passed:0']);
    expect(sandbox.calls.every((argv) => !argv.includes('--network'))).toBe(true);
    const events = (await dev.get(`/api/runs/${runId}/events`)).body.data.map((e: { kind: string; message: string }) => e.message).join('\n');
    expect(events).toMatch(/Search funnel: 2 source files/);
    expect(events).toMatch(/tokens/);
    const artifacts = (await dev.get(`/api/runs/${runId}/artifacts`)).body.data;
    expect(artifacts.some((a: { kind: string }) => a.kind === 'report')).toBe(true);
    const download = await dev.get(`/api/runs/${runId}/artifacts/${artifacts[0].id}`);
    expect(download.status).toBe(200);
    expect(ai.tasks).toEqual(['detect', 'patch']);
    // The corrected approval guard accepts real evidence (reproduction exits 1 by design).
    const reviewer = request.agent(app);
    await reviewer.post('/api/auth/login').set('Origin', origin).send({ email: 'reviewer@example.com', password, role: 'reviewer' });
    const decision = await reviewer.post(`/api/reviews/${patch.id}/decision`).set('Origin', origin).send({ decision: 'approved', reason: 'Exploit test red→green, suite intact.' });
    expect(decision.status).toBe(201);
  });

  it('continues the real orchestration and proof gates when the ML runtime is unavailable', async () => {
    closeMLWorker();
    const previous = process.env.MINI_ML_PYTHON;
    process.env.MINI_ML_PYTHON = join(folder, 'missing-classifier-runtime.exe');
    try {
      const { dev, runId } = await setup(fakeAi([[VULN_LINE, SAFE_LINE]]));
      expect((await dev.get(`/api/runs/${runId}`)).body.data.status).toBe('needs_review');
      const [row] = (await dev.get(`/api/runs/${runId}/ml-findings`)).body.data;
      expect(row.finding.cwe).toBe('CWE-89');
      expect(row.finding.severity).toBe('high');
      expect(row.ml.status).toBe('unknown');
      expect(row.ml.prediction.cwe).toBeNull();
      expect((await dev.get(`/api/runs/${runId}/verification`)).body.data.every((record: {status: string}) => record.status === 'passed')).toBe(true);
    } finally {
      closeMLWorker();
      if (previous === undefined) delete process.env.MINI_ML_PYTHON; else process.env.MINI_ML_PYTHON = previous;
    }
  });

  it('retries with feedback when a patch breaks existing tests, then gives up honestly', async () => {
    const ai = fakeAi([[VULN_LINE, SAFE_LINE]]);
    const { dev, runId } = await setup(ai, { breakSuite: true });
    const run = (await dev.get(`/api/runs/${runId}`)).body.data;
    expect(run.status).toBe('failed');
    expect(run.error).toMatch(/No patch passed all proofs within 3 attempts/);
    expect(ai.tasks).toEqual(['detect', 'patch', 'patch', 'patch']);
    const patches = (await dev.get(`/api/runs/${runId}/patches`)).body.data;
    expect(patches.map((p: { status: string }) => p.status)).toEqual(['rejected', 'rejected', 'rejected']);
  });

  it('feeds edit errors back to the AI and succeeds on a later attempt', async () => {
    const ai = fakeAi([['this text is not in the file', 'x'], [VULN_LINE, SAFE_LINE]]);
    const { dev, runId } = await setup(ai);
    expect((await dev.get(`/api/runs/${runId}`)).body.data.status).toBe('needs_review');
    const [patch] = (await dev.get(`/api/runs/${runId}/patches`)).body.data;
    expect(patch.attempt).toBe(2);
  });

  async function approveAndMerge(ai: AiClient, sandboxOptions: { breakSuite?: boolean }, github: ReturnType<typeof fakeGithub>, breakAfterApproval = false) {
    const ctx = await setup(ai, sandboxOptions, github);
    const [patch] = (await ctx.dev.get(`/api/runs/${ctx.runId}/patches`)).body.data;
    expect((await ctx.dev.post(`/api/reviews/${patch.id}/decision`).set('Origin', origin).send({ decision: 'approved', reason: 'Proofs reviewed.' })).status).toBe(201);
    if (breakAfterApproval) sandboxOptions.breakSuite = true;
    expect((await ctx.dev.post(`/api/reviews/${patch.id}/merge`).set('Origin', origin).send({})).status).toBe(202);
    await ctx.pipeline.idle();
    const merged = (await ctx.dev.get(`/api/runs/${ctx.runId}/patches`)).body.data.find((p: { id: string }) => p.id === patch.id);
    return { ...ctx, patch: merged };
  }

  it('merges a clean fix onto the latest code, re-proves it and opens a pull request for the developer', async () => {
    const github = fakeGithub();
    const { patch, developer } = await approveAndMerge(fakeAi([[VULN_LINE, SAFE_LINE]]), {}, github);
    expect(patch.merge.status).toBe('merged');
    expect(patch.merge.checks.map((c: { stage: string; passed: boolean }) => `${c.stage}:${c.passed}`)).toEqual([
      'apply:true', 'baseline:true', 'reproduction:true', 'security_retest:true', 'regression:true', 'publish:true',
    ]);
    expect(github.published[0].branch).toBe(`proofpatch/fix-${patch.id.slice(0, 8)}`);
    expect(github.published[0].storePy).toContain(SAFE_LINE);
    const [submission] = (await developer.get('/api/submissions')).body.data;
    expect(submission).toMatchObject({ status: 'fix_branch_ready', branch: github.published[0].branch, pullRequestUrl: 'https://github.com/example/vulnapp/pull/1' });
  });

  it('three-way merges around an unrelated upstream change', async () => {
    const github = fakeGithub((py) => py.replace('def checksum(data):', 'def checksum(data):\n    # upstream: sha256 of raw bytes'));
    const { patch } = await approveAndMerge(fakeAi([[VULN_LINE, SAFE_LINE]]), {}, github);
    expect(patch.merge.status).toBe('merged');
    expect(github.published[0].storePy).toContain('# upstream: sha256 of raw bytes');
    expect(github.published[0].storePy).toContain(SAFE_LINE);
  });

  it('lets the AI resolve a real conflict but publishes only after a reviewer confirms', async () => {
    const ai = fakeAi([[VULN_LINE, SAFE_LINE]]);
    const github = fakeGithub((py) => py.replace(VULN_LINE, VULN_LINE.replace('rows =', 'found =')).replace('    return rows', '    return found'));
    const { patch, dev, pipeline } = await approveAndMerge(ai, {}, github);
    expect(ai.tasks).toContain('merge');
    expect(patch.merge.status).toBe('awaiting_review');
    expect(patch.merge.resolvedByAi).toEqual(['vulnapp/store.py']);
    expect(github.published).toHaveLength(0);
    expect((await dev.post(`/api/reviews/${patch.id}/merge/confirm`).set('Origin', origin).send({})).status).toBe(202);
    await pipeline.idle();
    expect(github.published).toHaveLength(1);
    expect(github.published[0].storePy).toContain('found = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,))');
  });

  it('stops with a clear reason when the original suite is already failing (no silent red baseline)', async () => {
    const ai = fakeAi([[VULN_LINE, SAFE_LINE]]);
    const { dev, runId } = await setup(ai, { redBaseline: true });
    const run = (await dev.get(`/api/runs/${runId}`)).body.data;
    expect(run.status).toBe('failed');
    expect(run.error).toMatch(/not passing before any change/);
    expect(ai.tasks).toEqual([]); // no AI tokens spent on a repository whose proofs cannot hold
  });

  it('sends the fix back for patching when it breaks tests on the latest code', async () => {
    const github = fakeGithub();
    const { patch, dev } = await approveAndMerge(fakeAi([[VULN_LINE, SAFE_LINE]]), {}, github, true);
    expect(patch.merge.status).toBe('sent_back');
    expect(patch.merge.checks.find((c: { stage: string }) => c.stage === 'regression').passed).toBe(false);
    expect(github.published).toHaveLength(0);
    const runs = (await dev.get('/api/runs')).body.data.map((r: { id: string }) => r.id);
    expect(runs).toContain(patch.merge.sentBackRunId);
  });
});
