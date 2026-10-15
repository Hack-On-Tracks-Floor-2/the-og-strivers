import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { RepositoryMap } from './contracts.js';

/**
 * How a repository's tests are installed and run, per language. Every command writes JUnit XML to
 * /out/junit.xml so the same regression gate compares test-by-test results for every language.
 */
export type Language =
  | 'python' | 'javascript' | 'typescript' | 'go' | 'php'
  | 'java' | 'kotlin' | 'csharp' | 'ruby' | 'rust' | 'c' | 'cpp';
/** Sandbox image family that runs the tests. */
export type Runtime = 'python' | 'node' | 'go' | 'php';

/** Display name (from the repository map) → language key. */
export const LANGUAGE_KEYS: Record<string, Language> = {
  Python: 'python', JavaScript: 'javascript', TypeScript: 'typescript', Go: 'go', PHP: 'php', Java: 'java',
  Kotlin: 'kotlin', 'C#': 'csharp', Ruby: 'ruby', Rust: 'rust', C: 'c', 'C++': 'cpp',
};

export interface Toolchain {
  language: Language;
  runtime: Runtime;
  /** Human-readable, e.g. "Python · pytest" or "Go · go test". */
  label: string;
  framework: 'pytest' | 'node:test' | 'jest' | 'mocha' | 'vitest' | 'go test' | 'phpunit';
  /** Full test suite, with JUnit output. */
  suite: string[];
  /** One test file (the generated security test), with JUnit output and verbose failures. */
  only(path: string): string[];
  /** Where the generated attack test is written for a finding in `findingFile`, and how it must be named. */
  securityTestPath(findingFile: string, filename: string): string;
  securityTestName: RegExp;
  defaultSecurityTestName: string;
  /** Prompt guidance for writing the attack test in this framework. */
  testGuidance: string;
  /** ESM package ("type": "module"): tests must use import syntax. */
  esm: boolean;
}
/** Languages ProofPatch scans and confirms with AI, but cannot yet prove with an executed test. */
export interface DetectOnly {
  detectOnly: true;
  language: Language;
  label: string;
  reason: string;
}

const PYTEST = ['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'];

export function pythonToolchain(): Toolchain {
  return {
    language: 'python',
    runtime: 'python',
    label: 'Python · pytest',
    framework: 'pytest',
    suite: [...PYTEST, '--junitxml=/out/junit.xml'],
    only: (path) => [...PYTEST, '--junitxml=/out/junit.xml', '--tb=short', '-rP', path],
    securityTestPath: (_file, name) => `tests/proofpatch_security/${name}`,
    securityTestName: /^test_[A-Za-z0-9_]*\.py$/,
    defaultSecurityTestName: 'test_proofpatch_security.py',
    testGuidance:
      'Write ONE pytest file with 1–3 test functions (def test_...). Import the code the same way the existing tests do. ' +
      'Use tmp_path for files; catch expected exceptions with try/except or pytest.raises.',
    esm: false,
  };
}

type NodeFramework = 'node:test' | 'jest' | 'mocha' | 'vitest';
function nodeToolchain(framework: NodeFramework, esm: boolean, ts: boolean): Toolchain {
  const ext = ts ? 'ts' : 'js';
  const base: Record<NodeFramework, string[]> = {
    'node:test': ['node', ...(ts ? ['--experimental-strip-types', '--no-warnings'] : []), '--test',
      '--test-reporter=spec', '--test-reporter-destination=stdout', '--test-reporter=junit', '--test-reporter-destination=/out/junit.xml'],
    jest: ['env', 'JEST_JUNIT_OUTPUT_FILE=/out/junit.xml', 'CI=true', 'npx', '--no-install', 'jest', '--ci', '--reporters=default', '--reporters=jest-junit'],
    mocha: ['npx', '--no-install', 'mocha', '--reporter', 'xunit', '--reporter-option', 'output=/out/junit.xml'],
    vitest: ['npx', '--no-install', 'vitest', 'run', '--reporter=default', '--reporter=junit', '--outputFile.junit=/out/junit.xml'],
  };
  const cmd = base[framework];
  const style = esm || ts
    ? "Use import syntax (import assert from 'node:assert/strict')."
    : "This package is CommonJS: use require() (const assert = require('node:assert/strict')).";
  const api = {
    'node:test': "Use the built-in runner: import { test } from 'node:test' (or require('node:test')).",
    jest: 'Use Jest globals (test, expect); do not import jest.',
    mocha: 'Use Mocha globals (describe, it) with node:assert.',
    vitest: "Import { test, expect } from 'vitest'.",
  }[framework];
  return {
    language: ts ? 'typescript' : 'javascript',
    runtime: 'node',
    label: `${ts ? 'TypeScript' : 'JavaScript'} · ${framework}`,
    framework,
    suite: [...cmd, ...(framework === 'mocha' ? ['--recursive'] : [])],
    // Jest's --reporters swallows following arguments, so the test path must come right after "jest".
    only: (path) => (framework === 'jest' ? [...cmd.slice(0, 6), '--runTestsByPath', path, ...cmd.slice(6)] : [...cmd, path]),
    securityTestPath: (_file, name) => `test/proofpatch_security/${name}`,
    securityTestName: new RegExp(`^[A-Za-z0-9_-]+\\.test\\.${ext}$`),
    defaultSecurityTestName: `proofpatch-security.test.${ext}`,
    testGuidance:
      `Write ONE ${framework} test file named *.test.${ext} with 1–3 tests. ${api} ${style} ` +
      `Load the code under test with a relative path from test/proofpatch_security/ (e.g. '../../src/file${ts ? '' : '.js'}'), the same ` +
      'way the existing tests import it. Use os.tmpdir()/fs.mkdtempSync for files; wrap calls that a safe fix may reject ' +
      'in try/catch or assert.throws.',
    esm,
  };
}

function goToolchain(): Toolchain {
  const gotestsum = ['gotestsum', '--junitfile', '/out/junit.xml', '--format', 'standard-verbose', '--'];
  return {
    language: 'go',
    runtime: 'go',
    label: 'Go · go test',
    framework: 'go test',
    suite: [...gotestsum, './...'],
    // A Go test belongs to its package: run only the ProofPatch tests in that package's directory.
    only: (path) => [...gotestsum, '-run', '^TestProofPatch', `./${dirname(path).replace(/^\.$/, '')}`.replace(/\/$/, '') || '.'],
    securityTestPath: (file) => `${dirname(file) === '.' ? '' : `${dirname(file)}/`}proofpatch_security_test.go`,
    securityTestName: /^proofpatch_security_test\.go$/,
    defaultSecurityTestName: 'proofpatch_security_test.go',
    testGuidance:
      'Write ONE Go test file that is saved next to the vulnerable file, in the SAME package (use the same "package" line ' +
      'as that file). Name every test function TestProofPatch<Something>(t *testing.T). Use only the standard library ' +
      '(testing, os, path/filepath, strings); use t.TempDir() for files.',
    esm: false,
  };
}

function phpToolchain(): Toolchain {
  const phpunit = ['vendor/bin/phpunit', '--log-junit', '/out/junit.xml'];
  return {
    language: 'php',
    runtime: 'php',
    label: 'PHP · PHPUnit',
    framework: 'phpunit',
    suite: phpunit,
    only: (path) => [...phpunit, path],
    securityTestPath: () => 'tests/ProofPatchSecurityTest.php',
    securityTestName: /^ProofPatchSecurityTest\.php$/,
    defaultSecurityTestName: 'ProofPatchSecurityTest.php',
    testGuidance:
      'Write ONE PHPUnit test file containing "final class ProofPatchSecurityTest extends \\PHPUnit\\Framework\\TestCase" with ' +
      '1–3 public test methods (testSomething). Load the code the same way the existing tests do (composer autoload or ' +
      "require_once __DIR__ . '/../src/File.php'). Use sys_get_temp_dir() for files; use expectException or try/catch " +
      'for input a safe fix may reject.',
    esm: false,
  };
}

const detectOnly = (language: Language, name: string, reason: string): DetectOnly => ({
  detectOnly: true,
  language,
  label: `${name} · detection only`,
  reason,
});

/** Picks the toolchain for a mapped repository; detect-only languages are scanned but not proven. */
export async function detectToolchain(root: string, map: RepositoryMap): Promise<Toolchain | DetectOnly | { unsupported: string }> {
  const primary = map.languages[0];
  const language = LANGUAGE_KEYS[primary ?? ''];
  if (language === 'python')
    return map.testCommands.length ? pythonToolchain() : { unsupported: 'Python repository without a pytest suite.' };
  if (language === 'javascript' || language === 'typescript') {
    const pkg = JSON.parse((await readFile(join(root, 'package.json'), 'utf8').catch(() => '{}')) || '{}') as {
      type?: string;
      scripts?: Record<string, string>;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    const script = pkg.scripts?.test ?? '';
    const esm = pkg.type === 'module';
    const ts = language === 'typescript';
    if (deps.vitest || /\bvitest\b/.test(script)) return nodeToolchain('vitest', esm, ts);
    if (deps.jest || /\bjest\b/.test(script)) return nodeToolchain('jest', esm, ts);
    if (deps.mocha || /\bmocha\b/.test(script)) return nodeToolchain('mocha', esm, ts);
    if (/node\s+(--[\w-]+\s+)*--test/.test(script) || map.hasNodeTests) return nodeToolchain('node:test', esm, ts);
    return { unsupported: `${primary} repository without a node:test, Jest, Vitest or Mocha test suite.` };
  }
  if (language === 'go')
    return existsSync(join(root, 'go.mod')) ? goToolchain() : { unsupported: 'Go repository without a go.mod module.' };
  if (language === 'php') {
    const composer = await readFile(join(root, 'composer.json'), 'utf8').catch(() => '');
    return /phpunit\/phpunit/.test(composer)
      ? phpToolchain()
      : detectOnly('php', 'PHP', 'No PHPUnit dependency in composer.json, so fixes cannot be proven with tests.');
  }
  const names: Partial<Record<Language, string>> = { java: 'Java', kotlin: 'Kotlin', csharp: 'C#', ruby: 'Ruby', rust: 'Rust', c: 'C', cpp: 'C++' };
  if (language && names[language])
    return detectOnly(language, names[language]!, `Automatic patch proof for ${names[language]} is not available yet; findings are confirmed by AI for a reviewer to triage.`);
  return {
    unsupported: `${primary ?? 'Unknown'} is not supported. Supported: Python, JavaScript, TypeScript, Go, PHP (proven fixes) and Java, Kotlin, C#, Ruby, Rust, C, C++ (detection).`,
  };
}
