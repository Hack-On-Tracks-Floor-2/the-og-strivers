import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { RepositoryMap } from './contracts.js';

/**
 * How a repository's tests are installed and run, per language. Every command writes JUnit XML to
 * /out/junit.xml so the same regression gate compares test-by-test results for every language.
 */
export type Language = 'python' | 'javascript';
export interface Toolchain {
  language: Language;
  /** Human-readable, e.g. "Python · pytest" or "JavaScript · node:test". */
  label: string;
  framework: 'pytest' | 'node:test' | 'jest' | 'mocha';
  /** Full test suite, with JUnit output. */
  suite: string[];
  /** One test file (the generated security test), with JUnit output and verbose failures. */
  only(path: string): string[];
  /** Where the generated attack test is written, and how it must be named. */
  securityTestDir: string;
  securityTestName: RegExp;
  defaultSecurityTestName: string;
  /** Prompt guidance for writing the attack test in this framework. */
  testGuidance: string;
  /** ESM package ("type": "module"): tests must use import syntax. */
  esm: boolean;
}

const PYTEST = ['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'];

export function pythonToolchain(): Toolchain {
  return {
    language: 'python',
    label: 'Python · pytest',
    framework: 'pytest',
    suite: [...PYTEST, '--junitxml=/out/junit.xml'],
    only: (path) => [...PYTEST, '--junitxml=/out/junit.xml', '--tb=short', '-rP', path],
    securityTestDir: 'tests/proofpatch_security',
    securityTestName: /^test_[A-Za-z0-9_]*\.py$/,
    defaultSecurityTestName: 'test_proofpatch_security.py',
    testGuidance:
      'Write ONE pytest file with 1–3 test functions (def test_...). Import the code the same way the existing tests do. ' +
      'Use tmp_path for files; catch expected exceptions with try/except or pytest.raises.',
    esm: false,
  };
}

function nodeToolchain(framework: 'node:test' | 'jest' | 'mocha', esm: boolean): Toolchain {
  const junit = {
    'node:test': ['--test-reporter=spec', '--test-reporter-destination=stdout', '--test-reporter=junit', '--test-reporter-destination=/out/junit.xml'],
    jest: [],
    mocha: [],
  }[framework];
  const base = {
    'node:test': ['node', '--test', ...junit],
    jest: ['env', 'JEST_JUNIT_OUTPUT_FILE=/out/junit.xml', 'CI=true', 'npx', '--no-install', 'jest', '--ci', '--reporters=default', '--reporters=jest-junit'],
    mocha: ['npx', '--no-install', 'mocha', '--reporter', 'xunit', '--reporter-option', 'output=/out/junit.xml'],
  }[framework];
  const style = esm
    ? "This package is an ES module: use import syntax (import assert from 'node:assert/strict')."
    : "This package is CommonJS: use require() (const assert = require('node:assert/strict')).";
  const api = {
    'node:test': "Use the built-in runner: const { test } = require('node:test') (or import { test } from 'node:test').",
    jest: 'Use Jest globals (test, expect); do not import jest.',
    mocha: "Use Mocha globals (describe, it) with node:assert.",
  }[framework];
  return {
    language: 'javascript',
    label: `JavaScript · ${framework}`,
    framework,
    suite: [...base, ...(framework === 'mocha' ? ['--recursive'] : [])],
    // Jest's --reporters swallows following arguments, so the test path must come right after "jest".
    only: (path) => (framework === 'jest' ? [...base.slice(0, 6), '--runTestsByPath', path, ...base.slice(6)] : [...base, path]),
    securityTestDir: 'test/proofpatch_security',
    securityTestName: /^[A-Za-z0-9_-]+\.test\.js$/,
    defaultSecurityTestName: 'proofpatch-security.test.js',
    testGuidance:
      `Write ONE ${framework} test file named *.test.js with 1–3 tests. ${api} ${style} ` +
      "Load the code under test with a relative path from test/proofpatch_security/ (e.g. '../../src/file.js'), the same " +
      'way the existing tests import it. Use os.tmpdir()/fs.mkdtempSync for files; wrap calls that a safe fix may reject ' +
      'in try/catch or assert.throws.',
    esm,
  };
}

/** Picks the toolchain for a mapped repository, or explains why it is not supported. */
export async function detectToolchain(root: string, map: RepositoryMap): Promise<Toolchain | { unsupported: string }> {
  const primary = map.languages[0];
  if (primary === 'Python')
    return map.testCommands.length ? pythonToolchain() : { unsupported: 'Python repository without a pytest suite.' };
  if (primary === 'JavaScript') {
    const pkg = JSON.parse((await readFile(join(root, 'package.json'), 'utf8').catch(() => '{}')) || '{}') as {
      type?: string;
      scripts?: Record<string, string>;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    const script = pkg.scripts?.test ?? '';
    const esm = pkg.type === 'module';
    if (deps.jest || /\bjest\b/.test(script)) return nodeToolchain('jest', esm);
    if (deps.mocha || /\bmocha\b/.test(script)) return nodeToolchain('mocha', esm);
    if (/node\s+--test/.test(script) || map.hasNodeTests) return nodeToolchain('node:test', esm);
    return { unsupported: 'JavaScript repository without a node:test, Jest or Mocha test suite.' };
  }
  return {
    unsupported: `${primary ?? 'Unknown'} is detected but not yet supported end-to-end. Supported: Python (pytest) and JavaScript (node:test, Jest, Mocha).`,
  };
}
