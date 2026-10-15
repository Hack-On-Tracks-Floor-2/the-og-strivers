import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
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
export type Runtime = 'python' | 'node' | 'go' | 'php' | 'java' | 'dotnet' | 'ruby' | 'rust' | 'c';

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
  framework: 'pytest' | 'node:test' | 'jest' | 'mocha' | 'vitest' | 'go test' | 'phpunit' | 'junit' | 'dotnet test' | 'rspec' | 'cargo test' | 'ctest' | 'make test';
  /** A generated security test must contain this (e.g. a test function or annotation). */
  testPattern?: RegExp;
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

/** Java or Kotlin with Maven. Surefire writes per-class JUnit XML; they are concatenated into /out/junit.xml. */
function mavenToolchain(language: 'java' | 'kotlin', junit5: boolean): Toolchain {
  const kt = language === 'kotlin';
  const run = (extra: string[]) => [
    'sh', '-c',
    'mvn -B -o -q -Dmaven.repo.local=/tmp/m2 -Dsurefire.useFile=false -DtrimStackTrace=true test "$@"; rc=$?; ' +
      'cat target/surefire-reports/TEST-*.xml > /out/junit.xml 2>/dev/null; exit $rc',
    'mvn', ...extra,
  ];
  const ext = kt ? 'kt' : 'java';
  return {
    language,
    runtime: 'java',
    label: `${kt ? 'Kotlin' : 'Java'} · Maven + JUnit ${junit5 ? 5 : 4}`,
    framework: 'junit',
    testPattern: /@Test\b/,
    suite: run([]),
    only: () => run(['-Dtest=ProofPatchSecurityTest', '-Dsurefire.failIfNoSpecifiedTests=false']),
    // Same package as the vulnerable class: src/main/<lang>/a/b/X → src/test/<lang>/a/b/ProofPatchSecurityTest.
    securityTestPath: (file) => {
      const m = /^(.*?)src\/main\/(java|kotlin)\/(.*)\/[^/]+$/.exec(file);
      return m ? `${m[1]}src/test/${m[2]}/${m[3]}/ProofPatchSecurityTest.${ext}` : `src/test/${kt ? 'kotlin' : 'java'}/ProofPatchSecurityTest.${ext}`;
    },
    securityTestName: new RegExp(`^ProofPatchSecurityTest\\.${ext}$`),
    defaultSecurityTestName: `ProofPatchSecurityTest.${ext}`,
    testGuidance:
      `Write ONE ${kt ? 'Kotlin' : 'Java'} test class named ProofPatchSecurityTest in the SAME package as the vulnerable class ` +
      `(same "package" line), using JUnit ${junit5 ? '5 (org.junit.jupiter.api.Test, org.junit.jupiter.api.Assertions.*)' : '4 (org.junit.Test, org.junit.Assert.*)'} ` +
      'with 1–3 @Test methods. Use only the JDK and JUnit. Use java.nio.file.Files.createTempDirectory for files; use ' +
      `${junit5 ? 'assertThrows' : 'try/catch'} for input a safe fix may reject.`,
    esm: false,
  };
}

/** C# with dotnet test. The TRX report is written as /out/junit.xml and read by the TRX-aware parser. */
function dotnetToolchain(testProject: string, framework: 'xunit' | 'nunit' | 'mstest'): Toolchain {
  const dir = dirname(testProject);
  const run = (extra: string[]) => [
    'dotnet', 'test', testProject, '--nologo', '--verbosity', 'quiet', '--results-directory', '/out', '--logger', 'trx;LogFileName=junit.xml', ...extra,
  ];
  const attr = { xunit: '[Fact] (using Xunit;)', nunit: '[Test] in a [TestFixture] class (using NUnit.Framework;)', mstest: '[TestMethod] in a [TestClass] (using Microsoft.VisualStudio.TestTools.UnitTesting;)' }[framework];
  return {
    language: 'csharp',
    runtime: 'dotnet',
    label: `C# · dotnet test (${framework})`,
    framework: 'dotnet test',
    testPattern: /\[(Fact|Theory|Test|TestMethod)\b/,
    suite: run([]),
    only: () => run(['--filter', 'FullyQualifiedName~ProofPatchSecurityTests']),
    securityTestPath: () => `${dir === '.' ? '' : `${dir}/`}ProofPatchSecurityTests.cs`,
    securityTestName: /^ProofPatchSecurityTests\.cs$/,
    defaultSecurityTestName: 'ProofPatchSecurityTests.cs',
    testGuidance:
      `Write ONE C# test class named ProofPatchSecurityTests (saved in the test project ${testProject}) with 1–3 tests using ` +
      `${attr}. Reference the code under test the same way the existing tests do (same namespaces). Use Path.GetTempPath() ` +
      'for files; use Assert.Throws or try/catch for input a safe fix may reject.',
    esm: false,
  };
}

function rspecToolchain(): Toolchain {
  return {
    language: 'ruby',
    runtime: 'ruby',
    label: 'Ruby · RSpec',
    framework: 'rspec',
    testPattern: /\b(it|specify|example)\s*\(?\s*['"]/,
    suite: ['rspec-junit'],
    only: (path) => ['rspec-junit', path],
    securityTestPath: () => 'spec/proofpatch_security_spec.rb',
    securityTestName: /^proofpatch_security_spec\.rb$/,
    defaultSecurityTestName: 'proofpatch_security_spec.rb',
    testGuidance:
      'Write ONE RSpec file with a describe block and 1–3 examples (it "..."). Load the code the same way the existing ' +
      "specs do (require 'spec_helper' if they do, or require_relative '../lib/...'). Use Dir.mktmpdir for files; use " +
      'expect { }.to raise_error or begin/rescue for input a safe fix may reject.',
    esm: false,
  };
}

/** Rust library crate: the attack test is an integration test in tests/, run with cargo test. */
function cargoToolchain(crate: string): Toolchain {
  return {
    language: 'rust',
    runtime: 'rust',
    label: 'Rust · cargo test',
    framework: 'cargo test',
    testPattern: /#\[test\]/,
    suite: ['cargo-junit'],
    only: () => ['cargo-junit', '--test', 'proofpatch_security'],
    securityTestPath: () => 'tests/proofpatch_security.rs',
    securityTestName: /^proofpatch_security\.rs$/,
    defaultSecurityTestName: 'proofpatch_security.rs',
    testGuidance:
      `Write ONE Rust integration test file (tests/proofpatch_security.rs) with 1–3 #[test] functions. Use the crate as ` +
      `"use ${crate}::...;" (only its public API). Use std::env::temp_dir() for files; use std::panic::catch_unwind or ` +
      'match on Result for input a safe fix may reject.',
    esm: false,
  };
}

/**
 * C / C++. The regression suite is the repository's own CTest (CMake) or `make test`. The attack test is
 * a standalone program that #includes the vulnerable source and has its own main(); the sandbox compiles
 * it with AddressSanitizer + UBSan, so memory-safety bugs fail the test instead of passing silently.
 */
function cToolchain(language: 'c' | 'cpp', build: 'cmake' | 'make'): Toolchain {
  const ext = language === 'c' ? 'c' : 'cpp';
  return {
    language,
    runtime: 'c',
    label: `${language === 'c' ? 'C' : 'C++'} · ${build === 'cmake' ? 'CMake + CTest' : 'make test'} + ASan`,
    framework: build === 'cmake' ? 'ctest' : 'make test',
    testPattern: /\bint\s+main\s*\(/,
    suite: ['c-suite'],
    only: (path) => ['c-security-test', path],
    securityTestPath: (file) => `proofpatch_security/proofpatch_security.${/\.(c|h)$/.test(file) ? 'c' : ext}`,
    securityTestName: /^proofpatch_security\.(c|cpp)$/,
    defaultSecurityTestName: `proofpatch_security.${ext}`,
    testGuidance:
      `Write ONE standalone ${language === 'c' ? 'C' : 'C++'} program (saved as proofpatch_security/proofpatch_security.${ext}) that ` +
      '#includes the vulnerable source file by relative path (e.g. #include "../src/parser.c") so it compiles on its own ' +
      'with no other files, and defines its own int main(void). If the included file already defines main, write ' +
      '#define main proofpatch_original_main before the #include and #undef main after it. main() performs the attack ' +
      'and returns 0 if the attack was blocked, 1 if it succeeded. It is compiled with -fsanitize=address,undefined, so ' +
      'for memory-safety bugs simply exercise the bug (e.g. an over-long input): the sanitizer aborts the vulnerable ' +
      'version, while a correct fix must handle the input safely and return 0. Use only the C/C++ standard library and ' +
      'POSIX; use mkdtemp under /tmp for files.',
    esm: false,
  };
}

/** First file (depth ≤ 4) whose name matches and whose content passes `accept`. */
async function findFile(root: string, name: RegExp, accept: (text: string) => boolean, depth = 4): Promise<string | null> {
  const walk = async (dir: string, level: number): Promise<string | null> => {
    const entries = await readdir(join(root, dir), { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isFile() && name.test(e.name) && accept(await readFile(join(root, rel), 'utf8').catch(() => ''))) return rel;
    }
    if (level >= depth) return null;
    for (const e of entries)
      if (e.isDirectory() && !/^(\.|node_modules$|bin$|obj$|target$|vendor$)/.test(e.name)) {
        const hit = await walk(dir ? `${dir}/${e.name}` : e.name, level + 1);
        if (hit) return hit;
      }
    return null;
  };
  return walk('', 0);
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
  if (language === 'java' || language === 'kotlin') {
    const pom = await readFile(join(root, 'pom.xml'), 'utf8').catch(() => '');
    if (pom) return mavenToolchain(language, /junit-jupiter|junit-bom|<version>5\./.test(pom) || !/<artifactId>junit<\/artifactId>/.test(pom));
    if (existsSync(join(root, 'build.gradle')) || existsSync(join(root, 'build.gradle.kts')))
      return detectOnly(language, language === 'java' ? 'Java' : 'Kotlin', 'Gradle builds are scanned but not yet proven; Maven (pom.xml) projects get full proofs.');
  }
  if (language === 'csharp') {
    const project = await findFile(root, /\.csproj$/, (t) => /Microsoft\.NET\.Test\.Sdk/.test(t));
    if (project) {
      const text = await readFile(join(root, project), 'utf8');
      return dotnetToolchain(project, /nunit/i.test(text) ? 'nunit' : /MSTest/i.test(text) ? 'mstest' : 'xunit');
    }
    return detectOnly('csharp', 'C#', 'No test project (Microsoft.NET.Test.Sdk) found, so fixes cannot be proven with tests.');
  }
  if (language === 'ruby') {
    const gemfile = await readFile(join(root, 'Gemfile'), 'utf8').catch(() => '');
    if (gemfile && (/rspec/.test(gemfile) || existsSync(join(root, 'spec')))) return rspecToolchain();
    return detectOnly('ruby', 'Ruby', 'Only Bundler + RSpec projects get full proofs; this one is scanned only.');
  }
  if (language === 'rust') {
    const cargo = await readFile(join(root, 'Cargo.toml'), 'utf8').catch(() => '');
    const name = /\[package\][^[]*?\bname\s*=\s*"([^"]+)"/.exec(cargo)?.[1];
    if (name && existsSync(join(root, 'src', 'lib.rs'))) return cargoToolchain(name.replace(/-/g, '_'));
    return detectOnly('rust', 'Rust', 'Only library crates (src/lib.rs) get full proofs: the attack test must call the crate as a library.');
  }
  const names: Partial<Record<Language, string>> = { java: 'Java', kotlin: 'Kotlin', csharp: 'C#', ruby: 'Ruby', rust: 'Rust', c: 'C', cpp: 'C++' };
  if (language === 'c' || language === 'cpp') {
    const cmake = await readFile(join(root, 'CMakeLists.txt'), 'utf8').catch(() => '');
    if (/\b(enable_testing|add_test|include\s*\(\s*CTest)\b/i.test(cmake)) return cToolchain(language, 'cmake');
    const makefile = await readFile(join(root, 'Makefile'), 'utf8').catch(() => '');
    if (/^test\s*:/m.test(makefile)) return cToolchain(language, 'make');
    return detectOnly(language, names[language]!, 'No CTest (enable_testing/add_test in CMakeLists.txt) or "make test" target, so there is no suite to prove a fix against.');
  }
  if (language && names[language])
    return detectOnly(language, names[language]!, `Automatic patch proof for ${names[language]} is not available yet; findings are confirmed by AI for a reviewer to triage.`);
  return {
    unsupported: `${primary ?? 'Unknown'} is not supported. Supported: Python, JavaScript, TypeScript, Go, PHP, Java, Kotlin, C#, Ruby, Rust (proven fixes) and C, C++ (detection).`,
  };
}
