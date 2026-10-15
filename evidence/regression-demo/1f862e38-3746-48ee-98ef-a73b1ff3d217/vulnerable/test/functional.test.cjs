const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { readReport } = require('../src/reports.cjs');

let root;
before(() => {
  root = mkdtempSync(join(tmpdir(), 'patchproof-functional-'));
  mkdirSync(join(root, 'monthly'));
  writeFileSync(join(root, 'hello.txt'), 'Hello, report!');
  writeFileSync(join(root, 'monthly', 'october.txt'), 'October totals');
  writeFileSync(join(root, 'with spaces.txt'), 'spaces work');
  writeFileSync(join(root, 'empty.txt'), '');
});
after(() => rmSync(root, { recursive: true, force: true }));

test('reads an existing report', () => assert.equal(readReport(root, 'hello.txt'), 'Hello, report!'));
test('reads nested reports', () => assert.equal(readReport(root, 'monthly/october.txt'), 'October totals'));
test('supports spaces in report names', () => assert.equal(readReport(root, 'with spaces.txt'), 'spaces work'));
test('preserves empty report contents', () => assert.equal(readReport(root, 'empty.txt'), ''));
test('preserves missing-file errors', () => assert.throws(() => readReport(root, 'missing.txt'), { code: 'ENOENT' }));
