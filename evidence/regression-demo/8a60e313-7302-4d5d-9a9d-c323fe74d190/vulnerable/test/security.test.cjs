const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { readReport } = require('../src/reports.cjs');

let folder;
let root;
before(() => {
  folder = mkdtempSync(join(tmpdir(), 'patchproof-security-'));
  root = join(folder, 'public');
  mkdirSync(join(root, 'nested'), { recursive: true });
  mkdirSync(join(folder, 'public-backup'));
  writeFileSync(join(folder, 'private.txt'), 'CONTROLLED_PRIVATE_MARKER');
  writeFileSync(join(folder, 'public-backup', 'private.txt'), 'CONTROLLED_BACKUP_MARKER');
  // Prove the attack targets exist so ENOENT cannot masquerade as a fix.
  assert.equal(require('node:fs').readFileSync(join(folder, 'private.txt'), 'utf8'), 'CONTROLLED_PRIVATE_MARKER');
});
after(() => rmSync(folder, { recursive: true, force: true }));

test('blocks parent directory traversal', () => assert.throws(() => readReport(root, '../private.txt'), { code: 'EACCES' }));
test('blocks sibling with the same directory prefix', () => assert.throws(() => readReport(root, '../public-backup/private.txt'), { code: 'EACCES' }));
test('blocks traversal through a nested directory', () => assert.throws(() => readReport(root, 'nested/../../private.txt'), { code: 'EACCES' }));
