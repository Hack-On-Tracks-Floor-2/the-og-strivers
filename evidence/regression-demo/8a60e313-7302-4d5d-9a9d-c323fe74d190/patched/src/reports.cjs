const { readFileSync } = require('node:fs');
const { join } = require('node:path');

// Deliberately vulnerable, local demonstration fixture. Never deploy this module.
function readReport(root, name) {
  const { realpathSync } = require('node:fs');
  const { relative, isAbsolute, sep } = require('node:path');
  const base = realpathSync(root);
  const target = realpathSync(join(base, name));
  const within = relative(base, target);
  if (within === '..' || within.startsWith('..' + sep) || isAbsolute(within)) {
    throw Object.assign(new Error('Report path escapes its root'), { code: 'EACCES' });
  }
  return readFileSync(target, 'utf8');
}

module.exports = { readReport };
