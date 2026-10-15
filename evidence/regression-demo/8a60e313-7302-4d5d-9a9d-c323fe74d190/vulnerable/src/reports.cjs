const { readFileSync } = require('node:fs');
const { join } = require('node:path');

// Deliberately vulnerable, local demonstration fixture. Never deploy this module.
function readReport(root, name) {
  return readFileSync(join(root, name), 'utf8');
}

module.exports = { readReport };
