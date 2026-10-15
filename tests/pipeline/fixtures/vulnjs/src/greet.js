// Tiny greeting service used as a ProofPatch test fixture (intentionally vulnerable).
const { execSync } = require('node:child_process');

function greet(name) {
  // Vulnerable: user input is interpolated into a shell command.
  return execSync(`echo Hello ${name}`).toString().trim();
}

function shout(text) {
  return String(text).toUpperCase();
}

module.exports = { greet, shout };
