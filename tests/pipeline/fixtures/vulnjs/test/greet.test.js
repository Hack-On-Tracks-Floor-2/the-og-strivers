const { test } = require('node:test');
const assert = require('node:assert/strict');
const { greet, shout } = require('../src/greet.js');

test('greets by name', () => {
  assert.equal(greet('Ada'), 'Hello Ada');
});

test('shouts', () => {
  assert.equal(shout('hi'), 'HI');
});
