import test from 'node:test';
import assert from 'node:assert/strict';
import { parseExpectedRevision } from '../src/task-api-v1.js';

test('parseExpectedRevision', async () => {
  assert.strictEqual(parseExpectedRevision({ headers: { 'if-match': '"7"' } }), 7);
  assert.strictEqual(parseExpectedRevision({ headers: { 'if-match': 'W/"7"' } }), 7);
  assert.strictEqual(parseExpectedRevision({ headers: {} }, { expectedRevision: 7 }), 7);
  assert.throws(() => parseExpectedRevision({ headers: {} }), { code: 'missing_revision' });

  for (const value of [-1, 1.5, 'abc', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => parseExpectedRevision({ headers: {} }, { expectedRevision: value }),
      { code: 'invalid_revision' },
    );
  }

  assert.throws(
    () => parseExpectedRevision({ headers: { 'if-match': '"7"' } }, { expectedRevision: 7 }),
    { code: 'duplicate_revision' },
  );
});

test('parseExpectedRevision accepts zero as a valid revision', () => {
  assert.equal(parseExpectedRevision({ headers: {} }, { expectedRevision: 0 }), 0);
});

test('parseExpectedRevision accepts the maximum safe integer', () => {
  assert.equal(
    parseExpectedRevision({ headers: {} }, { expectedRevision: Number.MAX_SAFE_INTEGER }),
    Number.MAX_SAFE_INTEGER,
  );
});

test('parseExpectedRevision rejects wildcard If-Match', () => {
  assert.throws(
    () => parseExpectedRevision({ headers: { 'if-match': '*' } }),
    { code: 'invalid_revision' },
  );
});
