import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtureRoot = path.join(root, 'tests', 'fixtures', 'assertions');

test('W0 creates a correct and violating fixture for each assertion family', () => {
  const fixtures = fs.readdirSync(fixtureRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(fixtures, [
    'amm',
    'erc4626',
    'erc4626-donation',
    'erc4626-rounding',
    'lending',
    'lending-liquidation',
    'poc',
  ]);
  for (const fixture of fixtures) {
    assert.ok(fs.existsSync(path.join(fixtureRoot, fixture, 'correct')));
    assert.ok(fs.existsSync(path.join(fixtureRoot, fixture, 'violating')));
    assert.ok(fs.existsSync(path.join(fixtureRoot, fixture, 'meta.json')));
  }
});
