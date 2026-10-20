import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const wrapper = resolve('flare-scan/tools/solc-wrapper.js');
function compile(source, extra = {}) {
  const input = { language: 'Solidity', sources: { 'X.sol': { content: source } }, settings: { outputSelection: { '*': { '': ['ast'], '*': ['abi', 'evm.bytecode'] } } } };
  return spawnSync(process.execPath, [wrapper, '--standard-json'], { input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, SOLC_VERSION: '', ...extra } });
}
test('compiler returns real AST and bytecode, handles caret constraints', () => {
  const run = compile('pragma solidity ^0.8.24; contract X { function f() public pure returns(uint) {return 1;} }');
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.sources['X.sol'].ast.nodeType, 'SourceUnit');
  assert.ok(result.contracts['X.sol'].X.evm.bytecode.object.length > 0);
});
test('compiler failure never becomes successful empty output', () => {
  const run = compile('pragma solidity ^0.8.24; contract X { broken syntax }');
  assert.notEqual(run.status, 0);
  assert.ok(JSON.parse(run.stdout).errors.some(e => e.severity === 'error'));
  assert.notEqual(compile('pragma solidity 0.8.19; contract X {}', { SOLC_VERSION: '0.8.28' }).status, 0);
});
test('combined JSON resolves imports and returns source maps and AST', () => {
  const dir = mkdtempSync(join(tmpdir(), 'solc-space test-'));
  try {
    writeFileSync(join(dir, 'Y.sol'), 'pragma solidity ^0.8.19; contract Y {function y() public pure returns(uint){return 42;}}');
    writeFileSync(join(dir, 'X.sol'), 'pragma solidity 0.8.19; import "./Y.sol"; contract X is Y {}');
    const run = spawnSync(process.execPath, [wrapper, join(dir, 'X.sol'), '--combined-json', 'abi,bin,ast', '--optimize'], { cwd: dir, encoding: 'utf8', env: { ...process.env, SOLC_VERSION: '' } });
    assert.equal(run.status, 0, run.stderr);
    const result = JSON.parse(run.stdout);
    assert.ok(result.version.startsWith('0.8.19'));
    assert.equal(result.sourceList.length, 2);
    const c = result.contracts[`${dir}/X.sol:X`];
    assert.ok(c.bin.length); assert.ok(c['bin-runtime'].length); assert.ok(c.srcmap.length);
    assert.equal(result.sources[`${dir}/Y.sol`].AST.nodeType, 'SourceUnit');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
