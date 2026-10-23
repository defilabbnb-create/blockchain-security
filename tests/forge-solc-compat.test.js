import assert from 'node:assert/strict';
import test from 'node:test';
import normalizeFoundryOutput from '../scripts/solc-foundry-compat.cjs';

test('normalizes legacy source ids and derives creation total cost for Foundry', () => {
  const output = normalizeFoundryOutput(JSON.stringify({
    sources: { 'legacy.sol': { id: '0' } },
    contracts: { 'legacy.sol': { Legacy: { evm: { gasEstimates: { creation: {
      codeDepositCost: '180400', executionCost: '20228',
    } } } } } },
  }));
  const normalized = JSON.parse(output);
  assert.equal(normalized.sources['legacy.sol'].id, 0);
  assert.equal(normalized.contracts['legacy.sol'].Legacy.evm.gasEstimates.creation.totalCost, '200628');
});

test('preserves existing or non-numeric compiler gas estimates', () => {
  const output = normalizeFoundryOutput(JSON.stringify({
    contracts: { 'modern.sol': { Modern: { evm: { gasEstimates: { creation: {
      codeDepositCost: '10', executionCost: '20', totalCost: '30',
    } } } } }, 'unknown.sol': { Unknown: { evm: { gasEstimates: { creation: {
      codeDepositCost: 'infinite', executionCost: '20',
    } } } } } },
  }));
  const contracts = JSON.parse(output).contracts;
  assert.equal(contracts['modern.sol'].Modern.evm.gasEstimates.creation.totalCost, '30');
  assert.equal(Object.hasOwn(contracts['unknown.sol'].Unknown.evm.gasEstimates.creation, 'totalCost'), false);
});
