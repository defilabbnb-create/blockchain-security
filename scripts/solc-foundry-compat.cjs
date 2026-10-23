function normalizeFoundryOutput(compiledJson) {
  const output = JSON.parse(compiledJson);
  for (const source of Object.values(output.sources || {})) {
    const id = source && source.id;
    if (typeof id === 'string' && /^\d+$/.test(id) && Number(id) <= 0xffffffff) {
      source.id = Number(id);
    }
  }
  for (const contracts of Object.values(output.contracts || {})) {
    for (const contract of Object.values(contracts || {})) {
      const creation = contract.evm && contract.evm.gasEstimates && contract.evm.gasEstimates.creation;
      if (!creation || Object.prototype.hasOwnProperty.call(creation, 'totalCost')) continue;
      const deposit = creation.codeDepositCost;
      const execution = creation.executionCost;
      if (/^\d+$/.test(String(deposit)) && /^\d+$/.test(String(execution))) {
        creation.totalCost = (BigInt(deposit) + BigInt(execution)).toString();
      }
    }
  }
  return JSON.stringify(output);
}

module.exports = normalizeFoundryOutput;
