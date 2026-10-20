import test from 'node:test';
import assert from 'node:assert/strict';
import { createReplayArtifact, replayEvidenceStatus, verifyReplayArtifact, REPLAY_ARTIFACT_MAX_BYTES } from '../src/replay-artifact.js';

test('creates a hashed, deeply immutable replay artifact', () => {
  const analysisInput = { target: 'VaultV2', options: { compiler: '0.8.23' } };
  const events = [{ type: 'compile', state: 'completed' }, { type: 'test', state: 'passed' }];
  const evidenceRefs = [{ path: 'static-analysis.json', sha256: 'a'.repeat(64) }];
  const artifact = createReplayArtifact({ analysisInput, events, evidenceRefs, artifactId: 'replay-1', createdAt: '2026-01-01T00:00:00.000Z' });

  assert.equal(artifact.schemaVersion, 1);
  assert.equal(artifact.artifactId, 'replay-1');
  assert.equal(artifact.createdAt, '2026-01-01T00:00:00.000Z');
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/);
  assert.equal(verifyReplayArtifact(artifact), true);
  assert.equal(Object.isFrozen(artifact), true);
  assert.equal(Object.isFrozen(artifact.analysisInput), true);
  assert.equal(Object.isFrozen(artifact.events), true);
  assert.equal(Object.isFrozen(artifact.evidenceRefs), true);
  assert.throws(() => { artifact.analysisInput.options.compiler = 'changed'; }, TypeError);
  assert.deepEqual(analysisInput, { target: 'VaultV2', options: { compiler: '0.8.23' } });
});

test('supports the evidence alias while emitting evidenceRefs', () => {
  const artifact = createReplayArtifact({ input: { run: 3 }, events: [], evidence: [{ id: 'e1' }] });
  assert.deepEqual(artifact.analysisInput, { run: 3 });
  assert.deepEqual(artifact.evidenceRefs, [{ id: 'e1' }]);
  assert.equal(verifyReplayArtifact(artifact), true);
});

test('rejects functions, cycles, and unsupported JSON values', () => {
  assert.throws(() => createReplayArtifact({ analysisInput: { callback() {} } }), /functions/);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => createReplayArtifact({ analysisInput: cyclic }), /cyclic/);
  assert.throws(() => createReplayArtifact({ analysisInput: { value: 1n } }), /JSON serializable/);
  assert.throws(() => createReplayArtifact({ analysisInput: { value: Number.NaN } }), /finite JSON numbers/);
});

test('rejects artifacts whose final JSON representation exceeds 2 MiB', () => {
  const oversized = 'x'.repeat(REPLAY_ARTIFACT_MAX_BYTES);
  assert.throws(() => createReplayArtifact({ analysisInput: { oversized } }), /exceeds/);
});

test('verification detects content changes and malformed envelopes', () => {
  const artifact = createReplayArtifact({ analysisInput: { target: 'A' }, events: [{ type: 'start' }], evidenceRefs: [] });
  const changed = structuredClone(artifact);
  changed.events[0].type = 'tampered';
  assert.equal(verifyReplayArtifact(changed), false);
  assert.equal(verifyReplayArtifact({ ...artifact, sha256: '0'.repeat(64) }), false);
  assert.equal(verifyReplayArtifact({ ...artifact, schemaVersion: 2 }), false);
  assert.equal(verifyReplayArtifact(null), false);
});

test('accepts a bounded replay context and detects replay tampering', () => {
  const artifact = createReplayArtifact({
    analysisInput: { target: 'VaultV2' },
    replay: {
      transactions: [{ txIndex: 0, transactionHash: `0x${'a'.repeat(64)}` }],
      traces: [{ txIndex: 0, hash: 'b'.repeat(64) }],
      assetChanges: [{ asset: `0x${'1'.repeat(40)}`, before: '100', after: '90' }],
      permissionChanges: [{ role: 'WITHDRAWER_ROLE', account: `0x${'2'.repeat(40)}`, before: true, after: false }],
      stateDiff: [{ path: 'vault.totalAssets', before: '100', after: '90' }],
      seed: '0x5ec0a11',
      fork: { chainId: 31337, blockNumber: 42, blockHash: `0x${'c'.repeat(64)}` },
      command: 'npx hardhat test --grep Vault',
    },
  });
  assert.equal(verifyReplayArtifact(artifact), true);
  const changed = structuredClone(artifact);
  changed.replay.stateDiff[0].after = '80';
  assert.equal(verifyReplayArtifact(changed), false);
});

test('rejects incomplete or unsafe replay context fields', () => {
  assert.throws(() => createReplayArtifact({ replay: { fork: { blockNumber: 1 } } }), /chainId/);
  assert.throws(() => createReplayArtifact({ replay: { fork: { chainId: 31337, blockNumber: -1 } } }), /blockNumber/);
  assert.throws(() => createReplayArtifact({ replay: { transactions: [{ transactionHash: 'bad' }] } }), /transactionHash/);
  assert.throws(() => createReplayArtifact({ replay: { unexpected: true } }), /unsupported field/);
});

test('validates structured raw calldata, transaction sequence, initial state, trace, and storage diff evidence', () => {
  const zeroWord = `0x${'0'.repeat(64)}`;
  const artifact = createReplayArtifact({
    artifactId: 'structured-replay',
    analysisInput: { target: 'VaultV2' },
    replay: {
      seed: '0x5ec0a11',
      command: 'npx hardhat test --grep replay',
      fork: { chainId: 31337, blockNumber: 42, blockHash: `0x${'c'.repeat(64)}` },
      transactions: [{
        txIndex: 0,
        transactionHash: `0x${'a'.repeat(64)}`,
        from: `0x${'1'.repeat(40)}`,
        to: `0x${'2'.repeat(40)}`,
        value: '0',
        data: '0x12345678',
        status: 'success',
      }],
      sequence: [{ txIndex: 0, transactionHash: `0x${'a'.repeat(64)}` }],
      initialState: {
        chainId: 31337,
        blockNumber: 42,
        blockHash: `0x${'c'.repeat(64)}`,
        accounts: [{ address: `0x${'1'.repeat(40)}`, balance: '100', nonce: '0', codeHash: 'd'.repeat(64) }],
        storage: [{ address: `0x${'2'.repeat(40)}`, slot: `0x${'0'.repeat(64)}`, value: zeroWord }],
      },
      traces: [{ txIndex: 0, transactionHash: `0x${'a'.repeat(64)}`, traceHash: 'b'.repeat(64), state: 'available', steps: 4, effectCount: 1 }],
      storageDiff: [{ address: `0x${'2'.repeat(40)}`, slot: `0x${'0'.repeat(64)}`, before: zeroWord, after: `0x${'1'.repeat(64)}`, txIndex: 0 }],
      assetChanges: [],
      permissionChanges: [],
      stateDiff: [],
    },
  });
  assert.equal(verifyReplayArtifact(artifact), true);
  const status = replayEvidenceStatus(artifact.replay);
  assert.equal(status.state, 'complete');
  assert.equal(status.replayable, true);
  assert.equal(status.confirmationEligible, false);
  assert.deepEqual(status.dimensions, {
    rawCalldata: 'available', transactionSequence: 'available', initialState: 'available',
    traces: 'available', storageDiff: 'available', assetChanges: 'available', permissionChanges: 'available', stateDiff: 'available',
    seed: 'available', fork: 'available', replayCommand: 'available',
  });
});

test('rejects malformed raw calldata, storage words, and duplicate sequence indexes', () => {
  assert.throws(() => createReplayArtifact({ replay: { transactions: [{ data: '0x123' }] } }), /even-length/);
  assert.throws(() => createReplayArtifact({ replay: { storageDiff: [{ address: `0x${'1'.repeat(40)}`, slot: `0x${'0'.repeat(64)}`, value: '0x01' }] } }), /32-byte storage/);
  assert.throws(() => createReplayArtifact({ replay: { transactions: [{ txIndex: 0 }, { txIndex: 1 }], sequence: [0, 0] } }), /duplicated/);
  assert.throws(() => createReplayArtifact({ replay: { transactions: [{ data: '0x12', input: '0x34' }] } }), /must match/);
  assert.throws(() => createReplayArtifact({ replay: { assetChanges: [{ token: 'USDC', before: '1', after: '2' }] } }), /EVM address/);
  assert.throws(() => createReplayArtifact({ replay: { permissionChanges: [{ role: 'admin', account: `0x${'1'.repeat(40)}`, before: 'yes', after: false }] } }), /must be boolean/);
});

test('rejects replay evidence whose transaction index and hash do not identify the same transaction', () => {
  const firstHash = `0x${'a'.repeat(64)}`;
  const secondHash = `0x${'b'.repeat(64)}`;
  const transactions = [
    { txIndex: 0, transactionHash: firstHash },
    { txIndex: 1, transactionHash: secondHash },
  ];

  assert.throws(() => createReplayArtifact({
    replay: { transactions, sequence: [{ txIndex: 0, transactionHash: secondHash }] },
  }), /different transactions/);
  assert.throws(() => createReplayArtifact({
    replay: { transactions, traces: [{ txIndex: 3, traceHash: 'c'.repeat(64) }] },
  }), /unknown transaction 3/);
  assert.throws(() => createReplayArtifact({
    replay: { transactions, storageDiff: [{
      address: `0x${'1'.repeat(40)}`, slot: `0x${'0'.repeat(64)}`,
      before: `0x${'0'.repeat(64)}`, after: `0x${'1'.repeat(64)}`, transactionHash: `0x${'c'.repeat(64)}`,
    }] },
  }), /unknown transaction/);
  assert.throws(() => createReplayArtifact({
    replay: { traces: [{ txIndex: 0, traceHash: 'd'.repeat(64) }] },
  }), /transactions is missing/);
  assert.throws(() => createReplayArtifact({
    replay: { transactions: [{ txIndex: 0, transactionHash: firstHash }, { txIndex: 1, transactionHash: firstHash }] },
  }), /transactionHash is duplicated/);
});

test('checks initial-state anchors against the fork without rejecting equivalent quantities', () => {
  const blockHash = `0x${'c'.repeat(64)}`;
  const stateRoot = `0x${'d'.repeat(64)}`;
  const base = {
    initialState: { chainId: 31337, blockNumber: 42, blockHash, stateRoot, timestamp: '0x64' },
    fork: { chainId: '0x7a69', blockNumber: '0x2a', blockHash, stateRoot, timestamp: 100 },
  };
  assert.equal(verifyReplayArtifact(createReplayArtifact({ replay: base })), true);
  assert.throws(() => createReplayArtifact({ replay: {
    ...base,
    fork: { ...base.fork, blockNumber: 43 },
  } }), /blockNumber does not match/);
  assert.throws(() => createReplayArtifact({ replay: {
    ...base,
    fork: { ...base.fork, blockHash: `0x${'e'.repeat(64)}` },
  } }), /blockHash does not match/);
  assert.throws(() => createReplayArtifact({ replay: {
    ...base,
    fork: { ...base.fork, timestamp: 101 },
  } }), /timestamp does not match/);
});

test('reports partial replay evidence without treating it as a confirmed finding', () => {
  const artifact = createReplayArtifact({ replay: { transactions: [{ txIndex: 0, data: '0x' }], seed: 7 } });
  const status = replayEvidenceStatus(artifact.replay);
  assert.equal(status.state, 'partial');
  assert.equal(status.replayable, false);
  assert.equal(status.confirmationEligible, false);
  assert.ok(status.limitations.includes('missing_or_partial_initialState'));
  assert.equal(replayEvidenceStatus(undefined).state, 'insufficient');
});

