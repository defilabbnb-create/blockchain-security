import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TaskStateStore } from '../src/task-state.js';
import { TaskWorker } from '../src/task-worker.js';
import { createResourceTaskHandlers } from '../src/resource-task-handlers.js';

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'resource-task-handler-'));
  const project = join(dir, 'project');
  await mkdir(project);
  await writeFile(join(project, 'README.md'), '# fixture\n');
  await writeFile(join(project, 'package.json'), '{"name":"fixture"}\n');
  const store = new TaskStateStore({ path: join(dir, 'tasks.json') });
  const handlers = createResourceTaskHandlers({ artifactRoots: [dir], evidenceRoot: join(dir, 'evidence'), timeoutMs: 60_000, taskStore: store });
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, project, store, handlers };
}

async function fakeBytecodeAnalyzer(root, report, exitCode = 0) {
  await mkdir(join(root, 'scripts'), { recursive: true });
  const encoded = JSON.stringify(report);
  await writeFile(join(root, 'scripts', 'bytecode_analysis.py'), [
    'import json, pathlib, sys',
    `report = ${JSON.stringify(encoded)}`,
    'pathlib.Path(sys.argv[3]).write_text(report, encoding="utf-8")',
    'pathlib.Path(sys.argv[5]).write_text("{}\\n", encoding="utf-8")',
    `raise SystemExit(${exitCode})`,
    '',
  ].join('\n'));
}

function validReport(runtimeBytecode, decompilation = { state: 'not_performed', highLevelSemanticsRecovered: false }) {
  const bytes = Buffer.from(runtimeBytecode.slice(2), 'hex');
  return {
    schemaVersion: 1,
    analysisType: 'deterministic_evm_runtime_disassembly',
    runtimeBytecode,
    bytecodeSha256: createHash('sha256').update(bytes).digest('hex'),
    bytecodeBytes: bytes.length,
    decompilation,
  };
}

function collectionRpc({ reorg = false, failAt = null, transactions = [], receiptUnsupported = false, traceUnsupported = false, debugUnsupported = false, storageUnsupported = false } = {}) {
  const calls = [];
  const address = '0x' + '11'.repeat(20);
  const code = '0x6000600055';
  const blocks = new Map([
    [10, '0x' + 'aa'.repeat(32)],
    [11, '0x' + 'bb'.repeat(32)],
  ]);
  let failed = false;
  return {
    calls,
    address,
    async request({ method, params }) {
      calls.push({ method, params });
      if (method === 'eth_chainId') return { value: '0x1', raw: Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x1"}') };
      if (method === 'eth_getBlockByNumber') {
        const number = Number.parseInt(String(params[0]), 16);
        if (number === failAt && !failed) {
          failed = true;
          const error = new Error('temporary provider failure');
          error.code = 'RPC_TRANSPORT';
          error.retryable = true;
          throw error;
        }
        const hash = number === 10 && reorg ? '0x' + 'cc'.repeat(32) : blocks.get(number);
        return { value: { number: params[0], hash, timestamp: '0x64', transactions }, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { number: params[0], hash, timestamp: '0x64', transactions } })) };
      }
      if (method === 'eth_getCode') return { value: code, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: code })) };
      if (method === 'eth_getLogs') return { value: [], raw: Buffer.from('{"jsonrpc":"2.0","id":1,"result":[] }') };
      if (method === 'eth_getTransactionReceipt') {
        if (receiptUnsupported) { const error = new Error('method unavailable'); error.code = 'RPC_UNSUPPORTED'; throw error; }
        const value = { transactionHash: params[0], blockHash: blocks.get(10), blockNumber: '0xa', status: '0x1', logs: [] };
        return { value, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: value })) };
      }
      if (method === 'debug_traceTransaction') {
        if (debugUnsupported) { const error = new Error('method unavailable'); error.code = 'RPC_UNSUPPORTED'; throw error; }
        const value = { type: 'CALL', from: address, to: address, gas: '0x5208', calls: [] };
        return { value, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: value })) };
      }
      if (method === 'trace_transaction') {
        if (traceUnsupported) { const error = new Error('method unavailable'); error.code = 'RPC_UNSUPPORTED'; throw error; }
        const value = [{ type: 'call', action: { from: address, to: address }, result: { gasUsed: '0x5208' } }];
        return { value, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: value })) };
      }
      if (method === 'eth_getStorageAt') {
        if (storageUnsupported) { const error = new Error('method unavailable'); error.code = 'RPC_UNSUPPORTED'; throw error; }
        const value = '0x' + '00'.repeat(31) + '2a';
        return { value, raw: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: value })) };
      }
      throw new Error(`unexpected method ${method}`);
    },
  };
}

test('collection normalizes full transaction details and preserves hash-only limitation', async (t) => {
  const f = await fixture(t);
  const hashOnly = '0x' + 'ab'.repeat(32);
  const fullHash = '0x' + 'cd'.repeat(32);
  const rpc = collectionRpc({ transactions: [hashOnly, {
    hash: fullHash,
    from: '0x' + '22'.repeat(20),
    to: '0x' + '33'.repeat(20),
    value: '0xde0b6b3a7640000',
    input: '0x12345678',
    nonce: '0x2',
    gas: '0x5208',
    gasPrice: '0x3b9aca00',
    type: '0x2',
    blockHash: '0x' + 'aa'.repeat(32),
    blockNumber: '0xa',
  }] });
  const handlers = createResourceTaskHandlers({ artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000, rpcRequest: rpc.request });
  const task = await f.store.create({ type: 'v1-resource-collection', payload: { resource: 'collection', input: {
    projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1', address: rpc.address,
    fromBlock: '10', toBlock: '10', includeTransactions: true,
  } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded', JSON.stringify(finished));
  const [hashRow, fullRow] = finished.checkpoint.records[0].transactions;
  assert.equal(hashRow.transactionDetailsState, 'unavailable');
  assert.equal(fullRow.transactionDetailsState, 'available');
  assert.equal(fullRow.from, '0x' + '22'.repeat(20));
  assert.equal(fullRow.to, '0x' + '33'.repeat(20));
  assert.equal(fullRow.value, '0xde0b6b3a7640000');
  assert.equal(fullRow.input, '0x12345678');
  assert.equal(fullRow.gas, '0x5208');
});

test('collection rejects transaction details with a mismatched block anchor', async (t) => {
  const f = await fixture(t);
  const rpc = collectionRpc({ transactions: [{ hash: '0x' + 'ab'.repeat(32), blockHash: '0x' + 'ff'.repeat(32) }] });
  const handlers = createResourceTaskHandlers({ artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000, rpcRequest: rpc.request });
  const task = await f.store.create({ type: 'v1-resource-collection', payload: { resource: 'collection', input: {
    projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1', address: rpc.address,
    fromBlock: '10', toBlock: '10', includeTransactions: true,
  } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'failed');
  assert.match(finished.error || finished.history.at(-1)?.reason || JSON.stringify(finished), /blockHash|锚点/);
});

test('project resource task runs the fixed importer and persists hashed evidence', async (t) => {
  const f = await fixture(t);
  const task = await f.store.create({ type: 'v1-resource-projects', payload: { resource: 'projects', input: { projectId: 'fixture', sourcePath: f.project } } });
  const worker = new TaskWorker({ store: f.store, handlers: f.handlers });
  await worker.runOnce();
  await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded');
  assert.equal(finished.checkpoint.phase, 'evidence_ready');
  assert.equal(finished.checkpoint.complete, true);
  for (const item of finished.checkpoint.artifacts) {
    const bytes = await readFile(item.path);
    assert.equal(bytes.length, item.bytes);
    assert.match(item.sha256, /^[a-f0-9]{64}$/);
  }
});

test('bytecode resource task runs deterministic disassembly without claiming semantic proof', async (t) => {
  const f = await fixture(t);
  const task = await f.store.create({ type: 'v1-resource-bytecode', payload: { resource: 'bytecode', input: { runtimeBytecode: '0x60003560e01c60005700', hardfork: 'cancun' } } });
  const worker = new TaskWorker({ store: f.store, handlers: f.handlers });
  await worker.runOnce();
  await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded');
  assert.equal(finished.checkpoint.phase, 'evidence_ready');
  assert.equal(finished.checkpoint.sourceVerified, false);
  assert.equal(finished.checkpoint.confirmedVulnerabilities, 0);
  assert.ok(finished.checkpoint.artifacts.some(({ kind }) => kind === 'unified-ir'));
});

test('decompile task preserves failed Heimdall states as failed', async (t) => {
  const f = await fixture(t);
  const runtimeBytecode = '0x6000';
  await fakeBytecodeAnalyzer(f.dir, validReport(runtimeBytecode, { state: 'failed', error: 'engine failed' }));
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000 });
  const task = await f.store.create({ type: 'v1-resource-decompile', payload: { resource: 'decompile', input: { runtimeBytecode } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'failed');
  assert.equal(finished.checkpoint.decompilationState, 'failed');
  assert.equal(finished.checkpoint.crossValidation.state, 'not_recorded');
  assert.equal(finished.checkpoint.crossValidation.comparedHighLevelEngineCount, 0);
  assert.match(finished.checkpoint.crossValidation.agreementScope, /不验证伪码语义/);
});

test('decompile task carries opcode-only scope separately from high-level engine comparison', async (t) => {
  const f = await fixture(t);
  const runtimeBytecode = '0x6000';
  const crossValidation = {
    state: 'opcode_consistent',
    enginesConfigured: ['heimdall-rs'],
    enginesCompleted: [],
    comparedEngineCount: 0,
    comparedHighLevelEngineCount: 0,
    agreementScope: 'opcode/PC tokenization only; no high-level decompiler agreement or semantic proof',
    opcodePcCrossCheck: { state: 'consistent', isSecondHighLevelDecompiler: false, semanticsProven: false },
  };
  await fakeBytecodeAnalyzer(f.dir, validReport(runtimeBytecode, { state: 'failed', crossValidation }));
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000 });
  const task = await f.store.create({ type: 'v1-resource-decompile', payload: { resource: 'decompile', input: { runtimeBytecode } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.checkpoint.crossValidation.opcodePcCrossCheck.state, 'consistent');
  assert.equal(finished.checkpoint.crossValidation.comparedHighLevelEngineCount, 0);
  assert.equal(finished.checkpoint.crossValidation.opcodePcCrossCheck.semanticsProven, false);
});

test('decompile task rejects a report whose bytecode fingerprint does not match input', async (t) => {
  const f = await fixture(t);
  const runtimeBytecode = '0x6000';
  const report = validReport('0x6001', { state: 'completed', highLevelSemanticsRecovered: false });
  await fakeBytecodeAnalyzer(f.dir, report);
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000 });
  const task = await f.store.create({ type: 'v1-resource-decompile', payload: { resource: 'decompile', input: { runtimeBytecode } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'failed');
  assert.equal(finished.checkpoint.inputBinding.matched, false);
  assert.match(finished.history.at(-1).error, /指纹/);
});

test('decompile task cannot succeed when a reported output artifact is missing', async (t) => {
  const f = await fixture(t), runtimeBytecode = '0x6000';
  await fakeBytecodeAnalyzer(f.dir, validReport(runtimeBytecode, {
    state: 'completed', highLevelSemanticsRecovered: false,
    artifacts: [{ path: 'decompiled.sol', kind: 'solidity-pseudocode', size: 12, sha256: 'a'.repeat(64) }],
  }));
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000 });
  const task = await f.store.create({ type: 'v1-resource-decompile', payload: { resource: 'decompile', input: { runtimeBytecode } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'failed');
  assert.equal(finished.checkpoint.decompilerArtifactValidation.complete, false);
  assert.match(finished.history.at(-1).error, /产物缺失/);
});

test('bytecode retry refuses an input file changed after its checkpoint', async (t) => {
  const f = await fixture(t), inputPath = join(f.dir, 'runtime.json');
  const original = Buffer.from('0x6000');
  await writeFile(inputPath, original);
  const originalHash = createHash('sha256').update(original).digest('hex');
  await writeFile(inputPath, '0x6001');
  let spawned = false;
  const handlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000,
    spawnProcess: () => { spawned = true; throw new Error('must not spawn for changed retry input'); },
  });
  const task = { taskId: 'changed-retry-input', type: 'v1-resource-bytecode', attempts: 2 };
  const result = await handlers['v1-resource-bytecode']({
    resource: 'bytecode', input: { inputPath },
  }, {
    task, lastCheckpoint: { phase: 'analysis_preparing', inputSha256: originalHash },
    signal: new AbortController().signal, checkpoint: async () => {},
  });
  assert.equal(result.status, 'blocked', result.reason);
  assert.match(result.reason, /SHA-256 与上次检查点不一致/);
  assert.equal(spawned, false);
});

test('bytecode task binds reports to runtime bytes extracted from JSON input', async (t) => {
  const f = await fixture(t), inputPath = join(f.dir, 'runtime.json');
  await writeFile(inputPath, JSON.stringify({ runtimeBytecode: { onchainBytecode: '0x6000' } }));
  await fakeBytecodeAnalyzer(f.dir, validReport('0x6000'));
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000 });
  const task = await f.store.create({ type: 'v1-resource-bytecode', payload: { resource: 'bytecode', input: { inputPath } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded');
  assert.notEqual(finished.checkpoint.inputSha256, finished.checkpoint.bytecodeSha256);
  assert.equal(finished.checkpoint.inputBinding.matched, true);
});

test('contractId bytecode analysis resolves only the exact bound and archived block code', async (t) => {
  const f = await fixture(t), rpc = collectionRpc();
  await writeFile(join(f.project, 'Vault.sol'), 'pragma solidity ^0.8.20; contract Vault {}\n');
  const runtimeBytecode = '0x6000600055';
  const evidenceRoot = join(f.dir, 'evidence');
  const projectHandlers = createResourceTaskHandlers({ artifactRoots: [f.dir], evidenceRoot, timeoutMs: 60_000, taskStore: f.store });
  const projectTask = await f.store.create({ type: 'v1-resource-projects', payload: { resource: 'projects', input: { projectId: 'bound-fixture', sourcePath: f.project } } });
  let worker = new TaskWorker({ store: f.store, handlers: projectHandlers });
  await worker.runOnce(); await worker.waitForIdle();
  const imported = await f.store.get(projectTask.taskId);
  assert.equal(imported.state, 'succeeded');
  const manifestArtifact = imported.checkpoint.artifacts.find(({ kind }) => kind === 'project-import-manifest');
  const manifest = JSON.parse(await readFile(manifestArtifact.path, 'utf8'));
  const source = manifest.files.find(({ path, included, kind }) => path === 'Vault.sol' && included && kind === 'source');
  const contractId = `source-${createHash('sha256').update(`bound-fixture\0${manifest.sourceFingerprint}\0${source.path}\0${source.sha256}`).digest('hex').slice(0, 32)}`;
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot,
    timeoutMs: 60_000, taskStore: f.store, rpcRequest: rpc.request });
  const bindingTask = await f.store.create({ type: 'v1-resource-contracts', payload: { resource: 'contracts', input: {
    projectId: 'bound-fixture', contractId, chainId: '1', address: rpc.address,
  } } });
  const collectionTask = await f.store.create({ type: 'v1-resource-collection', payload: { resource: 'collection', input: {
    projectId: 'bound-fixture', chainId: '1', rpcUrl: 'http://127.0.0.1:8545', address: rpc.address,
    fromBlock: '10', toBlock: '10',
  } } });
  worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  await worker.runOnce(); await worker.waitForIdle();
  assert.equal((await f.store.get(bindingTask.taskId)).state, 'succeeded');
  assert.equal((await f.store.get(collectionTask.taskId)).state, 'succeeded');
  await fakeBytecodeAnalyzer(f.dir, validReport(runtimeBytecode));
  const bytecodeTask = await f.store.create({ type: 'v1-resource-bytecode', payload: { resource: 'bytecode', input: {
    projectId: 'bound-fixture', contractId, chainId: '1', address: rpc.address, block: '10',
  } } });
  worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(bytecodeTask.taskId);
  assert.equal(finished.state, 'succeeded', JSON.stringify(finished));
  assert.equal(finished.checkpoint.contractCodeReference.bindingTaskId, bindingTask.taskId);
  assert.equal(finished.checkpoint.contractCodeReference.collectionTaskId, collectionTask.taskId);
  assert.equal(finished.checkpoint.contractCodeReference.blockNumber, 10);
  assert.equal(finished.checkpoint.contractCodeReference.codeHash, `0x${createHash('sha256').update(Buffer.from(runtimeBytecode.slice(2), 'hex')).digest('hex')}`);
});

test('contractId analysis rejects mixed explicit bytecode input', async (t) => {
  const f = await fixture(t);
  const handlers = createResourceTaskHandlers({ artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000, taskStore: f.store });
  const result = await handlers['v1-resource-bytecode']({ resource: 'bytecode', input: {
    projectId: 'fixture', contractId: 'source-id', chainId: '1', address: '0x' + '11'.repeat(20), block: '1', runtimeBytecode: '0x6000',
  } }, { task: { type: 'v1-resource-bytecode', taskId: 'mixed-input', attempts: 1 }, lastCheckpoint: null, signal: new AbortController().signal, checkpoint: async () => {} });
  assert.equal(result.status, 'blocked');
  assert.match(result.reason, /不能与显式字节码输入同时使用/);
});

test('bytecode timeout kills the child process group and records partial evidence', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.dir, 'scripts'), { recursive: true });
  await writeFile(join(f.dir, 'scripts', 'bytecode_analysis.py'), [
    'import hashlib, json, pathlib, subprocess, sys, time',
    'input_value = pathlib.Path(sys.argv[1]).read_text().strip()',
    'raw = bytes.fromhex(input_value[2:])',
    'report = {"schemaVersion":1,"analysisType":"deterministic_evm_runtime_disassembly",',
    '          "runtimeBytecode":input_value,"bytecodeSha256":hashlib.sha256(raw).hexdigest(),',
    '          "bytecodeBytes":len(raw),"decompilation":{"state":"not_performed"}}',
    'pathlib.Path(sys.argv[3]).write_text(json.dumps(report), encoding="utf-8")',
    'pathlib.Path(sys.argv[5]).write_text("{}\\n", encoding="utf-8")',
    'child = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"])',
    'print(child.pid, flush=True)',
    'time.sleep(30)',
    '',
  ].join('\n'));
  const handlers = createResourceTaskHandlers({ root: f.dir, artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 250 });
  const task = await f.store.create({ type: 'v1-resource-bytecode', payload: { resource: 'bytecode', input: { runtimeBytecode: '0x6000' } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle({ timeoutMs: 5_000 });
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'partial');
  assert.equal(finished.checkpoint.execution.timedOut, true);
  const output = await readFile(finished.checkpoint.artifacts.find(({ kind }) => kind === 'stdout').path, 'utf8');
  const childPid = Number(output.trim());
  assert.ok(Number.isInteger(childPid) && childPid > 1);
  let alive = true;
  for (let attempt = 0; attempt < 100 && alive; attempt++) {
    try { process.kill(childPid, 0); await new Promise((resolve) => setTimeout(resolve, 20)); }
    catch (error) { if (error.code === 'ESRCH') alive = false; else throw error; }
  }
  assert.equal(alive, false, 'timed-out task left a child process running');
});

test('unsupported collection resource is blocked with an explicit capability gap', async (t) => {
  const f = await fixture(t);
  const task = await f.store.create({ type: 'v1-resource-collection', payload: { resource: 'collection', input: { sourcePath: f.project } } });
  const worker = new TaskWorker({ store: f.store, handlers: f.handlers });
  await worker.runOnce();
  await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'blocked');
  assert.match(finished.history.at(-1).reason, /RPC|采集/);
});

test('collection worker archives read-only blocks and checkpoints cursors', async (t) => {
  const f = await fixture(t);
  const rpc = collectionRpc();
  const handlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000,
    rpcRequest: rpc.request,
  });
  const task = await f.store.create({ type: 'v1-resource-collection', payload: {
    resource: 'collection', input: {
      projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1', address: rpc.address,
      fromBlock: '10', toBlock: '11', includeLogs: true, includeTransactions: true,
    },
  } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded', JSON.stringify(finished));
  assert.equal(finished.checkpoint.nextBlock, 12);
  assert.equal(finished.checkpoint.blockCursor.completedThrough, 11);
  assert.equal(finished.checkpoint.addressCursor.address, rpc.address);
  assert.ok(finished.checkpoint.archiveRefs.length >= 7);
  assert.equal(finished.checkpoint.capabilities.methods.eth_chainId.state, 'available');
  assert.equal(finished.checkpoint.capabilities.methods.eth_getBlockByNumber.state, 'available');
  assert.equal(finished.checkpoint.capabilities.methods.eth_getCode.state, 'available');
  assert.equal(finished.checkpoint.capabilities.methods.eth_getLogs.state, 'available');
  assert.equal(finished.checkpoint.capabilities.transactions.requested, true);
  assert.equal(finished.checkpoint.capabilities.transactions.receipts.state, 'not_requested');
  assert.equal(finished.checkpoint.capabilities.transactions.traces.state, 'not_requested');
  const codeRef = finished.checkpoint.archiveRefs.find((item) => item.kind === 'rpc.eth_getCode');
  assert.ok(codeRef);
  const metadata = JSON.parse(await readFile(codeRef.metadataPath, 'utf8'));
  assert.equal(metadata.provenance.block_number, 10);
  assert.equal(metadata.provenance.contract_address, rpc.address);
  assert.match(metadata.provenance.code_hash, /^0x[a-f0-9]{64}$/);
  const normalized = finished.checkpoint.records[0];
  assert.equal(normalized.provenance.project_id, 'fixture');
  assert.equal(normalized.provenance.chain_id, 1);
  assert.equal(normalized.provenance.block_number, 10);
  assert.equal(normalized.provenance.block_hash, normalized.blockHash);
  assert.equal(normalized.provenance.contract_address, rpc.address);
  assert.equal(normalized.provenance.code_hash, normalized.codeHash);
  assert.match(normalized.provenance.content_hash, /^[a-f0-9]{64}$/);
  assert.equal(normalized.provenance.schema_version, 1);
  assert.equal(normalized.provenance.tool_version, 'resource-collection/1');
  assert.equal(normalized.provenance.source_ref.block.contentHash, finished.checkpoint.archiveRefs.find((item) => item.kind === 'rpc.eth_getBlockByNumber').contentHash);
  assert.equal(normalized.provenance.source_ref.code.contentHash, codeRef.contentHash);
  assert.equal(normalized.provenance.provenance.recordKind, 'normalized_collection_block');
  assert.equal(normalized.capabilities.transactions.receipts.state, 'not_requested');
  assert.equal(normalized.provenance.provenance.capabilities.transactions.receipts.state, 'not_requested');
  assert.ok(rpc.calls.every(({ method }) => ['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getLogs'].includes(method)));
});

test('collection captures ordered receipts, trace fallback, and requested storage with raw provenance', async (t) => {
  const f = await fixture(t);
  const txHash = '0x' + 'ab'.repeat(32);
  const slot = '0x' + '00'.repeat(32);
  const rpc = collectionRpc({ transactions: [txHash], debugUnsupported: true });
  const handlers = createResourceTaskHandlers({ artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000, rpcRequest: rpc.request });
  const task = await f.store.create({ type: 'v1-resource-collection', payload: { resource: 'collection', input: {
    projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1', address: rpc.address,
    fromBlock: '10', toBlock: '10', includeTransactions: true, includeReceipts: true, includeTraces: true, storageSlots: [slot],
  } } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded', JSON.stringify(finished));
  const record = finished.checkpoint.records[0];
  assert.deepEqual(record.transactions.map((tx) => [tx.transactionHash, tx.transactionIndex]), [[txHash, 0]]);
  assert.equal(record.transactions[0].receipt.state, 'available');
  assert.equal(record.transactions[0].trace.state, 'available');
  assert.equal(record.transactions[0].trace.method, 'trace_transaction');
  assert.match(record.transactions[0].trace.hash, /^[a-f0-9]{64}$/);
  assert.equal(record.storage[0].slot, slot);
  assert.equal(record.storage[0].value, '0x' + '00'.repeat(31) + '2a');
  assert.equal(finished.checkpoint.capabilities.transactions.receipts.state, 'available');
  assert.equal(finished.checkpoint.capabilities.transactions.traces.state, 'available');
  assert.equal(finished.checkpoint.capabilities.storage.slots[0].state, 'available');
  for (const method of ['eth_getTransactionReceipt', 'trace_transaction', 'eth_getStorageAt']) {
    const ref = finished.checkpoint.archiveRefs.find((item) => item.kind === `rpc.${method}`);
    assert.ok(ref, `missing archived ${method} response`);
    const metadata = JSON.parse(await readFile(ref.metadataPath, 'utf8'));
    assert.equal(metadata.provenance.chain_id, 1);
    assert.equal(metadata.provenance.block_number, 10);
    assert.equal(metadata.provenance.block_hash, '0x' + 'aa'.repeat(32));
  }
  assert.ok(rpc.calls.findIndex(({ method }) => method === 'eth_getTransactionReceipt') < rpc.calls.findIndex(({ method }) => method === 'debug_traceTransaction'));
  assert.ok(rpc.calls.findIndex(({ method }) => method === 'debug_traceTransaction') < rpc.calls.findIndex(({ method }) => method === 'trace_transaction'));
});

test('collection capability probe records unsupported optional RPCs without inventing traces', async (t) => {
  const f = await fixture(t);
  const txHash = '0x' + 'cd'.repeat(32);
  const slot = '0x' + '00'.repeat(32);
  const rpc = collectionRpc({ transactions: [txHash], receiptUnsupported: true, debugUnsupported: true, traceUnsupported: true, storageUnsupported: true });
  const request = async (options) => {
    if (options.method === 'eth_getLogs') {
      const error = new Error('method unavailable');
      error.code = 'RPC_UNSUPPORTED';
      throw error;
    }
    return rpc.request(options);
  };
  const handlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000,
    rpcRequest: request,
  });
  const task = await f.store.create({ type: 'v1-resource-collection', payload: {
    resource: 'collection', input: {
      projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1',
      fromBlock: '10', toBlock: '10', address: rpc.address, includeTransactions: true, includeReceipts: true, includeTraces: true, includeLogs: false, storageSlots: [slot],
    },
  } });
  const worker = new TaskWorker({ store: f.store, handlers });
  await worker.runOnce(); await worker.waitForIdle();
  const finished = await f.store.get(task.taskId);
  assert.equal(finished.state, 'succeeded', JSON.stringify(finished));
  assert.equal(finished.checkpoint.capabilities.methods.eth_getLogs.state, 'unsupported');
  assert.equal(finished.checkpoint.capabilities.transactions.receipts.state, 'unsupported');
  assert.equal(finished.checkpoint.capabilities.transactions.traces.state, 'unsupported');
  assert.equal(finished.checkpoint.capabilities.storage.slots[0].state, 'unsupported');
  assert.equal(finished.checkpoint.records[0].transactions[0].receipt.state, 'unavailable');
  assert.equal(finished.checkpoint.records[0].transactions[0].trace.state, 'unavailable');
  assert.equal(finished.checkpoint.records[0].storage[0].state, 'unsupported');
  assert.equal(finished.checkpoint.records[0].provenance.provenance.capabilities.methods.eth_getLogs.state, 'unsupported');
  assert.equal(rpc.calls.some(({ method }) => method === 'eth_getLogs'), false);
});

test('collection retry reuses the checkpoint evidence directory and archive references', async (t) => {
  const f = await fixture(t);
  const firstRpc = collectionRpc({ failAt: 11 });
  const firstHandlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000, rpcRequest: firstRpc.request,
  });
  let currentCheckpoint = null;
  const firstContext = {
    task: { taskId: 'collection-resume', type: 'v1-resource-collection', attempts: 1 },
    get lastCheckpoint() { return currentCheckpoint; }, signal: new AbortController().signal,
    checkpoint: async (value) => { currentCheckpoint = value; },
  };
  const input = { resource: 'collection', input: { projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1', address: firstRpc.address, fromBlock: '10', toBlock: '11' } };
  const failed = await firstHandlers['v1-resource-collection'](input, firstContext);
  assert.equal(failed.status, 'failed');
  assert.equal(currentCheckpoint.lastBlock, 10);
  const attemptDirectory = currentCheckpoint.attemptDirectory;
  const secondRpc = collectionRpc();
  const secondHandlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000, rpcRequest: secondRpc.request,
  });
  const resumed = await secondHandlers['v1-resource-collection'](input, {
    ...firstContext,
    task: { ...firstContext.task, attempts: 2 },
  });
  assert.equal(resumed.status, 'succeeded', JSON.stringify(resumed));
  assert.equal(resumed.checkpoint.attemptDirectory, attemptDirectory);
  assert.ok(resumed.checkpoint.archiveRefs.every((ref) => ref.path.startsWith(`${attemptDirectory}/`)));
  assert.equal(resumed.checkpoint.archiveRefs.some((ref) => ref.path.includes('attempt-2-')), false);
});

test('collection worker fails closed when a checkpoint block hash changes', async (t) => {
  const f = await fixture(t);
  const first = collectionRpc();
  const handlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000,
    rpcRequest: first.request,
  });
  const task = { taskId: 'collection-reorg', type: 'v1-resource-collection', attempts: 1 };
  let checkpoint = null;
  const context = {
    task,
    lastCheckpoint: null,
    signal: new AbortController().signal,
    checkpoint: async (value) => { checkpoint = value; },
  };
  const input = { resource: 'collection', input: { projectId: 'fixture', rpcUrl: 'http://127.0.0.1:8545', chainId: '1', address: first.address, fromBlock: '10', toBlock: '10' } };
  const initial = await handlers['v1-resource-collection'](input, context);
  assert.equal(initial.status, 'succeeded');
  assert.equal(checkpoint.lastBlock, 10);
  const second = collectionRpc({ reorg: true });
  const resumedContext = { ...context, lastCheckpoint: checkpoint, task: { ...task, attempts: 2 }, checkpoint: async (value) => { checkpoint = value; } };
  const resumedHandlers = createResourceTaskHandlers({
    artifactRoots: [f.dir], evidenceRoot: join(f.dir, 'evidence'), timeoutMs: 60_000,
    rpcRequest: second.request,
  });
  const result = await resumedHandlers['v1-resource-collection'](input, resumedContext);
  assert.equal(result.status, 'blocked');
  assert.match(result.reason, /哈希变化|fail-closed/);
  assert.equal(result.result.state, 'reorg_detected');
});
