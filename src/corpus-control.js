/**
 * 离线语料任务控制面（LaneW）。
 *
 * 该模块只管理本地语料相关的离线泳道：
 *   - static      静态分析（scripts/review-static.py）
 *   - dynamic     动态复现（scripts/benchmark-dynamic-*.cjs）
 *   - decompiler  反编译（scripts/bytecode_analysis.py + heimdall）
 *   - fetch       离线抓取校验（work/corpus-fetch-cache）
 *   - eval        本地评测（scripts/eval_pipeline.py）
 *
 * 红线：链上采集（campaign / defi-campaign / chain-scan / soak）一律拒绝。
 * 泳道只允许调用白名单内的本地脚本，且只读本地语料目录、benchmark 目录与 work 目录。
 */
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, open, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { freemem as osFreemem, cpus as osCpus } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';

export const CORPUS_API_VERSION = 'v1';
export const CORPUS_SCHEMA_VERSION = 1;
export const CORPUS_HEARTBEAT_STALE_MS = 120_000;
export const CORPUS_CHAIN_COLLECTION_CODE = 'chain_collection_disabled';
export const CORPUS_CHAIN_COLLECTION_MESSAGE = '离线阶段不开放链上采集：campaign / defi-campaign / chain-scan 请求一律拒绝，不会启动任何链上扫描。';
export const CORPUS_PAUSE_SEMANTICS = 'sample_boundary';

const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const CHILD_GRACE_MS = 5_000;
const CHILD_KILL_MS = 5_000;
const HEARTBEAT_PERSIST_INTERVAL_MS = 2_000;
// Per-lane sample concurrency. Every sample spawns a compiler plus Slither, both
// of which are memory hungry, so the default stays conservative and the value is
// clamped against the machine instead of trusted from configuration.
const CORPUS_LANE_CONCURRENCY = 2;
const CORPUS_MAX_LANE_CONCURRENCY = 8;
// 动态复现泳道的并发默认值。它的子进程只是在内存态 EVM 上跑一段攻击脚本，
// 单样本约一秒，内存占用远低于编译器加 Slither 的组合，因此可以给更高默认值。
const CORPUS_DYNAMIC_LANE_CONCURRENCY = 4;
// 按 laneId 区分的并发默认值。未列出的泳道回落到 CORPUS_LANE_CONCURRENCY。
const CORPUS_LANE_CONCURRENCY_BY_LANE = Object.freeze({ dynamic: CORPUS_DYNAMIC_LANE_CONCURRENCY });
// Assumed resident cost of one in-flight analyzer child. The lane only scales up
// while reported free memory can absorb another one.
const CORPUS_SAMPLE_MEMORY_BUDGET_BYTES = 2 * 1024 * 1024 * 1024;
const CORPUS_MIN_FREE_MEMORY_BYTES = 2 * 1024 * 1024 * 1024;

/** 泳道注册表。layer 表示该泳道产出的语料层。 */
export const CORPUS_LANES = Object.freeze({
  static: { laneId: 'static', label: '静态分析', layer: 'static', scope: 'corpus', script: 'scripts/review-static.py' },
  dynamic: { laneId: 'dynamic', label: '动态复现', layer: 'dynamic', scope: 'benchmark', script: 'scripts/benchmark-dynamic-*.cjs' },
  decompiler: { laneId: 'decompiler', label: '反编译', layer: 'decompiler', scope: 'corpus', script: 'scripts/bytecode_analysis.py' },
  fetch: { laneId: 'fetch', label: '离线抓取校验', layer: 'fetch', scope: 'corpus', script: 'work/corpus-fetch-cache' },
  eval: { laneId: 'eval', label: '本地评测', layer: 'eval', scope: 'benchmark', script: 'scripts/eval_pipeline.py' },
});

/** 泳道允许调用的本地脚本白名单（相对项目根）。链上采集脚本不在其中。 */
const ALLOWED_SCRIPTS = Object.freeze(new Set([
  'scripts/review-static.py',
  'scripts/bytecode_analysis.py',
  'scripts/eval_pipeline.py',
  'scripts/benchmark-dynamic-runner.cjs',
  'scripts/benchmark-dynamic-storage-write.cjs',
  'scripts/benchmark-dynamic-access-control.cjs',
  'scripts/benchmark-dynamic-bectoken-overflow.cjs',
  'scripts/benchmark-dynamic-predictable-randomness.cjs',
  'scripts/benchmark-dynamic-old-blockhash.cjs',
  'scripts/benchmark-dynamic-reentrancy-extra.cjs',
  'scripts/benchmark-dynamic-case-runner.cjs',
  'scripts/benchmark-dynamic-vault-lending.cjs',
  'scripts/benchmark-dynamic-amm-calls.cjs',
  'scripts/benchmark-dynamic-clean-controls.cjs',
  'scripts/benchmark-dynamic-observation.cjs',
]));

const CHAIN_LANE_PATTERN = /(campaign|chain[-_ ]?scan|defi|collection|soak|mainnet|onchain|on-chain|chain)/i;
const CHAIN_LANE_IDS = Object.freeze(new Set([
  'campaign', 'defi-campaign', 'defi_campaign', 'chain-scan', 'chainscan', 'chain_scan',
  'collection', 'chain-collection', 'onchain', 'soak', 'rpc-pool',
]));

/** 明确的链上采集请求路径：命中即由后端拒绝。 */
const CHAIN_COLLECTION_PATHS = Object.freeze(new Set([
  '/api/v1/corpus/chain-collection',
  '/api/v1/corpus/chain-collection/start',
  '/api/v1/corpus/campaign',
  '/api/v1/corpus/campaign/start',
  '/api/v1/corpus/defi-campaign',
  '/api/v1/corpus/defi-campaign/start',
  '/api/v1/corpus/chain-scan',
  '/api/v1/corpus/chain-scan/start',
  '/api/v1/corpus/rpc-pool',
]));

/**
 * 链上采集守卫是否放开。
 * 离线阶段（代号 LaneW）默认关闭；只有显式设置 CORPUS_CHAIN_COLLECTION=1 才允许创建链上采集任务。
 */
export function chainCollectionAllowed(env = process.env) {
  return ['1', 'true', 'on', 'yes'].includes(String(env.CORPUS_CHAIN_COLLECTION || '').toLowerCase());
}

const STATIC_SHARD_KEYS = new Set([
  'compilerVersion', 'compilerSelection', 'compilerCandidates', 'compilerPinnedVersion',
  'compilerAttempts', 'compilerFallbackUsed', 'findingCount', 'analysisState',
  'analysisOutputSha256', 'analysisEvidence', 'failureKind', 'findingsSha256',
]);
const DECOMPILER_SHARD_KEYS = new Set(['artifact', 'artifactSha256', 'bytecodeReport', 'selectorComparison']);

export class CorpusControlError extends Error {
  constructor(code, message, status = 400, details = undefined) {
    super(String(message));
    this.name = 'CorpusControlError';
    this.code = code;
    this.status = status;
    if (details !== undefined) this.details = details;
  }
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sampleId(identity) {
  const payload = JSON.stringify({
    commit: identity.commit,
    path: identity.path,
    repo: identity.repo,
  });
  return sha256Hex(payload);
}

function layerOwnsKey(layer, key) {
  if (layer === 'static') return key.startsWith('static') || STATIC_SHARD_KEYS.has(key);
  if (layer === 'dynamic') return key.startsWith('dynamic') || key === 'confirmedVulnerability';
  if (layer === 'decompiler') return key.startsWith('decompiler') || DECOMPILER_SHARD_KEYS.has(key);
  return key.startsWith('fetch');
}

function layerPatch(layer, analysis) {
  const patch = {};
  for (const [key, value] of Object.entries(analysis)) if (layerOwnsKey(layer, key)) patch[key] = value;
  return patch;
}

function isoNow(clock) {
  return new Date(clock()).toISOString();
}

async function readJsonFile(path) {
  try {
    return { ok: true, value: JSON.parse(await readFile(path, 'utf8')) };
  } catch (error) {
    if (error?.code === 'ENOENT') return { ok: false, error: 'not_found', message: `文件不存在：${path}` };
    if (error instanceof SyntaxError) return { ok: false, error: 'invalid_json', message: `JSON 解析失败：${path}` };
    return { ok: false, error: 'read_failed', message: `读取失败：${path}` };
  }
}

async function pathExists(path) {
  try { await readFile(path); return true; }
  catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
}

async function fileSha256(path) {
  const bytes = await readFile(path);
  return sha256Hex(bytes);
}

async function atomicWriteJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try { await rename(temporary, path); }
  catch (error) { await rm(temporary, { force: true }); throw error; }
}

function safeRelative(root, candidate) {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..');
}

/** Free memory in bytes, or null when the platform cannot report it. */
function availableMemoryBytes() {
  try {
    // freemem() reports kilobytes on POSIX and bytes on Windows.
    const raw = typeof osFreemem === 'function' ? osFreemem() : null;
    if (!Number.isFinite(raw) || raw <= 0) return null;
    return process.platform === 'win32' ? raw : raw * 1024;
  } catch {
    return null;
  }
}

/** Logical CPU count, or 0 when it cannot be determined. */
function logicalCpuCount() {
  try {
    const list = osCpus();
    return Array.isArray(list) ? list.length : 0;
  } catch {
    return 0;
  }
}

/**
 * Per-lane default concurrency. A lane with no explicit entry uses the shared
 * conservative default, because every other lane spawns a compiler plus Slither.
 */
export function defaultConcurrencyForLane(laneId) {
  return CORPUS_LANE_CONCURRENCY_BY_LANE[laneId] || CORPUS_LANE_CONCURRENCY;
}

/**
 * Decide how many samples may run at once.
 *
 * Parallelism competes for two real limits: logical CPUs and free memory. Each
 * analyzer child runs a compiler plus Slither, so a purely CPU-based bound can
 * push the machine into swap. When memory cannot be measured the lane falls back
 * to serial execution rather than guessing.
 */
export function resolveLaneConcurrency(options = {}) {
  const requested = options.requested;
  const laneDefault = typeof options.laneId === 'string' ? defaultConcurrencyForLane(options.laneId) : null;
  const defaultConcurrency = Number.isSafeInteger(options.defaultConcurrency) && options.defaultConcurrency > 0
    ? options.defaultConcurrency
    : laneDefault ?? CORPUS_LANE_CONCURRENCY;
  const maxConcurrency = Number.isSafeInteger(options.maxConcurrency) && options.maxConcurrency > 0
    ? options.maxConcurrency : CORPUS_MAX_LANE_CONCURRENCY;
  let limit = Number.isSafeInteger(requested) && requested > 0 ? requested : defaultConcurrency;
  limit = Math.min(limit, maxConcurrency);
  const cpuCount = options.cpuCount;
  if (Number.isSafeInteger(cpuCount) && cpuCount > 0) limit = Math.min(limit, cpuCount);
  const freeBytes = options.freeBytes;
  if (Number.isSafeInteger(freeBytes) && freeBytes > 0) {
    const affordable = Math.floor((freeBytes - CORPUS_MIN_FREE_MEMORY_BYTES) / CORPUS_SAMPLE_MEMORY_BUDGET_BYTES);
    limit = Math.min(limit, affordable);
  } else {
    limit = 1;
  }
  return Math.max(1, limit);
}

export class CorpusControlPlane {
  constructor(options = {}) {
    const projectRoot = resolve(options.projectRoot || process.cwd());
    this.projectRoot = projectRoot;
    this.workRoot = resolve(options.workRoot || join(projectRoot, 'work', 'corpus-control'));
    this.statePath = resolve(options.statePath || join(this.workRoot, 'tasks.json'));
    this.manifestPath = resolve(options.manifestPath || join(projectRoot, 'training-data', 'github-vulnerabilities', 'manifest.json'));
    this.v2ManifestPath = resolve(options.v2ManifestPath || join(projectRoot, 'training-data', 'github-vulnerabilities-v2', 'manifest.json'));
    this.groundTruthPath = resolve(options.groundTruthPath || join(projectRoot, 'work', 'ground-truth-fingerprints-P0.json'));
    this.baselinePath = resolve(options.baselinePath || join(projectRoot, 'work', 'baseline-P0.json'));
    this.shardRoot = resolve(options.shardRoot || join(projectRoot, 'work', 'corpus-shards'));
    this.benchmarkRoot = resolve(options.benchmarkRoot || join(projectRoot, 'benchmark', 'contracts'));
    this.compilerCacheRoot = resolve(options.compilerCacheRoot || join(projectRoot, 'work', 'compiler-cache'));
    this.evidenceRoot = resolve(options.evidenceRoot || join(this.workRoot, 'evidence'));
    this.fetchCacheRoot = resolve(options.fetchCacheRoot || join(projectRoot, 'work', 'corpus-fetch-cache'));
    this.pythonBin = options.pythonBin || 'python3';
    this.nodeBin = options.nodeBin || 'node';
    this.clock = options.clock || (() => Date.now());
    this.heartbeatStaleMs = Number.isSafeInteger(options.heartbeatStaleMs) && options.heartbeatStaleMs > 0
      ? options.heartbeatStaleMs : CORPUS_HEARTBEAT_STALE_MS;
    this.tasks = new Map();
    this.loaded = false;
    // Keyed by laneId -> Map(itemId -> child handle). A lane can now hold several
    // concurrent samples instead of exactly one.
    this.activeChildren = new Map();
    // Keyed by laneId -> the first child's pid, used as the lane liveness marker
    // while any child is in flight. Survives per-sample churn so the frontend can
    // still report a concurrent lane as running.
    this.lanePid = new Map();
    // An explicit override still wins; when absent each lane falls back to its own
    // default inside resolveLaneConcurrency, so storing 0 here means "unconfigured".
    this.maxLaneConcurrency = Number.isSafeInteger(options.maxLaneConcurrency) && options.maxLaneConcurrency > 0
      ? Math.min(options.maxLaneConcurrency, CORPUS_MAX_LANE_CONCURRENCY)
      : 0;
    this.lastPersistAt = 0;
    this.persistPending = false;
  }

  /** Resolve how many samples may run in parallel on this machine. */
  #resolveConcurrency(laneId) {
    return resolveLaneConcurrency({
      laneId,
      requested: this.maxLaneConcurrency,
      cpuCount: logicalCpuCount(),
      freeBytes: availableMemoryBytes(),
    });
  }

  // ------------------------------------------------------- 供测试观察内部决策
  // 只读透传，不改变任何运行时行为；并发收敛与机器探测本身难以在用例里
  // 直接复现，这里给出最小观测面以便断言泳道级默认值确实生效。

  resolveConcurrencyForTest(laneId) {
    return this.#resolveConcurrency(laneId);
  }

  cpuCountForTest() {
    return logicalCpuCount();
  }

  memoryForTest() {
    return availableMemoryBytes();
  }

  /** 只读透出任务视图，供断言 pid/running 语义。 */
  taskViewForTest(task) {
    return this.#taskView(task, { nowMs: this.clock() });
  }

  /**
   * 拉起一个长驻子进程并走与 #runChild 相同的登记路径。
   * 只用于验证并发下的 pid 存活标记，不经过任何语料脚本。
   */
  async spawnProbeChildForTest(task, lifetimeMs) {
    const child = spawn(process.execPath, ['-e', `setTimeout(() => {}, ${lifetimeMs})`], {
      cwd: this.projectRoot, env: this.#childEnv({}), detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const handle = { child, pid: child.pid, pgid: child.pid, taskId: task.laneId, itemId: child.pid };
    let laneChildren = this.activeChildren.get(task.laneId);
    if (!laneChildren) { laneChildren = new Map(); this.activeChildren.set(task.laneId, laneChildren); }
    laneChildren.set(handle.pid, handle);
    if (laneChildren.size === 1) this.lanePid.set(task.laneId, child.pid ?? null);
    task.pid = this.lanePid.get(task.laneId) ?? child.pid ?? null;
    child.stdout?.resume();
    child.stderr?.resume();
    // 与 #runChild 保持一致的收尾语义：泳道清空时作废存活标记。
    child.once('close', () => {
      const remaining = this.activeChildren.get(task.laneId);
      if (!remaining) return;
      remaining.delete(handle.pid);
      if (remaining.size === 0) {
        this.activeChildren.delete(task.laneId);
        this.lanePid.delete(task.laneId);
        task.pid = null;
      }
    });
    return handle;
  }

  // ---------------------------------------------------------------- 状态持久化

  /** 公开入口：加载已持久化的任务状态（恢复时校验 PID 存活）。 */
  async load() {
    await this.#load();
    return this;
  }

  async #load() {
    if (this.loaded) return;
    this.loaded = true;
    const read = await readJsonFile(this.statePath);
    if (!read.ok) return;
    const state = read.value;
    if (!state || typeof state !== 'object' || !Array.isArray(state.tasks)) return;
    for (const task of state.tasks) {
      if (!task || typeof task.laneId !== 'string') continue;
      this.tasks.set(task.laneId, {
        ...task,
        itemResults: task.itemResults && typeof task.itemResults === 'object' ? task.itemResults : {},
        history: Array.isArray(task.history) ? task.history : [],
      });
    }
    // 恢复时必须校验 PID 是否存活；进程已退出的任务不能再显示为运行中。
    let recovered = false;
    for (const task of this.tasks.values()) {
      if (['running', 'paused', 'pausing'].includes(task.state) && !this.#pidAlive(task.pid)) {
        this.#record(task, 'interrupted', '恢复时校验发现任务进程已退出，标记为已中断。');
        task.state = 'interrupted';
        task.stale = true;
        task.pid = null;
        task.endedAt = task.endedAt || isoNow(this.clock);
        recovered = true;
      }
    }
    // 恢复结论落盘，避免下次重启再次把已死任务当成运行中。
    if (recovered) await this.#persist({ force: true });
  }

  async #persist({ force = false } = {}) {
    const now = this.clock();
    if (!force && now - this.lastPersistAt < HEARTBEAT_PERSIST_INTERVAL_MS) {
      this.persistPending = true;
      return;
    }
    this.lastPersistAt = now;
    this.persistPending = false;
    const payload = {
      schemaVersion: CORPUS_SCHEMA_VERSION,
      laneId: 'W',
      generatedAt: new Date(now).toISOString(),
      persistenceFile: this.statePath,
      pauseSemantics: CORPUS_PAUSE_SEMANTICS,
      tasks: [...this.tasks.values()],
    };
    await atomicWriteJson(this.statePath, payload);
  }

  #record(task, action, detail = null) {
    task.history = Array.isArray(task.history) ? task.history : [];
    task.history.push({ at: isoNow(this.clock), action, detail });
    if (task.history.length > 200) task.history.splice(0, task.history.length - 200);
  }

  #pidAlive(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try { process.kill(pid, 0); return true; }
    catch (error) { return error?.code === 'EPERM'; }
  }

  // ---------------------------------------------------------------- 语料读取

  async #manifest() {
    const read = await readJsonFile(this.manifestPath);
    if (!read.ok) return { ok: false, error: read.error, message: read.message, value: null };
    return { ok: true, value: read.value };
  }

  async #samples() {
    const manifest = await this.#manifest();
    if (!manifest.ok) return { ok: false, error: manifest.error, message: manifest.message, samples: [] };
    const samples = Array.isArray(manifest.value?.samples) ? manifest.value.samples : [];
    return { ok: true, samples, manifest: manifest.value };
  }

  async #benchmarkCases() {
    let entries = [];
    try { entries = await readdir(this.benchmarkRoot, { withFileTypes: true }); }
    catch (error) { return { ok: false, error: 'read_failed', message: `无法读取 benchmark 目录：${this.benchmarkRoot}`, cases: [] }; }
    const cases = [];
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue;
      const caseDir = join(this.benchmarkRoot, entry.name);
      const truth = await readJsonFile(join(caseDir, 'ground-truth.json'));
      if (!truth.ok) continue;
      cases.push({ caseId: entry.name, caseDir, truth: truth.value });
    }
    return { ok: true, cases };
  }

  async #layerCounts(samples) {
    const layers = {};
    for (const layer of ['static', 'dynamic', 'decompiler']) {
      const counts = {};
      for (const sample of samples) {
        const analysis = sample?.analysis && typeof sample.analysis === 'object' ? sample.analysis : {};
        const value = analysis[layer] ?? 'not_recorded';
        counts[value] = (counts[value] || 0) + 1;
      }
      layers[layer] = counts;
    }
    return layers;
  }

  async #activeShardFiles() {
    const rows = [];
    const walk = async (directory) => {
      let entries = [];
      try { entries = await readdir(directory, { withFileTypes: true }); }
      catch { return; }
      for (const entry of entries) {
        const full = join(directory, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'history') continue;
          await walk(full);
          continue;
        }
        if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
        rows.push(full);
      }
    };
    await walk(this.shardRoot);
    return rows;
  }

  async #latestLaneReport() {
    let entries = [];
    try { entries = await readdir(join(this.projectRoot, 'work'), { withFileTypes: true }); }
    catch { return null; }
    let latest = null;
    for (const entry of entries) {
      if (!entry.isFile() || !/^lane-.*-report\.json$/.test(entry.name)) continue;
      const read = await readJsonFile(join(this.projectRoot, 'work', entry.name));
      if (!read.ok) continue;
      const at = Date.parse(read.value?.generatedAt || '');
      if (!Number.isFinite(at)) continue;
      if (!latest || at > latest.at) latest = { at, iso: new Date(at).toISOString(), path: join(this.projectRoot, 'work', entry.name), laneId: read.value?.laneId ?? null };
    }
    return latest;
  }

  // ---------------------------------------------------------------- 任务视图

  #taskView(task, { nowMs }) {
    const heartbeatAt = task.lastHeartbeatAt || null;
    const heartbeatMs = heartbeatAt ? Date.parse(heartbeatAt) : NaN;
    const ageMs = Number.isFinite(heartbeatMs) ? Math.max(0, nowMs - heartbeatMs) : null;
    // A lane is live when its recorded marker pid still exists, or when this process
    // is holding children for that lane. The second clause keeps a concurrent lane
    // visible even in the brief window where the marker pid has been reaped but a
    // sibling sample is still running.
    const laneHasChildren = (this.activeChildren.get(task.laneId)?.size || 0) > 0;
    const pidAlive = laneHasChildren || this.#pidAlive(task.pid);
    const heartbeatStale = ageMs === null ? true : ageMs > this.heartbeatStaleMs;
    const lane = CORPUS_LANES[task.laneId] || null;
    const baseState = task.state || 'idle';
    const interrupted = baseState === 'interrupted';
    const stale = heartbeatStale && ['running', 'paused', 'pausing'].includes(baseState);
    const reportedState = stale ? 'unknown' : baseState;
    const running = baseState === 'running' && !stale && pidAlive;
    const labels = {
      idle: '空闲', running: '运行中', paused: '已暂停', pausing: '暂停中',
      completed: '已完成', failed: '失败', stopped: '已停止', interrupted: '已中断', unknown: '状态未知',
    };
    return {
      laneId: task.laneId,
      label: lane?.label || task.laneId,
      layer: task.layer || lane?.layer || null,
      state: reportedState,
      lastKnownState: baseState,
      statusLabel: labels[reportedState] || reportedState,
      running,
      paused: reportedState === 'paused',
      stale,
      interrupted,
      heartbeatStale,
      pidAlive,
      pid: Number.isInteger(task.pid) ? task.pid : null,
      createdAt: task.createdAt || null,
      startedAt: task.startedAt || null,
      endedAt: task.endedAt || null,
      lastHeartbeatAt: heartbeatAt,
      lastHeartbeatAgeMs: ageMs,
      heartbeatStaleAfterMs: this.heartbeatStaleMs,
      completedCount: Number.isInteger(task.completedCount) ? task.completedCount : 0,
      totalCount: Number.isInteger(task.totalCount) ? task.totalCount : 0,
      currentStage: task.currentStage || null,
      currentItemId: task.currentItemId || null,
      filters: task.filters || {},
      failure: task.failure || null,
      itemSummary: task.itemSummary || { passed: 0, failed: 0, skipped: 0, total: 0 },
      pauseSemantics: CORPUS_PAUSE_SEMANTICS,
      pendingPause: task.pauseRequested === true,
      history: Array.isArray(task.history) ? task.history.slice(-20) : [],
      interpretation: stale
        ? '心跳已超过新鲜度阈值，实际运行状态未知；不得据此认为任务仍在运行。'
        : '状态来自本地持久化控制文件与进程存活校验。',
    };
  }

  async listTasks() {
    await this.#load();
    const nowMs = this.clock();
    const items = Object.keys(CORPUS_LANES).map((laneId) => {
      const task = this.tasks.get(laneId);
      if (!task) {
        return {
          laneId,
          label: CORPUS_LANES[laneId].label,
          layer: CORPUS_LANES[laneId].layer,
          state: 'idle',
          lastKnownState: 'idle',
          statusLabel: '空闲',
          running: false,
          paused: false,
          stale: false,
          interrupted: false,
          heartbeatStale: false,
          pidAlive: false,
          pid: null,
          createdAt: null,
          startedAt: null,
          endedAt: null,
          lastHeartbeatAt: null,
          lastHeartbeatAgeMs: null,
          heartbeatStaleAfterMs: this.heartbeatStaleMs,
          completedCount: 0,
          totalCount: 0,
          currentStage: null,
          currentItemId: null,
          filters: {},
          failure: null,
          itemSummary: { passed: 0, failed: 0, skipped: 0, total: 0 },
          pauseSemantics: CORPUS_PAUSE_SEMANTICS,
          pendingPause: false,
          history: [],
          interpretation: '尚未创建过该泳道任务。',
        };
      }
      return this.#taskView(task, { nowMs });
    });
    return { items, total: items.length };
  }

  async getTask(laneId) {
    await this.#load();
    const task = this.tasks.get(laneId);
    if (!task) return null;
    return this.#taskView(task, { nowMs: this.clock() });
  }

  // ---------------------------------------------------------------- 概览

  async overview() {
    const nowMs = this.clock();
    const manifestRead = await this.#manifest();
    const samples = manifestRead.ok && Array.isArray(manifestRead.value?.samples) ? manifestRead.value.samples : [];
    const manifestSha256 = manifestRead.ok ? await fileSha256(this.manifestPath).catch(() => null) : null;
    const layers = await this.#layerCounts(samples);
    const v2 = await readJsonFile(this.v2ManifestPath);
    const groundTruth = await readJsonFile(this.groundTruthPath);
    const baseline = await readJsonFile(this.baselinePath);
    const shardFiles = await this.#activeShardFiles();
    const mergedSamples = samples.filter((sample) => sample?.analysisProvenance && typeof sample.analysisProvenance === 'object').length;
    const laneReport = await this.#latestLaneReport();
    const { items: taskViews } = await this.listTasks();

    const heartbeats = taskViews
      .map((task) => task.lastHeartbeatAt)
      .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
    const lastHeartbeatAt = heartbeats.length
      ? heartbeats.sort((a, b) => Date.parse(b) - Date.parse(a))[0]
      : null;
    const lastHeartbeatMs = lastHeartbeatAt ? Date.parse(lastHeartbeatAt) : NaN;
    const heartbeatAgeMs = Number.isFinite(lastHeartbeatMs) ? Math.max(0, nowMs - lastHeartbeatMs) : null;
    const heartbeatStale = heartbeatAgeMs === null ? true : heartbeatAgeMs > this.heartbeatStaleMs;
    const runningLanes = taskViews.filter((task) => task.running).map((task) => task.laneId);

    return {
      corpus: {
        manifest: {
          path: this.manifestPath,
          available: manifestRead.ok,
          error: manifestRead.ok ? null : manifestRead.error,
          message: manifestRead.ok ? null : manifestRead.message,
          sha256: manifestSha256,
          schemaVersion: manifestRead.ok ? manifestRead.value?.schemaVersion ?? null : null,
          generatedAt: manifestRead.ok ? manifestRead.value?.generatedAt ?? null : null,
          analysisGeneratedAt: manifestRead.ok ? manifestRead.value?.analysisGeneratedAt ?? null : null,
          artifactGeneratedAt: manifestRead.ok ? manifestRead.value?.artifactGeneratedAt ?? null : null,
          corpusMergedAt: manifestRead.ok ? manifestRead.value?.corpusMergedAt ?? null : null,
          sampleCount: samples.length,
          collectedCount: manifestRead.ok ? manifestRead.value?.collectedCount ?? null : null,
          layers,
        },
        v2Manifest: {
          path: this.v2ManifestPath,
          available: v2.ok,
          error: v2.ok ? null : v2.error,
          sha256: v2.ok ? await fileSha256(this.v2ManifestPath).catch(() => null) : null,
          schemaVersion: v2.ok ? v2.value?.schemaVersion ?? null : null,
          generatedAt: v2.ok ? v2.value?.generatedAt ?? null : null,
          collectedCount: v2.ok ? v2.value?.collectedCount ?? null : null,
          sampleCount: v2.ok && Array.isArray(v2.value?.samples) ? v2.value.samples.length : null,
        },
        groundTruth: groundTruth.ok ? {
          path: this.groundTruthPath,
          fingerprint: groundTruth.value?.fingerprint ?? null,
          fingerprintAlgorithm: groundTruth.value?.fingerprintAlgorithm ?? null,
          fileCount: groundTruth.value?.fileCount ?? null,
          generatedAt: groundTruth.value?.generatedAt ?? null,
        } : { path: this.groundTruthPath, available: false, error: groundTruth.error },
        baseline: baseline.ok ? {
          path: this.baselinePath,
          laneId: baseline.value?.laneId ?? null,
          state: baseline.value?.state ?? null,
          generatedAt: baseline.value?.generatedAt ?? null,
          corpusCounts: baseline.value?.corpusCounts ?? null,
        } : { path: this.baselinePath, available: false, error: baseline.error },
        shards: {
          root: this.shardRoot,
          activeFileCount: shardFiles.length,
          mergedSampleCount: mergedSamples,
          byLane: shardFiles.reduce((acc, file) => {
            const rel = relative(this.shardRoot, file);
            const lane = rel.split(sep)[0];
            acc[lane] = (acc[lane] || 0) + 1;
            return acc;
          }, {}),
        },
        latestLaneReport: laneReport ? { path: laneReport.path, laneId: laneReport.laneId, generatedAt: laneReport.iso } : null,
      },
      heartbeat: {
        stale: heartbeatStale,
        staleAfterMs: this.heartbeatStaleMs,
        lastHeartbeatAt,
        lastHeartbeatAgeMs: heartbeatAgeMs,
        runningLanes,
        running: runningLanes.length > 0 && !heartbeatStale,
        interpretation: heartbeatStale
          ? '心跳超过新鲜度阈值，没有可确认正在运行的泳道；此处的数字来自已保存记录，不代表实时任务。'
          : '心跳在新鲜度阈值内；仍需结合各泳道的 PID 存活校验。',
      },
      chainCollection: {
        enabled: false,
        rejected: true,
        code: CORPUS_CHAIN_COLLECTION_CODE,
        message: CORPUS_CHAIN_COLLECTION_MESSAGE,
      },
      tasks: taskViews,
      interpretation: '语料统计来自本地 manifest 与分片目录的已保存内容；静态线索不等于已确认漏洞，本控制面不代表链上状态。',
    };
  }

  async filters() {
    const samples = (await this.#samples());
    const categories = new Map();
    const byCategoryLayer = new Map();
    for (const sample of samples.samples) {
      const category = typeof sample?.category === 'string' && sample.category ? sample.category : 'unclassified';
      categories.set(category, (categories.get(category) || 0) + 1);
      const analysis = sample?.analysis && typeof sample.analysis === 'object' ? sample.analysis : {};
      for (const layer of ['static', 'dynamic', 'decompiler']) {
        const state = analysis[layer] ?? 'not_recorded';
        const key = `${category}::${layer}`;
        if (!byCategoryLayer.has(key)) byCategoryLayer.set(key, { category, layer, states: {} });
        const row = byCategoryLayer.get(key);
        row.states[state] = (row.states[state] || 0) + 1;
      }
    }
    const cases = await this.#benchmarkCases();
    const benchmarkIssues = new Map();
    for (const item of cases.cases) {
      const issues = Array.isArray(item.truth?.knownIssues) ? item.truth.knownIssues : [];
      for (const issue of issues) benchmarkIssues.set(issue, (benchmarkIssues.get(issue) || 0) + 1);
    }
    return {
      categories: [...categories.entries()]
        .map(([category, count]) => ({ category, sampleCount: count }))
        .sort((a, b) => b.sampleCount - a.sampleCount || a.category.localeCompare(b.category)),
      layers: [
        { layer: 'static', label: '静态分析', scope: 'corpus' },
        { layer: 'dynamic', label: '动态复现', scope: 'benchmark' },
        { layer: 'decompiler', label: '反编译', scope: 'corpus' },
        { layer: 'fetch', label: '离线抓取校验', scope: 'corpus' },
        { layer: 'eval', label: '本地评测', scope: 'benchmark' },
      ],
      categoryLayerStates: [...byCategoryLayer.values()]
        .map((row) => ({ category: row.category, layer: row.layer, states: row.states }))
        .sort((a, b) => a.category.localeCompare(b.category) || a.layer.localeCompare(b.layer)),
      benchmarkIssueCategories: [...benchmarkIssues.entries()]
        .map(([category, count]) => ({ category, caseCount: count }))
        .sort((a, b) => b.caseCount - a.caseCount || a.category.localeCompare(b.category)),
      interpretation: '类别来自本地 manifest 的样本分类与 benchmark 的 ground-truth 问题标签；过滤只影响离线泳道的待处理项。',
    };
  }

  // ---------------------------------------------------------------- 泳道校验

  #assertOfflineLane(laneId) {
    const value = String(laneId || '').trim();
    if (!value) throw new CorpusControlError('missing_lane_id', '缺少 laneId。', 400);
    if (CHAIN_LANE_IDS.has(value.toLowerCase()) || CHAIN_LANE_PATTERN.test(value)) {
      throw new CorpusControlError(CORPUS_CHAIN_COLLECTION_CODE, CORPUS_CHAIN_COLLECTION_MESSAGE, 400, { laneId: value });
    }
    if (!CORPUS_LANES[value]) throw new CorpusControlError('not_found', `未知泳道：${value}`, 404, { laneId: value });
    return value;
  }

  #assertScriptAllowed(scriptPath) {
    const absolute = resolve(this.projectRoot, scriptPath);
    if (!safeRelative(this.projectRoot, absolute)) {
      throw new CorpusControlError('script_not_allowed', '泳道只能调用项目目录内的本地脚本。', 400, { scriptPath });
    }
    const relativePath = relative(this.projectRoot, absolute).split(sep).join('/');
    if (!ALLOWED_SCRIPTS.has(relativePath)) {
      throw new CorpusControlError('script_not_allowed', `脚本不在离线白名单内：${relativePath}`, 400, { scriptPath: relativePath });
    }
    return absolute;
  }

  #assertOfflineEnv(env) {
    const blocked = ['DYNAMIC_FORK_RPC_URL', 'DYNAMIC_FORK_BLOCK_NUMBER', 'RPC_URL', 'DEFI_CLOUD_AI_API_KEY'];
    for (const key of blocked) if (env[key]) throw new CorpusControlError('chain_collection_disabled', CORPUS_CHAIN_COLLECTION_MESSAGE, 400, { env: key });
  }

  // ---------------------------------------------------------------- 任务创建与控制

  async createTask(input = {}) {
    await this.#load();
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new CorpusControlError('invalid_request', '请求体必须是 JSON 对象。', 400);
    }
    const unknown = Object.keys(input).filter((key) => !['laneId', 'layer', 'category', 'scope'].includes(key));
    if (unknown.length) throw new CorpusControlError('unknown_field', `请求包含未知字段：${unknown.join(', ')}`, 400);

    let laneId = typeof input.laneId === 'string' ? input.laneId.trim() : '';
    if (laneId === 'corpus' || laneId === 'all') {
      const layer = typeof input.layer === 'string' ? input.layer.trim() : '';
      if (!layer) throw new CorpusControlError('missing_layer', 'laneId=corpus 时必须提供 layer。', 400);
      laneId = layer;
    }
    laneId = this.#assertOfflineLane(laneId);
    const lane = CORPUS_LANES[laneId];

    if (input.layer !== undefined) {
      if (typeof input.layer !== 'string' || !input.layer.trim()) throw new CorpusControlError('invalid_field', 'layer 必须是非空字符串。', 400);
      if (input.layer.trim() !== lane.layer) throw new CorpusControlError('invalid_layer', `泳道 ${laneId} 只产出 ${lane.layer} 层。`, 400, { layer: lane.layer });
    }
    if (input.scope !== undefined) {
      if (typeof input.scope !== 'string' || !input.scope.trim()) throw new CorpusControlError('invalid_field', 'scope 必须是非空字符串。', 400);
      if (input.scope.trim() !== lane.scope) throw new CorpusControlError('invalid_scope', `泳道 ${laneId} 的处理范围是 ${lane.scope}。`, 400, { scope: lane.scope });
    }
    let category = null;
    if (input.category !== undefined && input.category !== null) {
      if (typeof input.category !== 'string' || !input.category.trim()) throw new CorpusControlError('invalid_field', 'category 必须是非空字符串。', 400);
      category = input.category.trim();
      const known = await this.#knownCategories();
      if (!known.has(category)) throw new CorpusControlError('unknown_category', `未知漏洞类别：${category}`, 400, { category });
    }

    const existing = this.tasks.get(laneId);
    if (existing && ['running', 'paused', 'pausing'].includes(existing.state)) {
      throw new CorpusControlError('conflict', `泳道 ${laneId} 已在运行或暂停中。`, 409, { laneId });
    }
    const now = isoNow(this.clock);
    const task = {
      laneId,
      layer: lane.layer,
      state: 'idle',
      createdAt: existing?.createdAt || now,
      startedAt: null,
      endedAt: null,
      lastHeartbeatAt: null,
      pid: null,
      completedCount: 0,
      totalCount: 0,
      currentStage: null,
      currentItemId: null,
      filters: { category, layer: lane.layer },
      failure: null,
      itemResults: existing?.itemResults && typeof existing.itemResults === 'object' ? existing.itemResults : {},
      itemSummary: { passed: 0, failed: 0, skipped: 0, total: 0 },
      history: [],
      pauseRequested: false,
      stopRequested: false,
    };
    this.#record(task, 'created', `创建离线泳道任务（类别过滤：${category || '全部'}）。`);
    this.tasks.set(laneId, task);
    await this.#persist({ force: true });
    return this.#taskView(task, { nowMs: this.clock() });
  }

  async #knownCategories() {
    const samples = await this.#samples();
    const categories = new Set();
    for (const sample of samples.samples) if (typeof sample?.category === 'string' && sample.category) categories.add(sample.category);
    const cases = await this.#benchmarkCases();
    for (const item of cases.cases) for (const issue of (Array.isArray(item.truth?.knownIssues) ? item.truth.knownIssues : [])) categories.add(issue);
    return categories;
  }

  async start(laneId, options = {}) {
    await this.#load();
    const id = this.#assertOfflineLane(laneId);
    const existing = this.tasks.get(id);
    if (existing && ['running', 'paused', 'pausing'].includes(existing.state)) {
      throw new CorpusControlError('conflict', `泳道 ${id} 已在运行或暂停中。`, 409, { laneId: id });
    }
    const lane = CORPUS_LANES[id];
    const now = isoNow(this.clock);
    const task = existing || {
      laneId: id,
      layer: lane.layer,
      createdAt: now,
      itemResults: {},
      history: [],
    };
    task.state = 'running';
    task.startedAt = now;
    task.endedAt = null;
    task.lastHeartbeatAt = now;
    task.pid = null;
    task.completedCount = 0;
    task.totalCount = 0;
    task.currentStage = '准备中';
    task.currentItemId = null;
    task.failure = null;
    task.pauseRequested = false;
    task.stopRequested = false;
    task.filters = { category: options.category ?? task.filters?.category ?? null, layer: lane.layer };
    task.itemSummary = { passed: 0, failed: 0, skipped: 0, total: 0 };
    this.#record(task, 'started', `启动离线泳道 ${id}。`);
    this.tasks.set(id, task);
    await this.#persist({ force: true });
    this.#runTask(task, { onlyFailed: false }).catch((error) => {
      task.state = 'failed';
      task.failure = { message: String(error?.message || error).slice(0, 400) };
      this.#record(task, 'failed', task.failure.message);
      this.#persist({ force: true }).catch(() => {});
    });
    return this.#taskView(task, { nowMs: this.clock() });
  }

  async pause(laneId) {
    await this.#load();
    const id = this.#assertOfflineLane(laneId);
    const task = this.tasks.get(id);
    if (!task) throw new CorpusControlError('not_found', `泳道 ${id} 没有正在进行的任务。`, 404, { laneId: id });
    if (task.state !== 'running') throw new CorpusControlError('invalid_state', `泳道 ${id} 当前状态是 ${task.state}，无法暂停。`, 409, { laneId: id, state: task.state });
    task.pauseRequested = true;
    task.state = 'pausing';
    this.#record(task, 'pause_requested', '收到暂停请求；当前样本会跑完，随后在样本边界挂起。');
    await this.#persist({ force: true });
    return this.#taskView(task, { nowMs: this.clock() });
  }

  async resume(laneId) {
    await this.#load();
    const id = this.#assertOfflineLane(laneId);
    const task = this.tasks.get(id);
    if (!task) throw new CorpusControlError('not_found', `泳道 ${id} 没有可继续的任务。`, 404, { laneId: id });
    if (!['paused', 'pausing'].includes(task.state)) throw new CorpusControlError('invalid_state', `泳道 ${id} 当前状态是 ${task.state}，无法继续。`, 409, { laneId: id, state: task.state });
    task.pauseRequested = false;
    task.state = 'running';
    task.lastHeartbeatAt = isoNow(this.clock);
    this.#record(task, 'resumed', '已从样本边界继续执行。');
    await this.#persist({ force: true });
    return this.#taskView(task, { nowMs: this.clock() });
  }

  async stop(laneId) {
    await this.#load();
    const id = this.#assertOfflineLane(laneId);
    const task = this.tasks.get(id);
    if (!task) throw new CorpusControlError('not_found', `泳道 ${id} 没有可停止的任务。`, 404, { laneId: id });
    if (!['running', 'paused', 'pausing'].includes(task.state)) {
      throw new CorpusControlError('invalid_state', `泳道 ${id} 当前状态是 ${task.state}，无需停止。`, 409, { laneId: id, state: task.state });
    }
    task.stopRequested = true;
    task.pauseRequested = false;
    this.#record(task, 'stop_requested', '收到停止请求；将以进程组方式终止子进程。');
    await this.#persist({ force: true });
    const laneChildren = this.activeChildren.get(id);
    if (laneChildren) {
      for (const handle of [...laneChildren.values()]) await this.#terminateChild(handle);
      this.activeChildren.delete(id);
    }
    this.lanePid.delete(id);
    task.state = 'stopped';
    task.endedAt = isoNow(this.clock);
    task.pid = null;
    this.#record(task, 'stopped', '任务已停止。');
    await this.#persist({ force: true });
    return this.#taskView(task, { nowMs: this.clock() });
  }

  async rerunFailed(laneId) {
    await this.#load();
    const id = this.#assertOfflineLane(laneId);
    const existing = this.tasks.get(id);
    if (!existing) throw new CorpusControlError('not_found', `泳道 ${id} 没有可重跑的任务。`, 404, { laneId: id });
    if (['running', 'paused', 'pausing'].includes(existing.state)) {
      throw new CorpusControlError('conflict', `泳道 ${id} 正在运行，无法重跑失败项。`, 409, { laneId: id });
    }
    const failed = Object.entries(existing.itemResults || {}).filter(([, value]) => value?.state === 'failed').map(([key]) => key);
    if (!failed.length) throw new CorpusControlError('no_failed_items', `泳道 ${id} 没有失败项可重跑。`, 409, { laneId: id });
    const now = isoNow(this.clock);
    existing.state = 'running';
    existing.startedAt = now;
    existing.endedAt = null;
    existing.lastHeartbeatAt = now;
    existing.completedCount = 0;
    existing.totalCount = failed.length;
    existing.currentStage = '重跑失败项';
    existing.failure = null;
    existing.pauseRequested = false;
    existing.stopRequested = false;
    existing.itemSummary = { passed: 0, failed: 0, skipped: 0, total: failed.length };
    this.#record(existing, 'rerun_failed_requested', `仅重跑 ${failed.length} 个失败项。`);
    await this.#persist({ force: true });
    this.#runTask(existing, { onlyFailed: true, onlyFailedIds: failed }).catch((error) => {
      existing.state = 'failed';
      existing.failure = { message: String(error?.message || error).slice(0, 400) };
      this.#persist({ force: true }).catch(() => {});
    });
    return this.#taskView(existing, { nowMs: this.clock() });
  }

  // ---------------------------------------------------------------- 泳道执行

  async #items(task) {
    const lane = CORPUS_LANES[task.laneId];
    const category = task.filters?.category || null;
    if (lane.scope === 'corpus') {
      const samples = await this.#samples();
      if (!samples.ok) throw new CorpusControlError('corpus_unavailable', samples.message || '无法读取语料 manifest。', 503, { error: samples.error });
      const rows = samples.samples
        .filter((sample) => !category || sample?.category === category)
        .map((sample) => ({
          itemId: sampleId(sample),
          sample,
          label: `${sample.repo} · ${sample.path}`,
          category: sample.category || 'unclassified',
        }));
      return rows;
    }
    const cases = await this.#benchmarkCases();
    if (!cases.ok) throw new CorpusControlError('benchmark_unavailable', cases.message, 503);
    const rows = cases.cases
      .filter((item) => !category || (Array.isArray(item.truth?.knownIssues) ? item.truth.knownIssues : []).includes(category))
      .map((item) => ({
        itemId: item.caseId,
        case: item,
        label: item.caseId,
        category: (Array.isArray(item.truth?.knownIssues) ? item.truth.knownIssues : []).join(',') || 'clean',
      }));
    return rows;
  }

  async #runTask(task, { onlyFailed, onlyFailedIds = null }) {
    const lane = CORPUS_LANES[task.laneId];
    const allItems = await this.#items(task);
    const items = onlyFailed
      ? allItems.filter((item) => (onlyFailedIds || []).includes(item.itemId))
      : allItems;
    task.totalCount = items.length;
    task.completedCount = 0;
    task.currentStage = onlyFailed ? '重跑失败项' : '执行中';
    task.itemSummary = { passed: 0, failed: 0, skipped: 0, total: items.length };
    await this.#persist({ force: true });

    // A worker pool keeps the sample-boundary contract: pause and stop are only
    // observed before a new sample is dispatched, and in-flight children are
    // never interrupted mid-run by this loop.
    let nextIndex = 0;
    const recordOutcome = async (item, outcome, started) => {
      if (task.stopRequested) return;
      const durationMs = this.clock() - started;
      task.itemResults = task.itemResults && typeof task.itemResults === 'object' ? task.itemResults : {};
      task.itemResults[item.itemId] = { state: outcome.state, reason: outcome.reason ?? null, at: isoNow(this.clock), durationMs };
      if (outcome.state === 'passed') task.itemSummary.passed += 1;
      else if (outcome.state === 'failed') task.itemSummary.failed += 1;
      else task.itemSummary.skipped += 1;
      task.completedCount += 1;
      task.lastHeartbeatAt = isoNow(this.clock);
      this.#record(task, 'item_finished', `${item.itemId} → ${outcome.state}${outcome.reason ? ` (${outcome.reason})` : ''}`);
      await this.#persist({ force: true });
    };

    const worker = async () => {
      for (;;) {
        // 样本边界：只有在这里才检查暂停与停止，绝不打断正在运行的编译器/forge/node 子进程。
        while (task.pauseRequested && !task.stopRequested) {
          task.state = 'paused';
          task.currentStage = '已暂停（样本边界）';
          task.lastHeartbeatAt = isoNow(this.clock);
          this.#record(task, 'paused', '在样本边界挂起。');
          await this.#persist({ force: true });
          await new Promise((resolveWait) => setTimeout(resolveWait, 250));
        }
        if (task.stopRequested) return;
        const index = nextIndex;
        if (index >= items.length) return;
        nextIndex += 1;
        const item = items[index];
        task.state = 'running';
        task.currentItemId = item.itemId;
        task.currentStage = `处理中：${item.label}`;
        task.lastHeartbeatAt = isoNow(this.clock);
        const started = this.clock();
        let outcome = { state: 'failed', reason: 'unknown_error' };
        try {
          outcome = await this.#runItem(task, item);
        } catch (error) {
          outcome = { state: 'failed', reason: `runner_error:${String(error?.message || error).slice(0, 200)}` };
        }
        await recordOutcome(item, outcome, started);
      }
    };

    const width = Math.max(1, Math.min(this.#resolveConcurrency(task.laneId), items.length || 1));
    if (width > 1) this.#record(task, 'concurrency', `样本并发度 ${width}（按 CPU 与可用内存收敛）。`);
    await Promise.all(Array.from({ length: width }, () => worker()));

    if (task.stopRequested) {
      task.state = 'stopped';
      task.endedAt = isoNow(this.clock);
      task.pid = null;
    } else if (task.pauseRequested) {
      task.state = 'paused';
    } else {
      task.state = task.itemSummary.failed > 0 ? 'failed' : 'completed';
      task.endedAt = isoNow(this.clock);
    }
    task.currentStage = task.state === 'completed' ? '已完成' : task.state === 'failed' ? '存在失败项' : task.state;
    task.pid = null;
    this.#record(task, 'finished', `泳道 ${task.laneId} 结束，状态 ${task.state}。`);
    await this.#persist({ force: true });
  }

  async #runItem(task, item) {
    switch (task.laneId) {
      case 'static': return this.#runStaticItem(task, item);
      case 'dynamic': return this.#runDynamicItem(task, item);
      case 'decompiler': return this.#runDecompilerItem(task, item);
      case 'fetch': return this.#runFetchItem(task, item);
      case 'eval': return this.#runEvalItem(task, item);
      default: return { state: 'failed', reason: 'unsupported_lane' };
    }
  }

  #childEnv(extra = {}) {
    const env = {
      ...process.env,
      PYTHONDONTWRITEBYTECODE: '1',
      DYNAMIC_EXECUTION_MODE: 'local',
      CAMPAIGN_PROJECT_ROOT: this.projectRoot,
    };
    delete env.DYNAMIC_FORK_RPC_URL;
    delete env.DYNAMIC_FORK_BLOCK_NUMBER;
    delete env.RPC_URL;
    for (const [key, value] of Object.entries(extra)) {
      if (value === undefined || value === null) delete env[key];
      else env[key] = String(value);
    }
    return env;
  }

  async #runChild(task, { command, args, env, timeoutMs = 600_000, cwd = this.projectRoot, itemId = null }) {
    const child = spawn(command, args, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const handle = { child, pid: child.pid, pgid: child.pid, taskId: task.laneId, itemId };
    let laneChildren = this.activeChildren.get(task.laneId);
    if (!laneChildren) { laneChildren = new Map(); this.activeChildren.set(task.laneId, laneChildren); }
    laneChildren.set(itemId === null ? handle.pid : itemId, handle);
    // task.pid 是泳道的存活标记，不是某个具体样本的句柄。并发时若在
    // laneChildren.size===1 时才写 pid，size>=2 的整个执行期 pid 恒为 null，
    // #taskView 的 pidAlive 随之恒为 false，前端将永远显示不出「运行中」。
    // 这里固定记录本泳道首个子进程的 pid：它稳定、可在恢复时校验存活，
    // 且不会因为后续样本的加入或退出而漂移到某个随机的样本上。
    if (laneChildren.size === 1) this.lanePid.set(task.laneId, child.pid ?? null);
    task.pid = this.lanePid.get(task.laneId) ?? child.pid ?? null;
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; this.#terminateChild(handle); }, timeoutMs);
    const onData = (chunk) => {
      task.lastHeartbeatAt = isoNow(this.clock);
      this.#persist().catch(() => {});
    };
    child.stdout?.on('data', (chunk) => { if (stdout.length < MAX_CAPTURE_BYTES) stdout += chunk.toString('utf8'); onData(chunk); });
    child.stderr?.on('data', (chunk) => { if (stderr.length < MAX_CAPTURE_BYTES) stderr += chunk.toString('utf8'); onData(chunk); });
    const result = await new Promise((resolveResult) => {
      child.once('error', (error) => resolveResult({ code: null, signal: null, error }));
      child.once('close', (code, signal) => resolveResult({ code, signal, error: null }));
    });
    clearTimeout(timer);
    const remaining = this.activeChildren.get(task.laneId);
    if (remaining) {
      remaining.delete(itemId === null ? handle.pid : itemId);
      if (remaining.size === 0) {
        this.activeChildren.delete(task.laneId);
        // 泳道内已无在途子进程：存活标记失效，清空以便恢复时判为已中断。
        this.lanePid.delete(task.laneId);
        task.pid = null;
      }
    }
    return { ...result, stdout, stderr, timedOut };
  }

  async #terminateChild(handle) {
    if (!handle?.child || handle.child.killed || handle.child.exitCode !== null) return;
    const pid = handle.pid;
    // 先优雅终止整个进程组，再强制 kill。
    try { process.kill(-pid, 'SIGTERM'); } catch { try { handle.child.kill('SIGTERM'); } catch {} }
    const grace = await Promise.race([
      new Promise((resolveWait) => handle.child.once('close', () => resolveWait('closed'))),
      new Promise((resolveWait) => setTimeout(() => resolveWait('timeout'), CHILD_GRACE_MS)),
    ]);
    if (grace !== 'closed') {
      try { process.kill(-pid, 'SIGKILL'); } catch { try { handle.child.kill('SIGKILL'); } catch {} }
      await Promise.race([
        new Promise((resolveWait) => handle.child.once('close', () => resolveWait('closed'))),
        new Promise((resolveWait) => setTimeout(() => resolveWait('timeout'), CHILD_KILL_MS)),
      ]);
    }
  }

  // ---------------------------------------------------------- static 泳道

  async #runStaticItem(task, item) {
    const sample = item.sample;
    const analysis = sample?.analysis && typeof sample.analysis === 'object' ? sample.analysis : {};
    const compilerVersion = analysis.compilerVersion;
    if (!compilerVersion) return { state: 'failed', reason: 'compiler_version_unknown' };
    const compiler = await this.#resolveCachedCompiler(compilerVersion);
    if (!compiler) return { state: 'failed', reason: 'compiler_not_cached_offline' };
    const objectPath = resolve(this.projectRoot, sample.objectPath || '');
    if (!safeRelative(this.projectRoot, objectPath)) return { state: 'failed', reason: 'object_path_outside_project' };
    let content = '';
    try { content = await readFile(objectPath, 'utf8'); }
    catch { return { state: 'failed', reason: 'source_object_unreadable' }; }
    if (sha256Hex(content) !== sample.sha256) return { state: 'failed', reason: 'source_hash_mismatch' };
    const target = (content.match(/\b(?:contract|library)\s+([A-Za-z_$][A-Za-z0-9_$]*)/) || [])[1] || null;
    if (!target) return { state: 'failed', reason: 'compilation_target_not_found' };

    const bundleDir = join(this.workRoot, 'tmp', task.laneId, item.itemId);
    await mkdir(bundleDir, { recursive: true });
    const bundlePath = join(bundleDir, 'verified-source.json');
    await writeFile(bundlePath, JSON.stringify({
      schemaVersion: 1,
      sources: { [sample.path]: { content } },
      metadata: { settings: { compilationTarget: { [sample.path]: target } } },
      compilation: { compilerVersion },
    }), 'utf8');

    const script = this.#assertScriptAllowed('scripts/review-static.py');
    let result = { code: null, stdout: '', stderr: '', timedOut: false };
    try {
      result = await this.#runChild(task, {
        command: this.pythonBin,
        args: [script, bundlePath],
        env: this.#childEnv(),
        timeoutMs: 300_000,
        itemId: item.itemId,
      });
    } finally {
      await rm(bundleDir, { recursive: true, force: true }).catch(() => {});
    }
    if (result.timedOut) return { state: 'failed', reason: 'analyzer_timeout' };
    const rows = result.stdout.split('\n').filter((line) => line.trim().startsWith('{'));
    let payload = {};
    if (rows.length) { try { payload = JSON.parse(rows[rows.length - 1]); } catch { payload = {}; } }
    const analyzerState = typeof payload.state === 'string' ? payload.state : 'failed';
    const status = result.code === 0 ? (analyzerState === 'completed' ? 'passed' : analyzerState === 'partial' ? 'partial' : 'failed') : 'failed';
    const reason = payload.reason || payload.error || payload.staticError || (status === 'failed' ? `analyzer_exit_${result.code}` : 'completed');
    const shardPatch = layerPatch('static', {
      static: status,
      staticReason: String(reason).slice(0, 240),
      staticState: analyzerState,
      compilerVersion,
      compilerSelection: analysis.compilerSelection || 'recorded_manifest_value',
      findingCount: Number.isInteger(payload.findingCount) ? payload.findingCount : null,
      analysisState: analyzerState,
    });
    if (Object.keys(shardPatch).length) await this.#writeShard(task, item, 'static', shardPatch, { analyzer: 'review-static.py', compiler: compilerVersion });
    return { state: status === 'failed' ? 'failed' : 'passed', reason: String(reason).slice(0, 240) };
  }

  // ---------------------------------------------------------- dynamic 泳道

  async #runDynamicItem(task, item) {
    const truth = item.case?.truth || {};
    const sourceFile = truth.sourceFile;
    if (typeof sourceFile !== 'string' || !sourceFile) return { state: 'failed', reason: 'ground_truth_source_file_missing' };
    const sourcePath = resolve(item.case.caseDir, sourceFile);
    if (!safeRelative(resolve(item.case.caseDir), sourcePath) || !sourcePath.endsWith('.sol')) {
      return { state: 'failed', reason: 'ground_truth_source_file_unsafe' };
    }
    const compilerVersion = truth.solcVersion;
    if (typeof compilerVersion !== 'string') return { state: 'failed', reason: 'ground_truth_compiler_version_missing' };
    const compiler = await this.#resolveCachedCompiler(compilerVersion);
    if (!compiler) return { state: 'failed', reason: 'compiler_not_cached_offline' };
    const runnerName = dynamicRunnerFor(item.case.caseId);
    if (!runnerName) return { state: 'failed', reason: 'unsupported_dynamic_case' };
    const script = this.#assertScriptAllowed(`scripts/${runnerName}`);

    const result = await this.#runChild(task, {
      command: this.nodeBin,
      args: [script, item.case.caseId, sourcePath],
      env: this.#childEnv({
        CAMPAIGN_SOLJSON: compiler.path,
        BENCHMARK_SOLC_VERSION: compilerVersion,
        BENCHMARK_SOLC_SHA256: compiler.sha256,
      }),
      timeoutMs: 300_000,
      itemId: item.itemId,
    });
    if (result.timedOut) return { state: 'failed', reason: 'poc_timeout' };
    const rows = result.stdout.split('\n').filter((line) => line.trim().startsWith('{'));
    let payload = {};
    if (rows.length) { try { payload = JSON.parse(rows[rows.length - 1]); } catch { payload = {}; } }

    const sourceSha256 = sha256Hex(await readFile(sourcePath));
    const bindingError = dynamicBindingError(payload, item.case.caseId, sourceSha256, compilerVersion, compiler.sha256);
    const evidence = {
      schemaVersion: 1,
      laneId: task.laneId,
      itemId: item.itemId,
      caseId: item.case.caseId,
      generatedAt: isoNow(this.clock),
      exitCode: result.code,
      signal: result.signal,
      sourceSha256,
      compilerVersion,
      compilerSha256: compiler.sha256,
      bindingError,
      result: payload,
      stdoutSha256: sha256Hex(result.stdout),
      stderrSha256: sha256Hex(result.stderr),
    };
    const evidencePath = join(this.evidenceRoot, task.laneId, `${item.itemId}.json`);
    await mkdir(dirname(evidencePath), { recursive: true });
    await atomicWriteJson(evidencePath, evidence);

    if (bindingError) {
      // 绑定失败同样要落盘：它是「跑过但不可信」的结论，不记分片会让整批
      // 出现无法解释的空洞——控制台只显示零落盘，看不出是失败还是漏跑。
      const identity = await this.#manifestSampleForCase(truth, sourceSha256) || benchmarkShardIdentity(item.case, sourceSha256);
      if (identity) {
        const patch = layerPatch('dynamic', {
          dynamic: 'failed',
          dynamicReason: String(bindingError).slice(0, 240),
          dynamicEvidence: relative(this.projectRoot, evidencePath),
          dynamicEvidenceSha256: await fileSha256(evidencePath).catch(() => null),
          confirmedVulnerability: false,
        });
        if (Object.keys(patch).length) {
          await this.#writeShard(task, { ...item, sample: identity }, 'dynamic', patch, { runner: runnerName, solc: compilerVersion });
        }
      }
      return { state: 'failed', reason: bindingError };
    }
    const pocState = typeof payload.pocState === 'string' ? payload.pocState : (typeof payload.state === 'string' ? payload.state : 'failed');
    const confirmed = payload.confirmedVulnerability === true;
    let dynamicState = 'failed';
    if (confirmed) dynamicState = 'passed';
    else if (['unconfirmed', 'control_passed', 'invalid_control'].includes(pocState)) dynamicState = 'unconfirmed';
    const reason = confirmed ? 'benchmark_local_poc_confirmed'
      : ['unconfirmed', 'control_passed', 'invalid_control'].includes(pocState) ? (payload.reason || `poc_state:${pocState}`)
        : (payload.reason || `poc_failed:${pocState}`);

    const sample = await this.#manifestSampleForCase(truth, sourceSha256);
    const shardTarget = sample || benchmarkShardIdentity(item.case, sourceSha256);
    if (shardTarget) {
      const shardPatch = layerPatch('dynamic', {
        dynamic: dynamicState,
        dynamicReason: String(reason).slice(0, 240),
        dynamicEvidence: relative(this.projectRoot, evidencePath),
        dynamicEvidenceSha256: await fileSha256(evidencePath).catch(() => null),
        confirmedVulnerability: confirmed,
      });
      // #writeShard 读的是 item.sample；benchmark 泳道的 item 从不带这个字段，
      // 必须显式传入，否则无论是否命中语料样本都会静默返回 null。
      if (Object.keys(shardPatch).length) {
        await this.#writeShard(task, { ...item, sample: shardTarget }, 'dynamic', shardPatch, { runner: runnerName, solc: compilerVersion });
      }
    }
    return { state: dynamicState === 'failed' ? 'failed' : 'passed', reason: String(reason).slice(0, 240) };
  }

  async #manifestSampleForCase(truth, sourceSha256) {
    const source = typeof truth.source === 'string' ? truth.source : '';
    if (!source.includes('/blob/')) return null;
    const [repo, rest] = source.split('https://github.com/')[1]?.split('/blob/') || [];
    if (!repo || !rest) return null;
    const [commit, path] = rest.split('/', 2);
    const samples = await this.#samples();
    return samples.samples.find((sample) => sample?.repo === repo && sample?.commit === commit && sample?.path === path && sample?.sha256 === sourceSha256) || null;
  }

  // ---------------------------------------------------------- decompiler 泳道

  async #runDecompilerItem(task, item) {
    const sample = item.sample;
    const analysis = sample?.analysis && typeof sample.analysis === 'object' ? sample.analysis : {};
    const artifactRelative = analysis.artifact;
    if (typeof artifactRelative !== 'string' || !artifactRelative) return { state: 'failed', reason: 'artifact_not_materialized' };
    const artifactPath = resolve(this.projectRoot, artifactRelative);
    if (!safeRelative(this.projectRoot, artifactPath)) return { state: 'failed', reason: 'artifact_path_outside_project' };
    const outputDir = join(this.workRoot, 'decompiler', task.laneId, item.itemId);
    await rm(outputDir, { recursive: true, force: true });
    await mkdir(outputDir, { recursive: true });
    const reportPath = join(outputDir, 'bytecode-report.json');
    const heimdallDir = join(outputDir, 'heimdall');
    const script = this.#assertScriptAllowed('scripts/bytecode_analysis.py');
    const result = await this.#runChild(task, {
      command: this.pythonBin,
      args: [script, artifactPath, '--output', reportPath, '--decompiler', 'heimdall', '--decompiler-output-dir', heimdallDir, '--decompiler-timeout', '120'],
      env: this.#childEnv(),
      timeoutMs: 300_000,
      itemId: item.itemId,
    });
    if (result.timedOut) return { state: 'failed', reason: 'decompiler_timeout' };
    const report = await readJsonFile(reportPath);
    if (!report.ok) return { state: 'failed', reason: `bytecode_report_${report.error}` };
    const decompilation = report.value?.decompilation && typeof report.value.decompilation === 'object' ? report.value.decompilation : {};
    const decompilerState = typeof decompilation.state === 'string' ? decompilation.state : 'failed';
    const status = decompilerState === 'completed' ? 'completed' : ['partial', 'timeout'].includes(decompilerState) ? 'partial' : 'failed';
    const shardPatch = layerPatch('decompiler', {
      decompiler: status,
      decompilerReason: String(decompilation.error || decompilerState).slice(0, 240),
      decompilerState,
      artifact: artifactRelative,
      artifactSha256: analysis.artifactSha256 ?? null,
      bytecodeReport: relative(this.projectRoot, reportPath),
    });
    if (Object.keys(shardPatch).length) await this.#writeShard(task, item, 'decompiler', shardPatch, { bytecodeAnalyzer: 'bytecode_analysis.py', decompiler: 'heimdall' });
    return { state: status === 'failed' ? 'failed' : 'passed', reason: String(decompilation.error || decompilerState).slice(0, 240) };
  }

  // ---------------------------------------------------------- fetch 泳道

  async #runFetchItem(task, item) {
    const sample = item.sample;
    const repo = typeof sample.repo === 'string' ? sample.repo : '';
    const commit = typeof sample.commit === 'string' ? sample.commit : '';
    const path = typeof sample.path === 'string' ? sample.path : '';
    if (!repo || !commit || !path) return { state: 'failed', reason: 'sample_identity_incomplete' };
    const cachePath = join(this.fetchCacheRoot, repo.replace(/\//g, '__'), commit, 'blob', path);
    if (!safeRelative(this.fetchCacheRoot, cachePath)) return { state: 'failed', reason: 'cache_path_outside_root' };
    let bytes = null;
    try { bytes = await readFile(cachePath); }
    catch { bytes = null; }
    if (!bytes) {
      const shardPatch = layerPatch('fetch', { fetch: 'missing', fetchReason: 'offline_cache_entry_missing', fetchSource: 'work/corpus-fetch-cache' });
      await this.#writeShard(task, item, 'fetch', shardPatch, { verifier: 'offline-cache' });
      return { state: 'failed', reason: 'offline_cache_entry_missing' };
    }
    const normalized = Buffer.from(bytes.toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/^\uFEFF/, ''), 'utf8');
    const digest = sha256Hex(normalized);
    const matched = digest === sample.sha256;
    const shardPatch = layerPatch('fetch', {
      fetch: matched ? 'cached' : 'mismatch',
      fetchReason: matched ? 'offline_cache_sha256_match' : 'offline_cache_sha256_mismatch',
      fetchSource: 'work/corpus-fetch-cache',
      fetchSha256: digest,
    });
    await this.#writeShard(task, item, 'fetch', shardPatch, { verifier: 'offline-cache' });
    return { state: matched ? 'passed' : 'failed', reason: matched ? 'offline_cache_sha256_match' : 'offline_cache_sha256_mismatch' };
  }

  // ---------------------------------------------------------- eval 泳道

  async #runEvalItem(task, item) {
    const script = this.#assertScriptAllowed('scripts/eval_pipeline.py');
    const caseRoot = join(this.workRoot, 'eval', task.laneId, 'cases');
    const resultsRoot = join(this.workRoot, 'eval', task.laneId, 'results', item.itemId);
    await mkdir(caseRoot, { recursive: true });
    await mkdir(resultsRoot, { recursive: true });
    const linkPath = join(caseRoot, item.case.caseId);
    await rm(linkPath, { recursive: true, force: true }).catch(() => {});
    try { await symlink(item.case.caseDir, linkPath, 'dir'); }
    catch { return { state: 'failed', reason: 'eval_case_link_failed' }; }
    const result = await this.#runChild(task, {
      command: this.pythonBin,
      args: [script, '--contracts', caseRoot, '--results', resultsRoot, '--layers', 'slither', '--timeout', '900'],
      env: this.#childEnv(),
      timeoutMs: 900_000,
      itemId: item.itemId,
    });
    await rm(linkPath, { force: true }).catch(() => {});
    if (result.timedOut) return { state: 'failed', reason: 'eval_timeout' };
    const rows = result.stdout.split('\n').filter((line) => line.trim().startsWith('{'));
    let payload = {};
    if (rows.length) { try { payload = JSON.parse(rows[rows.length - 1]); } catch { payload = {}; } }
    const scored = Number.isInteger(payload.scoredSampleCount) ? payload.scoredSampleCount : 0;
    const sampleCount = Number.isInteger(payload.sampleCount) ? payload.sampleCount : 0;
    const evidencePath = join(this.evidenceRoot, task.laneId, `${item.itemId}.json`);
    await atomicWriteJson(evidencePath, {
      schemaVersion: 1,
      laneId: task.laneId,
      itemId: item.itemId,
      caseId: item.case.caseId,
      generatedAt: isoNow(this.clock),
      exitCode: result.code,
      scoredSampleCount: scored,
      sampleCount,
      precision: payload.precision ?? null,
      recall: payload.recall ?? null,
      result: payload,
      stdoutSha256: sha256Hex(result.stdout),
      stderrSha256: sha256Hex(result.stderr),
    });
    if (result.code !== 0 && scored === 0) return { state: 'failed', reason: 'eval_not_scored' };
    return { state: 'passed', reason: `scored:${scored}/${sampleCount}` };
  }

  // ---------------------------------------------------------- 分片写入

  async #writeShard(task, item, layer, analysis, toolVersions) {
    const sample = item.sample;
    if (!sample) return null;
    const patch = layerPatch(layer, analysis);
    if (!Object.keys(patch).length) return null;
    const identity = { repo: sample.repo, commit: sample.commit, path: sample.path };
    const id = sampleId(identity);
    const laneSegment = `W-${task.laneId}`.replace(/[^A-Za-z0-9_.-]+/g, '_');
    // Synthetic benchmark fixtures have no entry in the corpus manifest.
    // corpus_merge.py resolves every active shard through by_id and raises
    // "分片源码绑定不匹配" for anything it cannot bind, which aborts the whole
    // merge rather than skipping one file. Park those shards under the lane's
    // history/ segment, which active_shard_files() excludes, so an offline batch
    // can never take the corpus merge down with it.
    const shardDir = sample.syntheticFixture
      ? join(this.shardRoot, laneSegment, BENCHMARK_SHARD_HISTORY_SEGMENT)
      : join(this.shardRoot, laneSegment);
    await mkdir(shardDir, { recursive: true });
    const row = {
      schemaVersion: 1,
      sampleId: id,
      identity,
      sourceSha256: sample.sha256,
      layer,
      analysis: patch,
      laneId: `W-${task.laneId}`,
      toolVersions: { ...toolVersions, node: process.version },
      generatedAt: isoNow(this.clock),
    };
    const path = join(shardDir, `${id}.${layer}.json`);
    await atomicWriteJson(path, row);
    return path;
  }

  // ---------------------------------------------------------- 编译器缓存

  async #resolveCachedCompiler(version) {
    const catalog = await readJsonFile(join(this.compilerCacheRoot, 'list.json'));
    if (!catalog.ok) return null;
    const filename = catalog.value?.releases?.[version];
    if (typeof filename !== 'string' || !filename.startsWith('soljson-v')) return null;
    const cachedName = filename.replace(/\.js$/, '.cjs');
    const cachedPath = join(this.compilerCacheRoot, cachedName);
    if (!(await pathExists(cachedPath))) return null;
    const localSha = `0x${await fileSha256(cachedPath)}`;
    const build = (catalog.value?.builds || []).find((row) => row?.path === filename);
    if (build?.sha256 && build.sha256.toLowerCase() !== localSha.toLowerCase()) return null;
    return { path: cachedPath, sha256: build?.sha256 || localSha, version };
  }

  // ---------------------------------------------------------------- 路由

  async handle(request, url, body) {
    const pathname = url.pathname;
    if (!pathname.startsWith('/api/v1/corpus')) return null;
    const method = request.method;
    // 链上采集相关路径一律由后端拒绝，前端置灰只是提示，真正拒绝在后端。
    if (CHAIN_COLLECTION_PATHS.has(pathname) || CHAIN_LANE_PATTERN.test(pathname.slice('/api/v1/corpus'.length))) {
      throw new CorpusControlError(CORPUS_CHAIN_COLLECTION_CODE, CORPUS_CHAIN_COLLECTION_MESSAGE, 400, { path: pathname, method });
    }
    const taskMatch = pathname.match(/^\/api\/v1\/corpus\/tasks\/([^/]+)(?:\/([a-z-]+))?$/);
    if (taskMatch) {
      const laneId = decodeURIComponent(taskMatch[1]);
      const action = taskMatch[2] || null;
      // 泳道名命中链上采集关键字时直接拒绝，不会启动任何链上扫描。
      if (CHAIN_LANE_IDS.has(laneId.toLowerCase()) || CHAIN_LANE_PATTERN.test(laneId)) {
        throw new CorpusControlError(CORPUS_CHAIN_COLLECTION_CODE, CORPUS_CHAIN_COLLECTION_MESSAGE, 400, { laneId, action });
      }
      if (!action) {
        if (method !== 'GET') throw new CorpusControlError('method_not_allowed', '该接口只支持 GET。', 405);
        const task = await this.getTask(laneId);
        if (!task) throw new CorpusControlError('not_found', `未知泳道：${laneId}`, 404, { laneId });
        return { status: 200, body: corpusEnvelope({ data: task }) };
      }
      if (method !== 'POST') throw new CorpusControlError('method_not_allowed', '泳道控制接口只支持 POST。', 405);
      if (action === 'start') return { status: 200, body: corpusEnvelope({ data: await this.start(laneId, { category: body?.category }) }) };
      if (action === 'pause') return { status: 200, body: corpusEnvelope({ data: await this.pause(laneId) }) };
      if (action === 'resume') return { status: 200, body: corpusEnvelope({ data: await this.resume(laneId) }) };
      if (action === 'stop') return { status: 200, body: corpusEnvelope({ data: await this.stop(laneId) }) };
      if (action === 'rerun-failed') return { status: 200, body: corpusEnvelope({ data: await this.rerunFailed(laneId) }) };
      throw new CorpusControlError('not_found', `未知泳道操作：${action}`, 404, { action });
    }
    if (pathname === '/api/v1/corpus/tasks') {
      if (method === 'GET') {
        const result = await this.listTasks();
        return { status: 200, body: corpusEnvelope({ data: result.items, total: result.total }) };
      }
      if (method === 'POST') {
        const created = await this.createTask(body || {});
        return { status: 200, body: corpusEnvelope({ data: created, accepted: true }) };
      }
      throw new CorpusControlError('method_not_allowed', '任务集合只支持 GET 或 POST。', 405);
    }
    if (pathname === '/api/v1/corpus') {
      if (method !== 'GET') throw new CorpusControlError('method_not_allowed', '语料接口索引只支持 GET。', 405);
      return {
        status: 200,
        body: corpusEnvelope({
          data: {
            lanes: Object.values(CORPUS_LANES).map((lane) => ({ laneId: lane.laneId, label: lane.label, layer: lane.layer, scope: lane.scope })),
            routes: [
              'GET /api/v1/corpus/overview',
              'GET /api/v1/corpus/tasks',
              'POST /api/v1/corpus/tasks',
              'POST /api/v1/corpus/tasks/:laneId/start',
              'POST /api/v1/corpus/tasks/:laneId/pause',
              'POST /api/v1/corpus/tasks/:laneId/resume',
              'POST /api/v1/corpus/tasks/:laneId/stop',
              'POST /api/v1/corpus/tasks/:laneId/rerun-failed',
              'GET /api/v1/corpus/filters',
            ],
            pauseSemantics: CORPUS_PAUSE_SEMANTICS,
            chainCollection: { enabled: false, code: CORPUS_CHAIN_COLLECTION_CODE, message: CORPUS_CHAIN_COLLECTION_MESSAGE },
          },
        }),
      };
    }
    if (pathname === '/api/v1/corpus/overview') {
      if (method !== 'GET') throw new CorpusControlError('method_not_allowed', '概览接口只支持 GET。', 405);
      return { status: 200, body: corpusEnvelope({ data: await this.overview() }) };
    }
    if (pathname === '/api/v1/corpus/filters') {
      if (method !== 'GET') throw new CorpusControlError('method_not_allowed', '过滤器接口只支持 GET。', 405);
      return { status: 200, body: corpusEnvelope({ data: await this.filters() }) };
    }
    if (pathname === '/api/v1/corpus/chain-collection') {
      // 任何试图通过控制面启动链上采集的请求都必须被后端拒绝。
      throw new CorpusControlError(CORPUS_CHAIN_COLLECTION_CODE, CORPUS_CHAIN_COLLECTION_MESSAGE, 400, { path: pathname, method });
    }
    throw new CorpusControlError('not_found', '离线语料接口不存在。', 404, { path: pathname });
  }
}

export function corpusEnvelope(data, generatedAt = new Date().toISOString()) {
  return { apiVersion: CORPUS_API_VERSION, schemaVersion: CORPUS_SCHEMA_VERSION, generatedAt, ...data };
}

/**
 * 兼容入口：允许用 `{ root }` 构造控制面（与 web-server 的调用方式一致）。
 */
export class CorpusControl extends CorpusControlPlane {
  constructor(options = {}) {
    super({ ...options, projectRoot: options.projectRoot || options.root || process.cwd() });
    this.pollTimer = null;
  }

  /** 启动后台刷新（不产生链上流量，只刷新本地视图与心跳判定）。 */
  startPolling(intervalMs = 4_000) {
    if (this.pollTimer) return this;
    this.pollTimer = setInterval(() => {
      this.lastViewAt = isoNow(this.clock);
    }, intervalMs);
    if (typeof this.pollTimer.unref === 'function') this.pollTimer.unref();
    return this;
  }

  stopPolling() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
  }
}

/** 路由分发：把内部异常转换成带 error.code 的标准响应体。 */
export async function handleCorpusRoute(request, url, body, control) {
  if (!control || typeof control.handle !== 'function') return null;
  try {
    return await control.handle(request, url, body);
  } catch (error) {
    if (error instanceof CorpusControlError) return corpusErrorBody(error);
    return corpusErrorBody(new CorpusControlError('internal_error', String(error?.message || '离线语料请求失败'), 500));
  }
}

/**
 * 链上采集启动路径（后端拒绝清单）。
 * 语料控制面内部路径由 CHAIN_COLLECTION_PATHS 覆盖；
 * 这里覆盖的是项目其它既有的链上采集入口。
 */
const CHAIN_COLLECTION_START_PATHS = Object.freeze([
  /^\/api\/campaign$/i,
  /^\/api\/defi-campaign$/i,
  /^\/api\/defi_campaign$/i,
  /^\/api\/chain-scan$/i,
  /^\/api\/chain_scan$/i,
  /^\/api\/soak$/i,
  /^\/api\/rpc-pool$/i,
  /^\/api\/v1\/chain-collection\/?$/i,
  /^\/api\/v1\/chain-collection\/.*$/i,
  /^\/api\/v1\/collection$/i,
  /^\/api\/v1\/collections$/i,
]);

/** 会创建链上采集任务的任务类型。 */
export const CHAIN_COLLECTION_TASK_TYPES = Object.freeze(new Set([
  'v1-resource-collection',
  'collection',
  'chain-collection',
  'chain_collection',
  'defi-campaign',
  'campaign',
  'chain-scan',
]));

/**
 * 判断一个请求是否属于“启动链上采集”。
 * 后端守卫点：POST 才会创建链上采集任务；GET 只读，不拦截。
 */
export function isChainCollectionStart(pathname, method = 'GET', body = null) {
  const verb = String(method || 'GET').toUpperCase();
  if (!['POST', 'PUT', 'PATCH'].includes(verb)) return false;
  const target = String(pathname || '');
  if (CHAIN_COLLECTION_START_PATHS.some((pattern) => pattern.test(target))) return true;
  if (target === '/api/v1/tasks') {
    const type = typeof body?.type === 'string' ? body.type.toLowerCase() : '';
    if (type && CHAIN_COLLECTION_TASK_TYPES.has(type)) return true;
    const resource = typeof body?.payload?.resource === 'string' ? body.payload.resource.toLowerCase() : '';
    if (resource === 'collection' || resource === 'collections') return true;
  }
  // 语料控制面里以链上语义命名泳道的启动请求同样必须被拒绝。
  const lane = typeof body?.laneId === 'string' ? body.laneId : null;
  if (lane && CHAIN_LANE_IDS.has(lane.trim().toLowerCase())) return true;
  return false;
}

export function corpusErrorBody(error, requestId = null) {
  const status = Number.isInteger(error?.status) ? error.status : 400;
  return {
    status,
    body: corpusEnvelope({
      error: {
        code: error?.code || 'invalid_request',
        message: String(error?.message || '离线语料请求失败'),
        ...(requestId ? { requestId } : {}),
        ...(error?.details !== undefined ? { details: error.details } : {}),
      },
    }),
  };
}

const DYNAMIC_RUNNER_MAP = Object.freeze({
  '01-arbitrary_location_write_simple': 'benchmark-dynamic-storage-write.cjs',
  '02-incorrect_constructor_name1': 'benchmark-dynamic-access-control.cjs',
  '03-simple_suicide': 'benchmark-dynamic-access-control.cjs',
  '04-unprotected0': 'benchmark-dynamic-access-control.cjs',
  '05-BECToken': 'benchmark-dynamic-bectoken-overflow.cjs',
  '08-guess_the_random_number': 'benchmark-dynamic-predictable-randomness.cjs',
  '09-old_blockhash': 'benchmark-dynamic-old-blockhash.cjs',
  '13-etherstore': 'benchmark-dynamic-reentrancy-extra.cjs',
  '16-simple_dao': 'benchmark-dynamic-reentrancy-extra.cjs',
  '06-integer_overflow_minimal': 'benchmark-dynamic-case-runner.cjs',
  '07-overflow_simple_add': 'benchmark-dynamic-case-runner.cjs',
  '19-mishandled': 'benchmark-dynamic-case-runner.cjs',
  '14-reentrance': 'benchmark-dynamic-runner.cjs',
  '15-reentrancy_simple': 'benchmark-dynamic-runner.cjs',
  '20-reentrancy_cross_function': 'benchmark-dynamic-runner.cjs',
  '21-erc4626-donation': 'benchmark-dynamic-vault-lending.cjs',
  '22-erc4626-rounding': 'benchmark-dynamic-vault-lending.cjs',
  '23-lending-health-factor': 'benchmark-dynamic-vault-lending.cjs',
  '24-lending-bad-debt': 'benchmark-dynamic-vault-lending.cjs',
  '25-amm-k-decrease': 'benchmark-dynamic-amm-calls.cjs',
  '26-amm-fee': 'benchmark-dynamic-amm-calls.cjs',
  '27-oracle-stale': 'benchmark-dynamic-amm-calls.cjs',
  '28-cross-call': 'benchmark-dynamic-amm-calls.cjs',
  '29-delegatecall': 'benchmark-dynamic-amm-calls.cjs',
  '30-reentrancy-withdraw': 'benchmark-dynamic-amm-calls.cjs',
  '31-clean-vault': 'benchmark-dynamic-clean-controls.cjs',
  '32-clean-lending': 'benchmark-dynamic-clean-controls.cjs',
  '33-clean-amm': 'benchmark-dynamic-clean-controls.cjs',
  '10-dos_address': 'benchmark-dynamic-observation.cjs',
  '11-dos_simple': 'benchmark-dynamic-observation.cjs',
  '12-eth_tx_order_dependence_minimal': 'benchmark-dynamic-observation.cjs',
  '17-timed_crowdsale': 'benchmark-dynamic-observation.cjs',
  '18-lotto': 'benchmark-dynamic-observation.cjs',
});

export function dynamicRunnerFor(caseId) {
  return DYNAMIC_RUNNER_MAP[caseId] || null;
}

export function dynamicBindingError(payload, caseId, sourceSha256, compilerVersion, compilerSha256) {
  if (!payload || typeof payload !== 'object' || !Object.keys(payload).length) return 'runner_result_missing';
  if (payload.caseId !== caseId) return 'runner_case_id_mismatch';
  if (payload.sourceSha256 !== sourceSha256) return 'runner_source_hash_mismatch';
  const reportedVersion = payload.compilerVersion;
  if (typeof reportedVersion !== 'string' || reportedVersion.split('+')[0] !== String(compilerVersion).split('+')[0]) {
    return 'runner_compiler_version_mismatch';
  }
  const reportedSha = payload.compilerArtifactSha256 || payload.compilerSha256;
  const normalize = (value) => String(value || '').toLowerCase().replace(/^0x/, '');
  if (typeof reportedSha !== 'string' || normalize(reportedSha) !== normalize(compilerSha256)) return 'runner_compiler_hash_mismatch';
  return null;
}

/**
 * Shard identity for benchmark cases that have no corpus sample to bind to.
 *
 * Phase-two benchmark contracts and the clean controls point at placeholder
 * origins (`github.com/example/defi-benchmarks`, `example.org/...`), so they
 * never appear in the corpus manifest and #manifestSampleForCase returns null.
 * Without an identity their dynamic result would be computed and then dropped on
 * the floor. These identities are namespaced under a dedicated repo so they can
 * never collide with a real corpus sampleId, and the caller routes them to an
 * archive segment the corpus merger skips (see BENCHMARK_SHARD_SEGMENT).
 */
export const BENCHMARK_SHARD_REPO = 'local-benchmark-fixtures';

// corpus_merge.py skips any shard whose relative path contains a `history`
// segment, so this is the archive landing spot for shards with no corpus binding.
export const BENCHMARK_SHARD_HISTORY_SEGMENT = 'history';

export function benchmarkShardIdentity(benchmarkCase, sourceSha256) {
  const caseId = benchmarkCase?.caseId;
  if (typeof caseId !== 'string' || !caseId) return null;
  if (typeof sourceSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sourceSha256)) return null;
  return {
    repo: BENCHMARK_SHARD_REPO,
    // The content hash stands in for an upstream commit: these fixtures have no
    // real revision, and keying on it keeps the id stable per source revision.
    commit: sourceSha256,
    path: `benchmark/contracts/${caseId}/${benchmarkCase?.truth?.sourceFile || 'source.sol'}`,
    sha256: sourceSha256,
    benchmarkCaseId: caseId,
    syntheticFixture: true,
  };
}
