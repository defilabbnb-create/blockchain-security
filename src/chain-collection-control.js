// 链上采集控制面：前端「一键开启」的后端。
//
// 为什么单独一个模块，而不是复用 src/corpus-control.js：
//   - corpus-control 管的是离线语料五条泳道（static/dynamic/decompiler/fetch/eval），
//     它的链上采集拦截是无条件的（CHAIN_COLLECTION_PATHS），语义是「离线阶段不做链上采集」，
//     不适合拿来当「按链启动采集」的入口。
//   - 真正的采集进程是 scripts/defi-campaign.py，它自己用 flock 保证单实例。
//   - chainCollectionAllowed() 之前是死代码：定义在 corpus-control.js 里，但没有任何地方调用它。
//     这里第一次真正接上它——环境变量 CORPUS_CHAIN_COLLECTION=1 现在是「首次使用时开关的默认值」，
//     前端开关的实际状态持久化在 work/chain-collection-control.json。
//
// 诚实性约束（见 .cursor/rules/silent-wrong-value-review.mdc）：
//   1. 只有心跳新鲜且 PID 存活才能报 running。进程已退出但报告仍写着 running 时必须报 stale，
//      不能报「运行中」。
//   2. 「开关已打开」与「现在正在采集」是两件事，分开报，不能混成一个字段。
//   3. 启动失败（spawn 失败、链 ID 不存在、过滤后没有链）必须报错，不能返回看起来成功的状态。
//   4. 过滤后一条链都没匹配到，必须直接失败，不允许跑一个空队列的采集。
//   5. 停止只发信号，不声称已经停完；是否真的停下由下一次 status 判定。
//   6. 开关打开但采集进程没起来时，如实报「启动失败」，不报「运行中」。

import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { normalizeCampaign } from './campaign-status.js';
import { chainCollectionAllowed } from './corpus-control.js';

export class ChainCollectionError extends Error {
  constructor(code, message, status = 400, details = undefined) {
    super(String(message));
    this.name = 'ChainCollectionError';
    this.code = code;
    this.status = status;
    if (details !== undefined) this.details = details;
  }
}

const ACTIVE_STATES = new Set(['initializing', 'running', 'waiting_for_new_candidates', 'draining']);

const STATE_LABELS = Object.freeze({
  disabled: '已关闭',
  starting: '正在启动，采集报告尚未生成',
  running: '采集中',
  waiting_for_new_candidates: '候选已处理完，等待新候选',
  draining: '正在结束已发出的请求',
  completed: '采集窗口已结束',
  queue_exhausted: '队列处理完，已提前停止',
  interrupted: '已中断',
  invalidated: '源码发生变化，本窗口作废',
  failed: '运行失败',
  stale: '心跳过期或进程已退出，不能视为仍在运行',
  idle: '未在运行',
  unknown: '采集状态未知',
});

const DEFAULT_DURATION_SEC = 3600;
const MIN_DURATION_SEC = 30;
const MAX_DURATION_SEC = 86400;
const START_GRACE_MS = 180_000;

/**
 * 按筛选条件过滤链。filters 为空表示不筛选。
 * 匹配 chainId、name、llamaName（均为大小写不敏感的字符串比较）。
 * 匹配不到的条目不会出现在结果里，也不会被静默忽略——调用方要自己核对数量。
 */
export function selectChains(chains, filters) {
  const list = Array.isArray(chains) ? chains : [];
  const wanted = new Set(
    (Array.isArray(filters) ? filters : [])
      .map((item) => String(item ?? '').trim().toLowerCase())
      .filter((item) => item.length > 0),
  );
  if (wanted.size === 0) return list.slice();
  return list.filter((chain) => {
    if (chain === null || typeof chain !== 'object') return false;
    const keys = [chain.chainId, chain.name, chain.llamaName]
      .filter((item) => item !== undefined && item !== null)
      .map((item) => String(item).trim().toLowerCase());
    return keys.some((key) => wanted.has(key));
  });
}

/** 哪些筛选条件一条链都没匹配到。用于启动前如实失败。 */
export function unmatchedChainFilters(chains, filters) {
  const list = Array.isArray(chains) ? chains : [];
  const wanted = (Array.isArray(filters) ? filters : [])
    .map((item) => String(item ?? '').trim())
    .filter((item) => item.length > 0);
  return wanted.filter((filter) => selectChains(list, [filter]).length === 0);
}

function defaultPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === 'EPERM'; }
}

async function readJsonFile(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new ChainCollectionError('state_read_failed', `读取 ${path} 失败：${error?.message || error}`, 500);
  }
}

async function atomicWriteJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(temporary, path);
}

export class ChainCollectionControl {
  constructor({
    projectRoot = process.cwd(),
    env = process.env,
    spawnProcess = spawn,
    clock = () => Date.now(),
    pidAlive = defaultPidAlive,
    python = 'python3',
    enabledDefault = undefined,
    guardFollowsSwitch = true,
    autoStart = true,
    statePath = undefined,
  } = {}) {
    this.projectRoot = projectRoot;
    this.env = env;
    this.spawnProcess = spawnProcess;
    this.clock = clock;
    this.pidAlive = pidAlive;
    this.python = python;
    // enabledDefault 为 undefined 时，用 CORPUS_CHAIN_COLLECTION 环境变量决定开关初始值。
    // 显式传入 true/false 时以传入值为准（命令行服务与库调用方各自决定）。
    this.defaultedFromEnv = enabledDefault === undefined;
    this.enabledDefault = this.defaultedFromEnv
      ? chainCollectionAllowed(env)
      : enabledDefault === true;
    // guardFollowsSwitch=false：链上采集守卫一律放行。
    // 这是库调用方的既有历史行为（PROGRESS-PHASE2 记载「库调用方式下 chainCollectionEnabled
    // 缺省视为放行」），不能因为加了前端开关就把它改掉。
    this.guardFollowsSwitch = guardFollowsSwitch !== false;
    // autoStart=false：切换开关不会拉起采集进程。
    // 库调用方（测试内嵌 startServer）用它避免意外启动真实采集。
    this.autoStart = autoStart !== false;
    this.statePath = statePath ?? join(projectRoot, 'work', 'chain-collection-control.json');
    this.campaignPath = join(projectRoot, 'work', 'defi-campaign.json');
    this.campaignLockPath = join(projectRoot, 'work', 'defi-campaign.lock');
    this.chainsPath = join(projectRoot, 'flare-scan', 'chains.json');
  }

  async #readState() {
    const raw = await readJsonFile(this.statePath);
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      // 还没有持久化状态：默认值决定开关的初始状态。
      // 这是 chainCollectionAllowed() 第一次真正生效——此前它没有任何调用方。
      return {
        version: 1,
        switchOn: this.enabledDefault,
        switchDefaulted: true,
        defaultSource: this.defaultedFromEnv ? 'env' : 'explicit',
        selected: null,
        run: null,
      };
    }
    const switchDefaulted = raw.switchDefaulted === true;
    return {
      version: 1,
      // 用户从未在页面上手动操作过时，开关跟随当前默认值（环境变量）。
      // 否则文件里的旧值会一直盖住环境变量的变化：改了环境变量重启服务也不生效。
      // 用户手动操作过之后（switchDefaulted=false），以用户的选择为准。
      switchOn: switchDefaulted ? this.enabledDefault : raw.switchOn === true,
      switchDefaulted,
      defaultSource: switchDefaulted ? (this.defaultedFromEnv ? 'env' : 'explicit') : (raw.defaultSource === 'env' ? 'env' : 'explicit'),
      selected: raw.selected ?? null,
      run: raw.run ?? null,
    };
  }

  async #writeState(state) {
    await atomicWriteJson(this.statePath, state);
  }

  /** 可采集的链（来自 flare-scan/chains.json，与采集脚本用的是同一份）。 */
  async availableChains() {
    const raw = await readJsonFile(this.chainsPath);
    const chains = Array.isArray(raw?.chains) ? raw.chains : [];
    return chains
      .filter((chain) => chain && typeof chain === 'object' && chain.chainId !== undefined && chain.chainId !== null)
      .map((chain) => ({
        chainId: String(chain.chainId),
        name: chain.name || '未知链',
        llamaName: chain.llamaName || null,
      }));
  }

  /**
   * 当前状态。
   * `enabled` = 开关是否打开（允许链上采集）
   * `running` = 现在是否真的在采集（心跳新鲜 + 进程存活）
   * 两者分开，不合并成一个字段。
   */
  async status() {
    const now = this.clock();
    const state = await this.#readState();
    const raw = await readJsonFile(this.campaignPath);
    const campaign = normalizeCampaign(raw, now, (pid) => this.pidAlive(pid));
    const available = await this.availableChains();

    const selectedChainIds = Array.isArray(state.selected?.chainIds) ? state.selected.chainIds.map(String) : null;
    const run = state.run && Number.isInteger(state.run.pid) ? state.run : null;
    const runAlive = run ? this.pidAlive(run.pid) : false;

    let running = false;
    let current = 'idle';
    let message = '';
    let heartbeatAt = null;
    let pid = null;
    let runId = null;
    let startedAt = null;
    let lastError = null;

    if (campaign) {
      heartbeatAt = campaign.heartbeatAt ?? null;
      pid = Number.isInteger(campaign.pid) ? campaign.pid : null;
      runId = campaign.runId ?? null;
      startedAt = campaign.startedAt ?? null;
      if (campaign.stale) {
        current = 'stale';
        message = STATE_LABELS.stale;
      } else if (ACTIVE_STATES.has(campaign.observedState)) {
        current = campaign.observedState;
        running = true;
        message = STATE_LABELS[current] || current;
      } else {
        current = campaign.observedState;
        message = STATE_LABELS[current] || current;
      }
    }

    // 进程刚起来、采集报告还没写出来的那一小段窗口：如实报「正在启动」，不报「运行中」。
    const startedMs = Date.parse(run?.startedAt || '');
    if (!running && run && runAlive && Number.isFinite(startedMs) && now - startedMs < START_GRACE_MS && current !== 'stale') {
      current = 'starting';
      running = true;
      pid = run.pid;
      startedAt = run.startedAt;
      message = STATE_LABELS.starting;
    }

    // 开关打开但进程已经不在了：如实报出来，不报「运行中」。
    if (state.switchOn && !running && run && !runAlive && current !== 'stale') {
      lastError = '采集进程已退出，开关仍是打开状态；再次开启会重新启动采集。';
    }

    return {
      enabled: state.switchOn === true,
      switchDefaulted: state.switchDefaulted === true,
      defaultSource: state.defaultSource || 'explicit',
      running,
      state: current,
      stateLabel: STATE_LABELS[current] || current,
      message,
      lastError,
      pid,
      runId,
      startedAt,
      heartbeatAt,
      heartbeatAgeMs: heartbeatAt ? Math.max(0, now - Date.parse(heartbeatAt)) : null,
      lastReportAt: campaign?.updatedAt ?? null,
      selectedChainIds,
      runningChainIds: run ? (Array.isArray(run.chainIds) ? run.chainIds.map(String) : null) : null,
      availableChainIds: available.map((chain) => chain.chainId),
      availableChains: available,
      durationSec: run?.durationSec ?? null,
      updatedAt: new Date(now).toISOString(),
      interpretation: 'running 为真需要心跳新鲜且进程存活；「开关已打开」与「现在正在采集」是两件事，分别显示。',
    };
  }

  /**
   * 守卫判断：链上采集请求当前是否应该被放行。
   * guardFollowsSwitch=false（库调用方）时一律放行，保持既有历史行为。
   */
  async guardAllows() {
    if (!this.guardFollowsSwitch) return true;
    return this.isEnabled();
  }

  /** 开关当前是否打开。用于请求路径上的守卫判断（每次现读，不缓存）。 */
  async isEnabled() {
    const state = await this.#readState();
    return state.switchOn === true;
  }

  /** 选择要覆盖的链。选择只影响下一次启动，不影响已在运行的采集。 */
  async select(chainIds) {
    if (chainIds === undefined || chainIds === null || !Array.isArray(chainIds)) {
      throw new ChainCollectionError('invalid_field', 'chainIds 必须是数组。', 400);
    }
    const available = await this.availableChains();
    const known = new Set(available.map((chain) => chain.chainId));
    const requested = chainIds.map((item) => String(item));
    const unknown = requested.filter((item) => !known.has(item));
    if (unknown.length) {
      throw new ChainCollectionError('unknown_chain', `未知链 ID：${unknown.join('、')}`, 400, { unknown });
    }
    const state = await this.#readState();
    state.selected = { chainIds: requested, updatedAt: new Date(this.clock()).toISOString() };
    await this.#writeState(state);
    return this.status();
  }

  /**
   * 打开/关闭开关。
   * 打开时如果当前没有采集在跑，会顺带启动一次采集——这样前端只需要一次点击。
   * 关闭时如果采集在跑，会请求停止。
   */
  async setEnabled(enabled) {
    if (typeof enabled !== 'boolean') {
      throw new ChainCollectionError('invalid_field', 'enabled 必须是布尔值。', 400);
    }
    const state = await this.#readState();
    state.switchOn = enabled;
    // 用户在页面上明确操作过之后，就不再由默认值决定开关。
    state.switchDefaulted = false;
    state.defaultSource = 'explicit';
    await this.#writeState(state);

    if (enabled) {
      const current = await this.status();
      if (!current.running && this.autoStart) {
        try {
          return await this.start();
        } catch (error) {
          // 开关已经是打开状态，但采集没起来。这个状态必须如实暴露，不能假装成功。
          const status = await this.status();
          return {
            ...status,
            enabled: true,
            startFailed: true,
            startError: String(error?.message || error),
            startErrorCode: error?.code || null,
          };
        }
      }
      return this.status();
    }

    const current = await this.status();
    if (current.running) {
      try {
        return await this.stop();
      } catch (error) {
        const status = await this.status();
        return {
          ...status,
          enabled: false,
          stopFailed: true,
          stopError: String(error?.message || error),
          stopErrorCode: error?.code || null,
        };
      }
    }
    return this.status();
  }

  /**
   * 启动采集。chainIds 省略时用已保存的选择；两者都没有则覆盖全部可用链。
   */
  async start({ chainIds = undefined, durationSec = DEFAULT_DURATION_SEC } = {}) {
    const state = await this.#readState();
    if (!state.switchOn) {
      throw new ChainCollectionError('chain_collection_disabled', '链上采集开关未打开，启动请求已被后端拒绝。', 400);
    }
    const duration = Number(durationSec);
    if (!Number.isInteger(duration) || duration < MIN_DURATION_SEC || duration > MAX_DURATION_SEC) {
      throw new ChainCollectionError('invalid_field', `durationSec 必须是 ${MIN_DURATION_SEC}–${MAX_DURATION_SEC} 的整数。`, 400);
    }
    const current = await this.status();
    if (current.running) {
      throw new ChainCollectionError('collection_already_running', '已经有采集在运行，请先停止再启动。', 409, { state: current.state });
    }

    // 采集脚本自己用 flock 保证单实例。这里先读锁文件里的 PID，
    // 避免拉起一个注定因为拿不到锁而立刻退出的进程，然后对外报「正在启动」。
    const lock = await readJsonFile(this.campaignLockPath);
    if (lock && Number.isInteger(lock.pid) && this.pidAlive(lock.pid)) {
      throw new ChainCollectionError('collection_already_running', `已有采集进程在运行（PID ${lock.pid}），请先停止再启动。`, 409, { pid: lock.pid });
    }

    const available = await this.availableChains();
    if (available.length === 0) {
      throw new ChainCollectionError('no_chains_available', '读取不到可用链列表，拒绝启动一个空采集。', 400);
    }
    const requested = chainIds === undefined
      ? (Array.isArray(state.selected?.chainIds) ? state.selected.chainIds : [])
      : (Array.isArray(chainIds) ? chainIds.map(String) : null);
    if (requested === null) {
      throw new ChainCollectionError('invalid_field', 'chainIds 必须是数组。', 400);
    }
    const known = new Set(available.map((chain) => chain.chainId));
    const unknown = requested.filter((item) => !known.has(item));
    if (unknown.length) {
      throw new ChainCollectionError('unknown_chain', `未知链 ID：${unknown.join('、')}`, 400, { unknown });
    }
    const effective = requested.length > 0 ? requested : available.map((chain) => chain.chainId);
    const unmatched = unmatchedChainFilters(available, effective);
    if (unmatched.length) {
      // 过滤后一条链都没匹配到：直接失败，不跑空队列。
      throw new ChainCollectionError('chain_filter_matched_nothing', `以下链 ID 没有匹配到任何链：${unmatched.join('、')}`, 400, { unmatched });
    }
    const selected = selectChains(available, effective);
    if (selected.length === 0) {
      throw new ChainCollectionError('chain_filter_matched_nothing', '过滤后没有任何链，拒绝启动一个空采集。', 400);
    }

    const args = [join('scripts', 'defi-campaign.py'), '--duration', String(duration)];
    for (const chain of selected) args.push('--chain', chain.chainId);

    let child;
    try {
      child = this.spawnProcess(this.python, args, {
        cwd: this.projectRoot,
        env: { ...this.env },
        detached: true,
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch (error) {
      throw new ChainCollectionError('spawn_failed', `启动采集进程失败：${error?.message || error}`, 500);
    }
    if (!child || !Number.isInteger(child.pid)) {
      throw new ChainCollectionError('spawn_failed', '启动采集进程失败：没有拿到进程号。', 500);
    }
    child.on?.('error', () => { /* 进程启动后自行失败由下一次 status 判定 */ });

    const now = this.clock();
    state.run = {
      pid: child.pid,
      startedAt: new Date(now).toISOString(),
      chainIds: selected.map((chain) => chain.chainId),
      durationSec: duration,
    };
    await this.#writeState(state);
    return this.status();
  }

  /**
   * 请求停止。发信号给进程组，让脚本自己收尾并写出终态。
   * 返回的是「已发出停止请求」，不代表已经停下。
   */
  async stop() {
    const state = await this.#readState();
    // 只用本控制面自己记录的 PID。采集报告里的 pid 来自上一轮运行，
    // 那台进程早已退出；PID 可能被系统回收给无关进程，拿它发信号会误杀。
    const pid = Number.isInteger(state.run?.pid) ? state.run.pid : null;
    if (!Number.isInteger(pid) || pid <= 0) {
      throw new ChainCollectionError('not_running', '当前没有可以停止的采集进程。', 409);
    }
    if (!this.pidAlive(pid)) {
      state.run = null;
      await this.#writeState(state);
      throw new ChainCollectionError('not_running', '采集进程已经退出，不需要停止。', 409);
    }
    let signaled = false;
    try {
      process.kill(-pid, 'SIGTERM');
      signaled = true;
    } catch { /* 进程组不存在时退回单进程 */ }
    if (!signaled) {
      try {
        process.kill(pid, 'SIGTERM');
        signaled = true;
      } catch (error) {
        throw new ChainCollectionError('stop_failed', `发送停止信号失败：${error?.message || error}`, 500);
      }
    }
    return { ...(await this.status()), stopRequested: true, stopRequestedAt: new Date(this.clock()).toISOString() };
  }
}

export { STATE_LABELS };
