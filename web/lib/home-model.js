// 首页数据层：把 /api/status 快照与链上采集控制面状态整理成首页要展示的几块。
//
// 诚实性约束（见 .cursor/rules/silent-wrong-value-review.mdc）：
// 1. “未记录”和“0”必须分开：findings 不是数组时 confirmed / pending 都为 null，而不是 0。
// 2. 首页只展示 confirmed / anomaly / unverified 三态；indeterminate 与 not_applicable
//    不进候选列表，但数量必须单独给出，调用方不能悄悄丢掉。
// 3. 金额：只有「已确认记录里显式带金额字段」时才有金额，否则 amountUsd = null（未记录）。
//    页面在未记录时只写「暂无数据来源（不是 0）」，绝不渲染一个假的 $0。
// 4. 每链「活动状态」只来自采集控制面（心跳新鲜 + PID 存活），不猜、不从全局状态推。
// 5. 链归属只认 chainId 或唯一名称；名称对应多条链、或没有链信息的记录，计入 unattributed。
// 6. 链卡片状态必须尊重总开关：总开关关闭时一律「采集未开启」，不能出现「已就绪」。
import { confidenceTier, CONFIDENCE_TIERS } from './confidence.js';
import { severityOf, severityOrder } from './severity.js';

export const HOME_CANDIDATE_TIERS = Object.freeze(['confirmed', 'anomaly', 'unverified']);
export const HOME_CANDIDATE_LIMIT = 8;
export const HISTORICAL_AFTER_MS = 24 * 60 * 60 * 1000;

// 赏金金额字段白名单。只有这些字段真的出现，页面才有金额可言。
// 目前后端没有任何写入点，所以首页金额长期是「未记录」，只能如实说明没有来源。
export const BOUNTY_AMOUNT_FIELDS = Object.freeze([
  'bountyUsd',
  'estimatedBountyUsd',
  'rewardUsd',
  'payoutUsd',
]);

const COLLECTION_LABELS = Object.freeze({
  initializing: '准备中',
  running: '采集运行中',
  waiting_for_new_candidates: '候选已处理完，等待新候选',
  draining: '正在结束已发出的请求',
  completed: '采集窗口已结束',
  queue_exhausted: '队列处理完，已提前停止',
  interrupted: '已中断',
  invalidated: '源码变化，窗口作废',
  failed: '运行失败',
  stale: '心跳过期或进程已退出，不能视为运行中',
});

export function collectionState(campaign) {
  if (campaign === null || typeof campaign !== 'object' || Array.isArray(campaign)) {
    return { state: 'none', running: false, label: '没有采集报告', heartbeatAt: null };
  }
  const heartbeatAt = campaign.heartbeatAt ?? campaign.updatedAt ?? null;
  // 后端已经把“心跳过期 / PID 已死”折算进 observedState；这里不重算，只认它。
  if (campaign.stale === true) return { state: 'stale', running: false, label: COLLECTION_LABELS.stale, heartbeatAt };
  const observed = typeof (campaign.observedState ?? campaign.state) === 'string' ? (campaign.observedState ?? campaign.state) : null;
  if (observed === null) return { state: 'unknown', running: false, label: '采集状态未知', heartbeatAt };
  const label = Object.hasOwn(COLLECTION_LABELS, observed) ? COLLECTION_LABELS[observed] : '采集状态未知';
  return { state: Object.hasOwn(COLLECTION_LABELS, observed) ? observed : 'unknown', running: observed === 'running', label, heartbeatAt };
}

function buildChainLookup(chains) {
  const byId = new Map();
  const byName = new Map();
  for (const chain of chains) {
    if (chain === null || typeof chain !== 'object') continue;
    if (chain.chainId !== undefined && chain.chainId !== null) byId.set(String(chain.chainId), chain);
    for (const label of [chain.name, chain.llamaName]) {
      if (typeof label !== 'string' || !label.trim()) continue;
      const key = label.trim().toLowerCase();
      if (!byName.has(key)) byName.set(key, new Set());
      byName.get(key).add(chain);
    }
  }
  return { byId, byName };
}

function attributeChain(finding, lookup) {
  const raw = finding?.chainId ?? finding?.chain;
  if (raw === undefined || raw === null || raw === '') return null;
  const text = String(raw).trim();
  if (lookup.byId.has(text)) return lookup.byId.get(text);
  const matches = lookup.byName.get(text.toLowerCase());
  return matches && matches.size === 1 ? [...matches][0] : null;
}

function reportAge(lastReportAt, now) {
  const reported = Date.parse(lastReportAt || '');
  if (!Number.isFinite(reported) || !Number.isFinite(now)) return { ageMs: null, historical: null, ageDays: null };
  const ageMs = now - reported;
  return {
    ageMs,
    historical: ageMs > HISTORICAL_AFTER_MS,
    // 历史提示条用整数天，避免出现「0 天前却是历史快照」这种自相矛盾的说法。
    ageDays: Math.max(1, Math.floor(ageMs / (24 * 60 * 60 * 1000))),
  };
}

function candidateSubject(finding) {
  return finding.contract || finding.address || finding.target || finding.protocol || null;
}

/** 读取一条记录里的赏金金额字段。没有明确字段就返回 null，不从别处猜。 */
export function bountyAmountOf(finding) {
  if (finding === null || typeof finding !== 'object' || Array.isArray(finding)) return null;
  for (const field of BOUNTY_AMOUNT_FIELDS) {
    const value = finding[field];
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  }
  return null;
}

/**
 * 链卡片开关的取舍。
 *
 * scope 是“下次运行要扫的链 ID 列表”。开关切换只改这个列表，
 * 不会中断正在运行的采集（后端一轮采集只有一个进程）。
 * 非法 chainId 原样返回，不静默吞掉。
 */
export function scopeAfterToggle(scope, chainId, enabled) {
  const current = Array.isArray(scope) ? scope.map((item) => String(item)) : [];
  if (chainId === undefined || chainId === null || String(chainId).trim() === '') return current;
  const id = String(chainId).trim();
  const has = current.includes(id);
  if (enabled === true) return has ? current : [...current, id];
  if (enabled === false) return current.filter((item) => item !== id);
  return current;
}

/**
 * 合并两份链清单：快照里的链（有 TVL、发现数等元信息）优先，
 * 采集控制面里多出来的链补在后面（没有元信息时如实显示“未记录”）。
 */
export function mergeChainSources(snapshotChains, availableChains) {
  const merged = [];
  const seen = new Set();
  for (const chain of Array.isArray(snapshotChains) ? snapshotChains : []) {
    if (chain === null || typeof chain !== 'object') continue;
    const chainId = chain.chainId === undefined || chain.chainId === null ? null : String(chain.chainId);
    if (chainId === null || seen.has(chainId)) continue;
    seen.add(chainId);
    merged.push({ ...chain, chainId });
  }
  for (const chain of Array.isArray(availableChains) ? availableChains : []) {
    if (chain === null || typeof chain !== 'object') continue;
    const chainId = chain.chainId === undefined || chain.chainId === null ? null : String(chain.chainId);
    if (chainId === null || seen.has(chainId)) continue;
    seen.add(chainId);
    merged.push({ ...chain, chainId, name: chain.name || '未知链' });
  }
  return merged;
}

const CHAIN_STATE_UNKNOWN = Object.freeze({ tone: 'idle', label: '状态未知' });

/**
 * 链卡片上的“现在是什么状态”。
 *
 * 规则：
 *   - 总开关关闭 → 一律“采集未开启”，无论 scope 怎样都不得出现 queued / live；
 *   - 开关状态未知 → “开关状态未知”，不猜；
 *   - 控制面说 running（心跳新鲜 + 进程存活）才算采集在跑；
 *   - 采集不区分链，运行中也只说“全局采集进行中”，不说某条链“正在扫”；
 *   - 失败 / 心跳过期 / 中断 → 异常；
 *   - 总开关打开、本轮没在跑且链在范围内 → 已就绪；
 *   - 总开关打开但链不在范围内 → 未纳入下一轮。
 */
export function chainCardState({ chainId, scope, status, enabled } = {}) {
  const id = chainId === undefined || chainId === null ? null : String(chainId);
  const effectiveScope = Array.isArray(scope) ? scope.map((item) => String(item)) : [];
  const inScope = id !== null && effectiveScope.includes(id);
  const hasStatus = Boolean(status) && typeof status === 'object' && !Array.isArray(status);
  // enabled 入参优先；调用方没给时才从控制面状态里读。
  const switchEnabled = enabled === undefined ? (hasStatus ? status.enabled : undefined) : enabled;
  // 总开关关着时，无论 scope 怎样都不得出现 queued / live。
  // 这一条必须排在最前面：即使控制面状态整个读不到，只要明确知道开关是关的，
  // 就得说「采集未开启」，不能因为别的字段缺失而退回「状态未知」——
  // 那等于把「确定没开」说成了「不知道开没开」。
  if (switchEnabled === false) return { tone: 'paused', label: '采集未开启', inScope };
  if (!hasStatus) return { ...CHAIN_STATE_UNKNOWN, inScope };
  if (switchEnabled !== true) return { tone: 'idle', label: '开关状态未知', inScope };

  if (status.running === true) return { tone: 'live', label: '全局采集进行中', inScope };
  if (status.state === 'failed') return { tone: 'error', label: '异常：采集失败', inScope };
  if (status.state === 'stale') return { tone: 'error', label: '异常：心跳已过期', inScope };
  if (status.state === 'interrupted' || status.state === 'invalidated') return { tone: 'error', label: '异常：本轮被中断', inScope };
  if (inScope) return { tone: 'queued', label: '已就绪', inScope };
  return { tone: 'paused', label: '未纳入下一轮', inScope };
}

export function buildHomeModel(snapshot, now = Date.now()) {
  const data = snapshot !== null && typeof snapshot === 'object' ? snapshot : {};
  const findings = Array.isArray(data.findings) ? data.findings : null;
  const chains = Array.isArray(data.chains) ? data.chains : [];
  const lookup = buildChainLookup(chains);
  const collection = collectionState(data.campaign);

  const tierCounts = Object.fromEntries(Object.keys(CONFIDENCE_TIERS).map((tier) => [tier, 0]));
  const perChain = new Map(chains.map((chain) => [chain, { candidates: 0, total: 0 }]));
  const candidates = [];
  let unattributed = 0;
  let bountySum = 0;
  let confirmedWithAmount = 0;
  let confirmedWithoutAmount = 0;

  (findings || []).forEach((finding, index) => {
    const verdict = confidenceTier(finding);
    tierCounts[verdict.tier] += 1;
    const chain = attributeChain(finding, lookup);
    if (chain === null) unattributed += 1;
    else {
      const bucket = perChain.get(chain);
      bucket.total += 1;
      if (HOME_CANDIDATE_TIERS.includes(verdict.tier)) bucket.candidates += 1;
    }
    if (HOME_CANDIDATE_TIERS.includes(verdict.tier)) {
      candidates.push({
        index,
        id: typeof finding.id === 'string' ? finding.id : null,
        title: finding.title || finding.check || '未命名记录',
        subject: candidateSubject(finding),
        chainName: chain ? chain.name : null,
        tier: verdict.tier,
        severity: severityOf(finding),
        finding,
      });
    }
    if (verdict.tier === 'confirmed') {
      const amount = bountyAmountOf(finding);
      if (amount === null) confirmedWithoutAmount += 1;
      else {
        confirmedWithAmount += 1;
        bountySum += amount;
      }
    }
  });

  candidates.sort((a, b) => (CONFIDENCE_TIERS[a.tier].rank - CONFIDENCE_TIERS[b.tier].rank)
    || ((severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9))
    || (a.index - b.index));

  // 「待处理线索」= 还没到已确认的记录（异常待确认 + 待验证）。
  // 不能把已确认也算进来：首页同时显示「待处理线索 N 个」和「已确认 M 个」，
  // 两个数字一旦重叠，同一条记录会被算两次。
  const pendingCount = tierCounts.anomaly + tierCounts.unverified;
  const candidateCount = tierCounts.confirmed + pendingCount;
  return {
    generatedAt: data.generatedAt ?? null,
    lastReportAt: data.lastReportAt ?? null,
    report: reportAge(data.lastReportAt, now),
    collection,
    headline: {
      // null 表示“findings 不可用”，和“可用但没有已确认条目”（0）是两回事。
      confirmed: findings === null ? null : tierCounts.confirmed,
      pending: findings === null ? null : pendingCount,
      candidateTotal: findings === null ? null : candidateCount,
      recorded: findings !== null,
    },
    // 金额：只有真的读到带金额字段的已确认记录才算数，否则是“未记录”。
    bounty: {
      amountUsd: confirmedWithAmount > 0 ? bountySum : null,
      recorded: confirmedWithAmount > 0,
      confirmedCount: findings === null ? null : tierCounts.confirmed,
      confirmedWithAmount,
      confirmedWithoutAmount,
      pendingCount: findings === null ? null : pendingCount,
      // 候选总数 = 已确认 + 待处理（与首页两个数字不重叠，合计等于候选列表长度）。
      candidateCount: findings === null ? null : candidateCount,
      anomalyCount: findings === null ? null : tierCounts.anomaly,
      unverifiedCount: findings === null ? null : tierCounts.unverified,
    },
    tiers: {
      confirmed: tierCounts.confirmed,
      anomaly: tierCounts.anomaly,
      unverified: tierCounts.unverified,
      // 首页不展示为卡片，但必须作为脚注给出，不能静默并入别的等级。
      indeterminate: tierCounts.indeterminate,
      notApplicable: tierCounts.not_applicable,
    },
    totalFindings: findings === null ? null : findings.length,
    unattributed,
    chains: chains.filter((chain) => chain !== null && typeof chain === 'object').map((chain) => ({
      chainId: chain.chainId ?? null,
      name: chain.name || '未知链',
      queueStatus: typeof chain.status === 'string' ? chain.status : null,
      tvlLabel: typeof chain.currentTvlLabel === 'string' ? chain.currentTvlLabel : null,
      activity: collection.running ? 'running_unscoped' : 'idle',
      candidates: perChain.get(chain).candidates,
      total: perChain.get(chain).total,
    })),
    candidates: candidates.slice(0, HOME_CANDIDATE_LIMIT),
    candidateTotal: candidates.length,
  };
}
