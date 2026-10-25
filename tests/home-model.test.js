import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHomeModel, chainCardState, collectionState, HOME_CANDIDATE_LIMIT } from '../web/lib/home-model.js';

const NOW = Date.parse('2026-10-25T00:00:00Z');
const chains = [
  { chainId: 14, name: 'Flare', llamaName: 'Flare', status: 'ready' },
  { chainId: 100, name: 'Gnosis Chain', llamaName: 'Gnosis', status: 'ready' },
  { chainId: 42220, name: 'Celo EVM', llamaName: 'Celo', status: 'candidate' },
];
const hypothesis = (extra = {}) => ({ id: 'h', kind: 'risk_hypothesis', status: 'unconfirmed_observation', severity: 'medium', ...extra });

test('“未记录”和“0”分开：findings 缺失时 confirmed 是 null，不是 0', () => {
  for (const bad of [undefined, null, 'x', {}, 7]) {
    const model = buildHomeModel({ findings: bad, chains }, NOW);
    assert.equal(model.headline.confirmed, null);
    assert.equal(model.headline.recorded, false);
    assert.equal(model.totalFindings, null);
  }
  const empty = buildHomeModel({ findings: [], chains }, NOW);
  assert.equal(empty.headline.confirmed, 0);
  assert.equal(empty.headline.recorded, true);
});

test('已确认只认 PoC 字段对（反方向：真正的确认不能被漏掉）', () => {
  const real = { id: 'c', status: 'poc_confirmed', confirmedVulnerability: true, severity: 'high' };
  const claimOnly = { id: 'x', status: 'poc_confirmed' };
  const loose = { id: 'y', status: 'invariant_violated', confirmed: true };
  const model = buildHomeModel({ findings: [real, claimOnly, loose, hypothesis()], chains }, NOW);
  assert.equal(model.headline.confirmed, 1);
  assert.equal(model.candidates[0].id, 'c');
  assert.equal(model.tiers.indeterminate, 2, '声称确认但字段不成对的记录必须落到无法判定');
});

test('无法判定与采集记录不进候选列表，但数量必须单独给出', () => {
  const findings = [
    { id: 'a', check: 'naming-convention', impact: 'Informational' },
    { id: 'b', kind: 'runtime_bytecode_analysis', status: 'unconfirmed_observation' },
    hypothesis({ id: 'c' }),
  ];
  const model = buildHomeModel({ findings, chains }, NOW);
  assert.equal(model.candidateTotal, 1);
  assert.equal(model.tiers.indeterminate, 1);
  assert.equal(model.tiers.notApplicable, 1);
  assert.equal(model.tiers.unverified, 1);
  assert.equal(model.totalFindings, 3);
});

test('候选排序：已确认 > 异常待确认 > 待验证，同级按严重度', () => {
  const findings = [
    hypothesis({ id: 'low', severity: 'low' }),
    hypothesis({ id: 'high', severity: 'high' }),
    { id: 'anom', status: 'invariant_violated', severity: 'low' },
    { id: 'conf', status: 'poc_confirmed', confirmedVulnerability: true, severity: 'low' },
  ];
  const ids = buildHomeModel({ findings, chains }, NOW).candidates.map((item) => item.id);
  assert.deepEqual(ids, ['conf', 'anom', 'high', 'low']);
});

test('候选列表有上限，但总数照实给出', () => {
  const findings = Array.from({ length: HOME_CANDIDATE_LIMIT + 5 }, (_, index) => hypothesis({ id: `h${index}` }));
  const model = buildHomeModel({ findings, chains }, NOW);
  assert.equal(model.candidates.length, HOME_CANDIDATE_LIMIT);
  assert.equal(model.candidateTotal, HOME_CANDIDATE_LIMIT + 5);
});

test('链归属：chainId、名称都能命中；没有链信息或名称不唯一的记录进 unattributed', () => {
  const ambiguous = [{ chainId: 1, name: 'Dup', llamaName: 'Dup' }, { chainId: 2, name: 'Dup', llamaName: 'Dup2' }];
  const findings = [
    hypothesis({ id: 'n', chain: '14' }),
    hypothesis({ id: 'name', chain: 'Gnosis Chain' }),
    hypothesis({ id: 'llama', chain: 'celo' }),
    hypothesis({ id: 'none' }),
    hypothesis({ id: 'unknown', chain: 'Nowhere' }),
  ];
  const model = buildHomeModel({ findings, chains }, NOW);
  const by = Object.fromEntries(model.chains.map((chain) => [chain.chainId, chain]));
  assert.equal(by[14].total, 1);
  assert.equal(by[100].total, 1);
  assert.equal(by[42220].total, 1);
  assert.equal(model.unattributed, 2);
  const dup = buildHomeModel({ findings: [hypothesis({ chain: 'Dup' })], chains: ambiguous }, NOW);
  assert.equal(dup.unattributed, 1, '名称对应两条链时不得猜一条');
  assert.equal(dup.chains.every((chain) => chain.total === 0), true);
});

test('各链分项加上 unattributed 等于记录总数，不丢不重', () => {
  const findings = [hypothesis({ chain: '14' }), hypothesis({ chain: 'Celo' }), hypothesis({}), { id: 's', check: 'x' }];
  const model = buildHomeModel({ findings, chains }, NOW);
  const attributed = model.chains.reduce((sum, chain) => sum + chain.total, 0);
  assert.equal(attributed + model.unattributed, model.totalFindings);
});

test('采集不区分链：运行中也只能报 running_unscoped，非运行态一律 idle', () => {
  const running = buildHomeModel({ findings: [], chains, campaign: { observedState: 'running', stale: false } }, NOW);
  assert.ok(running.chains.every((chain) => chain.activity === 'running_unscoped'));
  for (const campaign of [
    { observedState: 'completed' }, { observedState: 'stale', stale: true },
    { observedState: 'running', stale: true }, null, undefined, { observedState: 'weird' }, {},
  ]) {
    const model = buildHomeModel({ findings: [], chains, campaign }, NOW);
    assert.ok(model.chains.every((chain) => chain.activity === 'idle'), JSON.stringify(campaign));
  }
});

test('collectionState：心跳过期不能当运行中，未知取值不猜', () => {
  assert.equal(collectionState({ observedState: 'running', stale: true }).running, false);
  assert.equal(collectionState({ observedState: 'running' }).running, true);
  assert.equal(collectionState({ observedState: 'completed' }).running, false);
  assert.equal(collectionState({ observedState: 'bogus' }).state, 'unknown');
  assert.equal(collectionState({}).state, 'unknown');
  assert.equal(collectionState(null).state, 'none');
  assert.equal(collectionState([]).state, 'none');
});

test('报告新鲜度：超过 24 小时标为历史，时间无效返回 null 而不是 false', () => {
  const old = buildHomeModel({ findings: [], lastReportAt: '2026-10-16T19:38:46.942Z' }, NOW);
  assert.equal(old.report.historical, true);
  const fresh = buildHomeModel({ findings: [], lastReportAt: '2026-10-24T20:00:00Z' }, NOW);
  assert.equal(fresh.report.historical, false);
  for (const bad of [undefined, null, '', 'not-a-date']) {
    assert.equal(buildHomeModel({ findings: [], lastReportAt: bad }, NOW).report.historical, null);
  }
});

test('金额只从「已确认且显式带金额字段」的记录里来；否则是 null，不是 0', () => {
  // 未确认记录上的金额字段不算数：不是已确认，就不是「可提交的赏金」。
  const unconfirmed = buildHomeModel({ findings: [hypothesis({ bountyUsd: 5, valueUsd: 9 })], chains }, NOW);
  assert.equal(unconfirmed.bounty.amountUsd, null, '没有已确认记录带金额时必须是 null');
  assert.equal(unconfirmed.bounty.recorded, false, '没有可数的金额时不得声称记录到了金额');
  assert.equal(unconfirmed.bounty.confirmedWithAmount, 0);

  // 已确认且带金额字段：这才算得了。
  const confirmed = buildHomeModel({
    findings: [{ id: 'c', status: 'poc_confirmed', confirmedVulnerability: true, bountyUsd: 1200 }],
    chains,
  }, NOW);
  assert.equal(confirmed.bounty.amountUsd, 1200);
  assert.equal(confirmed.bounty.recorded, true);
  assert.equal(confirmed.bounty.confirmedWithAmount, 1);
  assert.equal(confirmed.bounty.confirmedWithoutAmount, 0);

  // 已确认但没有金额字段：金额仍然是「未记录」，不能变成 0。
  const noAmount = buildHomeModel({
    findings: [{ id: 'c', status: 'poc_confirmed', confirmedVulnerability: true }],
    chains,
  }, NOW);
  assert.equal(noAmount.bounty.amountUsd, null);
  assert.equal(noAmount.bounty.recorded, false);
  assert.equal(noAmount.bounty.confirmedWithoutAmount, 1);

  // 候选条目本身不携带金额，避免详情里再冒出一个没有依据的数。
  const stripped = JSON.stringify(
    confirmed.candidates.map(({ finding, ...rest }) => rest),
  );
  assert.doesNotMatch(stripped, /1200/, '候选条目里不应带出金额');
});

test('头部两个数字不重叠：已确认 + 待验证中 = 候选总数', () => {
  const findings = [
    { id: 'c1', status: 'poc_confirmed', confirmedVulnerability: true },
    { id: 'c2', status: 'poc_confirmed', confirmedVulnerability: true },
    { id: 'a1', status: 'invariant_violated' },
    hypothesis({ id: 'u1' }),
  ];
  const model = buildHomeModel({ findings, chains }, NOW);
  assert.equal(model.headline.confirmed, 2);
  assert.equal(model.bounty.pendingCount, 2, '待验证中不能再把已确认的算一遍');
  assert.equal(model.bounty.candidateCount, 4);
  assert.equal(model.headline.confirmed + model.bounty.pendingCount, model.bounty.candidateCount);
  assert.equal(model.bounty.candidateCount, model.candidateTotal);
});

test('异常输入不抛错：整个快照缺失或形状错误', () => {
  for (const bad of [undefined, null, 'x', 5, [], { chains: 'x', findings: 'y', campaign: 3 }]) {
    assert.doesNotThrow(() => buildHomeModel(bad, NOW));
  }
  assert.deepEqual(buildHomeModel(undefined, NOW).chains, []);
});

/* ------------------------------------------------------------------
 * chainCardState：总开关与链状态的先后顺序。
 *
 * 这是一组静默错值回归：
 *   - 总开关关闭时，任何链都不得显示「已就绪」（queued）或「全局采集进行中」（live）。
 *     「已就绪，未运行」在总开关关着的时候是假的 —— 用户会以为下一步什么都不用做。
 *   - 总开关打开、本轮没在跑、链在范围内，才是「已就绪」。
 *   - 采集不区分链，所以 running 只能给全局语义，不能说某条链「正在扫」。
 * ------------------------------------------------------------------ */

test('chainCardState：enabled=false 时无论 scope 怎样都不得返回 queued/live', () => {
  const status = { enabled: false, running: false, state: 'completed' };
  for (const scope of [[], ['14'], ['14', '100', '42220'], null, undefined, 'x']) {
    for (const chainId of ['14', '100', '42220', null, undefined]) {
      const state = chainCardState({ chainId, scope, status, enabled: false });
      assert.notEqual(state.tone, 'queued', `scope=${JSON.stringify(scope)} chainId=${chainId} 不得是 queued`);
      assert.notEqual(state.tone, 'live', `scope=${JSON.stringify(scope)} chainId=${chainId} 不得是 live`);
      assert.equal(state.tone, 'paused');
      assert.equal(state.label, '采集未开启');
    }
  }
});

test('chainCardState：enabled=false 时即便采集在跑也不得说「采集进行中」', () => {
  // 后端可能因为残留进程让 running 为真，但总开关关着就不是采集态。
  const state = chainCardState({ chainId: '14', scope: ['14'], status: { enabled: false, running: true, state: 'running' }, enabled: false });
  assert.equal(state.tone, 'paused');
  assert.equal(state.label, '采集未开启');
});

test('chainCardState：enabled=true 且在范围内且本轮没跑，才是「已就绪」', () => {
  const state = chainCardState({ chainId: '14', scope: ['14'], status: { enabled: true, running: false, state: 'completed' }, enabled: true });
  assert.equal(state.tone, 'queued');
  assert.equal(state.label, '已就绪');
  assert.equal(state.inScope, true);

  const outOfScope = chainCardState({ chainId: '100', scope: ['14'], status: { enabled: true, running: false, state: 'completed' }, enabled: true });
  assert.equal(outOfScope.tone, 'paused');
  assert.equal(outOfScope.label, '未纳入下一轮');
  assert.equal(outOfScope.inScope, false);
});

test('chainCardState：enabled=true 且在跑时只说全局采集，不点名某条链', () => {
  const state = chainCardState({ chainId: '14', scope: ['14'], status: { enabled: true, running: true, state: 'running' }, enabled: true });
  assert.equal(state.tone, 'live');
  assert.match(state.label, /全局/);
  assert.doesNotMatch(state.label, /正在扫|扫描中/);
});

test('chainCardState：开关状态未知时不猜，但已知关闭时仍要如实说未开启', () => {
  // enabled 明确为 false 时，即使控制面状态整个读不到，也要说「采集未开启」——
  // 「确定没开」比「不知道开没开」更确定，不能因为别的字段缺失就退化成未知。
  const knownOff = chainCardState({ chainId: '14', scope: ['14'], status: null, enabled: false });
  assert.equal(knownOff.tone, 'paused');
  assert.equal(knownOff.label, '采集未开启');

  // enabled 没给、状态也读不到：只能说状态未知，不能猜「已就绪」。
  const unknown = chainCardState({ chainId: '14', scope: ['14'], status: null });
  assert.equal(unknown.tone, 'idle');
  assert.equal(unknown.label, '状态未知');
  assert.notEqual(unknown.tone, 'queued');
});

test('chainCardState：失败 / 心跳过期 / 中断都是异常态', () => {
  for (const [state, label] of [['failed', /失败/], ['stale', /心跳/], ['interrupted', /中断/], ['invalidated', /中断/]]) {
    const card = chainCardState({ chainId: '14', scope: ['14'], status: { enabled: true, running: false, state }, enabled: true });
    assert.equal(card.tone, 'error', state);
    assert.match(card.label, label);
  }
});
