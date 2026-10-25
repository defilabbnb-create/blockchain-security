import test from 'node:test';
import assert from 'node:assert/strict';
import { render, bind, normalizeControl, masterConfirmCopy } from '../web/views/home.js';

const NOW = Date.parse('2026-10-25T00:00:00Z');
const chains = [{ chainId: 14, name: 'Flare', llamaName: 'Flare', status: 'ready' }];

/* ------------------------------------------------------------------
 * 首屏数字：「未记录」与「0」必须是两件事。
 *
 * 旧设计把赏金金额 $0 放在最大的位置。现在最大的位置是「待处理线索 N 个」，
 * 金额只有真的有数据来源时才出现。
 * ------------------------------------------------------------------ */

test('findings 缺失时大数字显示“未记录”，不是 0', () => {
  const html = render({ chains }, NOW);
  assert.match(html, /data-recorded="false"[^>]*>待处理线索 未记录</);
  assert.match(html, /data-pending-recorded="false"/);
  // 「未记录」不能被写成 0：大数字与已确认标签都不许出现裸的 0 个。
  assert.doesNotMatch(html, /data-recorded="false"[^>]*>\s*0\s*个/);
  assert.doesNotMatch(html, /data-confirmed-recorded="false"[^>]*>已确认 0 个/);
  assert.match(html, /data-confirmed-recorded="false"[^>]*>已确认 未记录</);
});

test('findings 可用但没有已确认条目时显示真实的 0', () => {
  const html = render({ findings: [], chains }, NOW);
  assert.match(html, /data-recorded="true"[^>]*>待处理线索 0 个/);
  assert.match(html, /data-confirmed-recorded="true"[^>]*>已确认 0 个/);
});

test('页面没有可信金额来源时不显示任何金额数字，只有占位', () => {
  const html = render({
    findings: [{ id: 'h', kind: 'risk_hypothesis', status: 'unconfirmed_observation', severity: 'high', bountyUsd: 1000 }],
    chains, campaign: { observedState: 'running' },
  }, NOW);
  // 未确认记录上的金额字段不是「可提交的赏金」，不得被显示成 1000。
  const amounts = html.match(/\$\s?[\d,]+/g) || [];
  assert.deepEqual(amounts, [], `页面没有可信金额来源时不得出现任何金额数字，实际出现：${amounts.join('、')}`);
  assert.match(html, /赏金估值：暂无数据来源（不是 0）/);
  assert.match(html, /data-bounty-recorded="false"/);
  assert.doesNotMatch(html, /\$0/);
});

test('有可信金额来源时才显示金额，且金额来自已确认记录', () => {
  const html = render({
    findings: [{ id: 'c', status: 'poc_confirmed', confirmedVulnerability: true, bountyUsd: 1200 }],
    chains,
  }, NOW);
  assert.match(html, /赏金估值：\$1,200/);
  assert.match(html, /data-bounty-recorded="true"/);
});

test('报告时间显示在首屏；超过 24 小时给出历史快照提示条', () => {
  // 页面时间按 Asia/Shanghai 渲染，断言也用同一口径算，避免写成 UTC 的硬编码。
  const stamp = (iso) => new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  }).format(new Date(iso)).replace(/\//g, '-');

  const fresh = render({ findings: [], chains, lastReportAt: '2026-10-24T20:00:00Z' }, NOW);
  assert.match(fresh, new RegExp(`报告时间 ${stamp('2026-10-24T20:00:00Z')}`));
  assert.doesNotMatch(fresh, /历史快照/);

  const old = render({ findings: [], chains, lastReportAt: '2026-10-16T19:38:46.942Z' }, NOW);
  assert.match(old, new RegExp(`报告时间 ${stamp('2026-10-16T19:38:46.942Z')}`));
  assert.match(old, /这是 \d+ 天前的历史快照，不代表当前状态/);
});

/* ------------------------------------------------------------------
 * 总开关：二次确认 + 请求体约定。
 * ------------------------------------------------------------------ */

test('总开关的行内二次确认文案：开启与关闭不同，且写明只读采集', () => {
  const open = masterConfirmCopy(true);
  assert.match(open.text, /确认开启/);
  assert.match(open.text, /将立即启动一轮只读采集/);
  assert.match(open.text, /不授权、不签名、不广播/);
  assert.equal(open.accept, '确认开启');

  const close = masterConfirmCopy(false);
  assert.match(close.text, /确认关闭/);
  assert.notEqual(close.text, open.text);
  assert.equal(close.accept, '确认关闭');
});

test('页面带二次确认容器与确认/取消按钮', () => {
  const html = render({ findings: [], chains }, NOW, { enabled: false, running: false, state: 'completed' });
  assert.match(html, /data-master-confirm/);
  assert.match(html, /data-confirm-accept/);
  assert.match(html, /data-confirm-cancel/);
  // 确认框默认收起，点开关才展开。
  assert.match(html, /data-master-confirm hidden/);
});

test('总开关在控制面读不到时禁用，并写明为什么', () => {
  const html = render({ findings: [], chains }, NOW, null);
  assert.match(html, /data-master-toggle[^>]*disabled/);
  assert.match(html, /采集控制面状态读取失败/);
});

test('总开关文案区分「已开启」「已关闭」「状态未知」，不假装知道', () => {
  const off = render({ findings: [], chains }, NOW, { enabled: false, running: false, state: 'completed' });
  assert.match(off, /data-master-switch-text>已关闭</);
  assert.match(off, /采集未开启/);

  const on = render({ findings: [], chains }, NOW, { enabled: true, running: false, state: 'completed' });
  assert.match(on, /data-master-switch-text>已开启</);
  assert.match(on, /当前没有任务在跑/);
});

test('后端报 startFailed / stopFailed 时如实显示中文错误', () => {
  const html = render({ findings: [], chains }, NOW, {
    enabled: false, running: false, state: 'failed', startFailed: true, startError: '采集进程启动失败：端口被占用',
  });
  assert.match(html, /开启失败：采集进程启动失败：端口被占用/);
});

/* ------------------------------------------------------------------
 * 链卡片：总开关关闭时必须是「采集未开启」。
 * ------------------------------------------------------------------ */

test('总开关关闭时链卡片一律「采集未开启」，不得出现「已就绪」', () => {
  const html = render({ findings: [], chains }, NOW, {
    enabled: false, running: false, state: 'completed', selectedChainIds: ['14'],
  });
  assert.match(html, /data-chain-state="paused"/);
  assert.match(html, /采集未开启/);
  assert.doesNotMatch(html, /已就绪/);
  assert.doesNotMatch(html, /data-chain-state="queued"/);
  assert.doesNotMatch(html, /data-chain-state="live"/);
});

test('总开关打开且本轮没跑时，在范围内的链才是「已就绪」', () => {
  const html = render({ findings: [], chains }, NOW, {
    enabled: true, running: false, state: 'completed', selectedChainIds: ['14'],
  });
  assert.match(html, /data-chain-state="queued"/);
  assert.match(html, /已就绪/);
});

test('链开关用 role="switch"，每条链一个', () => {
  const html = render({ findings: [], chains }, NOW, {
    enabled: false, running: false, state: 'completed', availableChains: [{ chainId: '14', name: 'Flare' }, { chainId: '100', name: 'Gnosis Chain' }],
  });
  assert.match(html, /role="switch"/);
  assert.match(html, /data-chain-toggle="14"/);
  assert.match(html, /data-chain-toggle="100"/);
  assert.doesNotMatch(html, /<form|<select/, '首页不做表单提交，也不做多选下拉');
});

/* ------------------------------------------------------------------
 * 采集不区分链：不能说某条链「正在扫」。
 * ------------------------------------------------------------------ */

test('运行中的采集不会被说成某条链正在扫描', () => {
  const html = render({ findings: [], chains, campaign: { observedState: 'running' } }, NOW);
  // 「采集不区分链」这句必须出现在渲染出来的说明文字里。
  assert.match(html, /采集不区分链/);
  const stopped = render({ findings: [], chains, campaign: { observedState: 'completed' } }, NOW);
  assert.match(stopped, /未在运行|没有任务在跑/);
  assert.doesNotMatch(stopped, /采集运行中/);
});

test('运行中的采集只说「在跑」，不说某条链正在扫', () => {
  const running = render({ findings: [], chains, campaign: { observedState: 'running', stale: false } }, NOW);
  assert.match(running, /采集正在运行/);
  assert.match(running, /采集不区分链/);
  // 任何链的名字后面都不能跟「正在扫」这类说法。
  assert.doesNotMatch(running, /Flare[^<]*正在扫/);
  assert.doesNotMatch(running, /正在扫描/);

  const stopped = render({ findings: [], chains, campaign: { observedState: 'completed' } }, NOW);
  assert.match(stopped, /当前没有任务在跑/);
  assert.doesNotMatch(stopped, /采集正在运行/);
});

test('控制面说在跑时也不能点名某条链「正在扫」', () => {
  const html = render({ findings: [], chains }, NOW, {
    enabled: true, running: true, state: 'running', selectedChainIds: ['14'],
  });
  assert.doesNotMatch(html, /Flare[^<]*正在扫/);
  assert.doesNotMatch(html, /正在扫描/);
  assert.match(html, /全局采集进行中/);
});

/* ------------------------------------------------------------------
 * 候选线索列表。
 * ------------------------------------------------------------------ */

test('候选行用通俗文案并链接到详情页', () => {
  const html = render({
    findings: [{ id: 'f1', title: '任意转账', kind: 'risk_hypothesis', status: 'unconfirmed_observation' }],
    chains,
  }, NOW);
  assert.match(html, /待进一步验证/);
  assert.match(html, /href="#finding\/f1"/);
  assert.match(html, /class="conf-badge/);
  assert.match(html, /class="sev-meter/);
});

test('没有 id 的候选不渲染死链接，写「暂无详情页」', () => {
  const html = render({
    findings: [{ title: '没有 id 的记录', kind: 'risk_hypothesis', status: 'unconfirmed_observation' }],
    chains,
  }, NOW);
  assert.match(html, /暂无详情页/);
  assert.doesNotMatch(html, /href="#finding\/"/);
  assert.doesNotMatch(html, /<a class="home-candidate-card"/);
});

test('历史报告明确标注，且无法判定的数量作为脚注出现', () => {
  const html = render({
    findings: [{ id: 'a', check: 'x' }, { id: 'b', check: 'y' }],
    chains, lastReportAt: '2026-10-16T19:38:46.942Z',
  }, NOW);
  assert.match(html, /历史快照/);
  assert.match(html, /另有 2 条无法判定/);
});

test('链名、标题、来源里的 HTML 一律转义', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const html = render({
    chains: [{ chainId: 1, name: payload, status: payload }],
    findings: [{ id: 'z"><b>', title: payload, contract: payload, kind: 'risk_hypothesis', status: 'unconfirmed_observation' }],
  }, NOW);
  assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /<b>/);
  assert.match(html, /&lt;img src=x/);
});

test('候选只展示前 N 条并说明总数；归不到链的记录有提示', () => {
  const findings = Array.from({ length: 12 }, (_, index) => ({ id: `h${index}`, kind: 'risk_hypothesis', status: 'unconfirmed_observation' }));
  const html = render({ findings, chains }, NOW);
  assert.match(html, /只显示前 8 条，共 12 条/);
  assert.match(html, /另有 12 条记录归不到具体链/);
});

test('快照整体缺失也能渲染，bind 是空操作', () => {
  for (const bad of [undefined, null, {}, { findings: 'x', chains: 'y' }]) assert.doesNotThrow(() => render(bad, NOW));
  assert.doesNotThrow(() => bind());
});

test('候选为空时脚注仍然出现：无法判定与归不到链的记录不能被吞掉', () => {
  // 这是一条静默丢值的回归：候选区原来在「没有候选」时提前 return，
  // 把已经算出来的「无法判定」「采集记录」「归不到链」几个数量一起丢了。
  // 结果是「没有候选」被说成了「什么记录都没有」。
  const html = render({
    findings: [
      { id: 'a', check: 'naming-convention', impact: 'Informational' },
      { id: 'b', kind: 'runtime_bytecode_analysis', status: 'unconfirmed_observation' },
    ],
    chains,
  }, NOW);
  assert.match(html, /暂无候选/);
  assert.match(html, /另有 1 条无法判定、1 条为采集记录/, '无法判定与采集记录的数量必须出现');
  assert.match(html, /另有 2 条记录归不到具体链/, '归不到链的记录数量必须出现');
});

test('有候选时脚注与归不到链的提示也都在', () => {
  const html = render({
    findings: [
      { id: 'u', kind: 'risk_hypothesis', status: 'unconfirmed_observation' },
      { id: 'i', check: 'naming-convention' },
    ],
    chains,
  }, NOW);
  assert.match(html, /另有 1 条无法判定/);
  assert.match(html, /另有 2 条记录归不到具体链/);
});

test('bind 在没有 DOM 的环境里不抛错（默认参数不能是 document）', () => {
  // 默认参数写 `document` 会在无浏览器环境求值时直接抛 ReferenceError，
  // 根本走不到函数体。
  assert.doesNotThrow(() => bind());
  assert.doesNotThrow(() => bind(undefined, {}));
  assert.doesNotThrow(() => bind(null, {}));
  assert.doesNotThrow(() => bind({}, {}));
});

test('控制面补进来的链没有统计时显示「未记录」，不是「0」', () => {
  // 快照里没有这条链，控制面才有：说明从来没查过它的统计，
  // 写成「暂无记录」等于宣称查过且为 0。
  const html = render({ findings: [], chains: [] }, NOW, {
    enabled: false, running: false, state: 'completed',
    availableChains: [{ chainId: 999, name: '测试链' }],
    selectedChainIds: ['999'],
  });
  assert.match(html, /测试链/);
  assert.match(html, /发现数未记录/);
  assert.doesNotMatch(html, /没有该链的发现记录/);
});

/* ------------------------------------------------------------------
 * 首次使用引导与高级视图入口。
 * ------------------------------------------------------------------ */

test('「3 步上手」默认展开，步骤顺序是开关 → 线索 → 证据', () => {
  const html = render({ findings: [], chains }, NOW);
  assert.match(html, /<details class="home-guide" data-home-guide open>/);
  const steps = html.match(/<li><span class="home-guide-num"[^>]*>(\d)<\/span>/g) || [];
  assert.equal(steps.length, 3);
  assert.match(html, /打开采集开关/);
  assert.match(html, /看候选线索/);
  assert.match(html, /点进去看证据/);
});

test('高级视图入口链接到 #map / #protocols / #execution / #overview', () => {
  const html = render({ findings: [], chains }, NOW);
  assert.match(html, /href="#map"/);
  assert.match(html, /href="#protocols"/);
  assert.match(html, /href="#execution"/);
  assert.match(html, /href="#overview"/);
});

test('localStorage 不可用时引导照样渲染，不抛错', () => {
  // Node 里没有 localStorage 全局；浏览器里可能被策略禁用。
  // 两种情况都只影响「引导是否默认展开」，不能把整页渲染搞崩。
  assert.equal(typeof globalThis.localStorage, 'undefined');
  assert.doesNotThrow(() => render({ findings: [], chains }, NOW));
});

/* ------------------------------------------------------------------
 * normalizeControl：形状认错时的诚实失败。
 * ------------------------------------------------------------------ */

test('normalizeControl：认不出控制面字段时报不可用，不假装读到', () => {
  // 空对象会被读成「已知」，页面就会把一个读不到状态的开关显示成可点的。
  for (const bad of [null, undefined, 'x', 5, [], {}, { status: {} }, { requestId: 'r', generatedAt: 'x' }]) {
    const control = normalizeControl(bad);
    assert.equal(control.known, false, JSON.stringify(bad));
    assert.equal(control.status, null, JSON.stringify(bad));
  }
});

test('normalizeControl：真实形状与包一层的形状都能认', () => {
  const flat = normalizeControl({ enabled: false, running: false, state: 'completed', availableChainIds: ['14'], availableChains: [{ chainId: '14', name: 'Flare' }], selectedChainIds: null });
  assert.equal(flat.known, true);
  assert.equal(flat.status.enabled, false);
  assert.deepEqual(flat.availableChainIds, ['14']);
  assert.deepEqual(flat.selectedChainIds, []);

  const nested = normalizeControl({ status: { enabled: true, running: true, state: 'running' }, availableChains: [{ chainId: '100', name: 'Gnosis Chain' }] });
  assert.equal(nested.known, true);
  assert.equal(nested.status.enabled, true);
  assert.deepEqual(nested.availableChainIds, ['100']);
});
