// severity-resolver 的回归测试。
//
// 这个模块决定每条未确认观察项的对外严重度，写错方向就是「过度评级」或「静默漏报」，
// 因此这里逐条钉住不可协商的口径：配置坏掉必须 fail-closed、下调必须留归因、
// 降级路径必须给出和正常路径一样的字段形状。
//
// 注意：这些断言钉的是评级口径本身。本地测试全绿只说明回归没坏，
// 既不代表任何一条观察项被确认成漏洞，也不代表被测合约存在可利用缺陷。
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSeverityResolver, resetSeverityCaches, SEVERITY_LABELS } from '../src/severity-resolver.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const ORDER = ['info', 'low', 'medium', 'high', 'critical'];

// 写一个可用的最小模型根目录。severityOrder 与 severityVocabulary 可通过 overrides 故意写坏，
// 用来验证配置校验是 fail-closed 的，而不是等到 resolve() 里才炸。
// 注意用 null 而不是 undefined 表示「删掉这个键」：解构默认值会把 undefined
// 悄悄还原成正常值，那样就测不到「配置缺失」这条路径了。
const VOCABULARY = {
  aliases: { informational: 'info' },
  unstatedMarker: 'unstated',
};

async function makeRoot(t, { severityOrder = ORDER, vocabulary = VOCABULARY, vulnerabilities, modelOverrides = {} } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'severity-resolver-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'scripts'), { recursive: true });
  await mkdir(join(root, 'data'), { recursive: true });
  const model = {
    schemaVersion: 1,
    severityRank: RANK,
    ...(severityOrder === null ? {} : { severityOrder }),
    recordOnlyKinds: ['dependency_trace'],
    // severityVocabulary 与 severityOrder 同级校验：缺了它就没人能判定
    // 字典里的 severity 是不是合法档位，配置校验必须 fail-closed 而不是退回默认别名。
    ...(vocabulary === null ? {} : { severityVocabulary: vocabulary }),
    categoryTitlePatterns: { reentrancy: ['reentrancy'] },
    entrySelectors: [{ entryId: 'lib-critical', titlePatterns: ['reentrancy'], quotePatterns: [], reason: '唯一条目' }],
    triggerDifficulty: {
      base: 1.0, minimum: 0.2, maximum: 1.0,
      signals: [
        { id: 'reentrancy_guard_observed', kind: 'mitigation', multiplier: 0.4, patterns: ['nonReentrant'], reason: '存在重入锁' },
        { id: 'precondition_recorded', kind: 'mitigation', multiplier: 0.97, source: 'conditions', patterns: [], reason: '作者记录了前置条件' },
      ],
    },
    adjustment: {
      criticalCapWithMitigation: true, categoryBaselineCapSeverity: 'medium',
      strongMitigationAt: 0.5, unratedSeverity: 'low', downgradeMitigationBelow: 0.95,
    },
    ...modelOverrides,
  };
  await writeFile(join(root, 'scripts', 'severity-model.json'), JSON.stringify(model));
  await writeFile(join(root, 'data', 'vulnerability-library.json'), JSON.stringify({
    schemaVersion: 1,
    generatedAt: '2026-10-22T00:00:00+00:00',
    vulnerabilities: vulnerabilities ?? [{ id: 'lib-critical', benchmarkCategory: 'reentrancy', severity: 'critical', status: 'active', category: 'vulnerability' }],
  }));
  return root;
}

// 每个用例前清缓存：resolver 内部按模块级变量缓存模型与字典，
// 不清会让上一个临时目录的配置串到下一个用例。
function fresh() {
  resetSeverityCaches();
}

test('仓库自带的 severity-model.json 自身通过配置校验', async () => {
  fresh();
  const resolver = await createSeverityResolver(PROJECT_ROOT);
  assert.equal(resolver.ready, true, '仓库内模型必须可用，否则所有条目都会静默退回 info');
  assert.deepEqual(resolver.severityLabels, SEVERITY_LABELS);
});

test('缺 severityOrder 时 fail-closed：ready=false 且 resolve 不抛异常', async (t) => {
  const root = await makeRoot(t, { severityOrder: null });
  fresh();
  const resolver = await createSeverityResolver(root);
  // 这条是本用例的核心：以前 resolver 会照常 ready，等真正需要下调时才在
  // stepDown() 里抛 TypeError，把「评级不可用」升级成「整条流水线崩溃」。
  assert.equal(resolver.ready, false);
  const out = resolver.resolve({ kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null, evidence: [{ quote: 'nonReentrant' }] });
  assert.equal(out.severity, 'info');
  assert.equal(out.severityBasis, 'unrated');
  assert.equal(out.severityFactors.unavailableReason, 'model_or_library_unreadable');
});

test('severityOrder 未覆盖全部 severityRank 档位时同样 fail-closed', async (t) => {
  // 少一档会让 order 与 rank 各自给出不同答案：索引和权重从此不一致。
  const root = await makeRoot(t, { severityOrder: ['info', 'low', 'medium', 'high'] });
  fresh();
  assert.equal((await createSeverityResolver(root)).ready, false);

  // 多出未知档位同样不可信：order 里有 rank 不认识的标签。
  const extra = await makeRoot(t, { severityOrder: [...ORDER, 'catastrophic'] });
  fresh();
  assert.equal((await createSeverityResolver(extra)).ready, false);

  // 重复档位会让连续下调停在原处，属于静默改变口径。
  const dup = await makeRoot(t, { severityOrder: ['info', 'low', 'low', 'high', 'critical'] });
  fresh();
  assert.equal((await createSeverityResolver(dup)).ready, false);
});

test('critical 封顶必须留下归因，否则 severity 与 downgradeReason 各说各话', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const resolver = await createSeverityResolver(root);
  const out = resolver.resolve({
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null,
    evidence: [{ quote: 'nonReentrant modifier' }],
  });
  // 条目 severity 是 critical，但引文里看得到重入锁，结果被封顶并继续下调。
  assert.equal(out.severity, 'low');
  assert.ok(
    out.severityDowngradeChain.includes('critical_capped_by_visible_mitigation'),
    '从 critical 降下来的原因必须出现在完整链路里',
  );
  // 单值字段保留最后一条以兼容既有消费方，但不能再丢掉第一步。
  assert.equal(out.severityDowngrade, out.severityDowngradeChain.at(-1));
});

test('没有命中任何下调规则时 chain 为 undefined，单值字段为 null', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const out = (await createSeverityResolver(root)).resolve({
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null, evidence: [{ quote: 'plain external call' }],
  });
  assert.equal(out.severityDowngrade, null);
  assert.equal(out.severityDowngradeChain, undefined);
});

test('降级路径与正常路径给出完全一致的 severityFactors 键集合', async (t) => {
  const okRoot = await makeRoot(t);
  const badRoot = await makeRoot(t, { severityOrder: null });
  fresh();
  const ok = (await createSeverityResolver(okRoot)).resolve({
    kind: 'risk_hypothesis', title: 'reentrancy', statedSeverity: null, evidence: [{ quote: 'nonReentrant' }],
  });
  fresh();
  const bad = (await createSeverityResolver(badRoot)).resolve({
    kind: 'risk_hypothesis', title: 'reentrancy', statedSeverity: null, evidence: [{ quote: 'nonReentrant' }],
  });
  // status-store 会把 severityFactors 摊平写进 finding，少一个键下游就拿到 undefined
  // 而不是显式的 null，调用方无法区分「没有值」和「字段不存在」。
  assert.deepEqual(Object.keys(ok.severityFactors).sort(), Object.keys(bad.severityFactors).sort());
  assert.equal(bad.severityFactors.reachableAssetsUsd, null);
  assert.equal(bad.severityFactors.severityScore, null);
  assert.equal(bad.severityFactors.severityScoreState, 'not_computable');
});

test('来源写明的 severity 直接采用，派生逻辑不得改写它', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const out = (await createSeverityResolver(root)).resolve({
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: 'low',
    evidence: [{ quote: 'nonReentrant modifier' }],
  });
  // 即使证据里看得到防护，显式来源也优先：下调只作用于派生路径。
  assert.equal(out.severity, 'low');
  assert.equal(out.severityBasis, 'explicit');
});

test('record_only kind 记为 info，不主张存在缺陷', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const out = (await createSeverityResolver(root)).resolve({
    kind: 'dependency_trace', title: 'reentrancy 字样出现在依赖名里', statedSeverity: null, evidence: [{ quote: 'x' }],
  });
  assert.equal(out.severity, 'info');
  assert.equal(out.severityBasis, 'record_only');
});

test('标题匹配不到任何字典类别时退回 unrated，不猜类别', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const out = (await createSeverityResolver(root)).resolve({
    kind: 'risk_hypothesis', title: '与任何类别无关的描述', statedSeverity: null, evidence: [{ quote: 'x' }],
  });
  assert.equal(out.severity, 'low');
  assert.equal(out.severityBasis, 'unrated');
  assert.equal(out.severityFactors.categoryWeight, null);
  assert.equal(out.severityFactors.severityEvidenceScore, null);
});

test('reachableAssetsUsd 未实测时恒为 null，severityScore 不可计算', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const out = (await createSeverityResolver(root)).resolve({
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null, evidence: [{ quote: 'plain call' }],
  });
  const factors = out.severityFactors;
  // 代入 0 会让所有未观测项看起来同样不可怕，代入估值则等于编造金额。
  assert.equal(factors.reachableAssetsUsd, null);
  assert.equal(factors.reachableAssetsUsdBasis, 'not_measured');
  assert.equal(factors.severityScore, null);
  assert.equal(factors.severityScoreState, 'not_computable');
  // 但可测的两项因子仍可用：它用于排序，不是金额也不是资金规模。
  assert.ok(Number.isFinite(factors.severityEvidenceScore));
  assert.equal(factors.severityEvidenceScore, factors.categoryWeight * factors.triggerDifficulty);
});

test('resolve 不把派生结果写回输入 finding', async (t) => {
  const root = await makeRoot(t);
  fresh();
  const resolver = await createSeverityResolver(root);
  const finding = {
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null, evidence: [{ quote: 'nonReentrant' }],
  };
  const snapshot = JSON.stringify(finding);
  const out = resolver.resolve(finding);
  // 纯函数契约：调用方传入的对象不会被就地改写，否则 status-store 里
  // applyDerivedSeverity 的 {...finding} 展开就会拿到已被污染的旧值。
  assert.equal(JSON.stringify(finding), snapshot);
  assert.equal(out.severity, 'low');
});

// ---- 词表 fail-closed（来自 work/vuln-module-audit.md 的 P1-1 / P1-5）----
//
// 以前 dictionary 用 informational、rank 用 info，resolve() 里的 Object.hasOwn
// 会把认不出的档位静默丢掉：没有日志、没有计数，权重池悄悄少一块。
// 现在这类值要么归一到 canonical 档位，要么让整份配置 fail-closed。

test('缺 severityVocabulary 时 fail-closed：不得退回内置默认别名', async (t) => {
  const root = await makeRoot(t, { vocabulary: null });
  fresh();
  const resolver = await createSeverityResolver(root);
  // 少一份词表声明就等于没人能判定字典里的 severity 合不合法。
  assert.equal(resolver.ready, false);
  assert.equal(resolver.describe().unavailableReason, 'model_or_library_unreadable');
});

test('别名指向词表外档位时 fail-closed', async (t) => {
  const root = await makeRoot(t, { vocabulary: { aliases: { informational: 'catastrophic' }, unstatedMarker: 'unstated' } });
  fresh();
  assert.equal((await createSeverityResolver(root)).ready, false);
});

test('别名与 canonical 档位重名时 fail-closed：同一字符串会有两种读法', async (t) => {
  const root = await makeRoot(t, { vocabulary: { aliases: { low: 'high' }, unstatedMarker: 'unstated' } });
  fresh();
  assert.equal((await createSeverityResolver(root)).ready, false);
});

test('未声明标记同时是 canonical 档位时 fail-closed', async (t) => {
  // 「来源没写」绝不能同时是一种可以参与评级的严重度，否则 unrated 会变成可评级的 info。
  const root = await makeRoot(t, { vocabulary: { aliases: {}, unstatedMarker: 'low' } });
  fresh();
  assert.equal((await createSeverityResolver(root)).ready, false);
});

test('字典用 informational 时归一到 info 并正常参与权重', async (t) => {
  // entryId 必须用 entrySelectors 里登记的那个，否则不会命中唯一条目，
  // 走的是 category_baseline 而不是 library_grounded —— 那测不到归一本身。
  const root = await makeRoot(t, {
    vulnerabilities: [{ id: 'lib-critical', benchmarkCategory: 'reentrancy', severity: 'informational', status: 'active', category: 'vulnerability' }],
  });
  fresh();
  const resolver = await createSeverityResolver(root);
  const out = resolver.resolve({
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null, evidence: [{ quote: 'plain call' }],
  });
  // 归一后它就是一条正常的 info 级条目背书，而不是被静默丢弃。
  assert.equal(out.severityBasis, 'library_grounded');
  assert.equal(out.severityFactors.libraryEntrySeverity, 'info');
  assert.equal(out.severityFactors.categoryWeight, RANK.info);
  // 归一是预期内的，不该被当成「词表外取值」报出来。
  assert.deepEqual(resolver.describe().droppedLibrarySeverities, []);
});

test('unstated 条目不进权重池，但仍如实计数', async (t) => {
  const root = await makeRoot(t, {
    vulnerabilities: [
      { id: 'lib-unstated', benchmarkCategory: 'reentrancy', severity: 'unstated', status: 'active', category: 'vulnerability' },
      { id: 'lib-critical', benchmarkCategory: 'reentrancy', severity: 'critical', status: 'active', category: 'vulnerability' },
    ],
  });
  fresh();
  const resolver = await createSeverityResolver(root);
  // unstated 是「来源没写」，它不参与基线计算：基线只由有背书的条目决定。
  assert.equal(resolver.ready, true, 'unstated 是预期内的保守标记，不该让模型失效');
  const described = resolver.describe();
  assert.equal(described.unstatedEntryCount, 1);
  assert.deepEqual(described.droppedLibrarySeverities, [], 'unstated 不属于词表外取值');
  const out = resolver.resolve({
    kind: 'risk_hypothesis', title: 'reentrancy candidate', statedSeverity: null, evidence: [{ quote: 'plain call' }],
  });
  assert.equal(out.severityFactors.libraryEntryId, 'lib-critical');
});

test('词表外严重级不再被静默丢弃：整份配置显式失败', async (t) => {
  const root = await makeRoot(t, {
    vulnerabilities: [{ id: 'lib-typo', benchmarkCategory: 'reentrancy', severity: 'criticalh', status: 'active', category: 'vulnerability' }],
  });
  fresh();
  const resolver = await createSeverityResolver(root);
  // 这是 P1-1 的核心：以前 'criticalh' 会被 Object.hasOwn 静默丢掉，评级照常出结果。
  assert.equal(resolver.ready, false);
  assert.equal(resolver.describe().unavailableReason, 'library_severity_outside_vocabulary');
  assert.deepEqual(
    resolver.describe().droppedLibrarySeverities.map((item) => item.severity),
    ['criticalh'],
  );
  const out = resolver.resolve({ kind: 'risk_hypothesis', title: 'reentrancy', statedSeverity: null, evidence: [{ quote: 'x' }] });
  assert.equal(out.severity, 'info');
  assert.equal(out.severityBasis, 'unrated');
});

test('词表外 benchmarkCategory 显式失败，不当作陌生类别静默通过', async (t) => {
  const root = await makeRoot(t, {
    vulnerabilities: [{ id: 'lib-newcat', benchmarkCategory: 'cross_chain_bridge', severity: 'high', status: 'active', category: 'vulnerability' }],
  });
  fresh();
  const resolver = await createSeverityResolver(root);
  // titleMatchers 里没有这个类别，条目永远匹配不上，会被当成 unrated 静默掉到 low。
  assert.equal(resolver.ready, false);
  assert.equal(resolver.describe().unavailableReason, 'library_category_outside_vocabulary');
  assert.deepEqual(
    resolver.describe().unknownBenchmarkCategories.map((item) => item.category),
    ['cross_chain_bridge'],
  );
});

test('仓库内字典与模型的词表互相自洽', async () => {
  fresh();
  const resolver = await createSeverityResolver(PROJECT_ROOT);
  const described = resolver.describe();
  assert.equal(described.unavailableReason, null, JSON.stringify(described, null, 1));
  assert.deepEqual(described.droppedLibrarySeverities, [], '仓库内字典不得出现词表外严重级');
  assert.deepEqual(described.unknownBenchmarkCategories, [], '仓库内字典不得出现词表外类别');
});

test('仓库内 SWC 条目的严重级全部是未声明（与 inventory 实测一致）', async () => {
  // 这条把 P0-2 的取证结论钉成回归：SWC Registry 在固定提交下没有任何 Severity 字段，
  // 字典里的 SWC 条目因此不得凭空带一个严重级去当评级上限。
  fresh();
  const raw = JSON.parse(await readFile(join(PROJECT_ROOT, 'data', 'vulnerability-library.json'), 'utf8'));
  const offenders = (raw.vulnerabilities || [])
    .filter((entry) => String(entry.id).startsWith('swc-') && entry.severity !== 'unstated')
    .map((entry) => `${entry.id}=${entry.severity}`);
  assert.deepEqual(offenders, [], `SWC 条目不得自带未申报来源的严重级：${offenders}`);
});