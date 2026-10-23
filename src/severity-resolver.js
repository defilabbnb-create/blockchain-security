// 未确认观察项的推导严重度。
//
// 口径（precision over recall）：
//   - 严重度描述的是「未确认观察项的估算影响」，不代表漏洞已确认，也不代表部署合约可被利用。
//   - 权重只能来自已核对的漏洞字典 data/vulnerability-library.json；字典里没有背书的，绝不猜测。
//   - reachableAssetsUsd 未实测时恒为 null，severityScore 随之不可计算；不代入 0，也不代入任何估值。
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export const SEVERITY_LABELS = ['critical', 'high', 'medium', 'low', 'info'];

let cachedModel = null;
let cachedLibrary = null;

// 词表外严重级一律显式失败，不静默丢弃。
// 以前 loadLibrary 把条目 severity 原样收下，resolve() 里再靠 Object.hasOwn(rank, …) 过滤，
// 过滤掉的那一档没有任何痕迹：字典写错一个词，评级就悄悄少一块权重，而且没人知道少了哪块。
// 现在把每一档落进 droppedLibrarySeverities，由 describe() 如实报出。
function usableSeverityVocabulary(raw, canonical) {
  const config = raw.severityVocabulary || {};
  const unstated = config.unstatedMarker;
  const aliases = config.aliases || {};
  // 「未声明」标记不能同时是 canonical 档位：那等于把「没填」变成一种可评级的严重度。
  if (typeof unstated !== 'string' || canonical.includes(unstated)) return null;
  if (typeof aliases !== 'object' || aliases === null || Array.isArray(aliases)) return null;
  const resolved = new Map();
  for (const [alias, target] of Object.entries(aliases)) {
    if (!canonical.includes(target)) return null;
    // 别名与 canonical 档位重名时，同一个字符串会有两种读法：解析结果是哪一边取决于查哪张表。
    // 自映射（alias === target）同样没有意义。
    if (alias === target || canonical.includes(alias) || alias === unstated) return null;
    resolved.set(alias, target);
  }
  return { unstated, aliases: resolved };
}

// 类别词表同样 fail-closed：字典里出现模型不认识的类别时，整份配置判定为不可用。
// 这不是「多一个类别无所谓」—— resolve() 靠 titleMatchers 判定 benchmarkCategory，
// 词表外的类别根本进不了候选，条目会被当成 unrated 静默掉到 low。
function usableCategoryVocabulary(raw) {
  const canonical = Object.keys(raw.categoryTitlePatterns || {});
  if (!canonical.length) return null;
  const unstated = raw.categoryVocabulary?.unstatedMarker ?? 'unstated';
  if (canonical.includes(unstated)) return null;
  return { canonical: new Set(canonical), unstated };
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

// 配置是模型的一部分：缺失或被改坏时宁可让全部条目退回 unrated，也不让它悄悄改变评级口径。
//
// severityOrder 是 downgrade 的执行依据：stepDown 用它做 indexOf 和下标减一。缺了它，
// 真正需要下调时会在 resolve() 里抛 TypeError，把「评级不可用」变成「整条流水线崩溃」。
// 因此它和 severityRank 同级校验，而不是留给运行时去炸。
function usableSeverityOrder(raw) {
  if (!Array.isArray(raw.severityOrder) || raw.severityOrder.length === 0) return null;
  // 必须恰好覆盖 severityRank 的全部档位，且是严格递增序列：
  // 多余的未知档位会让 order 与 rank 各自给出不同答案，重复档位会让连续下调停在原处。
  const rank = raw.severityRank;
  if (raw.severityOrder.length !== Object.keys(rank).length) return null;
  let previous = -Infinity;
  for (const label of raw.severityOrder) {
    if (!Object.hasOwn(rank, label)) return null;
    if (!(rank[label] > previous)) return null;
    previous = rank[label];
  }
  return raw.severityOrder;
}

async function loadModel(projectRoot) {
  if (cachedModel) return cachedModel;
  const raw = await readJson(join(projectRoot, 'scripts', 'severity-model.json'));
  const order = raw?.schemaVersion === 1 ? usableSeverityOrder(raw) : null;
  const vocabulary = raw?.schemaVersion === 1 ? usableSeverityVocabulary(raw, SEVERITY_LABELS) : null;
  const categories = raw?.schemaVersion === 1 ? usableCategoryVocabulary(raw) : null;
  if (raw?.schemaVersion !== 1 || !raw.severityRank || !Object.hasOwn(raw.severityRank, 'critical')
      || !order || !vocabulary || !categories || !Array.isArray(raw.entrySelectors)
      || !raw.adjustment || !raw.triggerDifficulty) return null;
  const compiled = {
    ...raw,
    vocabulary,
    categoryVocabulary: categories,
    titleMatchers: new Map(Object.entries(raw.categoryTitlePatterns || {})
      .map(([category, patterns]) => [category, (patterns || []).map((source) => new RegExp(source, 'i'))])),
    entrySelectors: (raw.entrySelectors || []).map((selector) => ({
      ...selector,
      titleRegex: (selector.titlePatterns || []).map((source) => new RegExp(source, 'i')),
      quoteRegex: (selector.quotePatterns || []).map((source) => new RegExp(source, 'i')),
    })),
    signals: (raw.triggerDifficulty.signals || []).map((signal) => ({
      ...signal, regex: (signal.patterns || []).map((source) => new RegExp(source, 'i')),
    })),
  };
  compiled.conditionSignal = compiled.signals.find((signal) => signal.source === 'conditions') || null;
  cachedModel = compiled;
  return compiled;
}

async function loadLibrary(projectRoot, model) {
  if (cachedLibrary) return cachedLibrary;
  const raw = await readJson(join(projectRoot, 'data', 'vulnerability-library.json'));
  const entries = Array.isArray(raw?.vulnerabilities)
    ? raw.vulnerabilities.filter((item) => item && typeof item.id === 'string' && item.benchmarkCategory) : [];
  const mapped = new Map();
  const dropped = new Map();
  const unknownCategories = new Map();
  const vocabulary = model?.vocabulary ?? null;
  const canonicalCategories = model?.categoryVocabulary?.canonical ?? null;
  // 词表本身不可用时无法判定，只能原样收下并全部计入 dropped，交给 fail-closed 路径处理。
  const canonicalSeverity = (rawSeverity) => {
    const value = String(rawSeverity || '').toLowerCase();
    if (!vocabulary) return value;
    const canonical = vocabulary.aliases.get(value) ?? value;
    // 未声明标记与词表外取值都返回空串：不进权重池，但也不会被当成一个档位去排序。
    if (canonical === vocabulary.unstated || !SEVERITY_LABELS.includes(canonical)) return '';
    return canonical;
  };
  const note = (bucket, key, id) => {
    if (!bucket.has(key)) bucket.set(key, []);
    bucket.get(key).push(id);
  };
  for (const entry of entries) {
    const rawSeverity = String(entry.severity || '').toLowerCase();
    const severity = canonicalSeverity(rawSeverity);
    // 所有「进不了权重池」的严重级都要留痕：未声明标记是预期内的，
    // 词表外的拼写错误不是。前者是口径，后者是数据缺陷，必须能被 describe() 区分出来。
    if (!severity) note(dropped, rawSeverity || '(空)', entry.id);
    if (canonicalCategories && !canonicalCategories.has(entry.benchmarkCategory)) {
      note(unknownCategories, entry.benchmarkCategory, entry.id);
    }
    const list = mapped.get(entry.benchmarkCategory) || [];
    list.push({
      id: entry.id,
      benchmarkCategory: entry.benchmarkCategory,
      severity,
      rawSeverity,
      status: String(entry.status || '').toLowerCase(),
      category: String(entry.category || '').toLowerCase(),
    });
    mapped.set(entry.benchmarkCategory, list);
  }
  cachedLibrary = {
    schemaVersion: raw?.schemaVersion ?? null,
    generatedAt: raw?.generatedAt || null,
    count: entries.length,
    mapped,
    // 排序让报出来的第一项稳定，否则同一份字典两次 describe() 会给出不同顺序。
    droppedLibrarySeverities: [...dropped.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([severity, entryIds]) => ({ severity, entries: entryIds.sort() })),
    unknownBenchmarkCategories: [...unknownCategories.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([category, entryIds]) => ({ category, entries: entryIds.sort() })),
  };
  return cachedLibrary;
}

export function resetSeverityCaches() {
  cachedModel = null;
  cachedLibrary = null;
}

function text(value) {
  return typeof value === 'string' ? value : '';
}

function evidenceText(finding) {
  return (Array.isArray(finding.evidence) ? finding.evidence : [])
    .map((item) => (item && typeof item === 'object' ? text(item.quote) : ''))
    .join('\n');
}

// conditions 是人工写下的前置条件，不是源码证据；只有明显比「无」更具体的才计入。
function substantiveConditions(finding, model) {
  const config = model.conditionSignal || {};
  const trivial = new Set((config.trivialValues || []).map((value) => String(value).trim()));
  const minLength = Number.isSafeInteger(config.minLength) ? config.minLength : 4;
  return (Array.isArray(finding.conditions) ? finding.conditions : [])
    .filter((item) => typeof item === 'string')
    .map((item) => item.trim())
    .filter((item) => item.length >= minLength && !trivial.has(item));
}

function categoryCandidates(model, finding) {
  const title = text(finding.title);
  const hits = [];
  for (const [category, regexes] of model.titleMatchers) {
    if (regexes.some((regex) => regex.test(title))) hits.push(category);
  }
  // 0 个或 ≥2 个类别命中都不算判定成功：宁可不评级，也不要猜错类别后给出更高的权重。
  return hits;
}

function selectEntry(model, category, entries, finding) {
  const title = text(finding.title);
  const quotes = evidenceText(finding);
  const matches = [];
  for (const selector of model.entrySelectors) {
    const entry = entries.get(selector.entryId);
    if (!entry || entry.benchmarkCategory !== category) continue;
    const titleHit = selector.titleRegex.some((regex) => regex.test(title));
    const quoteHit = selector.quoteRegex.some((regex) => regex.test(quotes));
    if (titleHit || quoteHit) matches.push({ entryId: selector.entryId, titleHit, quoteHit, reason: selector.reason });
  }
  return matches;
}

// 同一类别下 active+vulnerability 条目中最小的 severity：没有条目背书时用它作为保守上限。
function categoryBaselineSeverity(entries, model) {
  const cap = model.adjustment.categoryBaselineCapSeverity;
  const severities = entries
    .filter((entry) => entry.status === 'active' && entry.category === 'vulnerability')
    .map((entry) => entry.severity)
    .filter((severity) => Object.hasOwn(model.severityRank, severity))
    .sort((a, b) => model.severityRank[a] - model.severityRank[b]);
  const lowest = severities[0];
  if (!lowest) return null;
  // 没有唯一条目背书时封顶：不因「同一类别里最轻的条目很轻」就把观察项说成很严重。
  return Object.hasOwn(model.severityRank, cap) && model.severityRank[lowest] > model.severityRank[cap] ? cap : lowest;
}

function collectSignals(model, finding) {
  const quotes = evidenceText(finding);
  const conditions = substantiveConditions(finding, model);
  const signals = [];
  for (const signal of model.signals) {
    if (signal.source === 'conditions') {
      // 前置条件信号看的是「作者是否写下了非平凡的前置条件」，不是字符串匹配。
      if (!conditions.length) continue;
    } else {
      if (!quotes) continue;
      if (!signal.regex.some((regex) => regex.test(quotes))) continue;
    }
    signals.push({
      id: signal.id, kind: signal.kind, multiplier: signal.multiplier,
      reason: signal.reason,
    });
  }
  // 只对「引文里直接看得到」的缓解证据下调；看不到防护不等于没有防护，因此不存在上调（乘数 > 1）。
  const mitigationFactor = signals
    .filter((signal) => signal.kind === 'mitigation')
    .reduce((total, signal) => total * signal.multiplier, 1);
  const difficulty = signals.reduce((total, signal) => total * signal.multiplier, model.triggerDifficulty.base);
  const clamp = (value) => Math.min(model.triggerDifficulty.maximum, Math.max(model.triggerDifficulty.minimum, Number(value.toFixed(6))));
  return { signals, mitigationFactor: clamp(mitigationFactor), difficulty: clamp(difficulty) };
}

function emptyFactors(model, library, extra = {}) {
  return {
    librarySchemaVersion: library.schemaVersion,
    category: null,
    categoryCandidates: [],
    libraryEntryId: null,
    libraryEntrySeverity: null,
    categoryBaselineSeverity: null,
    categoryWeight: null,
    categoryWeightBasis: 'unknown',
    triggerDifficulty: null,
    triggerSignals: [],
    visibleMitigations: [],
    visibleMitigationFactor: null,
    reachableAssetsUsd: null,
    reachableAssetsUsdBasis: 'not_measured',
    severityEvidenceScore: null,
    severityScore: null,
    severityScoreState: 'not_computable',
    // model 为 null 表示配置本身不可用：这个原因必须写进因子对象，
    // 否则调用方无法区分「模型说这条不可评级」和「模型根本没加载起来」。
    unavailableReason: model ? null : 'model_unavailable',
    ...extra,
  };
}

function evaluateForCategory(finding, model, library, category) {
  const rank = model.severityRank;
  const entries = library.mapped.get(category) || [];
  const matches = selectEntry(model, category, new Map(entries.map((item) => [item.id, item])), finding);
  const baselineSeverity = categoryBaselineSeverity(entries, model);
  const { signals, mitigationFactor, difficulty } = collectSignals(model, finding);
  const visibleMitigations = signals.filter((signal) => signal.kind === 'mitigation').map((signal) => signal.id);
  const entry = matches.length === 1 ? entries.find((item) => item.id === matches[0].entryId) : null;

  const uniqueGrounded = matches.length === 1 && entry && Object.hasOwn(rank, entry.severity);
  const basis = uniqueGrounded ? 'library_grounded' : baselineSeverity ? 'category_baseline' : 'unrated';
  const capSeverity = uniqueGrounded ? entry.severity : baselineSeverity;
  const categoryWeight = Object.hasOwn(rank, capSeverity) ? rank[capSeverity] : null;

  return {
    severityBasis: basis,
    capSeverity: Object.hasOwn(rank, capSeverity) ? capSeverity : model.adjustment.unratedSeverity,
    entry,
    entryMatchReason: uniqueGrounded ? matches[0].reason : null,
    entryAmbiguity: matches.length > 1 ? matches.map((item) => item.entryId) : [],
    factors: emptyFactors(model, library, {
      category,
      libraryEntryId: uniqueGrounded ? entry.id : null,
      libraryEntrySeverity: uniqueGrounded ? entry.severity : null,
      categoryBaselineSeverity: baselineSeverity,
      categoryWeight,
      categoryWeightBasis: uniqueGrounded ? 'library_entry_severity'
        : basis === 'category_baseline' ? 'category_active_vulnerability_min_severity' : 'unknown',
      triggerDifficulty: difficulty,
      triggerSignals: signals,
      visibleMitigations,
      visibleMitigationFactor: mitigationFactor,
      severityEvidenceScore: categoryWeight === null ? null : Number((categoryWeight * difficulty).toFixed(6)),
    }),
  };
}

function finalize(evaluation, model, finding) {
  const order = model.severityOrder;
  const confidence = text(finding.confidence).trim().toLowerCase();
  let severity = evaluation.capSeverity;
  // 每次命中前进恰好一档。三条 if 是独立判定、可叠加的：模型文档明确写了 strongMitigationAt
  // 「再下调一档」，所以这里是逐条生效，而不是三次连续降级也不是只能生效一条。
  const stepDown = () => {
    const index = order.indexOf(severity);
    if (index <= 0) return false;
    severity = order[index - 1];
    return true;
  };

  // 条目 severity 是上限：引文里看得到防护时不允许直接断言 critical。
  // 这一步也必须留下归因，否则 severity 和 downgradeReason 会各说各话。
  const downgrades = [];
  if (model.adjustment.criticalCapWithMitigation && severity === 'critical'
      && evaluation.factors.visibleMitigations.length) {
    severity = 'high';
    downgrades.push('critical_capped_by_visible_mitigation');
  }
  if (evaluation.severityBasis !== 'unrated') {
    const mitigationFactor = evaluation.factors.visibleMitigationFactor;
    const weakConfidence = confidence === 'low';
    if (mitigationFactor <= model.adjustment.downgradeMitigationBelow && stepDown()) downgrades.push('visible_mitigation');
    if (mitigationFactor <= model.adjustment.strongMitigationAt && stepDown()) downgrades.push('visible_mitigation_strong');
    if (weakConfidence && stepDown()) downgrades.push('low_confidence');
  }
  if (evaluation.severityBasis === 'unrated') severity = model.adjustment.unratedSeverity;

  return {
    severity,
    severityBasis: evaluation.severityBasis,
    severityFactors: evaluation.factors,
    severityDowngrade: downgrades.length ? downgrades[downgrades.length - 1] : null,
    // 多个下调同时命中时保留完整链路：单值 severityDowngrade 只能代表最后一个，
    // 消费方若想知道「为什么从 critical 掉到 low」需要看到每一步。
    severityDowngradeChain: downgrades.length ? downgrades : undefined,
    severityEntryMatchReason: evaluation.entryMatchReason,
    severityEntryAmbiguity: evaluation.entryAmbiguity.length ? evaluation.entryAmbiguity : undefined,
  };
}

export function evaluateFindingSeverity(finding, model, library) {
  const rank = model.severityRank;
  const unrated = () => ({
    severity: model.adjustment.unratedSeverity,
    severityBasis: 'unrated',
    severityFactors: emptyFactors(model, library, { categoryWeightBasis: 'unknown' }),
    severityDowngrade: null,
  });

  // 只接受来源里明确写下的等级；派生结果永远不会写回 finding.severity。
  // 注意用 hasOwn 而不是 ??：statedSeverity 为 null 表示『来源没有写』，不能退回已兜底的 severity。
  const statedSource = Object.hasOwn(finding, 'statedSeverity') ? finding.statedSeverity : finding.severity;
  const stated = text(statedSource).trim().toLowerCase();
  if (Object.hasOwn(rank, stated)) {
    return {
      severity: stated,
      severityBasis: 'explicit',
      severityFactors: emptyFactors(model, library, { categoryWeightBasis: 'not_applicable' }),
      severityDowngrade: null,
    };
  }

  // 纯记录本身不是缺陷：字节码分析、依赖追踪、安全控制观察、覆盖缺口。
  if ((model.recordOnlyKinds || []).includes(text(finding.kind))) {
    return {
      severity: 'info',
      severityBasis: 'record_only',
      severityFactors: emptyFactors(model, library, { categoryWeightBasis: 'not_applicable' }),
      severityDowngrade: null,
    };
  }

  const candidates = categoryCandidates(model, finding).filter((category) => library.mapped.has(category));
  if (!candidates.length) return unrated();

  const evaluations = candidates.map((category) => evaluateForCategory(finding, model, library, category));
  if (evaluations.length === 1) return finalize(evaluations[0], model, finding);

  // 多个类别同时命中：逐个求值后取最保守的一个，而不是挑对自己有利或最严重的那个。
  const weakest = evaluations.reduce((best, evaluation) => (
    model.severityRank[evaluation.capSeverity] < model.severityRank[best.capSeverity] ? evaluation : best));
  const factors = {
    ...weakest.factors,
    // 结论来自跨类别取最小值，因此不能声称由某一个条目背书。
    category: null,
    categoryCandidates: candidates,
    libraryEntryId: null,
    libraryEntrySeverity: null,
    categoryWeightBasis: 'multi_category_min_severity',
  };
  return finalize({ ...weakest, severityBasis: 'multi_category_min', entryMatchReason: null, factors }, model, finding);
}

export async function createSeverityResolver(projectRoot) {
  const root = resolve(projectRoot);
  const model = await loadModel(root);
  const library = await loadLibrary(root, model);
  const unstated = model?.vocabulary.unstated ?? 'unstated';
  // 词表外的严重级与词表外的类别都视为模型不可用，而不是「有几条没评级成功」。
  // 前者意味着有人写了个解析器不认识的档位并让它参与排序，后者意味着一个类别永远匹配不上。
  // 两种情况都必须是显式失败：把它们当成可降级的噪声，等于让评级口径静默改变。
  const unexpectedLibrarySeverities = library.droppedLibrarySeverities.filter((item) => item.severity !== unstated);
  const vocabularyReady = unexpectedLibrarySeverities.length === 0 && library.unknownBenchmarkCategories.length === 0;
  const ready = Boolean(model) && vocabularyReady && library.count > 0;
  const unavailableReason = !model ? 'model_or_library_unreadable'
    : unexpectedLibrarySeverities.length ? 'library_severity_outside_vocabulary'
      : library.unknownBenchmarkCategories.length ? 'library_category_outside_vocabulary'
        : ready ? null : 'library_entries_absent';
  // 降级路径必须和正常路径给出同一套 severityFactors 键：消费方（status-store）直接把
  // 这个对象摊平写进 finding，缺键会让「模型不可用」的条目在下游读成 undefined，
  // 而不是显式的 null。
  const unavailable = () => ({
    severity: 'info',
    severityBasis: 'unrated',
    severityFactors: emptyFactors(null, library, {
      categoryWeightBasis: 'unknown',
      unavailableReason,
    }),
    severityDowngrade: null,
  });
  return {
    ready,
    severityLabels: SEVERITY_LABELS,
    resolve(finding) {
      return ready ? evaluateFindingSeverity(finding, model, library) : unavailable();
    },
    describe() {
      return {
        model: 'scripts/severity-model.json',
        library: 'data/vulnerability-library.json',
        libraryReady: library.count > 0,
        libraryEntryCount: library.count,
        libraryGeneratedAt: library.generatedAt,
        // unstatedEntries 是预期内的（来源没写严重级，评级退回类别基线）；
        // 下面两项不是。它们各自为空才说明词表是干净的。
        unstatedMarker: unstated,
        unstatedEntryCount: library.droppedLibrarySeverities
          .find((item) => item.severity === unstated)?.entries.length ?? 0,
        droppedLibrarySeverities: unexpectedLibrarySeverities,
        unknownBenchmarkCategories: library.unknownBenchmarkCategories,
        unavailableReason,
        note: '严重度是未确认观察项的估算影响，不代表漏洞已确认，也不代表部署合约可被利用；reachableAssetsUsd 未实测时不参与评分。',
      };
    },
  };
}