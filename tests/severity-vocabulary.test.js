// 词表一致性诊断（work/vuln-module-audit.md 的 P1-5）。
//
// 现状是三处类别词表各自为政：
//   - scripts/severity-model.json 的 categoryTitlePatterns  —— 评级唯一词表（本 agent 的范围）
//   - src/vulnerability-library.js 的 CATEGORY_INFO           —— Web 展示层映射（他人负责）
//   - scripts/vulnerability_inventory.py 的 PROJECT_CLASSES  —— inventory 口径（他人负责）
//
// 本文件不收敛它们（后两处不在本次可写范围内），而是把已测到的分叉钉成账目：
// 一旦分叉变大或形态变化，用例立刻失败并要求重新决策，而不是让差异静默扩大。
// 这是「暴露不一致」而不是「让不一致通过」。
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createSeverityResolver, resetSeverityCaches, SEVERITY_LABELS } from '../src/severity-resolver.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

// 已实测的分叉基线。改动这些数字本身不是错，但必须是有意识的改动：
// 要么收敛词表，要么更新本账目并在提交说明里写清为什么。
const KNOWN = {
  // inventory 用的是条目 id 风格（token_erc777_reentrancy_hook），
  // 字典用的是类别名风格（reentrancy）。同一概念两种拼法。
  inventoryOnly: [
    'initializer_reentrancy',
    'proxy_storage_collision',
    'token_erc777_reentrancy_hook',
    'token_fee_on_transfer',
  ],
  // CATEGORY_INFO 多出来的 5 类没有对应基准类别，会被 Web 渲染成「干净对照样本」。
  categoryInfoOnly: [
    'honeypots',
    'incorrect_interface',
    'race_condition',
    'short_addresses',
    'variable_shadowing',
  ],
  // 反向差集：模型有类别但展示层没有对应说明。
  modelOnly: [
    'erc4626_donation',
    'erc4626_rounding',
  ],
};

async function readJson(...parts) {
  return JSON.parse(await readFile(join(PROJECT_ROOT, ...parts), 'utf8'));
}

// inventory 的 PROJECT_CLASSES 是 Python 常量，只能从源码里读出来。
function inventoryClasses() {
  const result = spawnSync('python3', ['-c', [
    'import importlib.util, json',
    'spec = importlib.util.spec_from_file_location("inv", "scripts/vulnerability_inventory.py")',
    'mod = importlib.util.module_from_spec(spec)',
    'spec.loader.exec_module(mod)',
    'print(json.dumps(sorted(item["id"] for item in mod.PROJECT_CLASSES)))',
  ].join('\n')], { cwd: PROJECT_ROOT, encoding: 'utf8' });
  assert.equal(result.status, 0, `无法读取 inventory 的 PROJECT_CLASSES：${result.stderr}`);
  return JSON.parse(result.stdout);
}

async function categoryInfoKeys() {
  const source = await readFile(join(PROJECT_ROOT, 'src', 'vulnerability-library.js'), 'utf8');
  const block = source.match(/const CATEGORY_INFO = Object\.freeze\(\{([\s\S]*?)\n\}\);/);
  assert.ok(block, '未能定位 CATEGORY_INFO 字面量');
  return [...block[1].matchAll(/^\s{2}([a-z_]+):\s*\{/gm)].map((match) => match[1]).sort();
}

test('模型类别词表与字典实际使用的类别完全一致', async () => {
  const model = await readJson('scripts', 'severity-model.json');
  const library = await readJson('data', 'vulnerability-library.json');
  const canonical = new Set(Object.keys(model.categoryTitlePatterns));
  const used = new Set(library.vulnerabilities.filter((item) => item.benchmarkCategory).map((item) => item.benchmarkCategory));
  const missing = [...used].filter((item) => !canonical.has(item)).sort();
  assert.deepEqual(missing, [], `字典用了模型词表外的类别：${missing}`);
  // 这两个方向必须同时成立：多出来的类别会让标题永远匹配不上，条目被静默判为 unrated。
  const unused = [...canonical].filter((item) => !used.has(item)).sort();
  assert.deepEqual(unused, [], `模型里有字典从未使用的类别：${unused}`);
});

test('resolver 对仓库内字典判定为可用，且没有词表外取值', async () => {
  resetSeverityCaches();
  const resolver = await createSeverityResolver(PROJECT_ROOT);
  const described = resolver.describe();
  assert.equal(described.unavailableReason, null, JSON.stringify(described, null, 1));
  assert.deepEqual(described.droppedLibrarySeverities, []);
  assert.deepEqual(described.unknownBenchmarkCategories, []);
});

test('三处类别词表之间的已知分叉没有扩大', async (t) => {
  const model = await readJson('scripts', 'severity-model.json');
  const modelCategories = new Set(Object.keys(model.categoryTitlePatterns));
  const info = await categoryInfoKeys();
  const inventory = inventoryClasses();

  const inventoryOnly = inventory.filter((item) => !modelCategories.has(item)).sort();
  const categoryInfoOnly = info.filter((item) => !modelCategories.has(item)).sort();
  const modelOnly = [...modelCategories].filter((item) => !info.includes(item)).sort();

  // 收敛是好事，因此只在分叉「变大」时失败：多出任何一类都说明又有人在别处加了词表。
  const grew = (actual, known) => {
    const extra = actual.filter((item) => !known.includes(item));
    assert.deepEqual(
      extra, [],
      `类别词表又分叉了，新增 ${extra}。要么把三者收敛到 scripts/severity-model.json 的 categoryTitlePatterns，`
      + '要么确认它属于展示层专有类别并更新 KNOWN 账目。不要让它静默存在。',
    );
  };
  grew(inventoryOnly, KNOWN.inventoryOnly);
  grew(categoryInfoOnly, KNOWN.categoryInfoOnly);

  // modelOnly 方向相反：少一个说明展示层还没跟上，应该直接收敛而不是记账。
  assert.deepEqual(modelOnly, KNOWN.modelOnly.sort(),
    `模型类别缺展示层映射：${modelOnly}。请在 src/vulnerability-library.js 的 CATEGORY_INFO 补齐后同步本账目。`);
});

test('严重级词表：模型与 resolver 的 canonical 档位一致', async () => {
  const model = await readJson('scripts', 'severity-model.json');
  assert.deepEqual(Object.keys(model.severityRank).sort(), [...SEVERITY_LABELS].sort(),
    'severityRank 与 SEVERITY_LABELS 必须逐档对应，不能各自维护一份');
  assert.deepEqual(model.severityVocabulary.unstatedMarker, 'unstated');
  // 别名目标必须落在 canonical 档位内，否则归一后得到的仍是一个解析器不认识的档位。
  for (const [alias, target] of Object.entries(model.severityVocabulary.aliases)) {
    assert.ok(SEVERITY_LABELS.includes(target), `别名 ${alias} 指向词表外的 ${target}`);
    assert.ok(!SEVERITY_LABELS.includes(alias), `别名 ${alias} 与 canonical 档位重名`);
  }
  assert.ok(!SEVERITY_LABELS.includes('unstated'), '未声明标记不能同时是可评级的档位');
});

test('inventory 的实测结论仍然是「SWC 条目无严重级」', async () => {
  // 这是 P0-2 取证结论的回归锚点。inventory 产物是离线缓存跑出来的，
  // 不是实时抓取；一旦它变了，本地测试全绿也不能再当作「来源没写严重级」的证据。
  const raw = await readFile(join(PROJECT_ROOT, 'work', 'vulnerability-inventory.json'), 'utf8')
    .catch(() => { t.skip('缺少 vulnerability-inventory.json 实测产物'); return null; });
  if (!raw) return;
  const swc = JSON.parse(raw).swc;
  assert.deepEqual(swc.severityCounts, { unstated: 37 },
    `inventory 实测分布已变（${JSON.stringify(swc.severityCounts)}），build 脚本的严重级口径需重新取证`);
  assert.equal(swc.severityStatedCount, 0);
  assert.equal(swc.entryCount, 37);
});

test('SWC 条目唯一的类别会退到 unrated→low，而不是拿无出处的值当上限', async () => {
  // 去掉硬编码严重级后，bad_randomness / time_manipulation / front_running /
  // unchecked_low_level_calls / arithmetic 这几类的 active+vulnerability 条目
  // 全部变成 unstated，category_baseline 因此为 null，评级走 unrated→low。
  //
  // 这是「没有条目背书时的保守值」，不是漏报：severityBasis 会明确写成 unrated，
  // categoryWeight 为 null、消费方能分辨「没评级」与「评成 low」。
  // 这里把它钉住，防止有人为了让基线不为空而重新塞回拍脑袋常数。
  resetSeverityCaches();
  const model = await readJson('scripts', 'severity-model.json');
  const library = await readJson('data', 'vulnerability-library.json');
  const rankable = new Set(SEVERITY_LABELS);
  const provided = new Set(library.vulnerabilities
    .filter((item) => item.status === 'active' && item.category === 'vulnerability'
      && rankable.has(item.severity) && item.benchmarkCategory)
    .map((item) => item.benchmarkCategory));
  const unbacked = Object.keys(model.categoryTitlePatterns).filter((item) => !provided.has(item));
  // 与 inventory 的实测结论一致：这几类没有带严重级出处的条目背书。
  assert.deepEqual(unbacked.sort(), [
    'arithmetic', 'bad_randomness', 'front_running', 'time_manipulation', 'unchecked_low_level_calls',
  ], `失去基线提供者的类别变成了 ${unbacked}。若是有意补充了带出处的条目，请同步更新本账目并给出 URL。`);
});

test('语义提醒：本地词表自洽不等于任何漏洞已被确认', () => {
  // 这不是装饰性断言。档位只描述「未确认观察项的估算影响」，
  // 写清楚以免有人把「三处词表对齐了」读成「漏洞已被验证」。
  assert.equal(Object.keys(RANK).length, 5);
});