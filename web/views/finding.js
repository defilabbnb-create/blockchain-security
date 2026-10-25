import { escapeHTML, formatDate, value } from '../lib/format.js';
import { severityOf, severityOrder } from '../lib/severity.js';
import { compareByConfidence } from '../lib/confidence.js';
import { findingSignals } from '../lib/badges.js';

// 每页渲染多少条。849 条一次全渲染会把页面撑到 21 万像素，浏览器直接卡住。
const PAGE_SIZE = 30;

// 状态文案：界面上优先用通俗词，原始状态值保留在 title 里便于追溯。
const STATUS_LABELS = {
  unconfirmed_observation: '待核验观察',
  static_signal: '静态信号',
  invariant_violated: '安全规则被打破',
  poc_confirmed: '已复现确认',
  confirmed: '已确认',
  reproduced: '已复现',
  passed: '通过',
  violated: '被违反',
  unavailable: '不可用',
  poc_failed: '复现未成功',
  hypothesis: '待验证假设',
};

const SEVERITY_FILTERS = [
  { key: 'all', label: '全部' },
  { key: 'critical', label: '严重' },
  { key: 'high', label: '高危' },
  { key: 'medium', label: '中危' },
  { key: 'low', label: '低危' },
];

// 「这一条根本没有记录状态」不是「状态是空字符串」。给它一个独立筛选项，
// 否则这批记录在任何状态下拉里都选不到，等于被静默藏起来。
const MISSING_STATUS = '__missing__';

// 视图状态：数据全量留在内存里，DOM 只放当前已经渲染的那一部分。
let view = null;

function statusKeyOf(finding) {
  return String(finding.status || finding.state || '');
}

function statusLabelOf(status) {
  const key = String(status || '');
  return STATUS_LABELS[key] || key || '未记录';
}

/** 状态徽章：图标 + 文字 + 颜色三重编码，灰度或色盲下也能分辨。 */
function statusBadge(status) {
  const key = String(status || '');
  const tone = /^(poc_confirmed|confirmed|reproduced)$/.test(key) ? 'ok'
    : /violated|failed/.test(key) ? 'danger'
      : /adapter|unavailable|error/.test(key) ? 'warn'
        : /static|hypothesis/.test(key) ? 'info' : 'muted';
  const icon = { ok: '✓', danger: '!', warn: '·', info: 'i', muted: '–' }[tone];
  const title = key ? `原始状态：${key}` : '这条记录没有写状态字段';
  return `<span class="status-badge tone-${tone}" title="${escapeHTML(title)}">`
    + `<span class="status-badge-icon" aria-hidden="true">${icon}</span>`
    + `<span class="status-badge-text">${escapeHTML(statusLabelOf(key))}</span></span>`;
}

/**
 * 三步进度：规则检查 → 本地运行 → 复现验证。
 *
 * 每一步只依据 finding 上真实存在的字段判定，绝不推测「已完成」：
 *   - 规则检查：记录里写明了检查项编号，或这条记录本身来自一条安全规则。
 *   - 本地运行：真的跑过（跑出规则被打破，或复现脚本跑出了结果）。
 *   - 复现验证：后端同时给出「已复现确认」和确认标记，两者缺一不可。
 */
export function progressSteps(finding) {
  const status = String(finding.status || finding.state || '');
  const kind = String(finding.kind || '');
  const pocState = finding.pocState ? String(finding.pocState) : '';

  // 第 1 步：规则检查。有明确的检查项编号，或记录来自一条安全规则，才算做过规则检查。
  const hasCheck = typeof finding.check === 'string' && finding.check.trim() !== '';
  const hasRule = hasCheck || kind === 'invariant_violated';
  const rule = hasRule
    ? { state: 'done', note: hasCheck ? `检查项 ${finding.check}` : '已记录对应的安全规则' }
    : { state: 'none', note: '没有记录对应的检查项' };

  // 第 2 步：本地运行。只有真的跑过（跑出规则被打破、或跑过复现脚本）才算完成。
  const ranLocally = status === 'invariant_violated' || pocState === 'confirmed' || pocState === 'unconfirmed';
  const run = ranLocally
    ? { state: 'done', note: status === 'invariant_violated' ? '本地运行已观察到规则被打破' : '本地复现脚本已运行' }
    : pocState === 'error'
      ? { state: 'failed', note: '本地复现运行失败' }
      : { state: 'none', note: '没有本地运行记录' };

  // 第 3 步：复现验证。只有后端同时给出 poc_confirmed 且 confirmedVulnerability === true 才算复现成功。
  const confirmed = status === 'poc_confirmed' && finding.confirmedVulnerability === true;
  const reproduce = confirmed
    ? { state: 'done', note: '已复现：攻击路径可重复触发' }
    : { state: 'none', note: '尚未复现确认' };

  return [rule, run, reproduce];
}

function stepsHTML(finding) {
  const labels = ['规则检查', '本地运行', '复现验证'];
  const steps = progressSteps(finding);
  return `<ol class="finding-steps" aria-label="三步验证进度">${steps.map((step, index) => {
    const mark = { done: '✓', failed: '!', none: '–' }[step.state];
    const word = { done: '已完成', failed: '失败', none: '未完成' }[step.state];
    return `<li class="finding-step step-${step.state}"><span class="finding-step-mark" aria-hidden="true">${mark}</span>`
      + `<span class="finding-step-label">${labels[index]}</span>`
      + `<span class="finding-step-state">${word}</span>`
      + `<span class="finding-step-note">${escapeHTML(step.note)}</span></li>`;
  }).join('')}</ol>`;
}

function evidenceHTML(finding) {
  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  if (!evidence.length) return '<p class="finding-evidence-empty">这条记录没有附上可展开的证据行。</p>';
  return `<details class="finding-evidence"><summary>展开证据（${evidence.length} 条）</summary>`
    + evidence.map((item) => `<div class="audit-evidence">`
      + `<code>${escapeHTML(value(item.file))} · 第 ${escapeHTML(value(item.lineStart))}–${escapeHTML(value(item.lineEnd))} 行</code>`
      + `<blockquote>${escapeHTML(item.quote || '')}</blockquote></div>`).join('')
    + `</details>`;
}

function cardHTML(finding) {
  const id = finding.id || finding.findingId || '';
  const status = statusKeyOf(finding);
  const title = finding.title || finding.check || '未命名观察';
  const source = finding.source?.sha256 || finding.sourceSha256;
  const conditions = Array.isArray(finding.conditions) ? finding.conditions : [];
  const conditionList = conditions.length
    ? `<div class="finding-conditions"><b>还需要满足</b><ul>${conditions.map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul></div>`
    : '';
  const testPlan = finding.localTestPlan
    ? `<p class="finding-test-plan"><b>本地测试计划</b>${escapeHTML(finding.localTestPlan)}</p>` : '';
  // 「打开完整证据」只有在确实有 ID 时才给可点按钮；没有 ID 就明确写「暂无详情」，
  // 不渲染一个点了没反应的按钮。
  const openButton = id
    ? `<button type="button" class="audit-link finding-open" data-finding-id="${escapeHTML(id)}">打开完整证据</button>`
    : `<button type="button" class="audit-link finding-open" disabled title="这条记录没有可打开的证据 ID">暂无详情</button>`;
  return `<article class="audit-finding severity-${escapeHTML(severityOf(finding))}">`
    + `<div class="audit-finding-main">${findingSignals(finding)}`
    + `<h2>${escapeHTML(title)}</h2>`
    + `<p class="finding-where">${escapeHTML(finding.protocol || '未知协议')} · ${escapeHTML(finding.chain || '未知链')} · `
    + `${escapeHTML(finding.address || '地址未记录')}</p>`
    + `${finding.check ? `<p class="finding-check">检查项：<code>${escapeHTML(finding.check)}</code></p>` : ''}</div>`
    + `${statusBadge(status)}`
    + `<div class="audit-finding-evidence">${stepsHTML(finding)}${evidenceHTML(finding)}${conditionList}${testPlan}`
    + (source ? `<div class="evidence-hash"><span>来源指纹（SHA-256）</span><code>${escapeHTML(source)}</code>`
      + `<button type="button" class="copy-hash" data-copy="${escapeHTML(source)}" aria-label="复制来源指纹">复制</button></div>` : '')
    + `</div>${openButton}</article>`;
}

/** 默认排序：已确认 > 疑似 > 待验证 > 其它，同级按严重度。 */
function sortFindings(items) {
  return [...items].sort((a, b) => {
    const confidence = compareByConfidence(a, b);
    if (confidence !== 0) return confidence;
    const severity = (severityOrder[severityOf(a)] ?? 9) - (severityOrder[severityOf(b)] ?? 9);
    if (severity !== 0) return severity;
    return String(a.id || a.findingId || '').localeCompare(String(b.id || b.findingId || ''));
  });
}

function haystack(finding) {
  // 搜索要覆盖全量字段：地址、合约名、检查项、来源文件路径都在里面。
  // markdown 截断到 4000 字符，足够覆盖正文里出现的地址。
  return [
    finding.title, finding.check, finding.protocol, finding.chain, finding.address,
    finding.target, finding.contract, finding.kind, finding.source, finding.sourceSha256,
    finding.localTestPlan,
    typeof finding.markdown === 'string' ? finding.markdown.slice(0, 4000) : '',
  ].filter(Boolean).join(' ').toLowerCase();
}

function matches(finding, filters) {
  if (filters.severity !== 'all' && severityOf(finding) !== filters.severity) return false;
  if (filters.status !== 'all') {
    const key = statusKeyOf(finding);
    if (filters.status === MISSING_STATUS) {
      if (key !== '') return false;
    } else if (key !== filters.status) return false;
  }
  if (filters.query && !finding.__hay.includes(filters.query)) return false;
  return true;
}

function applyFilters() {
  const filters = { severity: view.severity, status: view.status, query: view.query };
  view.filtered = view.all.filter((finding) => matches(finding, filters));
  view.shown = Math.min(view.shown, view.filtered.length);
}

function rangeText() {
  const total = view.filtered.length;
  if (!total) return '没有符合当前筛选条件的线索';
  const from = view.shown ? 1 : 0;
  const to = view.shown;
  const filtered = view.severity !== 'all' || view.status !== 'all' || view.query;
  return filtered
    ? `第 ${from}–${to} 条，共 ${total} 条（筛选后；全部 ${view.all.length} 条）`
    : `第 ${from}–${to} 条，共 ${total} 条`;
}

function listHTML() {
  if (!view.all.length) {
    return '<div class="audit-empty audit-empty-wide"><strong>还没有线索</strong>'
      + '<span>完成一次静态检查或本地复现后，记录会出现在这里。</span></div>';
  }
  if (!view.filtered.length) {
    return '<div class="audit-empty audit-empty-wide"><strong>没有符合当前筛选条件的线索</strong>'
      + '<span>当前条件把所有记录都筛掉了。放宽条件或直接清除筛选，就能看到全部 '
      + `${view.all.length} 条记录。</span>`
      + '<button type="button" class="audit-link finding-clear" data-finding-clear>清除筛选</button></div>';
  }
  return view.filtered.slice(0, view.shown).map(cardHTML).join('');
}

function update(root) {
  applyFilters();
  const list = root.querySelector('[data-finding-list]');
  const range = root.querySelector('[data-finding-range]');
  const more = root.querySelector('[data-finding-more]');
  if (list) list.innerHTML = listHTML();
  if (range) range.textContent = rangeText();
  if (more) {
    const remaining = view.filtered.length - view.shown;
    more.hidden = remaining <= 0;
    more.textContent = remaining > 0 ? `显示更多（还有 ${remaining} 条）` : '没有更多了';
    more.disabled = remaining <= 0;
  }
}

export function render(data = {}) {
  const all = sortFindings(Array.isArray(data.findings) ? data.findings : []).map((finding) => ({
    ...finding, __hay: haystack(finding),
  }));
  const statusKeys = [...new Set(all.map((finding) => statusKeyOf(finding)))];
  const hasMissingStatus = statusKeys.includes('');
  view = {
    all, filtered: all, shown: Math.min(PAGE_SIZE, all.length),
    severity: 'all', status: 'all', query: '',
  };
  const campaignCount = all.filter((item) => item.origin === 'campaign').length;
  const confirmed = all.filter((item) => item.status === 'poc_confirmed' && item.confirmedVulnerability === true).length;
  // 严重度芯片上的计数基于全量数据，不是当前已渲染的那一批。
  const severityCounts = SEVERITY_FILTERS.map((item) => ({
    ...item,
    count: item.key === 'all' ? all.length : all.filter((finding) => severityOf(finding) === item.key).length,
  }));
  const lowRated = all.filter((finding) => {
    const severity = severityOf(finding);
    return severity === 'info' || severity === 'informational' || severity === 'unrated';
  }).length;

  return `<div class="audit-head"><div><span class="eyebrow">03 / 发现</span><h1>发现的线索</h1>`
    + `<p>这里列出自动检查和本地复现留下的线索。先看严重度和状态，再展开证据。共 ${all.length} 条，一次只显示一部分。</p></div>`
    + `<span class="audit-updated">快照时间 ${escapeHTML(formatDate(data.generatedAt))}</span></div>`
    + `<p class="audit-caution"><span class="audit-caution-icon" aria-hidden="true">!</span>`
    + `<b>静态线索不是已确认漏洞。</b>只有后端同时给出「已复现确认」并绑定确认标记的记录，才算漏洞已被复现验证；其余都还需要本地证据。</p>`
    + `<div class="finding-summary"><span><b>${all.length}</b> 条线索</span>`
    + `<span><b>${confirmed}</b> 条已复现确认</span>`
    + `<span><b>${campaignCount}</b> 条来自采集记录</span>`
    + `<span><b>${all.length - campaignCount}</b> 条来自静态检查</span></div>`
    + `<div class="finding-toolbar">`
    + `<div class="finding-severity-chips" role="group" aria-label="按严重度筛选">`
    + severityCounts.map((item) => `<button type="button" class="finding-chip${item.key === 'all' ? ' is-active' : ''}"`
      + ` data-finding-severity="${item.key}" aria-pressed="${item.key === 'all'}">`
      + `${escapeHTML(item.label)}<span class="finding-chip-count">${item.count}</span></button>`).join('')
    + `</div>`
    + `<label class="finding-status-field">状态<select data-finding-status aria-label="按状态下拉筛选">`
    + `<option value="all">全部状态</option>`
    + (hasMissingStatus ? `<option value="${MISSING_STATUS}">未记录状态</option>` : '')
    + statusKeys.filter(Boolean).map((status) => `<option value="${escapeHTML(status)}">${escapeHTML(statusLabelOf(status))}</option>`).join('')
    + `</select></label>`
    + `<label class="finding-filter">搜索<input type="search" data-finding-filter placeholder="协议、标题或地址" aria-label="搜索发现"></label>`
    + `</div>`
    + `<p class="finding-hint">严重度为「提示」或未分级的 ${lowRated} 条线索不在上面几个芯片里，只出现在「全部」中。`
    + `搜索和筛选都作用在全部 ${all.length} 条记录上，不是只作用在已经画出来的部分。</p>`
    + `<p class="finding-range" data-finding-range role="status" aria-live="polite"></p>`
    + `<section class="audit-findings" data-finding-list></section>`
    + `<div class="finding-more-wrap"><button type="button" class="finding-more" data-finding-more>显示更多</button>`
    + `<button type="button" class="audit-link finding-clear" data-finding-clear>清除筛选</button></div>`;
}

export function bind(root = document) {
  if (!view) return;
  update(root);

  root.querySelectorAll('[data-finding-severity]').forEach((button) => button.addEventListener('click', () => {
    view.severity = button.dataset.findingSeverity;
    view.shown = PAGE_SIZE;
    root.querySelectorAll('[data-finding-severity]').forEach((item) => {
      const active = item === button;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-pressed', String(active));
    });
    update(root);
  }));

  const status = root.querySelector('[data-finding-status]');
  if (status) status.addEventListener('change', () => { view.status = status.value; view.shown = PAGE_SIZE; update(root); });

  const filter = root.querySelector('[data-finding-filter]');
  if (filter) filter.addEventListener('input', () => {
    view.query = filter.value.trim().toLowerCase();
    view.shown = PAGE_SIZE;
    update(root);
  });

  const resetFilters = () => {
    view.severity = 'all'; view.status = 'all'; view.query = ''; view.shown = PAGE_SIZE;
    if (filter) filter.value = '';
    if (status) status.value = 'all';
    root.querySelectorAll('[data-finding-severity]').forEach((item) => {
      const active = item.dataset.findingSeverity === 'all';
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-pressed', String(active));
    });
    update(root);
  };
  // 空状态里那个「清除筛选」按钮在列表容器内部，由下面的事件委托处理；
  // 这里只绑定列表之外的那个，避免同一次点击被处理两遍。
  root.querySelectorAll('.finding-more-wrap [data-finding-clear]')
    .forEach((button) => button.addEventListener('click', resetFilters));

  const more = root.querySelector('[data-finding-more]');
  if (more) more.addEventListener('click', () => { view.shown = Math.min(view.shown + PAGE_SIZE, view.filtered.length); update(root); });

  // 列表里的按钮（复制、打开完整证据、空状态里的清除筛选）在每次重绘后都是新节点，
  // 所以这里用事件委托挂在列表容器上：重绘后按钮依然可用，也不会重复绑定。
  const list = root.querySelector('[data-finding-list]');
  if (list) {
    list.addEventListener('click', async (event) => {
      const clear = event.target.closest?.('[data-finding-clear]');
      if (clear) { resetFilters(); return; }
      const open = event.target.closest?.('[data-finding-id]');
      if (open) {
        root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'finding', id: open.dataset.findingId } }));
        return;
      }
      const copy = event.target.closest?.('[data-copy]');
      if (!copy) return;
      const original = copy.textContent;
      try { await navigator.clipboard.writeText(copy.dataset.copy); copy.textContent = '已复制'; }
      catch { copy.textContent = '请手动复制'; }
      window.setTimeout(() => { if (copy.isConnected) copy.textContent = original; }, 1600);
    });
  }
}
