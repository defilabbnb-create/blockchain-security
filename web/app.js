import * as overviewView from './views/overview.js';
import * as protocolView from './views/protocol.js';
import * as findingView from './views/finding.js';
import * as executionView from './views/execution.js';
import * as corpusView from './views/corpus.js';
import * as homeView from './views/home.js';
import { getJSON } from './lib/api.js';
import { scopeAfterToggle } from './lib/home-model.js';

const state = { snapshot: null, showAllChains: false, showAllFindings: false, selectedPath: null, asking: false, lastVulnRender: '', taskPage: null, taskCursors: [null], taskPageIndex: 0, loadingTasks: false, workspaceRoute: null, workspaceRequest: 0, homeControl: null };
const auditViews = { map: overviewView, protocols: protocolView, discoveries: findingView, execution: executionView, home: homeView };
const $ = (selector) => document.querySelector(selector);
const CORPUS_POLL_INTERVAL_MS = 4000;
let corpusPollTimer = null;

/* 链上采集开关的模块级状态。
 *
 * 位置很重要：启动代码在文件中部就会调用 startCollectionPolling()，
 * 而它读 COLLECTION_POLL_INTERVAL_MS。ES 模块按书写顺序求值，
 * 若这些声明落在启动代码之后，启动那一行会撞上暂时性死区
 * （ReferenceError），模块求值就此中止，页面上的交互全部失效，
 * 而后端与接口看起来一切正常。
 * 声明必须排在启动代码之前。 */
const COLLECTION_POLL_INTERVAL_MS = 5000;
const COLLECTION_STATE_CLASS = { running: 'running', starting: 'running', disabled: '', idle: '', completed: '', stale: 'warn', failed: 'danger', interrupted: 'warn', invalidated: 'warn', draining: 'running', waiting_for_new_candidates: 'running' };
let collectionPollTimer = null;
let collectionBusy = false;

/* ------------------------------------------------------------------
 * 外壳：抽屉、面包屑、错误横幅。
 *
 * 诚实性约束（见 .cursor/rules/silent-wrong-value-review.mdc）：
 *   - 接口读取失败时如实显示「读取失败：xxx」，并给出重试入口；
 *     绝不静默白屏，也不把失败说成成功。
 *   - 失败提示不会清空页面上已有的数据；它只说明「这次读取没成功」。
 * ------------------------------------------------------------------ */

/** 顶部横幅：统一显示接口读取失败，可点击重试。 */
function showGlobalError(message, retry) {
  const banner = $('#global-banner');
  const text = $('#global-banner-text');
  if (!banner || !text) return;
  text.textContent = message;
  banner.hidden = false;
  banner.dataset.state = 'error';
  const button = $('#global-banner-retry');
  if (button) {
    button.hidden = typeof retry !== 'function';
    button.onclick = typeof retry === 'function' ? () => { banner.hidden = true; retry(); } : null;
  }
}

/** 读取成功后收起失败横幅（不改动页面上的数据）。 */
function clearGlobalError() {
  const banner = $('#global-banner');
  if (banner && !banner.hidden) banner.hidden = true;
}

/** 统一的失败提示文案：永远带上失败原因。 */
function describeError(error, prefix = '读取失败') {
  const message = error?.message || String(error ?? '') || '未知原因';
  return `${prefix}：${message}`;
}

/* 抽屉：≤900px 时侧边栏变成可展开的顶部抽屉。
 *
 * 交互约定（可访问性）：
 *   - 汉堡按钮 aria-expanded 反映开关状态。
 *   - Esc 关闭抽屉，并把焦点还给汉堡按钮（焦点不能丢在已隐藏的抽屉里）。
 *   - 抽屉打开时焦点移进抽屉；点导航项后自动收起（窄屏下抽屉会挡住内容）。
 *   - 视口变宽回到桌面布局时，抽屉状态必须复位，否则会留下一个「看不见却开着」的抽屉。 */
const SIDEBAR_BREAKPOINT = '(max-width: 900px)';
function isDrawerMode() { return window.matchMedia(SIDEBAR_BREAKPOINT).matches; }

function setDrawerOpen(open) {
  const sidebar = $('#app-sidebar');
  const toggle = $('#nav-toggle');
  if (!sidebar || !toggle) return;
  sidebar.classList.toggle('drawer-open', open);
  toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  toggle.setAttribute('aria-label', open ? '关闭导航菜单' : '打开导航菜单');
  toggle.setAttribute('title', open ? '关闭导航菜单' : '打开导航菜单');
  document.body.classList.toggle('nav-drawer-open', open);
}

function closeDrawer({ restoreFocus = false } = {}) {
  const toggle = $('#nav-toggle');
  if (!isDrawerMode() && !document.body.classList.contains('nav-drawer-open')) return;
  setDrawerOpen(false);
  if (restoreFocus && toggle) toggle.focus();
}

/** 打开抽屉：把焦点送进抽屉第一个可点项，键盘用户不会「开着菜单却还在页面上」。 */
function openDrawer() {
  const sidebar = $('#app-sidebar');
  if (!sidebar) return;
  setDrawerOpen(true);
  const first = sidebar.querySelector('.nav-item');
  if (first && typeof first.focus === 'function') first.focus();
}

/** 路由名 → 人话页面名。面包屑与 aria-label 用它。 */
const ROUTE_LABELS = Object.freeze({
  home: '首页', discoveries: '发现', map: '风险地图', protocols: '协议', execution: '执行与复现',
  overview: '安全总览', 'analysis-tasks': '分析队列', projects: '项目管理', collection: '创建采集',
  scan: '创建扫描', tasks: '任务中心', 'findings-view': '漏洞中心', finding: '漏洞详情',
  dynamic: '动态检查', reverse: '代码查看', permissions: '权限与业务', replay: '调用重放',
  ai: '状态问答', sync: '模型与同步', corpus: '离线语料控制台', task: '任务详情',
});

/* 旧总览里的区块锚点。滚动到这些区块时，侧边栏高亮的仍然是「旧版总览」，
 * 而不是某个不存在的锚点链接 —— 否则用户滚到「链状态」时侧栏一个都不亮。
 * 声明放在这里：setActiveView() 与 syncNavigation() 都会读它，
 * 放在使用点之后会撞上暂时性死区，整个模块求值中止。 */
const OVERVIEW_ANCHOR_HASHES = Object.freeze(['overview', 'analysis-tasks', 'chains', 'routes', 'vulnerability-chains', 'findings', 'sync']);

function updateBreadcrumb(route) {
  const crumb = $('#breadcrumb-current');
  if (!crumb) return;
  const root = route?.name || 'overview';
  crumb.textContent = ROUTE_LABELS[root] || '安全总览';
}

/* 健康指示：圆点 + 文字 + title 三重编码。
 * 颜色不是唯一线索 —— 灰度与色盲显示下也能靠文字分辨状态。 */
const HEALTH_TONES = Object.freeze({
  ok: 'live', warn: 'warn', danger: 'danger', idle: '',
});

/**
 * 更新一个健康指示（圆点 + 文案）。
 * @param {string} dotSelector 圆点元素的 id
 * @param {string} textSelector 文案元素的 id
 * @param {string} text 文案（人话）
 * @param {'ok'|'warn'|'danger'|'idle'} tone 语气
 */
function setHealthIndicator(dotSelector, textSelector, text, tone = 'idle') {
  const dot = $(dotSelector);
  if (dot) dot.className = `status-dot ${HEALTH_TONES[tone] ?? ''}`.trim();
  const label = $(textSelector);
  if (label) label.textContent = text;
}

/** 刷新按钮的「正在刷新」反馈：按钮进入忙状态并转圈，避免用户重复点。 */
function setRefreshing(refreshing) {
  const button = $('#refresh-button');
  const status = $('#refresh-status');
  if (status) {
    status.hidden = !refreshing;
    status.textContent = refreshing ? '正在刷新…' : '';
  }
  if (!button) return;
  button.classList.toggle('is-refreshing', refreshing);
  button.setAttribute('aria-busy', refreshing ? 'true' : 'false');
  button.setAttribute('aria-label', refreshing ? '正在重新读取当前状态' : '重新读取当前状态');
  button.setAttribute('title', refreshing ? '正在重新读取当前状态' : '重新读取当前状态');
  button.disabled = refreshing;
}


function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function formatDate(value, withTime = true) {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--';
  return new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit', hour: withTime ? '2-digit' : undefined, minute: withTime ? '2-digit' : undefined, hour12: false }).format(date);
}

const taskStateLabels = Object.freeze({
  queued: '排队中', preparing: '准备中', running: '运行中', checkpointing: '保存进度',
  paused: '已暂停', cancelling: '取消中', cancelled: '已取消', succeeded: '已完成',
  partial: '部分完成', failed: '失败', blocked: '受阻',
});

const taskTypeLabels = Object.freeze({
  'local-source-analysis': '本地源码分析', analysis: '分析任务', scan: '扫描任务',
  collection: '采集任务', replay: '重放任务', decompile: '反编译任务',
  'v1-resource-projects': '项目导入任务', 'v1-resource-contracts': '合约采集任务',
  'v1-resource-collection': '链上采集任务', 'v1-resource-bytecode': '字节码任务',
  'v1-resource-decompile': '反编译任务',
});

const capabilityLabels = Object.freeze({
  projects: '项目', contracts: '合约', collection: '采集', bytecode: '字节码', decompile: '反编译',
  analysis: '分析', scans: '扫描', tasks: '任务', workers: '工作进程', findings: '漏洞', evidence: '证据',
  replay: '重放', rules: '规则', invariants: '不变量', reviews: '审查', reports: '报告', health: '健康状态',
});

const chainStateLabels = Object.freeze({
  ready: '可深挖', candidate: '候选队列', prefiltered: '预筛跳过探测',
  tested: '已测试', test_available: '待复现', needs_test: '需补测试',
  waiting: '等待门槛', unknown: '未知状态',
});

const evidenceStateLabels = Object.freeze({
  quote_verified: '历史报价证据（需重新报价）', connection_only: '仅兼容性连接',
  not_checked: '未检查', unavailable: '不可用', confirmed: '动态已确认',
  conditional: '条件性复现', static_candidate: '静态候选', decompiler_inference: '反编译推断',
  pending: '待确认', not_reproduced: '未复现', fixed: '已修复', accepted_risk: '已接受风险',
  false_positive: '误报', regression: '回归问题',
});
const triageStatusLabels = Object.freeze({
  unreviewed: '待处理', in_review: '复核中', false_positive: '误报', fixed: '已修复', accepted_risk: '已接受风险',
});
/* 证据类型：后端目前只产出 static_signal，其余按通用词保留，不臆造含义。 */
const evidenceKindLabels = Object.freeze({
  static_signal: '静态信号',
  dynamic_reproduction: '动态复现',
  replay_evidence: '重放证据',
  manual_note: '人工记录',
});

const analysisStateLabels = Object.freeze({
  completed: '已完成', partial: '部分完成', unavailable: '不可用', failed: '失败',
  passed: '通过', running: '运行中', pending: '待处理', not_performed: '未执行',
  truncated: '已截断', unverified: '未验证',
});

const severityLabels = Object.freeze({
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示',
  informational: '提示', Informational: '提示',
  CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '提示',
});

const confidenceLabels = Object.freeze({ low: '低', medium: '中', high: '高', confirmed: '已确认',
  LOW: '低', MEDIUM: '中', HIGH: '高', CONFIRMED: '已确认' });

function stateLabel(value, labels = analysisStateLabels) {
  const key = String(value ?? '').trim();
  return labels[key] || key || '未提供';
}

function setTaskPlaceholder(message) {
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = 5;
  cell.className = 'task-placeholder';
  cell.textContent = message;
  row.append(cell);
  $('#task-list').replaceChildren(row);
}

function renderTasks(tasks) {
  const body = $('#task-list');
  if (!tasks.length) {
    setTaskPlaceholder('当前页没有任务');
    return;
  }
  const rows = tasks.map((task) => {
    const row = document.createElement('tr');
    const id = document.createElement('td');
    const idCode = document.createElement('code');
    idCode.className = 'task-id';
    idCode.textContent = String(task.taskId ?? '未知');
    idCode.title = String(task.taskId ?? '');
    const detailLink = document.createElement('a');
    detailLink.className = 'task-detail-link';
    detailLink.href = `#task/${encodeURIComponent(String(task.taskId ?? ''))}`;
    detailLink.setAttribute('aria-label', `查看任务 ${task.taskId ?? '未知'} 详情`);
    detailLink.append(idCode);
    id.append(detailLink);

    const type = document.createElement('td');
    const typeName = String(task.type ?? 'unknown');
    type.textContent = taskTypeLabels[typeName] || '其他任务';
    type.title = typeName;

    const status = document.createElement('td');
    const badge = document.createElement('span');
    const stateName = String(task.state ?? 'unknown');
    badge.className = `task-state state-${Object.hasOwn(taskStateLabels, stateName) ? stateName : 'unknown'}`;
    badge.textContent = Object.hasOwn(taskStateLabels, stateName) ? taskStateLabels[stateName] : '未知状态';
    badge.title = stateName;
    status.append(badge);

    const updated = document.createElement('td');
    updated.textContent = formatDate(task.updatedAt || task.createdAt);

    const report = document.createElement('td');
    if (task.type === 'local-source-analysis' && ['succeeded', 'partial'].includes(task.state)) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'task-report-button';
      button.textContent = '查看报告';
      button.setAttribute('aria-label', `查看任务 ${task.taskId} 的报告`);
      button.addEventListener('click', () => openTaskReport(task));
      report.append(button);
    } else {
      report.textContent = '—';
      report.className = 'task-report-unavailable';
    }

    row.append(id, type, status, updated, report);
    return row;
  });
  body.replaceChildren(...rows);
}

function updateTaskControls() {
  $('#task-refresh').disabled = state.loadingTasks;
  $('#task-prev').disabled = state.loadingTasks || state.taskPageIndex === 0;
  $('#task-next').disabled = state.loadingTasks || !state.taskPage?.page?.hasMore;
  $('#task-page-count').textContent = `第 ${state.taskPageIndex + 1} 页`;
  $('#task-page-label').textContent = state.taskPage
    ? `${state.taskPage.items.length} 条 / 页 · ${formatDate(state.taskPage.consistency?.asOf)}`
    : '尚未加载';
  $('#task-table-wrap').setAttribute('aria-busy', String(state.loadingTasks));
}

async function loadTaskPage({ cursor = null, reset = false, targetIndex = null } = {}) {
  if (state.loadingTasks) return;
  state.loadingTasks = true;
  $('#task-list-status').textContent = `正在读取第 ${reset ? 1 : (targetIndex ?? state.taskPageIndex + 1) + 1} 页…`;
  $('#task-list-status').dataset.state = 'loading';
  updateTaskControls();
  if (!state.taskPage) setTaskPlaceholder('正在读取任务…');
  try {
    const query = new URLSearchParams({ limit: '20' });
    if (cursor) query.set('cursor', cursor);
    const response = await fetch(`/api/v1/tasks?${query}`, { cache: 'no-store', signal: AbortSignal.timeout(10000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error?.message || `服务返回状态 ${response.status}`);
    if (!Array.isArray(payload.items) || !payload.page || typeof payload.page.hasMore !== 'boolean') {
      throw new Error('任务列表响应格式无效');
    }
    state.taskPage = payload;
    if (reset) {
      state.taskCursors = [null];
      state.taskPageIndex = 0;
    } else if (targetIndex !== null) {
      state.taskPageIndex = targetIndex;
    } else if (cursor) {
      state.taskCursors = state.taskCursors.slice(0, state.taskPageIndex + 1);
      state.taskCursors.push(cursor);
      state.taskPageIndex += 1;
    }
    renderTasks(payload.items);
    $('#task-list-status').textContent = payload.items.length
      ? `已载入 ${payload.items.length} 条任务 · 数据版本 ${payload.consistency?.revision ?? '未知'}`
      : '当前页没有任务';
    $('#task-list-status').dataset.state = payload.items.length ? 'ready' : 'empty';
  } catch (error) {
    $('#task-list-status').textContent = `任务读取失败：${error.message}`;
    $('#task-list-status').dataset.state = 'error';
    if (!state.taskPage) setTaskPlaceholder('任务列表暂不可用');
  } finally {
    state.loadingTasks = false;
    updateTaskControls();
  }
}

async function openTaskReport(task) {
  const dialog = $('#task-report-dialog');
  $('#report-task-label').textContent = `${task.taskId} · ${taskStateLabels[task.state] || '未知状态'}`;
  $('#report-status').textContent = '正在读取归档报告…';
  $('#report-status').dataset.state = 'loading';
  $('#report-result').hidden = true;
  $('#report-sha256').textContent = '';
  $('#report-consistency').textContent = '';
  $('#task-report-json').textContent = '';
  dialog.showModal();
  try {
    const response = await fetch(`/api/v1/tasks/${encodeURIComponent(task.taskId)}/report`, { cache: 'no-store', signal: AbortSignal.timeout(20000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error?.message || `服务返回状态 ${response.status}`);
    const report = payload.data?.report;
    const sha256 = payload.data?.sha256;
    if (!report || typeof report !== 'object' || Array.isArray(report) || !/^[a-f0-9]{64}$/i.test(String(sha256 || ''))) {
      throw new Error('报告或 SHA-256（数据校验指纹）响应格式无效');
    }
    $('#report-sha256').textContent = sha256;
    $('#task-report-json').textContent = JSON.stringify(report, null, 2);
    const reportId = encodeURIComponent(task.taskId);
    $('#report-export-json').href = `/api/v1/reports/${reportId}?format=json`;
    $('#report-export-sarif').href = `/api/v1/reports/${reportId}?format=sarif`;
    $('#report-export-html').href = `/api/v1/reports/${reportId}?format=html`;
    const consistency = payload.consistency || {};
    $('#report-consistency').textContent = `一致性版本 ${consistency.revision ?? '未知'} · ${formatDate(consistency.asOf)}`;
    $('#report-result').hidden = false;
    $('#report-status').textContent = '报告已读取';
    $('#report-status').dataset.state = 'ready';
  } catch (error) {
    $('#report-status').textContent = `报告读取失败：${error.message}`;
    $('#report-status').dataset.state = 'error';
  }
}

function score(value) { return Number(value || 0).toFixed(1); }
function transferState(chain) {
  if (chain.transferability === 'quote_verified') return { label: evidenceStateLabels.quote_verified, className: 'verified' };
  if (chain.transferability === 'connection_only') return { label: evidenceStateLabels.connection_only, className: 'connection' };
  if (chain.transferability === 'not_checked') return { label: evidenceStateLabels.not_checked, className: 'connection' };
  return { label: '不可用', className: 'unavailable' };
}

function renderSnapshot(snapshot) {
  state.snapshot = snapshot;
  $('#service-health').textContent = '在线';
  renderCampaign(snapshot.campaign, snapshot.rpcPool, snapshot);
  const totals = snapshot.totals || {};
  const activeChain = snapshot.activeChain;
  $('#updated-at').textContent = `快照 ${formatDate(snapshot.generatedAt)}`;
  $('#active-task').textContent = snapshot.activeTask?.label || '等待任务';
  $('#active-chain').textContent = activeChain ? `${activeChain.name} · ${stateLabel(activeChain.status, chainStateLabels)}` : '暂无';
  $('#active-scope').textContent = '阶段数字来自已保存记录；请同时查看各阶段的更新时间。';
  $('#metric-ready').textContent = totals.ready ?? '--';
  $('#metric-candidates').textContent = totals.candidates ?? '--';
  $('#metric-quotes').textContent = totals.quoteVerified ?? '--';
  $('#metric-high').textContent = totals.high ?? '--';
  $('#metric-targets').textContent = snapshot.staticAnalysis?.targetCount ?? '--';
  const targetCount = snapshot.staticAnalysis?.targetCount || 0;
  const successCount = snapshot.staticAnalysis?.targets?.filter((target) => target.success).length || 0;
  $('#static-progress').style.width = `${targetCount ? Math.min(100, successCount / targetCount * 100) : 0}%`;
  const staticFindingCount = snapshot.staticAnalysis?.findingCount ?? '--';
  $('#metric-static-note').textContent = snapshot.staticAnalysis?.complete
    ? `最近汇总 ${successCount}/${targetCount} 个目标成功 · ${staticFindingCount} 条检测线索`
    : `最近汇总不完整 · ${successCount}/${targetCount} 个目标成功 · ${staticFindingCount} 条检测线索`;
  for (const [selector, value] of [['#nav-candidates', totals.candidates], ['#nav-routes', totals.quoteVerified], ['#nav-vuln', totals.testedChains], ['#nav-findings', totals.high]]) {
    const counter = $(selector);
    if (counter) counter.textContent = value ?? '--';
  }
  $('#chain-table-foot').textContent = `${totals.screenedChains || 0} 条已筛选 · ${totals.configuredChains || 0} 条配置队列`;
  $('#ask-context-time').textContent = formatDate(snapshot.generatedAt);
  $('#last-report').textContent = `源报告 ${formatDate(snapshot.lastReportAt)} · 快照 ${formatDate(snapshot.generatedAt)}`;

  const model = snapshot.model || {};
  $('#web-model').textContent = model.provider || '未配置';
  $('#desktop-model').textContent = model.role || '未记录';
  $('#sync-model').textContent = model.model || '未配置';
  $('#web-model-state').textContent = model.configured ? '已配置' : '未配置';
  $('#desktop-model-state').textContent = model.participatesInSecurityAnalysis ? '参与审查' : '不参与审查';
  $('#sync-model-state').textContent = model.baseUrlHost || '未配置';
  $('#sync-version').textContent = `同步 ${formatDate(snapshot.generatedAt)}`;
  const modelReady = model.configured === true;
  // 云端审查通道：圆点 + 文字同步更新。未配置只影响云端复核，
  // 网页其余功能照常可用 —— 所以文案要说清，不写成「服务异常」。
  setHealthIndicator('#model-dot', '#model-health', modelReady ? '已配置' : '未配置', modelReady ? 'ok' : 'warn');
  $('#side-sync-label').textContent = 'DSH / DHLsh 共享快照';
  $('#file-sync-state').textContent = '已写入';
  $('#side-sync-dot').className = `status-dot ${modelReady ? 'live' : 'warn'}`;

  renderChains(snapshot.chains || []);
  renderRoutes(snapshot);
  renderChart(snapshot.chains || []);
  renderVulnerabilityChains(snapshot.vulnerabilityChains || [], snapshot.staticAnalysis?.localSecurityTests);
  renderFindings(snapshot.findings || snapshot.highPriorityFindings || []);
}

function renderChains(chains) {
  const query = $('#chain-search').value.toLowerCase();
  const filter = $('#chain-filter').value;
  const filtered = chains.filter((chain) => `${chain.name} ${chain.chainId}`.toLowerCase().includes(query) && (filter === 'all' || filter === 'ready' && chain.readyForDeepDive || filter === 'quote_verified' && chain.transferability === filter || filter === 'rpc_failed' && !chain.rpc?.ok));
  const visible = state.showAllChains || query || filter !== 'all' ? filtered : filtered.slice(0, 8);
  $('#chain-list').innerHTML = visible.map((chain, index) => {
    const route = transferState(chain);
    const status = chain.status === 'ready' ? 'ready' : chain.status === 'candidate' ? 'candidate' : '';
    const statusText = stateLabel(chain.status, chainStateLabels);
    return `<tr>
      <td><div class="chain-name"><span class="chain-rank">${String(index + 1).padStart(2, '0')}</span><span class="status-dot ${status === 'ready' ? 'live' : status === 'candidate' ? 'warn' : ''}"></span><div><strong>${escapeHTML(chain.name)}</strong><span class="chain-id">#${escapeHTML(chain.chainId)}</span><div class="sub-label">${escapeHTML(statusText)}</div></div></div></td>
      <td><span class="value-label">${escapeHTML(chain.peakTvlLabel)}</span><div class="sub-label">${formatDate(chain.peakAt, false)}</div></td>
      <td><span class="value-label">${escapeHTML(chain.currentTvlLabel)}</span><div class="sub-label">峰值 ${(Number(chain.currentToPeakRatio || 0) * 100).toFixed(1)}%</div></td>
      <td><span class="route-status ${route.className}"><span class="status-dot ${route.className === 'verified' ? 'live' : route.className === 'connection' ? 'warn' : 'danger'}"></span>${route.label}</span></td>
      <td><span class="rpc-status ${chain.rpc?.ok ? 'ok' : chain.rpc?.error ? 'fail' : 'wait'}"><span class="status-dot ${chain.rpc?.ok ? 'live' : chain.rpc?.error ? 'danger' : 'warn'}"></span>${chain.rpc?.ok ? '已验证' : chain.rpc?.error ? '失败' : '待探测'}</span><div class="sub-label">${chain.rpc?.blockNumber ? `#${Number(chain.rpc.blockNumber).toLocaleString()}` : '--'}</div></td>
      <td class="score-cell"><span class="score-number">${score(chain.priorityScore)}</span><div class="score-track"><span style="width:${Math.min(100, Number(chain.priorityScore || 0))}%"></span></div></td>
    </tr>`;
  }).join('');
  if (!visible.length) $('#chain-list').innerHTML = '<tr><td colspan="6" class="sub-label">暂无链筛选报告</td></tr>';
}

function renderRoutes(snapshot) {
  const routes = snapshot.routes || [];
  if (!routes.length) {
    const connectionOnly = (snapshot.chains || []).flatMap((chain) => (chain.connectionRoutes || []).slice(0, 1).map((route) => ({ ...route, fromChain: chain.name })));
    $('#route-list').innerHTML = connectionOnly.length ? connectionOnly.slice(0, 4).map((route) => routeHTML(route, 'connection_only')).join('') : '<div class="route-empty">当前没有可展示的报价；仅兼容性连接仍需进一步验证。</div>';
    $('#route-foot').textContent = `${connectionOnly.length} 条兼容性连接`;
    return;
  }
  $('#route-list').innerHTML = routes.slice(0, 5).map((route) => routeHTML(route, 'quote_verified')).join('');
  $('#route-foot').textContent = `${routes.length} 条历史报价 · 转移前需重新报价`;
}

function routeHTML(route, type) {
  const verified = type === 'quote_verified';
  return `<div class="route-entry"><div class="route-origin"><span class="route-arrow">↗</span><div><strong>${escapeHTML(route.fromChain || '未知链')}</strong><small>链 ${escapeHTML(route.fromChainId || '--')} → ${escapeHTML(route.toChainId || '--')}</small></div></div><div class="route-detail"><div><span>状态</span><b class="${verified ? 'teal-text' : ''}">${verified ? '历史报价 · 待重询' : '仅兼容性连接'}</b></div><div><span>工具</span><b>${escapeHTML(route.tool || '兼容性层')}</b></div><div><span>预计输出 · 最小单位</span><b>${escapeHTML(route.quotedToAmount || (route.connectionCount ? `${route.connectionCount} 条连接` : '--'))}</b></div></div>${verified ? `<p class="route-observed">采集于 ${formatDate(route.observedAt)} · 不代表此刻仍可成交</p>` : ''}</div>`;
}

function renderChart(chains) {
  const values = chains.filter((chain) => chain.peakTvlUsd > 0).slice(0, 6);
  $('#value-chart').innerHTML = values.map((chain) => `<div class="retention-row"><span>${escapeHTML(chain.name)}</span><div class="retention-track"><i style="width:${Math.min(100, Math.max(0, chain.currentToPeakRatio * 100))}%"></i></div><b>${(chain.currentToPeakRatio * 100).toFixed(1)}%</b><small>${escapeHTML(chain.currentTvlLabel)} / ${escapeHTML(chain.peakTvlLabel)}</small></div>`).join('');
  $('.chart-axis').textContent = '横轴：当前锁定资产估值 / 历史峰值（每条链单独对比）';
  $('#value-foot').textContent = `来源：筛选报告 · ${formatDate(state.snapshot?.lastReportAt)}`;
}

function renderFindings(findings) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4, High: 1, Medium: 2, Low: 3, Informational: 4 };
  const ordered = [...findings].sort((a, b) => (rank[a.severity || a.impact] ?? 5) - (rank[b.severity || b.impact] ?? 5));
  const visible = state.showAllFindings ? ordered : ordered.slice(0, 5);
  $('#finding-count').textContent = `${ordered.length} 条`;
  $('#finding-list').innerHTML = visible.map((finding) => {
    const impact = String(finding.severity || finding.impact || '').trim();
    const confidence = String(finding.confidence || '').trim();
    const protocol = finding.protocol || finding.target || '未知协议';
    const chain = finding.chain || finding.contract || '未知链';
    const title = finding.title || finding.check || '未命名观察';
    const statusLabels = { unconfirmed_observation: '未确认观察', static_signal: '静态信号', poc_confirmed: 'PoC 已确认', poc_failed: 'PoC 未复现', invariant_violated: '不变量被打破' };
    const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
    const evidenceDetails = evidence.length ? `<details class="finding-evidence"><summary>证据 ${evidence.length} 条</summary>${evidence.map((item) => `<div><small>${escapeHTML(item.file || '未知文件')}${item.lineStart ? ` · L${escapeHTML(item.lineStart)}${item.lineEnd && item.lineEnd !== item.lineStart ? `–L${escapeHTML(item.lineEnd)}` : ''}` : ''}</small><blockquote>${escapeHTML(item.quote || '')}</blockquote></div>`).join('')}</details>` : '';
    const severityScore = Number.isFinite(finding.severityScore) ? `<small class="finding-severity-score">风险分 ${escapeHTML(finding.severityScore)}</small>` : '';
    const capital = typeof finding.minCapitalRequiredWei === 'string' ? `<small class="finding-severity-score">触发资金 ${escapeHTML(finding.minCapitalRequiredWei)} wei</small>` : '';
    return `<div class="finding-entry"><span class="severity ${(impact || 'info').toLowerCase()}">${escapeHTML(severityLabels[impact] || impact || '未分级')}</span><div><strong>${escapeHTML(title)}</strong><small>${escapeHTML(protocol)} · ${escapeHTML(chain)}${finding.address ? ` · ${escapeHTML(finding.address)}` : ''}</small><span class="finding-status">${escapeHTML(statusLabels[finding.status] || finding.status || '状态未记录')}</span>${severityScore}${capital}${evidenceDetails}</div><span class="finding-confidence">置信度 ${escapeHTML(confidenceLabels[confidence] || confidence || '未提供')}</span></div>`;
  }).join('');
  if (!visible.length) $('#finding-list').innerHTML = '<div class="sub-label">暂无高优先级待核验结果</div>';
}

function chainStatusLabel(chain) {
  if (chain.status === 'tested') return [chainStateLabels.tested, 'tested'];
  if (chain.status === 'test_available') return [chainStateLabels.test_available, 'available'];
  return [chainStateLabels.needs_test, 'needs-test'];
}

function renderVulnerabilityChains(chains, testReport) {
  const tested = chains.filter((chain) => chain.status === 'tested').length;
  $('#vulnerability-summary').textContent = `${tested}/${chains.length} 路径本地回归通过`;
  $('#security-tests-note').textContent = testReport?.complete ? 'Hardhat + Foundry 本地套件通过' : '全套未完成，请查看测试明细';
  if (!chains.length) { $('#vulnerability-list').textContent = '尚无链路分析报告'; return; }
  const chain = chains.find((item) => item.id === state.selectedPath) || chains[0];
  state.selectedPath = chain.id;
  const stamp = JSON.stringify({ chains, testReport, selected: chain.id });
  if (stamp === state.lastVulnRender) return;
  state.lastVulnRender = stamp;
  $('#vulnerability-tabs').innerHTML = chains.map((item, index) => `<button role="tab" aria-selected="${item.id === chain.id}" data-path="${escapeHTML(item.id)}"><span>0${index + 1}</span>${escapeHTML(item.title)}</button>`).join('');
  const [statusLabel] = chainStatusLabel(chain);
  $('#vulnerability-list').innerHTML = `<div class="lab-path"><div class="lab-path-header"><span class="eyebrow">路径验证 / 证据</span><span class="chain-state ${chain.status === 'tested' ? 'tested' : 'available'}">${statusLabel} · 未确认可利用</span></div><h3 class="lab-title">${escapeHTML(chain.title)}</h3><p class="lab-description">${escapeHTML(chain.interpretation)}</p><div class="lab-flow">${chain.steps.map((step, index) => `<div class="lab-step"><span class="lab-step-number">0${index + 1}</span><b>${escapeHTML(step.label)}</b><p>${escapeHTML(step.detail)}</p></div>`).join('')}</div><div class="lab-note">${escapeHTML(chain.validationScope || '本地回归，不等于主网验证。')}</div><details><summary>复现命令与回归输出</summary><code class="reproduce-command">${escapeHTML(chain.reproduceCommand)}</code><pre>${escapeHTML(chain.localTest?.output || '尚未运行')}</pre></details></div>
  <aside class="lab-evidence"><h4>证据与防护门槛</h4>${chain.sourceChecks.map((check) => `<div class="lab-check"><span class="status-dot ${check.ok ? 'live' : 'warn'}"></span><div><b>${escapeHTML(check.label)}</b><code>${escapeHTML(check.ref)}</code><small>源码文本检查：${check.ok ? '匹配' : '未匹配'}，不等于形式化证明</small>${check.snippet ? `<details class="lab-source-context"><summary>源码上下文 · ${escapeHTML(check.file)}#L${check.line}</summary><pre>${escapeHTML(check.snippet)}</pre></details>` : ''}</div></div>`).join('')}
  <details><summary>Slither 关联证据 · ${chain.evidence.length} 条</summary>${chain.evidence.map((evidence) => `<div class="lab-signal"><b>${escapeHTML(evidence.check)}</b><code>${escapeHTML(evidence.source)}</code><p>${escapeHTML(evidence.markdown.slice(0, 600))}</p></div>`).join('')}</details>
  <details><summary>本地套件与源码版本</summary><p class="lab-note">${chain.localTest?.sourceMatches ? '报告源码指纹匹配' : '结果过期或尚未绑定源码'}</p>${(testReport?.suites || []).map((suite) => `<p class="lab-note">${escapeHTML(suite.label)}：${escapeHTML(suite.status)}</p>`).join('')}</details></aside>`;
}

function renderRuntime(run) {
  if (!run) { $('#soak-caption').textContent = '尚未启动三小时测试'; return; }
  const elapsed = Math.floor((run.durationMs || 0) / 60000);
  const target = Math.round((run.targetDurationMs || 10800000) / 60000);
  const label = run.stale ? '心跳中断' : ({ running: '观测进行中', completed: '观测通过', failed: '发现失败', interrupted: '已中断' }[run.state] || '未验证');
  $('#soak-state').textContent = label;
  $('#soak-time').textContent = `${elapsed} / ${target} 分钟`;
  $('#soak-progress').value = Math.min(100, (run.durationMs || 0) / (run.targetDurationMs || 10800000) * 100);
  $('#soak-samples').textContent = `${run.sampleCount || 0} 轮采样 · ${run.failures || 0} 次失败 · ${formatDate(run.updatedAt)} 更新`;
  $('#soak-caption').textContent = '网页请求 · 实时事件推送 · 状态一致性 · 云端通道配置状态；按真实观测窗口记录。';
  $('#runtime-latency').textContent = run.latencyMs?.p95 == null ? '--' : `${run.latencyMs.p95} ms`;
}

async function loadStatus() {
  const response = await fetch('/api/status', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  renderSnapshot(await response.json());
  clearGlobalError();
}

async function refreshHealth() {
  try {
    const response = await fetch('/api/health', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
    const health = await response.json();
    const ok = response.ok && health.status !== 'down';
    $('#runtime-memory').textContent = health.memory?.rss ? `${(health.memory.rss / 1048576).toFixed(0)} MB` : '--';
    $('#runtime-uptime').textContent = `运行 ${Math.floor((health.uptimeSec || 0) / 60)} 分钟`;
    const text = ok ? (health.status === 'degraded' ? '降级' : '在线') : '异常';
    $('#service-health').textContent = text;
    // 圆点跟着文字走：在线=teal，降级/异常=amber/red，颜色不是唯一线索。
    setHealthIndicator('#service-dot', '#service-health', text, ok ? (health.status === 'degraded' ? 'warn' : 'ok') : 'danger');
  } catch {
    $('#service-health').textContent = '离线';
    setHealthIndicator('#service-dot', '#service-health', '离线', 'danger');
  }
}

function addMessage(role, content) {
  const stream = $('#ask-messages');
  const message = document.createElement('div');
  message.className = `message ${role}`;
  const tag = document.createElement('span');
  tag.className = 'message-tag';
  tag.textContent = role === 'user' ? '提问者' : '状态';
  const paragraph = document.createElement('p');
  paragraph.textContent = content;
  message.append(tag, paragraph);
  stream.appendChild(message);
  while (stream.children.length > 40) stream.firstElementChild.remove();
  stream.scrollTop = stream.scrollHeight;
}

async function ask(question) {
  const value = String(question || '').trim();
  if (!value || state.asking) return;
  state.asking = true;
  $('#ask-form button').disabled = true;
  addMessage('user', value);
  $('#ask-status').textContent = '正在读取当前快照…';
  try {
    const response = await fetch('/api/ask', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: value, useModel: false }), signal: AbortSignal.timeout(55000) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '问答失败');
    addMessage('assistant', data.answer + (data.evidence?.length ? `\n\n证据：${data.evidence.slice(0, 2).join('；')}` : ''));
    $('#ask-status').textContent = data.fallbackReason || '结构化状态回答 · 事实绑定快照';
  } catch (error) {
    addMessage('assistant', `读取失败：${error.message}`);
    $('#ask-status').textContent = '问答暂不可用';
  } finally { state.asking = false; $('#ask-form button').disabled = false; }
}

$('#vulnerability-tabs').addEventListener('click', (event) => { const tab = event.target.closest('[data-path]'); if (!tab) return; state.selectedPath = tab.dataset.path; renderVulnerabilityChains(state.snapshot.vulnerabilityChains, state.snapshot.staticAnalysis.localSecurityTests); });
for (const id of ['#chain-search', '#chain-filter']) $(id).addEventListener('input', () => { if (state.snapshot) renderChains(state.snapshot.chains); });
$('#refresh-button').addEventListener('click', async () => {
  const button = $('#refresh-button');
  // 首页路由下必须重新拉取 /api/status 与采集控制面状态，
  // 否则用户点“刷新状态”看到的还是首次读到的缓存。
  // 这一分支的取数逻辑由「首页」任务接管；这里只负责外观反馈。
  if (parseWorkspaceRoute().name === 'home') {
    $('#service-health').textContent = '同步中';
    setRefreshing(true);
    try {
      await refreshHomeView({ reloadSnapshot: true });
      $('#service-health').textContent = '在线';
    } catch (error) {
      $('#service-health').textContent = '离线';
      homeMessage(`刷新失败：${error?.message || error}`, 'error');
    } finally {
      setRefreshing(false);
    }
    return;
  }
  $('#service-health').textContent = '同步中';
  setRefreshing(true);
  try {
    await loadStatus();
    $('#service-health').textContent = '在线';
    clearGlobalError();
  } catch (error) {
    $('#service-health').textContent = '离线';
    // 读取失败必须说清失败原因并给出重试入口，不能静默白屏。
    showGlobalError(describeError(error), () => { void $('#refresh-button')?.click(); });
  } finally {
    setRefreshing(false);
  }
});
$('#task-refresh').addEventListener('click', () => loadTaskPage({ reset: true }));
$('#task-next').addEventListener('click', () => {
  const cursor = state.taskPage?.page?.nextCursor;
  if (state.taskPage?.page?.hasMore && typeof cursor === 'string' && cursor) {
    loadTaskPage({ cursor });
  }
});
$('#task-prev').addEventListener('click', () => {
  if (state.taskPageIndex > 0) {
    const targetIndex = state.taskPageIndex - 1;
    loadTaskPage({ cursor: state.taskCursors[targetIndex], targetIndex });
  }
});
$('#close-report-dialog').addEventListener('click', () => $('#task-report-dialog').close());
// 失败横幅的关闭按钮：只是收起提示，不会改动页面上的数据。
$('#global-banner-close')?.addEventListener('click', () => { const banner = $('#global-banner'); if (banner) banner.hidden = true; });
$('#ask-form').addEventListener('submit', (event) => { event.preventDefault(); const input = $('#ask-input'); const value = input.value; input.value = ''; ask(value); });
document.querySelectorAll('[data-question]').forEach((button) => button.addEventListener('click', () => ask(button.dataset.question)));
$('#show-all-chains').addEventListener('click', (event) => { state.showAllChains = !state.showAllChains; event.currentTarget.innerHTML = state.showAllChains ? '收起队列 <span>↑</span>' : '查看队列 <span>→</span>'; if (state.snapshot) renderChains(state.snapshot.chains); });
$('#show-all-findings').addEventListener('click', (event) => { state.showAllFindings = !state.showAllFindings; event.currentTarget.innerHTML = state.showAllFindings ? '收起分析 <span>↑</span>' : '展开分析 <span>→</span>'; if (state.snapshot) renderFindings(state.snapshot.highPriorityFindings); });

/* ------------------------------------------------------------------
 * 抽屉（窄屏导航）的交互接线。
 *
 * 三条约定：
 *   1. 汉堡按钮是唯一的开关，aria-expanded 始终反映真实状态。
 *   2. Esc 关闭抽屉并把焦点还给汉堡按钮（焦点不能落在已隐藏的元素上）。
 *   3. 窄屏下点导航项后自动收起抽屉，否则新页面会被抽屉盖住。
 * ------------------------------------------------------------------ */
$('#nav-toggle')?.addEventListener('click', () => {
  if (document.body.classList.contains('nav-drawer-open')) closeDrawer({ restoreFocus: true });
  else openDrawer();
});
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (!document.body.classList.contains('nav-drawer-open')) return;
  closeDrawer({ restoreFocus: true });
});
// 窄屏点导航项后收起抽屉；桌面宽度下不干预（抽屉本就不存在）。
document.querySelectorAll('.nav-item').forEach((link) => link.addEventListener('click', () => {
  if (isDrawerMode()) closeDrawer();
}));
// 视口跨过断点时复位：回到桌面布局后不留一个「看不见却开着」的抽屉。
const drawerQuery = window.matchMedia(SIDEBAR_BREAKPOINT);
const onDrawerBreakpointChange = () => { if (!isDrawerMode()) setDrawerOpen(false); };
if (typeof drawerQuery.addEventListener === 'function') drawerQuery.addEventListener('change', onDrawerBreakpointChange);
else if (typeof drawerQuery.addListener === 'function') drawerQuery.addListener(onDrawerBreakpointChange);

try {
  const events = new EventSource('/api/events');
  events.addEventListener('snapshot', (event) => { try { renderSnapshot(JSON.parse(event.data)); } catch {} });
  events.addEventListener('snapshot-error', () => { $('#service-health').textContent = '读取异常'; });
  events.addEventListener('error', () => { $('#service-health').textContent = '重连中'; });
} catch {}
loadStatus().catch((error) => {
  $('#service-health').textContent = '离线';
  setHealthIndicator('#service-dot', '#service-health', '离线', 'danger');
  $('#updated-at').textContent = `读取失败：${error.message}`;
  // 首次读取失败也要说清并给重试入口，不能只剩一片空白。
  showGlobalError(describeError(error), () => { void loadStatus().catch((retryError) => {
    showGlobalError(describeError(retryError), () => { void loadStatus().catch(() => {}); });
  }); });
});
loadTaskPage({ reset: true });
refreshHealth();
setInterval(() => { if (!document.hidden) refreshHealth(); }, 15000);
// 链上采集开关：状态与采集进程分开轮询，切换后立刻刷新。
$('#collection-switch-toggle')?.addEventListener('click', () => { void toggleCollectionSwitch(); });
$('#collection-chain-scope')?.addEventListener('change', () => { void loadCollectionStatus(); });
void loadCollectionStatus();
startCollectionPolling();
const sections = ['overview', 'analysis-tasks', 'chains', 'routes', 'vulnerability-chains', 'findings', 'sync'].map((id) => document.getElementById(id));
let navFrame = null;
function syncNavigation() {
  navFrame = null;
  if (state.workspaceRoute) {
    setActiveView(state.workspaceRoute);
    return;
  }
  const current = [...sections].reverse().find((section) => section.getBoundingClientRect().top <= innerHeight * .25) || sections[0];
  const currentHash = current?.id || 'overview';
  const isOverviewSection = OVERVIEW_ANCHOR_HASHES.includes(currentHash);
  // 旧总览内部的显式锚点优先：「分析队列」「模型与同步」都有独立入口，
  // 点击后必须高亮自己，不能又被滚动位置改回「旧版总览」。
  const requestedHash = location.hash.replace(/^#/, '');
  const overviewNavHash = requestedHash === 'analysis-tasks' || requestedHash === 'sync'
    ? requestedHash
    : 'overview';
  document.querySelectorAll('.nav-item').forEach((link) => {
    const hash = link.getAttribute('href')?.slice(1) || '';
    // 旧总览内部滚动：高亮「旧版总览」；「分析队列」有自己的入口，单独高亮它。
    const active = isOverviewSection
      ? (overviewNavHash === 'analysis-tasks' ? hash === 'analysis-tasks' : hash === overviewNavHash)
      : hash === currentHash;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'location'); else link.removeAttribute('aria-current');
  });
}
function scheduleNavigation() { if (navFrame === null) navFrame = requestAnimationFrame(syncNavigation); }
addEventListener('scroll', scheduleNavigation, { passive: true });
addEventListener('resize', scheduleNavigation);
syncNavigation();

// 注意：路由首次渲染（routeWorkspace()）必须放在文件末尾的「启动段」里。
// workspaceFrame() 会同步读取 WORKSPACE_FLAG_CLASS 等模块级常量；
// 若在这里就调用 routeWorkspace()，那些常量尚未初始化（暂时性死区），
// 整个模块求值会中断 —— 页面只剩静态 HTML，所有交互失效。
// 首次渲染与 hashchange 监听统一放到文件末尾启动段执行。

function setDetailsHTML(element, html) {
  if (element.innerHTML === html) return;
  const opened = new Set([...element.querySelectorAll('details[open][data-key]')].map(x=>x.dataset.key));
  element.innerHTML = html;
  element.querySelectorAll('details[data-key]').forEach(x=>{ x.open=opened.has(x.dataset.key); });
}
function renderCampaignResult(x) {
  const statusLabel = {source_reviewed:'源码已审查',source_review_unavailable:'历史审查未完成',blocked:'待补证据',duplicate_source:'源码已去重'}[x.state] || stateLabel(x.state, evidenceStateLabels);
  const observations = (x.observations || []).map(o=>`<div class="campaign-observation"><b>${({risk_hypothesis:'待验证假设',security_control:'防护观察',coverage_gap:'覆盖缺口'})[o.kind] || '未分类观察'} · ${escapeHTML(o.title)}</b>${(o.evidence || []).map(e=>`<small>${escapeHTML(e.file)} · L${displayCount(e.lineStart)}–L${displayCount(e.lineEnd)}</small><code>${escapeHTML(e.quote)}</code>`).join('')}</div>`).join('');
  const graph = x.staticAnalysis?.callGraph;
  const unifiedIR = x.staticAnalysis?.unifiedIR;
  const discoveryPlan = x.staticAnalysis?.discoveryPlan;
  const discovery = discoveryPlan && ['planned','partial'].includes(discoveryPlan.state)
    ? `<p>业务验证计划：${displayCount(discoveryPlan.obligationCount)} 个入口 · ${displayCount(discoveryPlan.propertyCount)} 类性质；夹具通过 ${displayCount(discoveryPlan.fixturePassedPropertyCount)} 类，待测 ${displayCount(discoveryPlan.untestedPropertyCount)} 类。路径级验证 ${displayCount(discoveryPlan.pathSpecificPropertiesVerified)} 条；夹具通过不代表对应路径已经验证。</p><small>交互证据视图：${escapeHTML(discoveryPlan.html || '')}</small>`
    : discoveryPlan?.state === 'unavailable' ? `<p>业务验证计划不可用：${escapeHTML(discoveryPlan.reason || '')}</p>` : '';
  const graphCoverage = graph?.state === 'partial' ? `部分覆盖：省略路径 ${displayCount(graph.truncatedPathCount)} · 省略入口 ${displayCount(graph.truncatedEntrypointCount)} · 深度截断 ${displayCount(graph.depthCutoffEdgeCount)} · 遍历上限 ${graph.walkBudgetExceeded ? '已触及' : '未触及'}。` : '';
  const staticDetail = ['completed','partial'].includes(graph?.state)
    ? `<p>Slither（静态检测器）${escapeHTML(stateLabel(x.staticAnalysis.state))} · ${displayCount(x.staticAnalysis.detectors)} 个检测器 / ${displayCount(x.staticAnalysis.findingCount)} 条待复核线索。源码调用图：入口 ${displayCount(graph.entrypointCount)} · 状态写入路径 ${displayCount(graph.stateWritePathCount)} · 外部调用路径 ${displayCount(graph.externalCallPathCount)} · 资产调用路径 ${displayCount(graph.assetRelatedCallPathCount)}；均为静态候选，不代表可达或可利用。</p><small>调用图证据：${escapeHTML(graph.report || '')}</small>${unifiedIR?.documentId ? `<small>统一代码记录：${escapeHTML(unifiedIR.documentId)} · ${escapeHTML(unifiedIRReadableSummary(unifiedIR))}</small>` : ''}`
    : x.staticAnalysis ? `<p>静态分析：${escapeHTML(stateLabel(x.staticAnalysis.state))} · ${escapeHTML(x.staticAnalysis.staticError || '调用图或静态检测结果不可用')}</p>` : '';
  const dynamicTests = x.dynamicAnalysis?.tests;
  const dynamicResult = dynamicTests === null || dynamicTests === undefined
    ? `${escapeHTML(stateLabel(x.dynamicAnalysis?.state))}：${escapeHTML(x.dynamicAnalysis?.reason || '未提供原因')}`
    : `${displayCount(x.dynamicAnalysis.passed)}/${displayCount(dynamicTests)} 项通过，${displayCount(x.dynamicAnalysis.failed)} 项失败；`;
  const dynamic = x.dynamicAnalysis
    ? `<p>本地隔离检查：${dynamicResult} ${dynamicTransactionSummary(x.dynamicAnalysis)} ${dynamicExecutionBoundarySummary(x.dynamicAnalysis)}${x.dynamicAnalysis.sourceCoverage?.spanCount != null ? `采样源码位置 ${displayCount(x.dynamicAnalysis.sourceCoverage.spanCount)} 处。` : ''} ${escapeHTML((x.dynamicAnalysis.limitations || []).join('；'))}</p>${x.dynamicAnalysis.failureEvidence ? `<p>${escapeHTML(dynamicFailureEvidenceSummary(x.dynamicAnalysis.failureEvidence))}</p>${dynamicFailureEvidenceDetails(x.dynamicAnalysis.failureEvidence)}` : ''}${x.dynamicAnalysis.report?`<small>动态证据：${escapeHTML(x.dynamicAnalysis.report)}</small>`:''}${x.dynamicAnalysis.unifiedIR?.documentId?`<small>统一代码记录：${escapeHTML(x.dynamicAnalysis.unifiedIR.documentId)} · ${escapeHTML(unifiedIRReadableSummary(x.dynamicAnalysis.unifiedIR))}</small>`:''}` : '';
  const bytecodeIR = x.runtimeBytecodeAnalysis?.unifiedIR;
  const bytecode = x.runtimeBytecodeAnalysis
    ? x.runtimeBytecodeAnalysis.state === 'completed'
      ? `<p>运行时代码反汇编（${stateLabel(x.runtimeBytecodeAnalysis.state)}）${displayCount(x.runtimeBytecodeAnalysis.instructionCount)} 条指令 · 选择器候选 ${displayCount(x.runtimeBytecodeAnalysis.selectorCandidateCount)} · 调用点 ${displayCount(x.runtimeBytecodeAnalysis.externalCallSiteCount)} · 存储操作 ${displayCount(x.runtimeBytecodeAnalysis.storageOperationSiteCount)}；不是高层反编译。</p>${bytecodeIR?.documentId ? `<small>统一代码记录：${escapeHTML(bytecodeIR.documentId)} · ${escapeHTML(unifiedIRReadableSummary(bytecodeIR))}</small>` : ''}`
      : `<p>运行时代码反汇编：${escapeHTML(stateLabel(x.runtimeBytecodeAnalysis.state))} · ${escapeHTML(x.runtimeBytecodeAnalysis.reason || '未提供原因')}</p>`
    : '';
  return `<details data-key="${escapeHTML(`${x.chainId}:${x.address}`)}"><summary><span>${escapeHTML(x.chain)} · ${escapeHTML(x.protocol)}</span><b class="${x.state==='source_reviewed'?'teal-text':'amber-text'}">${escapeHTML(statusLabel)}</b></summary><code>${escapeHTML(x.address)}</code>${x.originProxy?`<small>代理实现 · 来源 ${escapeHTML(x.originProxy)}</small>`:''}<p>${escapeHTML(x.error || x.reviewSummary || '原始证据已留档；自动分析不构成漏洞确认。')}</p>${observations}${staticDetail}${graphCoverage?`<p class="amber-text">${escapeHTML(graphCoverage)}</p>`:''}${discovery}${dynamic}${bytecode}<small>${escapeHTML(x.evidence)}</small></details>`;
}

function stageCount(counts, key) {
  const value = counts?.[key];
  return value === null || value === undefined || value === '' || !Number.isSafeInteger(Number(value)) || Number(value) < 0
    ? '未记录' : Number(value).toLocaleString('zh-CN');
}

function stageState(value, labels, fallback = '未记录') {
  return labels[String(value || '')] || fallback;
}

function renderStageSummary(run, counts, snapshot) {
  const collectionState = stageState(run?.observedState || run?.state, {
    initializing: '准备采集', running: '正在采集', waiting_for_new_candidates: '等待新目标',
    draining: '正在收尾', completed: '采集已完成', queue_exhausted: '队列已处理完',
    interrupted: '采集中断', invalidated: '记录已作废', failed: '采集失败', stale: '记录已过期',
  }, '尚未开始');
  const qualified = run?.qualifiedProtocolChains ?? counts.qualifiedProtocolChains;
  const processed = stageCount(counts, 'runtimeBytecodeAnalyses');
  const source = stageCount(counts, 'verifiedSourceBundles');
  const reviews = stageCount(counts, 'sourceReviews');
  const cloudReviews = stageCount(counts, 'cloudReviewCompletions');
  const staticCount = stageCount(counts, 'staticAnalyses');
  const dynamicCount = stageCount(counts, 'dynamicTestsPerformed' in (counts || {}) ? 'dynamicTestsPerformed' : 'localTestsPerformed');
  const findings = stageCount(counts, 'reviewHypotheses');
  const rawFindings = counts?.reviewHypotheses;
  const discoveryBlocked = stageCount(counts, 'discoveryBlocked');
  const contractBlocked = stageCount(counts, 'contractBlocked');
  const staticUnavailable = stageCount(counts, 'staticAnalysisUnavailable');
  const failedDynamic = stageCount(counts, 'dynamicTestsFailed' in (counts || {}) ? 'dynamicTestsFailed' : 'localTestsFailed');
  const currentState = collectionState === '采集中断' || collectionState === '记录已过期' || collectionState === '采集失败'
    ? collectionState : `采集状态：${collectionState}`;
  const campaignTimestamp = run?.updatedAt ? `采集记录更新于 ${formatDate(run.updatedAt)}` : '采集记录更新时间未记录';
  const snapshotTimestamp = snapshot?.generatedAt ? `总览更新于 ${formatDate(snapshot.generatedAt)}` : '总览更新时间未记录';
  $('#stage-summary-updated').textContent = `${currentState} · ${campaignTimestamp} · ${snapshotTimestamp}`;
  const stages = [
    {
      number: '01', kind: 'collection', title: '采集', state: collectionState,
      primary: `筛选到 ${stageCount({ value: qualified }, 'value')} 个项目 / 链`,
      facts: [`已尝试 ${stageCount(counts, 'protocolChainsAttempted')} 个项目 / 链`, `已发现地址 ${stageCount(counts, 'protocolChainsWithAddresses')} 个项目 / 链`],
      note: `受阻：发现 ${discoveryBlocked} 项 · 合约 ${contractBlocked} 项`,
    },
    {
      number: '02', kind: 'processing', title: '处理', state: processed === '未记录' ? '等待记录' : '已有处理记录',
      primary: `读取到 ${processed} 份链上代码`,
      facts: [`已验证源码 ${source} 份`, `历史审查记录 ${reviews} 次`],
      note: `合约获取受阻 ${contractBlocked} 项`,
    },
    {
      number: '03', kind: 'analysis', title: '分析', state: staticCount === '未记录' && dynamicCount === '未记录' ? '等待记录' : '已有分析记录',
      primary: `自动检查 ${staticCount} 份`,
      facts: [`本地模拟测试 ${dynamicCount} 项`, `云端复核完成 ${cloudReviews} 次`],
      note: `自动检查不可用 ${staticUnavailable} 项`,
    },
    {
      number: '04', kind: 'results', title: '结果', state: rawFindings == null ? '等待记录' : Number(rawFindings) === 0 ? '暂无线索' : '待人工核对',
      primary: `${findings} 项待核验线索`,
      facts: [`本地模拟未通过 ${failedDynamic} 项`, '线索仍需人工复核'],
      note: '未通过或有线索，都不等于漏洞已确认',
    },
  ];
  const target = document.getElementById('stage-summary-grid');
  if (!target) return;
  target.innerHTML = stages.map((stage) => `<article class="stage-card stage-${stage.kind}"><div class="stage-card-top"><span class="stage-number">${stage.number}</span><h4>${stage.title}</h4><span class="stage-state">${escapeHTML(stage.state)}</span></div><strong class="stage-primary">${escapeHTML(stage.primary)}</strong><ul class="stage-facts">${stage.facts.map((fact) => `<li>${escapeHTML(fact)}</li>`).join('')}</ul><p class="stage-blocker"><b>${stage.kind === 'results' ? '说明' : '待补'}</b> ${escapeHTML(stage.note)}</p></article>`).join('');
}

function renderCampaign(run, rpc, snapshot) {
  const counts = run?.counts || {};
  const labels = [['protocolChainsAttempted','项目 / 链已尝试'],['deployedContracts','有部署代码'],['verifiedSourceBundles','已取源码'],['sourceReviews','历史审查记录'],['staticAnalyses','自动代码检查'],['staticCallGraphs','候选风险路径'],['runtimeBytecodeAnalyses','链上代码读取'],['dynamicTestsPerformed','本地模拟测试']];
  const displayCount = (key) => Object.hasOwn(counts, key) && Number.isSafeInteger(Number(counts[key])) && Number(counts[key]) >= 0 ? Number(counts[key]) : '未记录';
  $('#campaign-counters').innerHTML = labels.map(([key,label])=>`<div><b>${displayCount(key)}</b><span>${label}</span></div>`).join('');
  renderStageSummary(run, counts, snapshot);
  const campaignStateLabel = {initializing:'准备中',running:'正在采集分析',waiting_for_new_candidates:'等待新候选',draining:'正在结束已发出的请求',completed:'采集窗口结束',queue_exhausted:'队列已处理完',interrupted:'已中断',invalidated:'源码变更 / 窗口作废',failed:'运行失败',stale:'心跳过期 / 进程退出'}[run?.observedState || run?.state] || '尚未启动';
  $('#campaign-title').textContent = '合约采集任务';
  $('#soak-state').textContent = campaignStateLabel;
  const durationMs = run?.durationMs == null ? null : Number(run.durationMs);
  const targetDurationMs = run?.targetDurationMs == null ? null : Number(run.targetDurationMs);
  const hasDurations = Number.isFinite(durationMs) && durationMs >= 0 && Number.isFinite(targetDurationMs) && targetDurationMs > 0;
  $('#soak-time').textContent = hasDurations ? `${Math.floor(durationMs / 60000)} / ${Math.round(targetDurationMs / 60000)} 分钟` : '未记录';
  $('#soak-progress').value = hasDurations ? Math.min(100, durationMs / targetDurationMs * 100) : 0;
  $('#soak-caption').textContent = '采集窗口结束不表示目标均已审查或分析完成。';
  $('#soak-samples').textContent = `初筛 ${displayCount(run?.qualifiedProtocolChains)} 项 · 发现阻塞 ${displayCount(counts.discoveryBlocked)} · 合约阻塞 ${displayCount(counts.contractBlocked)}`;
  $('#campaign-active').textContent = run?.active?.length ? run.active.map(x=>`${x.chain} / ${x.protocol} · ${stateLabel(x.stage, { queued: '排队中', source_review: '源码审查', static_analysis: '静态分析', dynamic_analysis: '动态分析', decompilation: '反编译', collecting: '采集中', replay: '重放中' })}`).join(' ｜ ') : '这份记录未列出正在处理的对象。';
  $('#campaign-updated').textContent = `采集 ${formatDate(run?.updatedAt)}`;
  $('#campaign-performance').textContent = `历史审查记录 ${stageCount(counts, 'sourceReviews')} 次 · 云端审查完成 ${stageCount(counts, 'cloudReviewCompletions')} 次 · 连接自动切换 ${displayCount(run?.rpc?.runtime?.failovers)} 次 · 本地模拟测试未通过 ${displayCount(counts.dynamicTestsFailed ?? counts.localTestsFailed)} 项`;
  renderAnalysisCoverage(run, counts);
  setDetailsHTML($('#campaign-results'), (run?.recent || []).slice(-6).reverse().map(renderCampaignResult).join('') || '<p class="sub-label">真实处理结果会在这里持续出现。</p>');
  const rows = rpc?.chains || [];
  const total = rows.reduce((n,x)=>n+x.healthyCount,0);
  $('#runtime-latency').textContent = `${total} 个`;
  $('#rpc-summary').textContent = `验证连接 · ${rows.filter(x=>x.healthyCount).length} 条可用链 · ${rows.filter(x=>x.redundant).length} 条备用连接 · ${formatDate(rpc?.generatedAt)}`;
  setDetailsHTML($('#rpc-pool-list'), rows.map(c=>`<details data-key="${Number(c.chainId)}"><summary><span>${escapeHTML(c.name)}</span><b>${c.healthyCount} / ${c.endpoints.length} 发现时可用</b></summary>${c.endpoints.map(e=>`<div class="rpc-node"><code>${escapeHTML(e.url)}</code><small class="${e.healthy&&!e.runtime?.coolingDown?'teal-text':'amber-text'}">${e.healthy?`${e.latencyMs} ms · 已核对`:escapeHTML(e.error)}${e.runtime?` · 调用 ${Number(e.runtime.calls)} / 错误 ${Number(e.runtime.errors)}${e.runtime.coolingDown?' · 冷却中':''}`:''}</small></div>`).join('')}</details>`).join(''));
}

function displayCount(value) {
  return value == null || !Number.isFinite(Number(value)) ? '未提供' : Number(value).toLocaleString('zh-CN');
}

function recordedCount(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function renderAnalysisCoverage(run, counts) {
  const recent = Array.isArray(run?.recent) ? run.recent : [];
  const graphsInRecent = recent.filter((item) => ['completed', 'partial'].includes(item.staticAnalysis?.callGraph?.state)).length;
  const bytecodeInRecent = recent.filter((item) => item.runtimeBytecodeAnalysis?.state === 'completed').length;
  const dynamicInRecent = recent.filter((item) => ['passed', 'partial', 'failed', 'unavailable'].includes(item.dynamicAnalysis?.state)).length;
  const staticJobs = displayCount(counts.staticAnalyses);
  const staticUnavailable = displayCount(counts.staticAnalysisUnavailable);
  const staticPartial = displayCount(counts.staticAnalysisPartials);
  const graphCount = counts.staticCallGraphs == null ? null : displayCount(counts.staticCallGraphs);
  const dynamicTests = counts.dynamicTestsPerformed ?? counts.localTestsPerformed;
  const dynamicSuites = counts.dynamicTestSuites ?? counts.localTestSuites;
  const dynamicFailures = counts.dynamicTestsFailed ?? counts.localTestsFailed;
  const deployed = counts.deployedContracts;
  const bytecodeSuccess = counts.runtimeBytecodeAnalyses;
  const bytecodeUnavailable = counts.runtimeBytecodeAnalysisUnavailable;
  const bytecodeMetric = bytecodeSuccess == null || deployed == null
    ? '未提供'
    : `${displayCount(bytecodeSuccess)} / ${displayCount(deployed)}`;
  const graphMetric = graphCount == null
    ? (recent.length ? `${graphsInRecent} / ${recent.length}` : '未提供')
    : graphCount;
  const graphScope = graphCount == null
    ? `最近结果列表中有图报告 / ${recent.length} 个条目；不是全窗口总数。`
    : `候选路径 ${displayCount(counts.staticCallGraphPaths)} · 资产流提示 ${displayCount(counts.staticAssetFlowPaths)} · 部分图 ${displayCount(counts.staticCallGraphPartials)}。`;
  const bytecodeScope = bytecodeUnavailable == null
    ? '用于了解链上代码结构，不能替代已验证源码。'
    : `${displayCount(bytecodeUnavailable)} 个目标的代码结构暂不可用。`;
  const dynamicScope = recent.length
    ? `最近结果列表 ${dynamicInRecent} / ${recent.length} 项有执行结果；仅运行已有专用测试方案的目标。`
    : '只对已有专用测试方案的目标运行；不代表覆盖所有合约。';
  const cards = [
    {
      kind: 'static', tag: '源码 · 自动检查', title: '代码规则检查', value: `${staticJobs} 份`,
      detail: `不可用 ${staticUnavailable} · 部分 ${staticPartial} · 第 95 百分位耗时 ${run?.metrics?.staticAnalysis?.p95Ms == null ? '未提供' : `${(run.metrics.staticAnalysis.p95Ms / 1000).toFixed(1)} 秒`}`,
      scope: '按静态分析作业计数；只对已取得并进入分析阶段的源码执行。线索仍需复核。',
    },
    {
      kind: 'graph', tag: '源码 · 路径线索', title: '可能的风险路径', value: graphMetric,
      unit: graphCount == null ? '有记录 / 最近目标' : '份路径记录', detail: graphScope,
      scope: '由代码结构推算的检查线索；需要人工复核。',
    },
    {
      kind: 'bytecode', tag: '部署 · 链上代码', title: '代码结构读取', value: bytecodeMetric,
      unit: '已读取 / 有部署代码目标', detail: bytecodeScope,
      scope: '基于采集时的链上代码；代理和升级实现需另行检查。',
    },
    {
      kind: 'dynamic', tag: '本地 · 模拟', title: '本地模拟测试', value: `${displayCount(dynamicTests)} 项`,
      detail: `套件 ${displayCount(dynamicSuites)} · 失败 ${displayCount(dynamicFailures)} · 最近结果 ${dynamicInRecent} 项有执行`, scope: dynamicScope,
    },
  ];
  $('#analysis-coverage-grid').innerHTML = cards.map((card) => `<article class="coverage-card coverage-${card.kind}"><div class="coverage-card-head"><span>${card.tag}</span><i aria-hidden="true"></i></div><h5>${card.title}</h5><div class="coverage-value">${escapeHTML(card.value)}${card.unit ? `<small>${escapeHTML(card.unit)}</small>` : ''}</div><p class="coverage-detail">${escapeHTML(card.detail)}</p><p class="coverage-scope">${escapeHTML(card.scope)}</p></article>`).join('');
}

/* Resource workspace routes. Every view reads a versioned API resource and
 * renders an explicit empty/blocked state instead of filling gaps with demo data. */
async function apiJSON(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options, signal: options.signal || AbortSignal.timeout(12000) });
  let payload = null;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) {
    const message = payload?.error?.message || payload?.error || `HTTP ${response.status}`;
    const error = new Error(String(message));
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload || {};
}

async function optionalResource(path) {
  try { return { ok: true, path, data: await apiJSON(path) }; }
  catch (error) { return { ok: false, path, error }; }
}

/* ------------------------------------------------------------------
 * 链上采集开关（首页一键开启）。
 *
 * 诚实性约束（见 .cursor/rules/silent-wrong-value-review.mdc）：
 *   - 「开关已打开」与「现在正在采集」是两件事，分别显示，不能混成一个状态。
 *   - 后端返回 startFailed / stopFailed 时，如实显示错误，不假装成功。
 *   - 读取失败时保持上一次显示，不清空成误导性的默认状态。
 *   - 开关状态由后端决定，前端置灰只是提示，真正的拒绝在后端。
 * ------------------------------------------------------------------ */

function collectionScopeValue() {
  const select = $('#collection-chain-scope');
  return select && select.value ? select.value : 'all';
}

/** 把选中的链换算成后端要的 chainIds 数组；'all' 表示全部链。 */
function collectionScopeChainIds(status) {
  const scope = collectionScopeValue();
  if (scope === 'all') return [];
  const chains = Array.isArray(status?.availableChains) ? status.availableChains : [];
  const wanted = String(scope).split(',').map((item) => item.trim()).filter(Boolean);
  const ids = [];
  for (const chain of chains) {
    const names = [chain.chainId, chain.name, chain.llamaName].filter((item) => item !== undefined && item !== null).map((item) => String(item));
    if (names.some((name) => wanted.includes(name))) ids.push(chain.chainId);
  }
  return ids;
}

function renderCollectionScope(status) {
  const select = $('#collection-chain-scope');
  if (!select) return;
  const chains = Array.isArray(status?.availableChains) ? status.availableChains : [];
  const current = select.value;
  const selected = Array.isArray(status?.selectedChainIds) && status.selectedChainIds.length
    ? status.selectedChainIds.map(String)
    : null;
  const signature = `${chains.map((chain) => chain.chainId).join(',')}|${selected ? selected.join(',') : ''}`;
  if (select.dataset.signature !== signature) {
    select.dataset.signature = signature;
    select.innerHTML = '<option value="all">全部链</option>'
      + chains.map((chain) => `<option value="${escapeHTML(chain.chainId)}">${escapeHTML(chain.name)} · ${escapeHTML(chain.chainId)}</option>`).join('');
    if (selected && selected.length === 1 && chains.some((chain) => chain.chainId === selected[0])) {
      select.value = selected[0];
    } else if (current && current !== 'all' && chains.some((chain) => chain.chainId === current)) {
      select.value = current;
    } else {
      select.value = 'all';
    }
  }
  const note = $('#collection-scope-note');
  if (note) {
    note.textContent = selected && selected.length
      ? `已选择 ${selected.length} 条链。`
      : `全部 ${chains.length} 条已配置链。`;
  }
}

/** 渲染开关状态。enabled 与 running 分开呈现。 */
function renderCollectionSwitch(status) {
  if (!status) return;
  const toggle = $('#collection-switch-toggle');
  const label = $('#collection-switch-label');
  const statusText = $('#collection-switch-status');
  const message = $('#collection-switch-message');
  renderCollectionScope(status);

  if (toggle) {
    toggle.setAttribute('aria-pressed', status.enabled === true ? 'true' : 'false');
    toggle.disabled = collectionBusy;
    if (label) label.textContent = status.enabled ? '关闭链上采集' : '开启链上采集';
  }
  if (statusText) {
    const stateClass = COLLECTION_STATE_CLASS[status.state] || '';
    statusText.className = `switch-status ${stateClass}`;
    statusText.textContent = status.running
      ? `正在采集 · ${status.stateLabel}`
      : status.enabled
        ? `开关已打开 · ${status.stateLabel}`
        : '开关已关闭';
  }
  if (message) {
    let text = '';
    let tone = '';
    if (status.startFailed) {
      text = `开启失败：${status.startError || '未知原因'}`;
      tone = 'danger';
    } else if (status.stopFailed) {
      text = `停止请求失败：${status.stopError || '未知原因'}`;
      tone = 'danger';
    } else if (status.lastError) {
      text = status.lastError;
      tone = 'warn';
    } else if (status.running && status.heartbeatAt) {
      text = `最近心跳 ${formatDate(status.heartbeatAt)}。采集只读链上代码与已验证源码，不执行资产操作。`;
    } else if (status.enabled) {
      text = '开关已打开，当前没有采集在运行。';
    } else {
      text = '采集未开启。开启后自动启动一轮只读采集。';
    }
    message.className = `collection-switch-message ${tone}`;
    message.textContent = text;
  }
}

async function loadCollectionStatus() {
  try {
    const data = await apiJSON('/api/v1/chain-collection/status');
    renderCollectionSwitch(data);
  } catch {
    // 读取失败时保留上一次显示，不清空成误导性的默认状态。
    const statusText = $('#collection-switch-status');
    if (statusText && statusText.textContent === '读取开关状态…') statusText.textContent = '读取开关状态失败';
  }
}

function startCollectionPolling() {
  if (collectionPollTimer) clearInterval(collectionPollTimer);
  collectionPollTimer = setInterval(() => { if (!document.hidden) void loadCollectionStatus(); }, COLLECTION_POLL_INTERVAL_MS);
}

async function toggleCollectionSwitch() {
  if (collectionBusy) return;
  const toggle = $('#collection-switch-toggle');
  const message = $('#collection-switch-message');
  const wasEnabled = toggle?.getAttribute('aria-pressed') === 'true';
  collectionBusy = true;
  if (toggle) toggle.disabled = true;
  if (message) { message.className = 'collection-switch-message'; message.textContent = wasEnabled ? '正在关闭…' : '正在开启…'; }
  try {
    // 先把范围记下来，再切开关：这样「开启」用的就是刚选的链。
    if (!wasEnabled && collectionScopeValue() !== 'all') {
      const current = await apiJSON('/api/v1/chain-collection/status');
      const chainIds = collectionScopeChainIds(current);
      if (chainIds.length === 0) throw new Error('选中的链没有匹配到任何已配置链');
      await apiJSON('/api/v1/chain-collection/switch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chainIds }) });
    }
    const data = await apiJSON('/api/v1/chain-collection/switch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled: !wasEnabled }) });
    renderCollectionSwitch(data);
  } catch (error) {
    if (message) {
      message.className = 'collection-switch-message danger';
      message.textContent = `操作失败：${error.message}`;
    }
    await loadCollectionStatus();
  } finally {
    collectionBusy = false;
    if (toggle) toggle.disabled = false;
  }
}

function workspaceItems(payload) { return Array.isArray(payload?.items) ? payload.items : []; }
function workspaceValue(value, max = 220) {
  if (value === undefined || value === null || value === '') return '未提供';
  const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
function workspaceObject(value, max = 16000) {
  const text = JSON.stringify(value ?? {}, null, 2);
  return text.length > max ? `${text.slice(0, max)}\n…已截断，原始对象仍由接口保存` : text;
}
function workspaceError(result) { return result?.error ? `读取失败：${result.error.message}` : ''; }
function workspaceStatus(message, kind = 'info') { return `<div class="workspace-status workspace-status-${kind}">${escapeHTML(message)}</div>`; }
function capabilityState(capabilities, name) {
  const capability = capabilities?.capabilities?.[name];
  if (!capability) return { label: '未声明', kind: 'unknown', limitation: '服务未声明该资源能力。' };
  if (capability.executionState === 'blocked') return { label: '执行受阻', kind: 'blocked', limitation: capability.limitation || '当前没有可用执行器。' };
  if (capability.executionState === 'available') return { label: '可执行', kind: 'available', limitation: capability.limitation || '' };
  return { label: capability.state === 'available' ? '接口可用' : '不可用', kind: capability.state === 'available' ? 'available' : 'blocked', limitation: capability.limitation || '' };
}
function readableLimitation(value) {
  const text = String(value || '');
  if (/只读采集 worker.*fail-closed/i.test(text)) return '只读取公开信息，区块范围有限；任务会由后台执行，发现链上记录变化时会停止并保留证据。';
  return text.replace(/fail-closed/gi, '停止并保留证据').replace(/runner/gi, '后台任务').replace(/worker/gi, '后台任务');
}
/* ------------------------------------------------------------------
 * 工作区通用外观与小部件。
 *
 * 三条硬约束（对每一页都成立）：
 *   1. 页头必须有「只读 / 会改数据」标记，且是图标 + 文字 + 颜色三重编码，
 *      灰度与色盲显示下也能分辨。
 *   2. 空状态必须告诉用户下一步做什么，并给可点的入口，不能只写「没有记录」。
 *   3. 会写数据的按钮旁必须写清楚「会创建 / 修改什么」。
 * ------------------------------------------------------------------ */
const WORKSPACE_FLAG_TEXT = Object.freeze({
  read: '只读 · 只查看已有记录，不改任何数据',
  write: '会改数据 · 表单会创建或修改记录',
  mixed: '含写入操作 · 记录只读，按钮会改数据',
});
const WORKSPACE_FLAG_CLASS = Object.freeze({ read: 'ws-flag-readonly', write: 'ws-flag-write', mixed: 'ws-flag-write' });
const WORKSPACE_FLAG_ICON = Object.freeze({ read: '○', write: '✎', mixed: '✎' });

function workspaceFrame({ kicker, title, description, body, footer = '', mode = 'read', next = [] }) {
  const flagKey = WORKSPACE_FLAG_CLASS[mode] ? mode : 'read';
  const steps = Array.isArray(next) ? next.filter((step) => Array.isArray(step) && step[0] && step[1]) : [];
  const nextLinks = steps.length
    ? `<nav class="ws-next" aria-label="下一步建议"><strong>下一步</strong><span>${steps.map(([hash, label]) => `<a href="${escapeHTML(hash)}">${escapeHTML(label)} <span aria-hidden="true">→</span></a>`).join('')}</span></nav>`
    : '';
  return `<div class="workspace-head ws-head"><div class="ws-head-main"><div class="eyebrow">${escapeHTML(kicker)}</div><h1>${escapeHTML(title)}</h1><p class="ws-head-lead">${escapeHTML(description)}</p><div class="ws-head-meta"><span class="ws-flag ${WORKSPACE_FLAG_CLASS[flagKey]}"><i aria-hidden="true">${WORKSPACE_FLAG_ICON[flagKey]}</i>${escapeHTML(WORKSPACE_FLAG_TEXT[flagKey])}</span></div></div><div class="ws-head-side"><a class="workspace-back" href="#overview">返回安全总览</a></div></div><div class="workspace-body">${body}${nextLinks}</div>${footer ? `<div class="workspace-footer">${escapeHTML(footer)}</div>` : ''}`;
}

/** 空状态：说明发生了什么，并给出下一步可点入口。 */
function workspaceEmpty({ title = '这里还没有记录', text = '', links = [] }) {
  const steps = Array.isArray(links) ? links.filter((step) => Array.isArray(step) && step[0] && step[1]) : [];
  const linkHtml = steps.length
    ? `<div class="ws-empty-links">${steps.map(([href, label]) => `<a href="${escapeHTML(href)}">${escapeHTML(label)} <span aria-hidden="true">→</span></a>`).join('')}</div>`
    : '';
  return `<div class="ws-empty"><div class="ws-empty-title"><i aria-hidden="true">◌</i>${escapeHTML(title)}</div>${text ? `<p class="ws-empty-text">${escapeHTML(text)}</p>` : ''}${linkHtml}</div>`;
}

/** 长值：可换行显示，超长时截断，完整值放在 title 里。 */
function workspaceClip(value, max = 200) {
  const full = workspaceValue(value, 4000);
  if (!full || full === '未提供') return '<span class="ws-value">未提供</span>';
  const clipped = full.length > max;
  return `<span class="ws-value"${clipped ? ` title="${escapeHTML(full)}"` : ''}>${escapeHTML(clipped ? `${full.slice(0, max)}…` : full)}</span>`;
}

/** 地址 / 哈希这类等宽内容：单行省略号，完整值在 title 里。 */
function workspaceCode(value, max = 46) {
  const full = workspaceValue(value, 4000);
  if (!full || full === '未提供') return '<span class="ws-value">未提供</span>';
  const clipped = full.length > max;
  return `<code class="ws-clip" title="${escapeHTML(full)}">${escapeHTML(clipped ? `${full.slice(0, max)}…` : full)}</code>`;
}

/** 状态徽章：颜色 + 圆点图标 + 文字，三重编码。 */
function workspaceBadge(label, kind = 'muted') {
  const safe = ['ok', 'warn', 'danger', 'info', 'muted'].includes(kind) ? kind : 'muted';
  return `<span class="ws-badge ws-badge-${safe}"><i aria-hidden="true"></i>${escapeHTML(String(label ?? '未记录'))}</span>`;
}

const WORKSPACE_STATE_KIND = Object.freeze({
  queued: 'muted', preparing: 'info', running: 'info', checkpointing: 'info',
  pausing: 'warn', paused: 'warn', cancelling: 'warn', pending: 'muted',
  succeeded: 'ok', completed: 'ok', done: 'ok', passed: 'ok',
  partial: 'warn', failed: 'danger', blocked: 'danger', interrupted: 'danger',
  unavailable: 'warn', error: 'danger', cancelled: 'muted', stopped: 'muted',
  idle: 'muted', unknown: 'muted', not_performed: 'muted', idle_state: 'muted',
});

/** 工作区统一的状态徽章：中文标签 + 颜色。 */
function workspaceStateBadge(value, labels = {}) {
  const key = String(value ?? '').trim();
  const text = labels[key] || evidenceStateLabels[key] || taskStateLabels[key] || analysisStateLabels[key] || key || '未记录';
  return workspaceBadge(text, WORKSPACE_STATE_KIND[key] || 'muted');
}

/* 漏洞 / 证据状态里出现但共享标签表里没有的取值。这些是后端实际返回的原始值，
   保留原词在括号里，方便对照接口原文。 */
const WORKSPACE_EVIDENCE_LABELS = Object.freeze({
  hypothesis: '待确认（只是线索）',
  static_signal: '静态信号',
  unconfirmed_observation: '未确认的观察',
  observed: '已观察到',
  reproduced: '已复现',
  rejected: '已排除',
  insufficient: '证据不足',
  poc_confirmed: '复现验证通过（PoC）',
  poc_failed: '复现验证未通过（PoC）',
  invariant_violated: '安全规则被打破（不变量违反）',
});

function workspaceEvidenceLabel(value) {
  const key = String(value ?? '').trim();
  if (!key) return '未记录';
  return WORKSPACE_EVIDENCE_LABELS[key] || evidenceStateLabels[key] || key;
}

/* 漏洞的 check 字段是分析工具的规则 ID（多为英文短横线命名）。
   直接摆出来，小白看不懂；这里给出中文说法，括号里保留原规则 ID 对照。
   映射表来自当前实际出现的规则集合，没覆盖到的原样显示，不编造含义。 */
const WORKSPACE_CHECK_LABELS = Object.freeze({
  'arbitrary-send-erc20': '可把代币转给任意地址（可疑转出）',
  'calls-loop': '在循环里做外部调用',
  'cyclomatic-complexity': '逻辑分支过多',
  'dead-code': '存在不会执行的代码',
  'divide-before-multiply': '先除后乘（精度可能被吃掉）',
  'events-access': '事件参数可能被篡改',
  'incorrect-equality': '等值判断可能写错',
  'low-level-calls': '使用了底层调用（绕过常规检查）',
  'missing-zero-check': '缺少零值校验',
  'naming-convention': '命名不符合约定（代码风格问题）',
  'pragma': '缺少编译器版本声明',
  'reentrancy-benign': '重入风险（影响较小）',
  'reentrancy-events': '重入风险（事件先于状态更新）',
  'reentrancy-no-eth': '重入风险（无 ETH 转移）',
  'solc-version': '编译器版本较旧',
  'timestamp': '直接依赖区块时间（可能被操纵）',
  'unimplemented-functions': '有函数只有声明没有实现',
  'unindexed-event-address': '事件里的地址未建索引',
  'uninitialized-local': '局部变量未初始化',
  'unused-return': '调用结果没有检查',
});

/** 规则 ID 的人话说法；没收录的原样返回，不臆造含义。 */
function workspaceCheckLabel(value) {
  const key = String(value ?? '').trim();
  if (!key) return '未记录';
  const label = WORKSPACE_CHECK_LABELS[key];
  return label ? `${label}（${key}）` : key;
}

const WORKSPACE_SEVERITY_KEYS = Object.freeze({ critical: 'critical', high: 'high', medium: 'medium', low: 'low', informational: 'info', info: 'info' });
const WORKSPACE_SEVERITY_TEXT = Object.freeze({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' });

/** 严重度统一成小写键，避免 "High" / "high" 混在一起出现两个选项。 */
function workspaceSeverityKey(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  return WORKSPACE_SEVERITY_KEYS[raw] || '';
}
function workspaceSeverityLabel(value) {
  const key = workspaceSeverityKey(value);
  return key ? WORKSPACE_SEVERITY_TEXT[key] : '未分级';
}
/** 严重度徽章：图标 + 文字 + 颜色。 */
function workspaceSeverityBadge(value) {
  const key = workspaceSeverityKey(value);
  const icon = { critical: '▲', high: '▲', medium: '■', low: '▼', info: '·' }[key] || '·';
  const kind = { critical: 'danger', high: 'danger', medium: 'warn', low: 'info', info: 'info' }[key] || 'muted';
  return `<span class="ws-badge ws-badge-${kind}"><i aria-hidden="true">${icon}</i>${escapeHTML(workspaceSeverityLabel(value))}</span>`;
}
function workspaceCard(title, content, className = '') { return `<article class="workspace-card ${className}"><div class="workspace-card-head"><h2>${escapeHTML(title)}</h2></div>${content}</article>`; }
function workspaceCount(label, value) { return `<div class="workspace-count"><span>${escapeHTML(label)}</span><b>${escapeHTML(value)}</b></div>`; }
function workspaceCapability(name, capabilities) {
  const stateValue = capabilityState(capabilities, name);
  return `<span class="workspace-capability ${stateValue.kind}"><i></i>${escapeHTML(capabilityLabels[name] || name)} · ${escapeHTML(stateValue.label)}</span>`;
}
function workspaceTable(items, columns, emptyMessage = '接口返回空集；当前没有可展示记录。', emptyLinks = []) {
  if (!items.length) return workspaceEmpty({ title: '这里还没有记录', text: emptyMessage, links: emptyLinks });
  const head = columns.map((column) => `<th scope="col">${escapeHTML(column.label)}</th>`).join('');
  const rows = items.map((item) => `<tr>${columns.map((column) => `<td>${column.render ? column.render(item) : `<span>${escapeHTML(workspaceValue(item[column.key]))}</span>`}</td>`).join('')}</tr>`).join('');
  return `<div class="workspace-table-wrap"><table class="workspace-table"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div><p class="ws-table-hint"><span aria-hidden="true">↔</span>表格可左右滑动查看全部列</p>`;
}
function workspaceJsonDetails(label, value) {
  return `<details class="workspace-json"><summary>${escapeHTML(label)}</summary><pre>${escapeHTML(workspaceObject(value))}</pre></details>`;
}
function reverseArtifactControls(item) {
  const taskId = item?.taskId || item?.id;
  if (!taskId || !Array.isArray(item?.artifacts)) return '';
  const readable = item.artifacts.filter((artifact) => artifact?.kind === 'unified-ir'
    || ['solidity-pseudocode', 'yul-pseudocode', 'decompiler-output'].includes(artifact?.kind));
  return readable.map((artifact, index) => {
    if (!/^[0-9a-f]{64}$/i.test(String(artifact.sha256 || ''))) return '';
    const label = artifact.kind === 'unified-ir' ? '查看代码结构' : '查看还原代码';
    const target = `reverse-artifact-${escapeHTML(taskId)}-${index}`;
    return `<div class="reverse-artifact"><button type="button" class="workspace-link reverse-artifact-load" data-task-id="${escapeHTML(taskId)}" data-artifact-sha="${escapeHTML(artifact.sha256)}" data-target="${target}">${label}</button><span class="reverse-artifact-status" role="status"></span><pre id="${target}" hidden></pre></div>`;
  }).join('');
}
function reverseCrossValidationSummary(item) {
  const value = item?.crossValidation || item?.checkpoint?.crossValidation
    || item?.runtimeBytecodeAnalysis?.decompilation?.crossValidation;
  const cross = value && typeof value === 'object' ? value : {};
  const engines = cross.highLevelEngineComparison || {};
  const compared = Number.isSafeInteger(engines.comparedEngineCount) ? engines.comparedEngineCount : 0;
  const highLevel = compared > 0
    ? `已由另一种代码工具独立核对 ${compared} 次`
    : '尚未由另一种代码工具独立确认';
  const opcode = cross.opcodePcCrossCheck?.state || 'unavailable';
  const opcodeLabel = opcode === 'consistent' ? '机器指令与位置核对一致'
    : opcode === 'mismatch' ? '机器指令与位置核对不一致'
      : opcode === 'unavailable' ? '机器指令与位置核对不可用' : '机器指令核对状态未记录';
  return `<div class="reverse-validation"><strong>结果核对：</strong>${escapeHTML(highLevel)}；${escapeHTML(opcodeLabel)}。<span>指令和位置一致，只能说明这一层检查通过，不能证明还原出的代码含义正确。</span></div>`;
}
function resourceId(item) { return item?.taskId || item?.id || item?.findingId || item?.scanId || ''; }
function taskLink(item, label = null) {
  const id = resourceId(item);
  return id ? `<a class="workspace-link" href="#task/${encodeURIComponent(id)}">${escapeHTML(label || id)}</a>` : '<span>未提供</span>';
}
function taskActionControls(item, revision) {
  const id = item?.taskId;
  if (!id || !Number.isSafeInteger(revision)) return '';
  const actions = [];
  if (['queued', 'preparing', 'running', 'checkpointing'].includes(item.state)) actions.push(['pause', '暂停']);
  if (item.state === 'paused') actions.push(['resume', '恢复']);
  if (['queued', 'preparing', 'running', 'checkpointing', 'paused'].includes(item.state)) actions.push(['cancel', '取消']);
  if (!actions.length) return '';
  return `<div class="task-operator-actions" data-task-id="${escapeHTML(id)}" data-task-revision="${revision}">${actions.map(([action, label]) => `<button type="button" class="workspace-link" data-task-action="${action}">${label}</button>`).join('')}<span class="task-action-result" role="status" aria-live="polite"></span><p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>这些按钮会<b>修改该任务的运行状态</b>（暂停、恢复或取消），并写入任务历史。</span></p></div>`;
}
function findingLink(item, label = null) {
  const id = item?.findingId || item?.id || '';
  return id ? `<a class="workspace-link" href="#finding/${encodeURIComponent(id)}">${escapeHTML(label || id)}</a>` : '<span>未提供</span>';
}
function hideOverview(hidden) {
  const workspace = $('#workspace-view');
  const onAuditRoute = ['map', 'home', 'protocols', 'discoveries', 'execution'].includes(state.workspaceRoute?.name);
  // 审计视图（首页 / 风险地图 / 协议 / 发现 / 执行）和运维工作区互斥。
  // 以前审计路由也会走 hideOverview(true)，把工作区容器一并显示出来：
  // 从「任务中心」切到风险地图时，旧的任务中心内容（约 620px）还留在页面上，
  // 把真正的页面顶下去 690px，页面看起来正常但首屏是上一页的残留。
  workspace.hidden = !hidden || onAuditRoute;
  if (onAuditRoute) workspace.replaceChildren();
  const audit = $('#audit-view');
  if (audit) audit.hidden = !onAuditRoute;
  // 旧总览的页内目录（锚点小导航）只属于旧总览，别的视图里要一起收起来。
  const anchorNav = document.querySelector('.overview-anchor-nav');
  if (anchorNav) anchorNav.hidden = hidden;
  for (const element of document.querySelectorAll('.main-content > *:not(.topbar):not(#workspace-view):not(#audit-view):not(#global-banner):not(#main-region)')) element.hidden = hidden;
  document.querySelector('.main-content').classList.toggle('workspace-mode', hidden);
}
function setActiveView(route) {
  const root = route?.name || 'overview';
  // 面包屑跟着当前页走：旧版是固定「多链作战台」，用户不知道自己在哪一页。
  updateBreadcrumb(route);
  if (root === 'overview') {
    // 旧总览是一个页面，「分析队列」「模型与同步」是它的页内锚点。
    // 同一时刻只能高亮一个：滚到哪一块就高亮那一项，否则侧栏会亮起三行。
    highlightOverviewAnchor(route?.anchor);
    return;
  }
  document.querySelectorAll('.nav-item').forEach((link) => {
    const hash = link.getAttribute('href')?.slice(1) || '';
    const active = hash === root || (root === 'task' && hash === 'tasks') || (root === 'finding' && hash === 'finding');
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  });
}

/**
 * 旧总览内部的高亮：把当前区块映射到侧边栏的某一项。
 * 只有「旧版总览」「分析队列」「模型与同步」这三个是旧总览的页内入口。
 */
function highlightOverviewAnchor(anchorHash) {
  const hash = String(anchorHash || 'overview');
  // 页内目录会跳到 #chains / #routes 等区块；这些区块没有独立侧栏入口，
  // 因此应继续高亮「旧版总览」，而不是让整个侧栏失去当前位置。
  const hasNavEntry = [...document.querySelectorAll('.nav-item')].some((link) => link.getAttribute('href')?.slice(1) === hash);
  const target = hasNavEntry ? hash : 'overview';
  document.querySelectorAll('.nav-item').forEach((link) => {
    const linkHash = link.getAttribute('href')?.slice(1) || '';
    const active = linkHash === target;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'location'); else link.removeAttribute('aria-current');
  });
}

async function renderProjectsWorkspace() {
  const [projects, contracts, capabilities] = await Promise.all([optionalResource('/api/v1/projects?limit=100'), optionalResource('/api/v1/contracts?limit=100'), optionalResource('/api/v1/capabilities')]);
  const projectItems = workspaceItems(projects.data), contractItems = workspaceItems(contracts.data);
  const projectRows = workspaceTable(projectItems, [
    { label: '项目', render: (item) => `<strong>${escapeHTML(workspaceValue(item.input?.projectId || item.id))}</strong>` },
    { label: '状态', render: (item) => workspaceStateBadge(item.state, taskStateLabels) },
    { label: '源码目录', render: (item) => workspaceCode(item.input?.sourcePath, 44) },
    { label: '更新时间', render: (item) => `<span>${escapeHTML(formatDate(item.updatedAt || item.createdAt))}</span>` },
    { label: '任务', render: (item) => taskLink(item, '打开任务') },
  ], workspaceError(projects) || '还没有导入过本地项目。导入后这里会列出项目 ID、源码目录和对应任务。', [['#collection', '去导入本地项目']]);
  const contractRows = workspaceTable(contractItems, [
    { label: '合约', render: (item) => `<strong>${escapeHTML(workspaceValue(item.input?.contractId || item.id))}</strong>` },
    { label: '地址', render: (item) => workspaceCode(item.input?.address, 44) },
    { label: '链', render: (item) => `<span>${escapeHTML(workspaceValue(item.input?.chainId))}</span>` },
    { label: '状态', render: (item) => workspaceStateBadge(item.state, taskStateLabels) },
    { label: '任务', render: (item) => taskLink(item, '打开任务') },
  ], workspaceError(contracts) || '还没有关联到链上地址的合约。地址由你提供，系统尚未验证部署代码与源码是否一致。', [['#collection', '去创建采集任务']]);
  const capabilityBody = capabilities.ok
    ? `<div class="workspace-capability-list">${Object.entries(capabilities.data.capabilities || {}).map(([name]) => workspaceCapability(name, capabilities.data)).join(' ')}</div>`
    : workspaceStatus(workspaceError(capabilities) || '读取能力声明失败。', 'error');
  return workspaceFrame({
    kicker: '资源 / 项目',
    title: '项目管理',
    description: '这页列出已经导入到本机的项目和已关联的合约地址，并显示每项能力是否可执行。什么时候用：想知道「哪些代码在跑、跑到哪一步」时先看这里。',
    mode: 'read',
    body: `<div class="workspace-counts">${workspaceCount('项目任务', String(projectItems.length))}${workspaceCount('合约记录', String(contractItems.length))}${workspaceCount('能力项', capabilities.ok ? String(Object.keys(capabilities.data.capabilities || {}).length) : '未记录')}</div>${workspaceCard('当前能力', capabilityBody)}<div class="workspace-grid-two">${workspaceCard('项目任务', projectRows)}${workspaceCard('合约记录', contractRows)}</div>`,
    footer: `项目数据版本 ${workspaceValue(projects.data?.consistency?.revision ?? '未提供')} · 合约资源执行状态由能力接口声明`,
    next: [['#collection', '创建采集任务'], ['#tasks', '查看任务队列']],
  });
}

/* 后端返回的错误码。前端不自己判断能不能采集，一律以后端 error 字段为准。 */
function workspaceErrorCode(error) {
  const code = error?.payload?.error?.code ?? error?.code ?? error?.payload?.code ?? '';
  return typeof code === 'string' ? code : '';
}

/** 离线阶段被后端拒绝时的如实提示：说清是后端拒绝，不是前端拦的。 */
const WORKSPACE_OFFLINE_HINT = '当前处于离线阶段，后端拒绝链上采集';
function workspaceOfflineDetails(error) {
  const code = workspaceErrorCode(error);
  const message = error?.message ? String(error.message) : '';
  const isOffline = code === 'chain_collection_disabled' || /离线阶段不开放链上采集|链上采集.*拒绝/.test(message);
  return isOffline ? { code, message } : null;
}
function workspaceOfflineMessage(error) {
  const details = workspaceOfflineDetails(error);
  if (!details) return '';
  const backend = details.message || '链上采集启动请求已被后端拒绝。';
  return `${WORKSPACE_OFFLINE_HINT}。${backend}${details.code ? `（后端错误码：${details.code}）` : ''}`;
}
function workspaceOfflineNotice(error) {
  const details = workspaceOfflineDetails(error);
  if (!details) return '';
  return `<div class="workspace-status workspace-status-error"><strong>${escapeHTML(WORKSPACE_OFFLINE_HINT)}</strong><br>${escapeHTML(details.message || '链上采集启动请求已被后端拒绝。')}${details.code ? `<br>后端错误码：${escapeHTML(details.code)}` : ''}<br>这是后端的硬性拒绝，不是页面拦截；本页不会把它显示成成功。</div>`;
}

function collectionForm(capabilities) {
  const stateValue = capabilityState(capabilities, 'collection');
  const disabled = stateValue.kind === 'blocked';
  return `<form class="workspace-form" data-resource-form="collection"><div class="workspace-form-title">链上采集任务</div><p class="workspace-form-note">读取指定区块的公开信息，不会签名、授权或发交易。当前状态：${escapeHTML(stateValue.label)}。${escapeHTML(readableLimitation(stateValue.limitation))}</p><div class="workspace-form-grid"><label>项目 ID<input name="projectId" required maxlength="200" placeholder="已有项目 ID"></label><label>链 ID<input name="chainId" required maxlength="100" placeholder="例如 1"></label><label class="workspace-form-wide">只读链节点地址<input name="rpcUrl" required maxlength="2000" placeholder="https://…"></label><label>合约地址（可选）<input name="address" maxlength="100" placeholder="0x…"></label><label>开始区块<input name="fromBlock" required maxlength="100" placeholder="例如 1000000"></label><label>结束区块（可选）<input name="toBlock" maxlength="100" placeholder="默认只读一个区块"></label></div><button class="workspace-submit ws-submit-write" type="submit" ${disabled ? 'disabled' : ''}>${disabled ? '执行器未就绪' : '提交采集任务'}</button><p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>提交后会在本机任务队列里<b>创建一条采集任务记录</b>，只读取所填区块的公开信息；不会签名、不会授权、不会发交易。</span></p><span class="workspace-form-result" data-form-result></span></form>`;
}
function projectImportForm() {
  return `<form class="workspace-form" data-resource-form="project"><div class="workspace-form-title">导入本地项目</div><p class="workspace-form-note">提交后进入共享任务队列；不会执行资产操作。</p><div class="workspace-form-grid"><label>项目 ID<input name="projectId" required maxlength="200" placeholder="项目标识"></label><label class="workspace-form-wide">源码目录<input name="sourcePath" required maxlength="1000" placeholder="绝对路径（允许根目录内）"></label></div><button class="workspace-submit ws-submit-write" type="submit">提交项目导入</button><p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>提交后会在本机任务队列里<b>创建一条项目导入任务</b>，并登记这个项目 ID 与源码目录；不会执行资产操作。</span></p><span class="workspace-form-result" data-form-result></span></form>`;
}
async function renderCollectionWorkspace() {
  const [collection, projects, capabilities] = await Promise.all([optionalResource('/api/v1/collection?limit=100'), optionalResource('/api/v1/projects?limit=100'), optionalResource('/api/v1/capabilities')]);
  const rows = workspaceTable(workspaceItems(collection.data), [
    { label: '任务', render: (item) => taskLink(item, '打开任务') },
    { label: '项目', render: (item) => workspaceCode(item.input?.projectId, 34) },
    { label: '链 / 地址', render: (item) => `<code class="ws-clip" title="${escapeHTML(workspaceValue(item.input?.address))}">${escapeHTML(workspaceValue(item.input?.chainId))} / ${escapeHTML(workspaceValue(item.input?.address))}</code>` },
    { label: '状态', render: (item) => workspaceStateBadge(item.state, taskStateLabels) },
    { label: '检查点', render: (item) => workspaceJsonDetails('查看检查点', item.checkpoint || {}) },
  ], workspaceError(collection) || '还没有采集任务记录。填好下面的表单提交后，任务会出现在这里。', [['#tasks', '查看任务中心']]);
  const caps = capabilities.ok ? capabilities.data : null;
  const offlineNotice = `<div class="workspace-status workspace-status-warn"><strong>当前处于离线阶段</strong><br>离线阶段不开放链上采集：提交采集任务会被后端直接拒绝（错误码 chain_collection_disabled）。本页如实显示后端的拒绝结果，不会显示成功。</div>`;
  return workspaceFrame({
    kicker: '任务 / 采集',
    title: '创建采集任务',
    description: '这页用来把本地项目和链上只读采集任务放进本机队列。什么时候用：拿到一个已验证源码目录或一条链的只读节点地址时。提交只读取公开信息，不签名、不授权、不发交易。',
    mode: 'write',
    body: `${offlineNotice}<div class="workspace-grid-two">${workspaceCard('提交入口', `${projectImportForm()}${collectionForm(caps)}`)}${workspaceCard('现有采集任务', rows)}</div><div class="workspace-record-note">已发现项目任务：${escapeHTML(String(workspaceItems(projects.data).length))} 条。采集接口：${caps ? workspaceCapability('collection', caps) : workspaceError(capabilities)}</div>`,
    next: [['#projects', '查看项目管理'], ['#tasks', '查看任务中心']],
  });
}

function scanForm({ title = '本地源码分析任务', description = '提交已验证的源码包后，任务会进入队列并保留检查记录。只有已有专用方案的目标才会运行本地隔离测试。', button = '创建分析任务', effect = '提交后会在本机任务队列里<b>创建一条源码分析任务</b>，并保存这份源码包的检查记录；不会执行链上交易。' } = {}) {
  return `<form class="workspace-form" data-resource-form="scan"><div class="workspace-form-title">${escapeHTML(title)}</div><p class="workspace-form-note">${escapeHTML(description)}</p><div class="workspace-form-grid"><label class="workspace-form-wide">已验证源码包文件路径<input name="sourcePath" required maxlength="1000" placeholder="项目文件夹内的源码包"></label><label class="workspace-form-wide">依赖源码包路径（可选）<input name="dependencyPath" maxlength="1000" placeholder="项目文件夹内的依赖文件"></label></div><button class="workspace-submit ws-submit-write" type="submit">${escapeHTML(button)}</button><p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>${effect}</span></p><span class="workspace-form-result" data-form-result></span></form>`;
}
function decompileForm() {
  return `<form class="workspace-form" data-resource-form="decompile"><div class="workspace-form-title">整理一段合约代码</div><p class="workspace-form-note">粘贴以 0x 开头的完整代码，或填写项目 work 目录内的代码文件路径。生成内容是阅读辅助稿，不是原始源码。</p><div class="workspace-form-grid"><label class="workspace-form-wide">代码内容（可选）<textarea name="runtimeBytecode" rows="7" maxlength="262146" placeholder="0x 开头的十六进制代码"></textarea></label><label class="workspace-form-wide">或代码文件路径<input name="bytecodePath" maxlength="1000" placeholder="work/...json"></label></div><button class="workspace-submit ws-submit-write" type="submit">创建整理任务</button><p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>提交后会在本机任务队列里<b>创建一条代码整理任务</b>，并保存这次生成的阅读辅助稿；产物是工具推测的结果，不是项目原始源码。</span></p><span class="workspace-form-result" data-form-result role="status" aria-live="polite"></span></form>`;
}
async function renderScanWorkspace() {
  const [analysis, scans, capabilities] = await Promise.all([optionalResource('/api/v1/analysis?limit=100'), optionalResource('/api/v1/scans?limit=100'), optionalResource('/api/v1/capabilities')]);
  const analysisRows = workspaceTable(workspaceItems(analysis.data), [
    { label: '分析任务', render: (item) => taskLink(item, workspaceValue(item.taskId || item.id)) },
    { label: '类型', render: (item) => `<span>${escapeHTML(taskTypeLabels[item.type] || workspaceValue(item.type))}</span>` },
    { label: '状态', render: (item) => workspaceStateBadge(item.state, taskStateLabels) },
    { label: '更新时间', render: (item) => `<span>${escapeHTML(formatDate(item.updatedAt || item.createdAt))}</span>` },
  ], workspaceError(analysis) || '还没有源码分析任务。填好源码包路径提交后，任务会出现在这里。');
  const scanRows = workspaceTable(workspaceItems(scans.data), [
    { label: '扫描', render: (item) => taskLink(item, workspaceValue(item.scanId || item.taskId || item.id)) },
    { label: '状态', render: (item) => workspaceStateBadge(item.state, taskStateLabels) },
    { label: '创建时间', render: (item) => `<span>${escapeHTML(formatDate(item.createdAt))}</span>` },
  ], workspaceError(scans) || '还没有扫描记录。扫描任务与上面的分析任务共用同一个队列，完成后可以点进去看检查记录。', [['#tasks', '查看任务中心']]);
  const caps = capabilities.ok ? capabilities.data : null;
  return workspaceFrame({
    kicker: '任务 / 扫描',
    title: '创建扫描任务',
    description: '这页把一份已验证的源码包交给本机分析流程。什么时候用：拿到经过验证的源码、想跑静态检查和本地隔离测试时。静态线索只是线索，不会自动变成已确认漏洞。',
    mode: 'write',
    body: `<div class="workspace-grid-two">${workspaceCard('创建任务', scanForm())}${workspaceCard('分析任务', analysisRows)}</div>${workspaceCard('扫描记录', scanRows)}<div class="workspace-record-note">分析接口：${caps ? workspaceCapability('analysis', caps) : workspaceError(capabilities)} · 扫描接口：${caps ? workspaceCapability('scans', caps) : ''}</div>`,
    next: [['#dynamic', '查看动态检查'], ['#tasks', '查看任务中心']],
  });
}

async function renderTasksWorkspace() {
  const result = await optionalResource('/api/v1/tasks?limit=100');
  const items = workspaceItems(result.data);
  $('#nav-tasks').textContent = String(items.length);
  const rows = workspaceTable(items, [
    { label: '任务 ID', render: (item) => taskLink(item) },
    { label: '类型', render: (item) => `<span>${escapeHTML(taskTypeLabels[item.type] || workspaceValue(item.type))}</span>` },
    { label: '状态', render: (item) => workspaceStateBadge(item.state, taskStateLabels) },
    { label: '尝试次数', render: (item) => `<span>${escapeHTML(workspaceValue(item.attempts))}</span>` },
    { label: '更新时间', render: (item) => `<span>${escapeHTML(formatDate(item.updatedAt || item.createdAt))}</span>` },
  ], workspaceError(result) || '任务队列是空的。创建扫描任务或导入项目后，这里会出现对应的任务记录。', [['#scan', '去创建扫描任务'], ['#collection', '去创建采集任务']]);
  return workspaceFrame({
    kicker: '任务 / 队列',
    title: '任务中心',
    description: '这页列出本机队列里的所有任务。什么时候用：想知道某个分析跑到哪一步、卡住或失败时。点任务 ID 可以看检查点、错误原因和已归档报告。',
    mode: 'read',
    body: workspaceCard('任务队列', rows),
    footer: `一致性版本 ${workspaceValue(result.data?.consistency?.revision ?? '未提供')} · ${workspaceValue(result.data?.page?.hasMore ? '结果已分页' : '当前页已完整')}`,
    next: [['#scan', '创建扫描任务'], ['#findings-view', '查看漏洞中心']],
  });
}

/* 离线语料控制台（LaneW）。轮询间隔 4 秒；接口无数据时保持空状态，不崩溃。
 * CORPUS_POLL_INTERVAL_MS / corpusPollTimer 的声明在文件前部（auditViews 之后）：
 * 首次 routeWorkspace() 会调用 stopCorpusPolling()，声明放在这里会触发 TDZ。 */

/* 轮询会把整块面板重新渲染，所以页面状态（所选类别、泳道、上一次操作结果）
 * 必须存在模块级：否则每 4 秒一次的重绘会把用户的筛选和反馈抹掉。 */
const corpusViewState = {
  selection: { category: '', laneId: 'static' },
  feedback: { action: null, filter: null },
};

function stopCorpusPolling() {
  if (corpusPollTimer) clearInterval(corpusPollTimer);
  corpusPollTimer = null;
}

/** 读取面板里的当前选择，重绘后要保持一致。 */
function captureCorpusSelection() {
  const category = $('#workspace-view [data-corpus-category]');
  const lane = $('#workspace-view [data-corpus-filter-lane]');
  if (category) corpusViewState.selection.category = category.value || '';
  if (lane) corpusViewState.selection.laneId = lane.value || 'static';
}

/** 刷新语料面板内容；轮询期间任何读取失败都保持当前视图，不清空页面。 */
async function refreshCorpusWorkspace() {
  const view = $('#workspace-view');
  if (!view || state.workspaceRoute?.name !== 'corpus') return;
  captureCorpusSelection();
  const requestId = ++state.workspaceRequest;
  let html;
  try { html = await renderCorpusWorkspace(); }
  catch { return; }
  if (requestId !== state.workspaceRequest) return;
  if (!view.isConnected) return;
  view.innerHTML = html;
  wireWorkspaceForms();
}

function startCorpusPolling() {
  stopCorpusPolling();
  corpusPollTimer = setInterval(() => { void refreshCorpusWorkspace(); }, CORPUS_POLL_INTERVAL_MS);
}

async function renderCorpusWorkspace() {
  const [overview, filters] = await Promise.all([
    optionalResource('/api/v1/corpus/overview'),
    optionalResource('/api/v1/corpus/filters'),
  ]);
  if (!overview.ok) {
    return corpusView.render({
      data: {
        corpus: {},
        heartbeat: {},
        chainCollection: { code: 'chain_collection_disabled' },
        tasks: [],
        categories: [],
        readError: overview.error.message,
      },
      selection: corpusViewState.selection,
      feedback: corpusViewState.feedback,
    });
  }
  const payload = overview.data?.data || {};
  const categories = filters.ok && Array.isArray(filters.data?.data?.categories) ? filters.data.data.categories : [];
  return corpusView.render({ ...payload, categories, selection: corpusViewState.selection, feedback: corpusViewState.feedback });
}

function renderArchivedReportSummary(report) {
  const findings = Array.isArray(report?.findings) ? report.findings.filter((item) => item && typeof item === 'object') : null;
  const confirmed = findings?.filter((item) => item.confirmed === true).length;
  const labels = { completed: '已完成', succeeded: '已完成', failed: '失败', interrupted: '已中断', running: '运行中', partial: '部分完成', queued: '排队中' };
  const reportState = typeof report?.state === 'string' && report.state ? labels[report.state] || report.state : '未记录';
  const tested = report?.localTests?.tests ?? report?.dynamicAnalysis?.tests;
  const executed = Number.isSafeInteger(tested) && tested >= 0 ? tested : null;
  const showCount = (value) => Number.isSafeInteger(value) && value >= 0 ? String(value) : '未记录';
  return `<section class="workspace-status workspace-status-info" aria-label="归档报告摘要"><strong>报告状态：${escapeHTML(reportState)}</strong><p>风险记录：${findings === null ? '未记录' : showCount(findings.length)} 条 · 明确标记已确认：${showCount(confirmed)} 条${findings === null ? '' : ' · 其他记录不会自动视为已确认'}</p><p>动态检查：${executed === null ? '未记录' : `已运行 ${executed} 项`}</p></section>`;
}

async function renderTaskDetailWorkspace(id) {
  const task = await optionalResource(`/api/v1/tasks/${encodeURIComponent(id)}`);
  if (!task.ok) return workspaceFrame({ kicker: '任务 / 详情', title: '任务详情不可用', description: task.error.message, mode: 'read', body: workspaceStatus(task.error.message, 'error') });
  const item = task.data.data || task.data.task || task.data;
  const revision = task.data.consistency?.revision;
  // 归档报告只属于本地源码分析任务。后端只为 analysis / local-source-analysis
  // 提供 /api/v1/reports/{id}；对采集等其他任务请求必然 404。
  // 这里按任务类型决定是否请求，避免每次打开非分析任务都在控制台留下 404。
  const reportCapable = ['analysis', 'local-source-analysis'].includes(String(item.type || ''));
  const [report, replay] = await Promise.all([
    reportCapable ? optionalResource(`/api/v1/reports/${encodeURIComponent(id)}`) : Promise.resolve({ ok: false, path: null, error: { status: 404, message: '该任务类型不提供归档报告。' } }),
    optionalResource(`/api/v1/replay?taskId=${encodeURIComponent(id)}&limit=20`),
  ]);
  const archivedReport = report.data?.report || report.data;
  const reportBody = report.ok
    ? `${renderArchivedReportSummary(archivedReport)}${workspaceJsonDetails('查看报告内容（接口原文）', archivedReport)}`
    : workspaceStatus(report.error.status === 404 ? '该任务尚无可读取报告。' : report.error.message, report.error.status === 404 ? 'empty' : 'error');
  const checkpoint = item.checkpoint && typeof item.checkpoint === 'object' ? item.checkpoint : {};
  const lease = item.lease && typeof item.lease === 'object' ? item.lease : null;
  const checkpointFields = [
    ['阶段', 'phase'], ['已完成单元', 'completedUnits'], ['总单元数', 'totalUnits'],
    ['测试次数', 'tests'], ['随机种子', 'seed'], ['语料数量', 'corpus'],
    ['覆盖情况', 'coverage'], ['资源使用', 'resourceUsage'], ['预算', 'budget'],
    ['检查点时间', 'checkpointedAt'], ['产物数量', 'artifacts'],
  ];
  const checkpointBody = `<dl class="workspace-definition">${checkpointFields.map(([label, key]) => {
    const value = key === 'checkpointedAt' ? (item.checkpointedAt || checkpoint[key]) : checkpoint[key];
    return `<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value === undefined || value === null || value === '' ? '未记录' : workspaceValue(value, 500))}</dd></div>`;
  }).join('')}</dl>${workspaceJsonDetails('检查点原文', checkpoint)}`;
  const leaseBody = lease
    ? `<dl class="workspace-definition"><div><dt>工作进程</dt><dd>${escapeHTML(workspaceValue(lease.workerId))}</dd></div><div><dt>租约心跳</dt><dd>${escapeHTML(formatDate(lease.heartbeatAt))}</dd></div><div><dt>租约到期</dt><dd>${escapeHTML(formatDate(lease.expiresAt))}</dd></div><div><dt>租约时长</dt><dd>${escapeHTML(workspaceValue(lease.ttlMs))} 毫秒</dd></div></dl>`
    : workspaceStatus('当前没有活动工作进程租约；任务可能排队、暂停或已结束。', 'empty');
  const history = Array.isArray(item.history) ? item.history : [];
  const historyBody = history.length
    ? `<ol class="task-history">${history.slice().reverse().map((event) => `<li><div><b>${escapeHTML(stateLabel(event.to, taskStateLabels))}</b><span>${escapeHTML(formatDate(event.at))}</span></div><p>${escapeHTML(event.from ? `${stateLabel(event.from, taskStateLabels)} → ${stateLabel(event.to, taskStateLabels)}` : `进入${stateLabel(event.to, taskStateLabels)}`)} · ${escapeHTML(event.reason || '未提供原因')}</p>${event.workerId ? `<small>工作进程：${escapeHTML(event.workerId)}</small>` : ''}${event.checkpointSeq !== undefined ? `<small>检查点序号：${escapeHTML(event.checkpointSeq)}</small>` : ''}</li>`).join('')}</ol>`
    : workspaceStatus('任务没有阶段历史记录。', 'empty');
  const replayItems = workspaceItems(replay.data);
  const replayBody = replay.ok
    ? workspaceTable(replayItems, [
      { label: '重放产物', render: (entry) => `<code>${escapeHTML(workspaceValue(entry.artifactId || entry.id))}</code>` },
      { label: '证据状态', render: (entry) => `<span>${escapeHTML(workspaceValue(entry.replayEvidence?.state || entry.state || entry.status))}</span>` },
      { label: '交易数', render: (entry) => `<span>${escapeHTML(workspaceValue(entry.replay?.transactions?.length ?? entry.transactions?.length))}</span>` },
    ], '该任务没有已验证的重放产物。')
    : workspaceStatus(replay.error.message, 'error');
  const detailTitle = String(item.type || '').includes('collection') ? '采集任务详情' : (String(item.type || '').includes('analysis') || String(item.type || '').includes('scan') ? '扫描任务详情' : '任务详情');
  return workspaceFrame({ kicker: '任务 / 详情', title: detailTitle, description: `任务 ${id} 的状态、阶段历史、检查点和证据。所有字段来自任务 API；未记录内容不会被补写。`, mode: 'mixed', body: `<div class="workspace-grid-two">${workspaceCard('状态与时间', `<dl class="workspace-definition"><div><dt>任务 ID</dt><dd><code>${escapeHTML(id)}</code></dd></div><div><dt>类型</dt><dd>${escapeHTML(taskTypeLabels[item.type] || workspaceValue(item.type))}</dd></div><div><dt>状态</dt><dd><span class="workspace-state">${escapeHTML(stateLabel(item.state, taskStateLabels))}</span></dd></div><div><dt>优先级</dt><dd>${escapeHTML(workspaceValue(item.priority))}</dd></div><div><dt>尝试次数</dt><dd>${escapeHTML(workspaceValue(item.attempts))} / ${escapeHTML(workspaceValue(item.maxAttempts))}</dd></div><div><dt>检查点序号</dt><dd>${escapeHTML(workspaceValue(item.checkpointSeq))}</dd></div><div><dt>下次重试</dt><dd>${escapeHTML(formatDate(item.nextRetryAt))}</dd></div><div><dt>创建时间</dt><dd>${escapeHTML(formatDate(item.createdAt))}</dd></div><div><dt>更新时间</dt><dd>${escapeHTML(formatDate(item.updatedAt))}</dd></div><div><dt>错误</dt><dd>${escapeHTML(workspaceValue(item.error))}</dd></div></dl>${taskActionControls(item, revision)}`)}${workspaceCard('工作进程租约', leaseBody)}</div><div class="workspace-grid-two">${workspaceCard('阶段历史', historyBody)}${workspaceCard('当前检查点', checkpointBody)}</div><div class="workspace-grid-two">${workspaceCard('输入参数', workspaceJsonDetails('查看任务输入（接口原文）', item.payload || item.input || {}))}${workspaceCard('调用重放', replayBody)}</div>${workspaceCard('归档报告', reportBody)}` });
}

function renderFindingRows(items) {
  const search = String($('#workspace-finding-search')?.value || '').toLowerCase();
  const severity = $('#workspace-finding-severity')?.value || 'all';
  const status = $('#workspace-finding-status')?.value || 'all';
  const triageStatus = $('#workspace-finding-triage-status')?.value || 'all';
  const filtered = items.filter((item) => {
    const text = JSON.stringify(item).toLowerCase();
    return (!search || text.includes(search)) && (severity === 'all' || String(item.severity || item.impact) === severity)
      && (status === 'all' || String(item.status || item.state) === status)
      && (triageStatus === 'all' || String(item.triage?.triageStatus || 'unreviewed') === triageStatus);
  });
  const target = $('#workspace-finding-rows');
  if (!target) return;
  // 严重度用统一的人话标签 + 徽章：后端返回的 'High' / 'Medium' / 'Informational'
  // 混合大小写，直接显示会让表格里出现一半英文一半中文。
  // 「标题 / 规则」列：接口给了 title 就用中文标题，没有就退回规则的人话说法。
  const rowTitle = (item) => {
    const title = String(item?.title || item?.name || '').trim();
    return title ? title : workspaceCheckLabel(item?.check);
  };
  target.innerHTML = filtered.length ? filtered.map((item) => `<tr><td>${findingLink(item)}</td><td>${escapeHTML(rowTitle(item))}</td><td>${workspaceSeverityBadge(item.severity || item.impact)}</td><td>${escapeHTML(workspaceEvidenceLabel(item.status || item.state))}</td><td>${escapeHTML(triageStatusLabels[item.triage?.triageStatus] || '待处理')}</td><td>${escapeHTML(workspaceValue(item.target || item.contract))}</td></tr>`).join('') : `<tr><td colspan="6">${escapeHTML(search || severity !== 'all' || status !== 'all' || triageStatus !== 'all' ? '筛选后没有记录。' : '接口返回空集；当前没有漏洞记录。')}</td></tr>`;
}

function exportFindingList(items) {
  const search = String($('#workspace-finding-search')?.value || '').toLowerCase();
  const severity = $('#workspace-finding-severity')?.value || 'all';
  const status = $('#workspace-finding-status')?.value || 'all';
  const triageStatus = $('#workspace-finding-triage-status')?.value || 'all';
  const filtered = items.filter((item) => {
    const text = JSON.stringify(item).toLowerCase();
    return (!search || text.includes(search)) && (severity === 'all' || String(item.severity || item.impact) === severity)
      && (status === 'all' || String(item.status || item.state) === status)
      && (triageStatus === 'all' || String(item.triage?.triageStatus || 'unreviewed') === triageStatus);
  });
  const cell = (value) => {
    let text = String(value ?? '');
    if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const rows = [
    ['漏洞 ID', '标题', '严重度', '检测状态', '人工处置', '指派人', '标签', '目标'],
    ...filtered.map((item) => [item.findingId || item.id, item.title || item.check || item.name, severityLabels[item.severity] || severityLabels[item.impact] || item.severity || item.impact, workspaceEvidenceLabel(item.status || item.state), triageStatusLabels[item.triage?.triageStatus] || '待处理', item.triage?.assignee, (item.triage?.tags || []).join(', '), item.target || item.contract]),
  ];
  const blob = new Blob([`\ufeff${rows.map((row) => row.map(cell).join(',')).join('\r\n')}`], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = '漏洞列表.csv'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
/* 验证结论摘要：validation 是 { localTest, deploymentBound, exploitabilityEstablished }。
 * 直接把 JSON 摊给读者看不懂，翻译成中文；同时保留"没有确认可利用"这一事实，
 * 不因为本地测试通过就写成已确认漏洞。
 * 名字刻意不叫 workspaceValidationSummary，避免与并行任务可能新增的同名函数
 * 重复声明（ES 模块里重复函数声明是 SyntaxError，会让整个 app.js 加载失败）。 */
function findingValidationText(value) {
  const entry = value && typeof value === 'object' ? value : {};
  const localLabels = {
    passed_source_bound: '本地测试通过（仅绑定源码）',
    passed: '本地测试通过',
    failed: '本地测试未通过',
    not_run: '尚未运行本地测试',
    not_performed: '未执行本地测试',
  };
  const local = entry.localTest;
  const localText = localLabels[local] || (local ? String(local) : '未记录');
  const deployment = entry.deploymentBound === true ? '是' : '否';
  const exploitability = entry.exploitabilityEstablished === true ? '是' : '否';
  return `本地测试：${localText}；已绑定部署合约：${deployment}；已确认可利用：${exploitability}。`;
}
const findingFieldLabels = Object.freeze({
  findingId: '漏洞 ID', id: '记录 ID', title: '标题', check: '检测规则', severity: '严重度', impact: '影响等级',
  confidence: '置信度', status: '确认状态', state: '状态', target: '目标', contract: '合约', function: '函数', selector: '选择器',
  source: '来源', sourceRef: '来源引用', evidence: '证据', description: '说明', recommendation: '修复建议', createdAt: '创建时间', updatedAt: '更新时间',
  // 后端快照里的原始字段名，之前直接以英文显示在界面上，读者看不出含义。
  kind: '证据类型', confidenceScore: '置信度分值', evidenceStatus: '证据状态', confirmed: '是否已确认',
  sourceRefs: '来源清单', relatedSourceChecks: '关联检查点', validation: '验证结论', assetChanges: '资产变化',
  permissionChanges: '权限变化', trace: '调用轨迹', stateDiff: '状态差异', seed: '随机种子', fork: '分叉区块',
  markdown: '检测说明', chainId: '风险链路', element: '目标元素', origin: '来源类型', snapshotGeneratedAt: '快照生成时间',
  validated: '是否已验证', localTest: '本地测试', exploitability: '可利用性', relatedFindings: '关联漏洞',
});
async function renderFindingsWorkspace() {
  const result = await optionalResource('/api/v1/findings?limit=1000');
  const items = workspaceItems(result.data);
  state.workspaceFindings = items;
  $('#nav-findings-view').textContent = String(items.length);
  const severities = [...new Set(items.map((item) => item.severity || item.impact).filter(Boolean))];
  const statuses = [...new Set(items.map((item) => item.status || item.state).filter(Boolean))];
  const body = workspaceError(result) ? workspaceStatus(workspaceError(result), 'error') : `<div class="workspace-finding-tools"><div class="workspace-filters"><label>搜索<input id="workspace-finding-search" type="search" placeholder="标题、合约、规则"></label><label>严重度<select id="workspace-finding-severity"><option value="all">全部</option>${severities.map((value) => `<option value="${escapeHTML(value)}">${escapeHTML(severityLabels[value] || value)}</option>`).join('')}</select></label><label>检测状态<select id="workspace-finding-status"><option value="all">全部</option>${statuses.map((value) => `<option value="${escapeHTML(value)}">${escapeHTML(workspaceEvidenceLabel(value))}</option>`).join('')}</select></label><label>人工处置<select id="workspace-finding-triage-status"><option value="all">全部</option>${Object.entries(triageStatusLabels).map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}</select></label></div><button class="workspace-submit workspace-export" id="workspace-findings-export" type="button" title="导出当前已载入列表">导出当前列表 CSV</button></div><div class="workspace-table-wrap"><table class="workspace-table"><thead><tr><th>稳定 ID</th><th>标题 / 规则</th><th>严重度</th><th>检测状态</th><th>人工处置</th><th>目标</th></tr></thead><tbody id="workspace-finding-rows"></tbody></table></div>`;
  return workspaceFrame({ kicker: '风险 / 归并', title: '漏洞中心', description: '漏洞状态、严重度和证据链接来自分析资源；静态候选不会自动变成确认漏洞。', mode: 'read', body: workspaceCard('漏洞记录', body), footer: `当前记录 ${items.length} 条 · 数据版本 ${workspaceValue(result.data?.consistency?.revision ?? '未提供')}` });
}

async function renderFindingDetailWorkspace(id) {
  if (!id) {
    const result = await optionalResource('/api/v1/findings?limit=100');
    const items = workspaceItems(result.data);
    const rows = workspaceTable(items, [{ label: '漏洞', render: (item) => findingLink(item, workspaceValue(item.title || item.check || item.findingId || item.id)) }, { label: '严重度', render: (item) => workspaceSeverityBadge(item.severity || item.impact) }, { label: '状态', render: (item) => `<span>${escapeHTML(workspaceEvidenceLabel(item.status || item.state))}</span>` }], workspaceError(result) || '当前没有漏洞记录，请从漏洞中心选择一条。');
    return workspaceFrame({ kicker: '风险 / 详情', title: '漏洞详情', description: '请选择一条已有漏洞记录查看证据。', mode: 'read', body: workspaceCard('可用漏洞', rows) });
  }
  const finding = await optionalResource(`/api/v1/findings/${encodeURIComponent(id)}`);
  if (!finding.ok) return workspaceFrame({ kicker: '风险 / 详情', title: '漏洞详情不可用', description: finding.error.message, body: workspaceStatus(finding.error.message, 'error') });
  // 信封层级：响应是 { data: { finding: {...} } }。
  // 之前读成 data.data.finding，取到的其实是 { finding: {...} } 这层外壳，
  // 于是页面只剩一个名为「finding」的字段，标题退化成哈希，证据表永远为空。
  const item = finding.data?.data?.finding || finding.data?.finding || finding.data?.data || finding.data;
  // 证据接口按稳定 ID 过滤（finding-xxx），而路由里可能带的是另一套 ID（哈希）。
  // 两套 ID 都查一遍，避免出现「明明有证据却显示为空」的静默错值。
  const evidenceIds = [item?.findingId, id].filter((value) => typeof value === 'string' && value);
  const evidenceReads = await Promise.all(evidenceIds.map((value) => optionalResource(`/api/v1/evidence?findingId=${encodeURIComponent(value)}&limit=100`)));
  const evidenceItems = [];
  const seenEvidence = new Set();
  for (const read of evidenceReads) {
    if (!read.ok) continue;
    for (const row of workspaceItems(read.data)) {
      const key = String(row.evidenceId || row.id || JSON.stringify(row));
      if (seenEvidence.has(key)) continue;
      seenEvidence.add(key);
      evidenceItems.push(row);
    }
  }
  const evidenceError = evidenceReads.find((read) => !read.ok)?.error || null;
  // 字段值里的状态词与布尔值也要人话化：
  // 直接把 hypothesis / false 摆出来，读者只能猜含义。
  const findingFieldValue = (key, value) => {
    if (typeof value === 'boolean') return value ? '是' : '否';
    if (['status', 'state', 'evidenceStatus', 'kind'].includes(key)) return workspaceEvidenceLabel(value);
    // 规则 ID 给人话说法，括号里保留原 ID 对照。
    if (key === 'check') return workspaceCheckLabel(value);
    // 用 try/catch 而不是直接调用：这段代码可能被并行任务同时改动，
    // 直接调用一个尚未定义的函数会让整页渲染抛错（页面只剩「读取失败」）。
    // 调用失败就退回显示原始对象：不丢信息，也不假装有结论。
    if (key === 'validation' && value && typeof value === 'object') {
      try { return findingValidationText(value); }
      catch { return workspaceValue(value, 900); }
    }
    return workspaceValue(value, 900);
  };
  const fields = Object.entries(item || {}).filter(([key]) => !['evidence', 'raw', 'details', 'triage'].includes(key)).map(([key, value]) => `<div><dt>${escapeHTML(findingFieldLabels[key] || key)}</dt><dd>${escapeHTML(findingFieldValue(key, value))}</dd></div>`).join('');
  const triage = item.triage || { triageStatus: 'unreviewed', assignee: null, tags: [], notes: [] };
  const notes = Array.isArray(triage.notes) ? triage.notes.slice(-20).reverse() : [];
  const noteList = notes.length ? `<ol class="workspace-triage-notes">${notes.map((entry) => `<li><span>${escapeHTML(formatDate(entry.at))}</span><p>${escapeHTML(entry.note)}</p></li>`).join('')}</ol>` : '<p class="workspace-form-note">当前没有处置备注。</p>';
  const triageEditor = `<form class="workspace-form workspace-triage-form" data-finding-triage="${escapeHTML(item.findingId || id)}" data-revision="${escapeHTML(finding.data.consistency?.revision ?? '')}" data-current-status="${escapeHTML(triage.triageStatus || 'unreviewed')}"><div class="workspace-form-grid"><label>处置状态<select name="triageStatus">${Object.entries(triageStatusLabels).map(([value, label]) => `<option value="${value}" ${(triage.triageStatus || 'unreviewed') === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label><label>指派给<input name="assignee" maxlength="200" value="${escapeHTML(triage.assignee || '')}" placeholder="姓名或小组；留空可清除"></label><label class="workspace-form-wide">标签（逗号分隔）<input name="tags" maxlength="2000" value="${escapeHTML((triage.tags || []).join(', '))}" placeholder="例如：资产会计, 升级"></label><label class="workspace-form-wide">添加备注<textarea name="note" rows="3" maxlength="4000" placeholder="误报、修复或接受风险时需填写原因"></textarea></label></div><p class="workspace-form-note">人工处置仅用于跟踪，不会更改检测状态、严重度、确认结果或原始证据。</p><button class="workspace-submit" type="submit">保存处置</button><span class="workspace-form-result" data-triage-result role="status" aria-live="polite"></span></form><details class="workspace-triage-history"><summary>处置备注（${notes.length}）</summary>${noteList}</details>`;
  // 证据记录的真实字段是 markdown / kind / sourceRefs，
  // 早前只读 summary / description，两者恒为空，表格看起来"有证据但没内容"。
  const evidenceTable = workspaceTable(evidenceItems, [
    { label: '证据 ID', render: (row) => `<code>${escapeHTML(workspaceValue(row.evidenceId || row.id))}</code>` },
    { label: '类型', render: (row) => `<span>${escapeHTML(evidenceKindLabels[row.kind] || workspaceValue(row.kind))}</span>` },
    { label: '状态', render: (row) => `<span>${escapeHTML(workspaceEvidenceLabel(row.status || row.evidenceStatus))}</span>` },
    { label: '来源', render: (row) => `<code>${escapeHTML(workspaceValue(row.source || (Array.isArray(row.sourceRefs) ? row.sourceRefs.map((ref) => ref?.ref).filter(Boolean).join('、') : null)))}</code>` },
    { label: '摘要', render: (row) => `<span>${escapeHTML(workspaceValue(row.summary || row.description || row.markdown, 360))}</span>` },
  ], '该漏洞尚无单独证据记录。');
  // 证据接口读失败时不能装作"没有证据"：静默的空表会让人误以为证据确实为空。
  const evidenceBody = evidenceError
    ? `${workspaceStatus(evidenceError.message, 'error')}${evidenceItems.length ? evidenceTable : ''}`
    : evidenceTable;
  // 页头标题：接口没有 title 字段时，用「规则的人话说法」当标题，
  // 原 ID 放进 kicker 与描述里，避免标题退化成一串哈希。
  const humanTitle = String(item?.title || item?.name || '').trim() || workspaceCheckLabel(item?.check);
  const frameDescription = `查看检测依据并记录人工处置；分析结果与工作跟踪分开展示。漏洞 ID：${id}。`;
  return workspaceFrame({ kicker: '风险 / 详情', title: humanTitle, description: frameDescription, mode: 'write', body: `<div class="workspace-grid-two">${workspaceCard('判定与影响', `<dl class="workspace-definition">${fields || '<div><dt>记录</dt><dd>接口没有提供结构化字段。</dd></div>'}</dl>`)}${workspaceCard('证据', evidenceBody)}</div>${workspaceCard('人工处置', triageEditor)}${workspaceJsonDetails('漏洞原始对象', item)}` });
}

function dynamicEvidence(report) {
  const value = report?.localTests || report?.dynamicAnalysis || report?.dynamic || null;
  if (!value || typeof value !== 'object') return null;
  const results = Array.isArray(value.results) ? value.results : Array.isArray(value.tests) ? value.tests : [];
  const tests = Number.isSafeInteger(value.tests) ? value.tests : results.length || null;
  const passed = Number.isSafeInteger(value.passed) ? value.passed : results.filter((item) => item?.state === 'passed').length;
  const failed = Number.isSafeInteger(value.failed) ? value.failed : results.filter((item) => item?.state === 'failed').length;
  return { state: value.state || (tests === null ? 'not_performed' : 'completed'), tests, passed, failed, transactionEvidence: value.transactionEvidence, executionBoundary: value.executionBoundary, failureEvidence: value.failureEvidence, limitations: Array.isArray(value.limitations) ? value.limitations : [] };
}

const dynamicFailureFieldLabels = Object.freeze({
  seed: '随机种子', caller: '调用者', role: '权限角色', parameters: '调用参数', value: '转账金额',
  transactionSequence: '交易顺序', blockTime: '区块时间', initialState: '初始状态', dependencyCodeHashes: '依赖代码摘要',
  trace: '执行轨迹', stateDiff: '状态变化', events: '事件记录', assetChanges: '资产变化', permissionChanges: '权限变化',
  profit: '收益', cost: '成本', minimumSequence: '最小复现步骤', replayCommand: '重放命令',
});

function dynamicFailureEvidenceSummary(value) {
  if (!value || typeof value !== 'object') return '失败依据未提供。';
  const samples = Array.isArray(value.samples) ? value.samples : [];
  if (value.state === 'not_performed') return '没有记录到失败场景。';
  if (!samples.length) {
    return value.reason ? `失败依据暂不可用：${readableDynamicReason(value.reason)}` : '失败依据暂不可用。';
  }
  const scenarioSummary = samples.slice(0, 3).map((sample) => {
    const fields = sample?.fields && typeof sample.fields === 'object' ? sample.fields : {};
    const available = Object.entries(fields).filter(([, evidence]) => evidence?.state === 'available').map(([name]) => dynamicFailureFieldLabels[name] || name);
    const suffix = available.length ? `，已记录${available.slice(0, 4).join('、')}${available.length > 4 ? '等' : ''}` : '，没有记录可用的现场数据';
    return `${sample?.scenario || '未命名场景'}${suffix}`;
  });
  const omitted = samples.length - scenarioSummary.length;
  const scope = value.state === 'partial' ? '当前只绑定了失败断言与已捕获的交易/轨迹，记录仍不完整' : '当前记录了失败场景';
  return `${scope}：${scenarioSummary.join('；')}${omitted > 0 ? `；另有 ${omitted} 个场景未展开` : ''}。这里只说明测试场景失败，不等于确认存在漏洞。`;
}

function dynamicFailureEvidenceDetails(value) {
  if (!value || typeof value !== 'object') return '';
  return workspaceJsonDetails('查看失败依据（原始记录）', value);
}

function irCount(value, countKeys, collectionKeys) {
  for (const key of countKeys) {
    const number = Number(value?.[key]);
    if (Number.isSafeInteger(number) && number >= 0) return number;
  }
  for (const key of collectionKeys) if (Array.isArray(value?.[key])) return value[key].length;
  return null;
}

function unifiedIRReadableSummary(value) {
  if (!value || typeof value !== 'object') return '';
  const parts = [];
  const counts = [
    ['函数', irCount(value, ['functionCount', 'functionsCount'], ['functions'])],
    ['操作', irCount(value, ['operationCount', 'operationsCount'], ['operations'])],
    ['事件线索', irCount(value, ['eventCount', 'eventsCount'], ['events'])],
    ['错误类型线索', irCount(value, ['errorCount', 'errorsCount'], ['errors'])],
    ['控制流连接', irCount(value, ['controlFlowEdgeCount', 'controlFlowEdgesCount'], ['controlFlowEdges'])],
  ];
  for (const [label, count] of counts) if (count !== null) parts.push(`${label} ${count}`);
  if (!parts.length) parts.push('暂未提供结构化数量');
  const limits = [];
  if (value.semanticsProven === false) limits.push('只是代码线索，尚未证明真实语义');
  if (value.state === 'partial') limits.push('记录不完整');
  if (value.state === 'unavailable') limits.push('统一记录暂不可用');
  return `${parts.join(' · ')}${limits.length ? `；${limits.join('，')}。` : '。'}`;
}

function dynamicTransactionSummary(value) {
  const tx = value?.transactionEvidence;
  if (!tx || typeof tx !== 'object') return '交易统计未提供。';
  const number = (key) => Number.isFinite(Number(tx[key])) ? Number(tx[key]) : null;
  const submitted = number('submitted');
  const committed = number('committed');
  const reverted = number('reverted');
  const skipped = number('skipped');
  const traceValid = number('traceValid');
  const tracePartial = number('tracePartial');
  const traceUnavailable = number('traceUnavailable');
  const state = tx.state === 'available' ? '记录完整' : tx.state === 'partial' ? '记录部分完整' : tx.state === 'unavailable' ? '记录不可用' : '未执行';
  const pieces = [
    submitted == null ? '已检查交易未提供' : `已检查交易 ${submitted} 笔`,
    committed == null ? '' : `提交成功 ${committed} 笔`,
    reverted == null ? '' : `回滚 ${reverted} 笔`,
    skipped == null ? '' : `采样跳过 ${skipped} 笔`,
    `运行记录${state}`,
  ].filter(Boolean);
  if (traceValid != null || tracePartial != null || traceUnavailable != null) {
    pieces.push(`运行细节可用 ${traceValid ?? 0} 条${tracePartial ? `，不完整 ${tracePartial} 条` : ''}${traceUnavailable ? `，不可用 ${traceUnavailable} 条` : ''}`);
  }
  return `${pieces.join('；')}。`;
}

function dynamicExecutionBoundarySummary(value) {
  const boundary = value?.executionBoundary;
  if (!boundary || typeof boundary !== 'object') return '执行范围未提供。';
  if (boundary.forkState === 'not_performed' || boundary.externalTransactions === false) {
    return '执行范围：仅本机隔离模拟，未连接真实链，也未读取链上历史状态。';
  }
  if (boundary.forkState === 'performed') return '执行范围：已读取指定链上历史状态；仍只代表本次检查。';
  return '执行范围已记录，但当前报告没有说明是否连接真实链。';
}

function readableDynamicReason(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (/no target-specific local evm harness/i.test(text)) return '没有为这个目标准备专用的本地检查。';
  if (/no reviewed target-specific local harness/i.test(text)) return '这个目标目前没有可用的专用本地检查。';
  if (/timeout/i.test(text)) return '检查超时，结果暂时不可用。';
  if (/memory/i.test(text)) return '检查占用内存过高，已停止并保留部分记录。';
  return /[A-Za-z]{4}/.test(text) ? '报告已记录限制，请打开任务查看详情。' : text;
}

async function renderDynamicWorkspace() {
  const campaign = await optionalResource('/api/campaign');
  const run = campaign.data?.campaign || {};
  const recent = Array.isArray(run.recent) ? run.recent : [];
  const counts = run.counts || {};
  const performed = recordedCount(counts.dynamicTestsPerformed ?? counts.localTestsPerformed);
  const failed = recordedCount(counts.dynamicTestsFailed ?? counts.localTestsFailed);
  const recentReported = recent.filter((item) => ['passed', 'completed', 'partial', 'failed', 'unavailable'].includes(item.dynamicAnalysis?.state)).length;
  const recentNotPerformed = recent.filter((item) => item.dynamicAnalysis?.state === 'not_performed').length;
  const recentUnavailable = recent.filter((item) => item.dynamicAnalysis?.state === 'unavailable').length;
  const recentUnrecorded = recent.filter((item) => !item.dynamicAnalysis?.state).length;
  const resultLabels = {
    ...analysisStateLabels, not_performed: '尚未检查', passed: '检查通过', completed: '已完成',
    partial: '部分完成', unavailable: '结果不可用', failed: '运行失败',
  };
  const testCount = (evidence) => {
    if (evidence.tests == null) return '未记录';
    if (recordedCount(evidence.tests) === 0) return '已记录 0 项';
    const passedCount = evidence.passed == null ? '未记录' : displayCount(evidence.passed);
    const failedCount = evidence.failed == null ? '未记录' : displayCount(evidence.failed);
    return `通过 ${passedCount} · 未通过 ${failedCount}`;
  };
  const rows = workspaceTable(recent, [
    { label: '目标', render: (item) => `<span>${escapeHTML(workspaceValue(`${item.chain || '未知链'} · ${item.protocol || '未知项目'}`))}</span>` },
    { label: '检查状态', render: (item) => `<span class="workspace-state">${escapeHTML(item.dynamicAnalysis?.state ? stateLabel(item.dynamicAnalysis.state, resultLabels) : '未记录')}</span>` },
    { label: '检查结果', render: (item) => `<span>${escapeHTML(testCount(item.dynamicAnalysis || {}))}</span>` },
    { label: '检查详情', render: (item) => { const evidence = item.dynamicAnalysis || {}; return `<div>${escapeHTML(dynamicFailureEvidenceSummary(evidence.failureEvidence))}</div>${dynamicFailureEvidenceDetails(evidence.failureEvidence)}${workspaceJsonDetails('查看检查依据', { report: evidence.report, sourceHash: evidence.sourceHash, tests: evidence.tests, passed: evidence.passed, failed: evidence.failed, transactionEvidence: evidence.transactionEvidence, executionBoundary: evidence.executionBoundary, limitations: evidence.limitations })}`; } },
  ], workspaceError(campaign) || '当前报告没有可展示的目标明细；这不表示检查数量为 0。');
  const targetCount = recordedCount(counts.deployedContracts);
  const suiteCount = recordedCount(counts.dynamicTestSuites ?? counts.localTestSuites);
  const recentNote = recent.length
    ? `最近 ${recent.length} 条目标记录：有检查状态记录 ${recentReported} 条，明确未执行 ${recentNotPerformed} 条，其中结果不可用 ${recentUnavailable} 条，状态未记录 ${recentUnrecorded} 条。`
    : '报告没有最近目标明细；不能据此推断所有目标都已检查。';
  return workspaceFrame({ kicker: '检查 / 本地执行', title: '动态检查', description: '提交已验证的源码包进行检查；只有具备专用本地方案的目标会额外执行隔离测试。结果和未覆盖范围都会留在任务记录中。', mode: 'write', body: `<div class="workspace-boundary"><strong>检查范围：</strong>没有专用测试方案时会标记为“未执行”；未执行不代表通过，也不代表发现漏洞。</div><div class="workspace-counts">${workspaceCount('报告涉及的合约', targetCount === null ? '未记录' : displayCount(targetCount))}${workspaceCount('累计运行检查', performed === null ? '未记录' : displayCount(performed))}${workspaceCount('记录为未通过', failed === null ? '未记录' : displayCount(failed))}${workspaceCount('运行组数', suiteCount === null ? '未记录' : displayCount(suiteCount))}</div>${workspaceCard('提交源码检查', scanForm({ title: '源码分析与本地测试', description: '填写已验证源码包文件。系统会先做代码分析；只有命中已有专用方案时才运行隔离测试。', button: '提交检查任务' }))}${workspaceCard('最近目标结果', rows)}<div class="workspace-record-note">${escapeHTML(recentNote)} 上方数字来自整份报告；目标明细只显示最近记录。检查结果只覆盖实际运行的场景，不等于漏洞确认。报告状态：${escapeHTML(stateLabel(run.observedState || run.state, { interrupted: '已中断', completed: '已完成', running: '运行中', stale: '已过期' }))}。</div>` });
}

async function renderReverseWorkspace() {
  const [bytecode, decompile, campaign] = await Promise.all([optionalResource('/api/v1/bytecode?limit=100'), optionalResource('/api/v1/decompile?limit=100'), optionalResource('/api/campaign')]);
  const bytecodeItems = workspaceItems(bytecode.data), decompileItems = workspaceItems(decompile.data);
  const recent = Array.isArray(campaign.data?.campaign?.recent) ? campaign.data.campaign.recent.filter((item) => item?.runtimeBytecodeAnalysis) : [];
  const campaignRun = campaign.data?.campaign || {};
  const counts = campaignRun.counts || {};
  const ownCount = (key) => Object.hasOwn(counts, key) ? recordedCount(counts[key]) : null;
  const runtimeCount = ownCount('runtimeBytecodeAnalyses');
  const decompiledCount = ownCount('runtimeBytecodeDecompilations');
  const notRequestedCount = ownCount('runtimeBytecodeDecompilationsNotRequested');
  const incompleteCount = ownCount('runtimeBytecodeDecompilationsIncomplete');
  const recentDecompile = { completed: 0, partial: 0, failed: 0, not_performed: 0, missing: 0 };
  for (const item of recent) {
    const status = item.runtimeBytecodeAnalysis?.decompilationState;
    if (Object.hasOwn(recentDecompile, status)) recentDecompile[status] += 1;
    else recentDecompile.missing += 1;
  }
  const bytecodeRows = workspaceTable(recent.length ? recent : bytecodeItems, [
    { label: '目标', render: (item) => `<span>${escapeHTML(workspaceValue(item.chain ? `${item.chain} · ${item.protocol}` : item.contractId || item.id))}</span>` },
    { label: '代码读取', render: (item) => { const value = item.runtimeBytecodeAnalysis?.state || item.state; return `<span class="workspace-state">${escapeHTML(value ? stateLabel(value, { ...taskStateLabels, completed: '已读取', not_performed: '尚未读取', unavailable: '暂不可用' }) : '未记录')}</span>`; } },
    { label: '易读整理', render: (item) => { const value = item.runtimeBytecodeAnalysis?.decompilationState; return `<span>${escapeHTML(value ? stateLabel(value, { not_performed: '尚未整理', completed: '已生成', failed: '生成失败', partial: '部分生成', unavailable: '暂不可用' }) : '未记录')}</span>`; } },
    { label: '查看依据', render: (item) => { const value = item.runtimeBytecodeAnalysis || item; const ir = value.unifiedIR || {}; return `<div>${escapeHTML(unifiedIRReadableSummary(ir) || '统一代码记录未提供。')}</div>${reverseArtifactControls(item)}${workspaceJsonDetails('展开代码记录', { report: value.report, bytecodeSha256: value.bytecodeSha256, instructionCount: value.instructionCount, selectorCandidateCount: value.selectorCandidateCount, externalCallSiteCount: value.externalCallSiteCount, storageOperationSiteCount: value.storageOperationSiteCount, decompilationState: value.decompilationState, unifiedIR: ir })}`; } },
  ], workspaceError(campaign) || workspaceError(bytecode) || '当前没有已读取代码的目标记录。');
  const decompileEmpty = workspaceError(decompile) || (decompileItems.length ? '' : '当前没有易读版本任务或产物记录；报告没有记录不等于生成失败，也不代表已成功。');
  const decompileRows = workspaceTable(decompileItems, [
    { label: '目标', render: (item) => `<span>${escapeHTML(workspaceValue(item.contractId || item.id || item.taskId))}</span>` },
    { label: '生成状态', render: (item) => `<span>${escapeHTML(stateLabel(item.state, taskStateLabels))}</span>` },
    { label: '生成内容', render: (item) => `${reverseCrossValidationSummary(item)}${reverseArtifactControls(item)}${workspaceJsonDetails('查看生成记录', item.output || item.checkpoint || item.artifacts || {})}` },
    { label: '相关任务', render: (item) => taskLink(item, '打开任务') },
  ], decompileEmpty || '当前没有易读版本任务或产物记录。');
  const recentNote = recent.length
    ? `最近 ${recent.length} 个目标：易读版已生成 ${recentDecompile.completed} 个、部分生成 ${recentDecompile.partial} 个、明确尚未整理 ${recentDecompile.not_performed} 个、状态未记录 ${recentDecompile.missing} 个。`
    : '最近目标列表为空；不能据此推断所有目标都已完成代码整理。';
  const campaignSummary = runtimeCount === null
    ? (recent.length || bytecodeItems.length ? `报告没有记录代码读取总数；当前列出 ${recent.length || bytecodeItems.length} 个目标。` : '报告没有记录代码读取总数。')
    : `报告记录已读取代码 ${displayCount(runtimeCount)} 份。`;
  const decompileSummary = decompiledCount === null
    ? '报告没有记录易读版本的生成总数。'
    : `报告记录已生成易读版本 ${displayCount(decompiledCount)} 份；尚未请求 ${displayCount(notRequestedCount)} 份；生成不完整 ${displayCount(incompleteCount)} 份。`;
  return workspaceFrame({ kicker: '代码 / 阅读辅助', title: '代码查看', description: '查看已有代码记录，或提交代码生成阅读辅助稿。生成内容由工具推测，不是项目原始源码。', mode: 'write', body: `<div class="workspace-boundary"><strong>结果说明：</strong>生成内容可能不完整或不准确；请结合已验证源码和其他证据复核。</div><div class="workspace-counts">${workspaceCount('已读取代码', runtimeCount === null ? (recent.length || bytecodeItems.length ? `${recent.length || bytecodeItems.length} 条记录` : '未记录') : displayCount(runtimeCount))}${workspaceCount('已生成易读版本', decompiledCount === null ? '未记录' : displayCount(decompiledCount))}${workspaceCount('尚未请求整理', notRequestedCount === null ? '未记录' : displayCount(notRequestedCount))}${workspaceCount('生成不完整', incompleteCount === null ? '未记录' : displayCount(incompleteCount))}</div>${workspaceCard('提交代码整理', decompileForm())}<div class="workspace-grid-two">${workspaceCard('读取到的代码', bytecodeRows)}${workspaceCard('易读版本结果', decompileRows)}</div><div class="workspace-record-note">${escapeHTML(campaignSummary)} ${escapeHTML(decompileSummary)} ${escapeHTML(recentNote)} 原始编号、代码摘要和文件位置已收在各条记录的展开详情中。</div>` });
}

async function renderPermissionsWorkspace() {
  const [analysis, rules, invariants] = await Promise.all([optionalResource('/api/v1/analysis?limit=100'), optionalResource('/api/v1/rules?limit=100&allVersions=false'), optionalResource('/api/v1/invariants?limit=100&allVersions=false')]);
  const analysisItems = workspaceItems(analysis.data), ruleItems = workspaceItems(rules.data), invariantItems = workspaceItems(invariants.data);
  const body = `<div class="workspace-grid-three">${workspaceCard('分析与调用图', workspaceTable(analysisItems, [{ label: '任务', render: (item) => taskLink(item, workspaceValue(item.taskId || item.id)) }, { label: '阶段', render: (item) => `<span>${escapeHTML(stateLabel(item.state, taskStateLabels))}</span>` }, { label: '检查点', render: (item) => workspaceJsonDetails('查看', item.checkpoint || {}) }], workspaceError(analysis) || '当前没有分析记录。'))}${workspaceCard('规则版本', workspaceTable(ruleItems, [{ label: '规则', render: (item) => `<code>${escapeHTML(workspaceValue(item.ruleId || item.id))}</code>` }, { label: '名称', render: (item) => `<span>${escapeHTML(workspaceValue(item.name))}</span>` }, { label: '版本', render: (item) => `<span>${escapeHTML(workspaceValue(item.version))}</span>` }, { label: '启用', render: (item) => `<span>${item.enabled === true ? '是' : item.enabled === false ? '否' : '未提供'}</span>` }], workspaceError(rules) || '当前没有规则版本。'))}${workspaceCard('业务不变量', workspaceTable(invariantItems, [{ label: '不变量', render: (item) => `<code>${escapeHTML(workspaceValue(item.invariantId || item.id))}</code>` }, { label: '描述', render: (item) => `<span>${escapeHTML(workspaceValue(item.description || item.name, 300))}</span>` }, { label: '版本', render: (item) => `<span>${escapeHTML(workspaceValue(item.version))}</span>` }, { label: '状态', render: (item) => `<span>${escapeHTML(workspaceValue(item.state || item.enabled))}</span>` }], workspaceError(invariants) || '当前没有业务不变量。'))}</div>`;
  return workspaceFrame({ kicker: '模型 / 约束', title: '权限与业务模型', description: '展示自动分析、规则版本和不变量记录；接口目前只读时不会提供虚假的编辑成功状态。', mode: 'read', body, footer: '自动推断与用户规则来源由各资源记录区分；没有记录时不推断权限关系。' });
}

async function renderReplayWorkspace() {
  const [replay, evidence] = await Promise.all([optionalResource('/api/v1/replay?limit=100'), optionalResource('/api/v1/evidence?limit=100')]);
  const replayItems = workspaceItems(replay.data), evidenceItems = workspaceItems(evidence.data);
  return workspaceFrame({ kicker: '证据 / 执行', title: '调用轨迹和重放', description: '只展示已归档的重放产物与证据；没有重放执行器时明确显示不可用。', mode: 'read', body: `<div class="workspace-grid-two">${workspaceCard('重放产物', workspaceTable(replayItems, [{ label: '产物', render: (item) => `<code>${escapeHTML(workspaceValue(item.artifactId || item.id))}</code>` }, { label: '任务', render: (item) => taskLink(item, workspaceValue(item.taskId)) }, { label: '状态', render: (item) => `<span>${escapeHTML(workspaceValue(item.state || item.status))}</span>` }, { label: '来源', render: (item) => workspaceJsonDetails('查看来源', item.provenance || item) }], workspaceError(replay) || '当前没有重放产物。'))}${workspaceCard('证据记录', workspaceTable(evidenceItems, [{ label: '漏洞', render: (item) => findingLink(item, workspaceValue(item.findingId)) }, { label: '状态', render: (item) => `<span>${escapeHTML(evidenceStateLabels[item.status] || workspaceValue(item.status))}</span>` }, { label: '交易 / 区块', render: (item) => `<code>${escapeHTML(workspaceValue(item.transactionHash || item.txHash))} / ${escapeHTML(workspaceValue(item.blockNumber))}</code>` }, { label: '调用树', render: (item) => workspaceJsonDetails('查看调用树', item.callTree || item.trace || {}) }], workspaceError(evidence) || '当前没有证据记录。'))}</div><div class="workspace-status workspace-status-info">页面不执行签名、授权或链上广播；重新执行必须由隔离环境任务提供可验证结果。</div>` });
}

async function askWorkspace(question, target) {
  const value = String(question || '').trim();
  if (!value || !target) return;
  target.insertAdjacentHTML('beforeend', `<div class="workspace-chat-message user"><b>提问</b><span>${escapeHTML(value)}</span></div>`);
  try {
    const data = await apiJSON('/api/ask', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: value, useModel: false }), signal: AbortSignal.timeout(55000) });
    target.insertAdjacentHTML('beforeend', `<div class="workspace-chat-message assistant"><b>结构化状态</b><span>${escapeHTML(data.answer || '接口没有返回回答。')}</span><small>${escapeHTML(data.fallbackReason || '事实绑定快照')}</small></div>`);
  } catch (error) { target.insertAdjacentHTML('beforeend', `<div class="workspace-chat-message error"><b>读取失败</b><span>${escapeHTML(error.message)}</span></div>`); }
  target.scrollTop = target.scrollHeight;
}

function collaborationBoundary(snapshot, auditResult) {
  const campaign = snapshot?.campaign || {};
  const counts = campaign.counts || {};
  const auditItems = workspaceItems(auditResult?.data);
  const cloudCount = Object.hasOwn(counts, 'cloudReviewCompletions') ? recordedCount(counts.cloudReviewCompletions) : null;
  const historicalReviews = Object.hasOwn(counts, 'sourceReviews') ? recordedCount(counts.sourceReviews) : null;
  const cloudConfig = campaign.config?.cloudReviewConfiguration;
  const cloudState = cloudConfig === 'configured' ? '已配置' : cloudConfig === 'unavailable' ? '未配置' : '未记录';
  const cloudEvidence = cloudCount === null ? '云端审查完成次数：未记录' : `云端审查完成次数：${displayCount(cloudCount)}`;
  const historical = historicalReviews === null
    ? '历史审查记录：未记录'
    : `历史审查记录：${displayCount(historicalReviews)} 次（不能替代云端审查证据）`;
  const audit = auditResult?.ok ? `审查审计记录：${displayCount(auditItems.length)} 条` : '审查审计记录：暂不可读取';
  return `<div class="workspace-status ${cloudState === 'configured' && cloudCount !== null ? 'workspace-status-info' : 'workspace-status-warn'}"><strong>云端审查：${escapeHTML(cloudState)}</strong><br>${escapeHTML(cloudEvidence)} · ${escapeHTML(audit)}<br>${escapeHTML(historical)}。只有明确的云端完成次数和审计记录才计入云端进度。</div>`;
}

async function renderAiWorkspace() {
  const [status, audits, health] = await Promise.all([optionalResource('/api/status'), optionalResource('/api/v1/reviews/audit?limit=100'), optionalResource('/api/health')]);
  const snapshot = status.data || {}, model = snapshot.model || {}, auditItems = workspaceItems(audits.data);
  const auditTable = workspaceTable(auditItems, [{ label: '请求', render: (item) => `<code>${escapeHTML(workspaceValue(item.requestId || item.id))}</code>` }, { label: '决定', render: (item) => `<span>${escapeHTML(workspaceValue(item.decision || item.status))}</span>` }, { label: '清单哈希', render: (item) => `<code>${escapeHTML(workspaceValue(item.manifestSha256))}</code>` }, { label: '时间', render: (item) => `<span>${escapeHTML(formatDate(item.createdAt || item.at))}</span>` }], workspaceError(audits) || '当前没有审查审计记录。');
  const cloudReviewCount = snapshot.campaign?.counts?.cloudReviewCompletions;
  const cloudReviewLabel = cloudReviewCount === null || cloudReviewCount === undefined ? '未记录' : displayCount(cloudReviewCount);
  const modelState = model.configured ? '已配置' : '未配置';
  const modelDetail = model.configured
    ? `云端审查通道已配置：${model.baseUrlHost || '主机未记录'} · ${model.model || '模型未记录'}。配置检查不代表服务可达。`
    : '云端审查通道未配置；结构化状态与本地分析仍可使用。';
  const modelRole = model.participatesInSecurityAnalysis === true ? '云端通道用于安全审查；漏洞状态仍以报告证据和审计记录为准。' : '当前通道不参与安全审查。';
  const modelStatus = `<div class="workspace-status ${model.configured ? 'workspace-status-info' : 'workspace-status-warn'}"><strong>状态：${escapeHTML(modelState)}</strong><br>${escapeHTML(modelDetail)}<br>${escapeHTML(modelRole)}</div><div class="workspace-record-note">状态问答默认返回结构化事实；只有显式请求时才发送到已配置的云端通道。</div>`;
  return workspaceFrame({ kicker: '状态 / 协作', title: '状态问答与云端审查通道', description: '这里显示云端审查配置、审计证据和服务健康。网页问答默认使用当前快照中的结构化事实。', mode: 'mixed', body: `<div class="workspace-counts">${workspaceCount('云端审查通道', modelState)}${workspaceCount('云端审查完成', cloudReviewLabel)}${workspaceCount('服务健康', health.ok ? workspaceValue(health.data.status || '在线') : '不可用')}</div>${collaborationBoundary(snapshot, audits)}<div class="workspace-grid-two">${workspaceCard('云端审查通道状态', modelStatus)}${workspaceCard('审查审计记录', auditTable)}</div>${workspaceCard('结构化状态问答', `<div class="workspace-chat" id="workspace-ai-messages"><div class="workspace-chat-message assistant"><b>状态</b><span>默认只根据当前快照回答任务、证据和限制。</span></div></div><form class="workspace-ask-form" data-ai-form><input name="question" maxlength="2000" placeholder="询问当前任务、证据或限制" required><button type="submit">查询</button></form>`)}<div class="workspace-record-note">云端审查完成数只使用报告中的明确记录；没有记录时显示“未记录”。历史审查记录不会自动转换成云端结论。</div>` });
}

function wireWorkspaceForms() {
  for (const button of document.querySelectorAll('#workspace-view [data-corpus-action]')) button.addEventListener('click', async () => {
    const laneId = button.dataset.corpusLane;
    const action = button.dataset.corpusAction;
    const result = button.closest('.corpus-lane-card')?.querySelector('.corpus-action-result');
    if (!laneId || !action || button.disabled) return;
    if (action === 'apply-filter') return;
    button.disabled = true;
    if (result) { result.textContent = '正在提交…'; result.dataset.state = 'loading'; }
    try {
      const path = `/api/v1/corpus/tasks/${encodeURIComponent(laneId)}/${encodeURIComponent(action)}`;
      const body = action === 'start' ? { category: $('#workspace-view [data-corpus-category]')?.value || undefined } : {};
      await apiJSON(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      // 反馈写进模块级状态：轮询重绘后仍然可见（重绘会清空 DOM 里的 span）。
      corpusViewState.feedback.action = { laneId, state: 'ready', text: `已提交「${button.textContent}」` };
      await refreshCorpusWorkspace();
    } catch (error) {
      corpusViewState.feedback.action = { laneId, state: 'error', text: `操作失败：${error.message}` };
      if (result) { result.textContent = corpusViewState.feedback.action.text; result.dataset.state = 'error'; }
      button.disabled = false;
    }
  });
  for (const button of document.querySelectorAll('#workspace-view [data-corpus-apply-filter]')) button.addEventListener('click', async () => {
    const result = $('#workspace-view [data-corpus-filter-result]');
    const laneId = $('#workspace-view [data-corpus-filter-lane]')?.value || 'static';
    const category = $('#workspace-view [data-corpus-category]')?.value || '';
    captureCorpusSelection();
    button.disabled = true;
    if (result) { result.textContent = '正在创建任务…'; result.dataset.state = 'loading'; }
    try {
      await apiJSON('/api/v1/corpus/tasks', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(category ? { laneId, category } : { laneId }),
      });
      corpusViewState.feedback.filter = { state: 'ready', text: '已按过滤条件创建任务' };
      await refreshCorpusWorkspace();
    } catch (error) {
      corpusViewState.feedback.filter = { state: 'error', text: `创建失败：${error.message}` };
      if (result) { result.textContent = corpusViewState.feedback.filter.text; result.dataset.state = 'error'; }
    } finally { button.disabled = false; }
  });
  for (const button of document.querySelectorAll('#workspace-view [data-task-action]')) button.addEventListener('click', async () => {
    const controls = button.closest('.task-operator-actions');
    const result = controls?.querySelector('.task-action-result');
    if (!controls || !result || button.disabled) return;
    for (const actionButton of controls.querySelectorAll('button')) actionButton.disabled = true;
    result.textContent = '正在提交…'; result.dataset.state = 'loading';
    const taskId = controls.dataset.taskId;
    const revision = controls.dataset.taskRevision;
    try {
      const payload = await apiJSON(`/api/v1/tasks/${encodeURIComponent(taskId)}/${button.dataset.taskAction}`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'if-match': `W/"${revision}"` },
        body: JSON.stringify({ reason: `web ${button.dataset.taskAction}` }),
      });
      const updated = await renderTaskDetailWorkspace(taskId);
      $('#workspace-view').innerHTML = updated;
      wireWorkspaceForms();
      const status = $('#workspace-view .task-action-result');
      if (status) { status.textContent = `已${button.textContent} · ${stateLabel(payload.data?.state, taskStateLabels)}`; status.dataset.state = 'ready'; }
    } catch (error) {
      result.textContent = `操作失败：${error.message}`; result.dataset.state = 'error';
      for (const actionButton of controls.querySelectorAll('button')) actionButton.disabled = false;
    }
  });
  for (const button of document.querySelectorAll('#workspace-view .reverse-artifact-load')) button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.target);
    const status = button.parentElement.querySelector('.reverse-artifact-status');
    if (!target || button.disabled) return;
    button.disabled = true;
    status.textContent = '正在校验并读取…'; status.dataset.state = 'loading';
    try {
      const response = await apiJSON(`/api/v1/tasks/${encodeURIComponent(button.dataset.taskId)}/artifacts/${encodeURIComponent(button.dataset.artifactSha)}/content`);
      target.textContent = response.data?.content ?? '接口没有返回可读内容。';
      target.hidden = false;
      status.textContent = `已读取并校验 · ${displayCount(response.data?.bytes || 0)} 字节`; status.dataset.state = 'ready';
      button.textContent = '重新读取';
    } catch (error) {
      status.textContent = `暂时无法读取：${error.message}`; status.dataset.state = 'error';
    } finally { button.disabled = false; }
  });
  for (const form of document.querySelectorAll('#workspace-view form[data-finding-triage]')) {
    const status = form.elements.triageStatus;
    const note = form.elements.note;
    const updateNoteRequirement = () => {
      const needsReason = ['false_positive', 'fixed', 'accepted_risk'].includes(status.value) && status.value !== form.dataset.currentStatus;
      note.required = needsReason;
    };
    status.addEventListener('change', updateNoteRequirement);
    updateNoteRequirement();
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const resultNode = form.querySelector('[data-triage-result]');
      const submit = form.querySelector('button[type="submit"]');
      const nextStatus = status.value;
      const body = { assignee: form.elements.assignee.value.trim() || null, tags: form.elements.tags.value.split(',').map((tag) => tag.trim()).filter(Boolean) };
      const noteText = note.value.trim();
      if (nextStatus !== form.dataset.currentStatus) body.triageStatus = nextStatus;
      if (noteText) body.note = noteText;
      if (note.required && !noteText) { resultNode.textContent = '此处置状态需要填写原因。'; resultNode.dataset.state = 'error'; return; }
      submit.disabled = true; resultNode.textContent = '正在保存…'; resultNode.dataset.state = 'loading';
      try {
        const payload = await apiJSON(`/api/v1/findings/${encodeURIComponent(form.dataset.findingTriage)}/triage`, {
          method: 'PATCH', headers: { 'content-type': 'application/json', 'if-match': form.dataset.revision }, body: JSON.stringify(body),
        });
        const updated = await renderFindingDetailWorkspace(form.dataset.findingTriage);
        $('#workspace-view').innerHTML = updated;
        wireWorkspaceForms();
        const savedResult = $('#workspace-view [data-triage-result]');
        if (savedResult) { savedResult.textContent = `已保存 · 版本 ${payload.consistency?.revision ?? '未知'}`; savedResult.dataset.state = 'ready'; }
      } catch (error) {
        resultNode.textContent = `保存失败：${error.message}`; resultNode.dataset.state = 'error';
      } finally { if (submit.isConnected) submit.disabled = false; }
    });
  }
  for (const form of document.querySelectorAll('#workspace-view form[data-resource-form]')) form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const resultNode = form.querySelector('[data-form-result]');
    const data = Object.fromEntries(new FormData(form).entries());
    const resource = form.dataset.resourceForm;
    let path = '/api/v1/projects', body = { projectId: data.projectId, sourcePath: data.sourcePath };
    if (resource === 'collection') { path = '/api/v1/collection'; body = Object.fromEntries(Object.entries(data).filter(([, value]) => String(value).trim())); }
    if (resource === 'scan') {
      path = '/api/v1/tasks';
      const payload = Object.fromEntries(Object.entries(data).filter(([, value]) => String(value).trim()));
      body = { type: 'local-source-analysis', payload };
    }
    if (resource === 'decompile') {
      path = '/api/v1/decompile';
      const bytecode = String(data.runtimeBytecode || '').replace(/\s+/g, '');
      body = Object.fromEntries(Object.entries({ ...data, runtimeBytecode: bytecode }).filter(([, value]) => String(value).trim()));
      if (!body.bytecodePath && !body.runtimeBytecode) {
        resultNode.textContent = '请粘贴代码，或填写代码文件路径。'; resultNode.dataset.state = 'error'; return;
      }
    }
    form.querySelector('button[type="submit"]').disabled = true;
    resultNode.textContent = '正在提交…'; resultNode.dataset.state = 'loading';
    try {
      const response = await apiJSON(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      resultNode.textContent = `已创建任务 ${response.data?.taskId || response.data?.id || '未提供 ID'}`; resultNode.dataset.state = 'ready';
      form.reset();
    } catch (error) {
      const offline = workspaceOfflineMessage(error);
      resultNode.textContent = offline || `提交失败：${error.message}`;
      resultNode.dataset.state = 'error';
      if (offline) resultNode.insertAdjacentHTML('beforeend', `<span class="ws-inline-error-detail">${escapeHTML(error.message || '')}</span>`);
    }
    finally { form.querySelector('button[type="submit"]').disabled = false; }
  });
  const aiForm = $('#workspace-view form[data-ai-form]');
  if (aiForm) aiForm.addEventListener('submit', (event) => { event.preventDefault(); const input = aiForm.elements.question; const value = input.value; input.value = ''; askWorkspace(value, $('#workspace-ai-messages')); });
  for (const selector of ['#workspace-finding-search', '#workspace-finding-severity', '#workspace-finding-status', '#workspace-finding-triage-status']) $(selector)?.addEventListener('input', () => renderFindingRows(state.workspaceFindings || []));
  $('#workspace-findings-export')?.addEventListener('click', () => exportFindingList(state.workspaceFindings || []));
}

function parseWorkspaceRoute() {
  let raw;
  try { raw = decodeURIComponent(location.hash.replace(/^#/, '') || 'home'); }
  catch { return { name: 'overview', anchor: 'overview' }; }
  // 深链接可能带名字（#protocols/Flare）或只带 ID（#finding/<id>）。
  // 名字里可能自带斜杠，所以这里最多切两段，其余原样留在 id 里。
  const [name, ...rest] = raw.split('/');
  const id = rest.length ? rest.join('/') : null;
  if (['map', 'home', 'protocols', 'discoveries', 'execution', 'projects', 'collection', 'scan', 'tasks', 'findings-view', 'finding', 'dynamic', 'reverse', 'permissions', 'replay', 'ai', 'task', 'corpus'].includes(name)) {
    // #protocols/<链名> 是协议页的深链接：除了 id，再把链名单独放进 protocol，
    // 让协议页能定位并高亮到那张链卡片（否则 route.protocol 永远是 undefined）。
    if (name === 'protocols' && id) return { name, id, protocol: id };
    return { name, id: id || null };
  }
  return { name: 'overview', anchor: name };
}
async function renderAuditRoute(route) {
  hideOverview(true);
  const audit = $('#audit-view');
  audit.hidden = false;
  const requestId = ++state.workspaceRequest;
  const snapshot = state.snapshot || await getJSON('/api/status');
  if (!state.snapshot) state.snapshot = snapshot;
  const [contractsResult, invariantsResult] = route.name === 'protocols'
    ? await Promise.allSettled([getJSON('/api/v1/contracts?limit=100'), getJSON('/api/v1/invariants?limit=100&allVersions=false')])
    : [];
  const data = {
    ...snapshot,
    findings: snapshot.findings || snapshot.highPriorityFindings || [],
    contracts: contractsResult?.[0]?.status === 'fulfilled' && Array.isArray(contractsResult[0].value.items) ? contractsResult[0].value.items : [],
    invariants: invariantsResult?.[0]?.status === 'fulfilled' && Array.isArray(invariantsResult[0].value.items) ? invariantsResult[0].value.items : [],
    campaignContracts: (snapshot.campaign?.recent || []).filter((item) => item.address),
    dynamicResults: (snapshot.campaign?.recent || []).filter((item) => item.dynamicAnalysis).map((item) => ({ ...item.dynamicAnalysis, name: `${item.protocol || '未知协议'} · ${item.chain || '未知链'}` })),
  };
  const view = auditViews[route.name];
  // 首页要额外的链上采集控制面状态：链卡片开关和链状态都来自它。
  // 读失败时传 null，首页如实显示「开关不可用」，不会用默认值假装成功。
  let homeControl = null;
  if (route.name === 'home') {
    try {
      // 后端 GET /api/v1/chain-collection/status 把状态对象直接放在顶层，
      // 这里归一化成 { status, availableChains, selectedChainIds }，
      // 避免首页去猜接口形状（猜错会把「读到 200」显示成「读不到」）。
      homeControl = homeView.normalizeControl(await apiJSON('/api/v1/chain-collection/status'));
      state.homeControl = homeControl;
    } catch {
      homeControl = state.homeControl || null;
    }
  }
  if (route.name === 'home') audit.innerHTML = view.render(data, Date.now(), homeControl);
  else audit.innerHTML = view.render(data);
  appendAuditGuidance(audit, route.name);
  if (route.name === 'home') view.bind(audit, await homeHandlers());
  else view.bind(audit);
  if (requestId !== state.workspaceRequest) return;
  if (route.protocol) {
    // 深链接定位：按名称找对应的那张链卡片，找不到就如实说明，不随便高亮第一张。
    const wanted = String(route.protocol);
    const cards = [...audit.querySelectorAll('[data-protocol-detail]')];
    const target = cards.find((card) => card.dataset.protocolDetail === wanted) || null;
    for (const card of cards) card.classList.toggle('is-targeted', card === target);
    if (target) target.scrollIntoView({ block: 'center' });
    else audit.querySelector('[data-protocol-missing]')?.removeAttribute('hidden');
  }
}

/* ------------------------------------------------------------------
 * 首页交互（总开关 + 链开关）。
 *
 * 诚实性约束：
 *   - 总开关只发送 { enabled: boolean }；后端禁止 enabled 与 chainIds 同时出现。
 *   - 链开关只发送 { chainIds: [...] }；它只改「下一轮要扫的链」范围，
 *     不中断正在跑的一轮采集。
 *   - 后端返回 startFailed / stopFailed 时如实显示错误，不假装成功。
 *   - 读取失败时保留上一次显示，不清空成误导性的默认状态。
 * ------------------------------------------------------------------ */
function homeMessage(text, tone = '') {
  const node = document.querySelector('#audit-view [data-home-message]');
  if (!node) return;
  node.textContent = text || '';
  node.dataset.tone = tone;
}

async function homeHandlers() {
  return {
    onMasterToggle: async ({ enabled }) => {
      const next = enabled === true;
      const result = await apiJSON('/api/v1/chain-collection/switch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        // 请求体只能是 { enabled }：后端明确禁止与 chainIds 同时出现。
        body: JSON.stringify({ enabled: next }),
      });
      // 后端把状态对象放在响应顶层，这里统一归一化后再存，
      // 免得后面按 availableChainIds 取链时读的是错误层级。
      const normalized = homeView.normalizeControl(result);
      state.homeControl = normalized;
      await refreshHomeView();
      if (result?.startFailed) homeMessage(`开启失败：${result.startError || '未知原因'}`, 'error');
      else if (result?.stopFailed) homeMessage(`停止失败：${result.stopError || '未知原因'}`, 'error');
      else homeMessage(next ? '链上采集已开启。' : '链上采集已关闭。', 'success');
    },
    onToggle: async ({ chainId, enabled }) => {
      const current = state.homeControl && typeof state.homeControl === 'object' ? state.homeControl : null;
      if (!current) throw new Error('采集控制面状态未就绪，开关暂不可用');
      const allIds = Array.isArray(current.availableChainIds) ? current.availableChainIds.map(String) : [];
      // 后端语义：未选任何链 = 覆盖全部链。所以空范围要当成「全部链」解读。
      const selected = Array.isArray(current.selectedChainIds) && current.selectedChainIds.length
        ? current.selectedChainIds.map(String)
        : allIds;
      const nextScope = scopeAfterToggle(selected, chainId, enabled);
      // 后端把「空范围」读成「全部链」。用户关掉最后一条链时，
      // 如果照直发空数组，这条链反而会被重新打开——而且是静默反转。
      // 所以这里保留最后一条链，并如实告诉用户为什么它没有关掉。
      if (!nextScope.length) {
        homeMessage(
          `无法只关掉这一条链：后端把「一条都不选」理解成「全部链都选」。`
          + `「${chainId}」仍留在下一轮采集范围里。想只跑部分链，请先打开另一条再关掉这一条。`,
          'warn',
        );
        return;
      }
      const result = await apiJSON('/api/v1/chain-collection/switch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chainIds: nextScope }),
      });
      state.homeControl = homeView.normalizeControl(result);
      await refreshHomeView();
      homeMessage(enabled ? '已把这条链加入下一轮采集。' : '已把这条链移出下一轮采集。', 'success');
    },
    onError: (error) => {
      const message = `操作失败：${error?.message || error}`;
      homeMessage(message, 'error');
      return message;
    },
  };
}

async function refreshHomeView({ reloadSnapshot = false } = {}) {
  const audit = $('#audit-view');
  if (!audit || audit.hidden) return;
  const failures = [];
  let snapshot = state.snapshot;
  if (reloadSnapshot) {
    // 刷新按钮必须重新拉取 /api/status，不能继续用首次读到的缓存。
    try {
      await loadStatus();
      snapshot = state.snapshot;
    } catch (error) {
      failures.push(`读取状态快照失败：${error?.message || error}`);
      snapshot = state.snapshot;
    }
  } else if (!snapshot) {
    snapshot = await getJSON('/api/status');
    state.snapshot = snapshot;
  }
  let control = state.homeControl;
  try {
    control = homeView.normalizeControl(await apiJSON('/api/v1/chain-collection/status'));
    state.homeControl = control;
  } catch (error) {
    failures.push(`读取采集控制面失败：${error?.message || error}`);
    control = state.homeControl;
  }
  // 快照可能整个读不到（首屏就没读到、刷新也失败）。
  // 这时不能去读 snapshot.findings —— 那会抛 TypeError，把「读取失败」
  // 变成「页面整个崩掉」。渲染层对空快照有兜底：数字显示「未记录」。
  const safeSnapshot = snapshot && typeof snapshot === 'object' ? snapshot : {};
  const findings = Array.isArray(safeSnapshot.findings)
    ? safeSnapshot.findings
    : (Array.isArray(safeSnapshot.highPriorityFindings) ? safeSnapshot.highPriorityFindings : []);
  const scrollTop = window.scrollY;
  audit.innerHTML = homeView.render({ ...safeSnapshot, findings }, Date.now(), control);
  homeView.bind(audit, await homeHandlers());
  window.scrollTo({ top: scrollTop });
  if (failures.length) homeMessage(failures.join('；'), 'error');
}

function appendAuditGuidance(root, viewName) {
  if (root.querySelector('.audit-next-step')) return;
  // 「下一步」条的链接必须指向真实存在的路由，否则点了只会停在原地。
  const guidance = {
    map: { text: '先在地图上挑一条值得先看的链，点开它，再去看这条链的合约和安全规则。', links: [['protocols', '去「协议」看链和合约'], ['discoveries', '去「发现」看全部线索']] },
    protocols: { text: '确认安全规则的状态后，再进入完整证据和本地复现。', links: [['discoveries', '去「发现」挑一条线索'], ['execution', '去「执行」看运行结果']] },
    discoveries: { text: '先确认一条线索的来源和证据，再去「执行」看它有没有跑过。', links: [['execution', '去「执行」看复现结果'], ['protocols', '回「协议」看这条线索属于哪条链']] },
    execution: { text: '这里没有结果时，先回「发现」挑一条线索，再回到本页看它跑没跑过。', links: [['discoveries', '回「发现」挑一条线索'], ['protocols', '去「协议」看安全规则状态']] },
  }[viewName];
  if (!guidance) return;
  const nav = document.createElement('nav');
  nav.className = 'audit-next-step';
  nav.setAttribute('aria-label', '下一步');
  nav.innerHTML = `<strong>下一步</strong><span>${guidance.text}</span>${guidance.links.map(([hash, label]) => `<a href="#${hash}">${label} <span aria-hidden="true">→</span></a>`).join('')}`;
  root.append(nav);
}
async function routeWorkspace() {
  const route = parseWorkspaceRoute();
  state.workspaceRoute = route.name === 'overview' ? null : route;
  setActiveView(route);
  if (route.name !== 'corpus') stopCorpusPolling();
  if (auditViews[route.name]) {
    try { await renderAuditRoute(route); }
    catch (error) {
      hideOverview(true);
      $('#audit-view').hidden = false;
      $('#audit-view').innerHTML = `<div class="audit-empty">读取视图失败：${escapeHTML(error.message)}</div>`;
    }
    return;
  }
  if (route.name === 'overview') {
    hideOverview(false);
    if (route.anchor && document.getElementById(route.anchor)) requestAnimationFrame(() => document.getElementById(route.anchor).scrollIntoView({ block: 'start' }));
    return;
  }
  hideOverview(true);
  const requestId = ++state.workspaceRequest;
  const workspace = $('#workspace-view');
  // 读取中用骨架 + 一句说明：只有一行「正在读取…」时，页面看起来像坏了。
  workspace.innerHTML = workspaceFrame({ kicker: '实时资源', title: '正在读取…', description: '正在读取持久化接口。', body: `<div class="ws-loading" aria-busy="true" aria-live="polite"><div class="ws-skeleton"></div><div class="ws-skeleton"></div><div class="ws-skeleton"></div><div class="ws-skeleton"></div><p class="ws-loading-note">正在读取本机持久化数据…</p></div>` });
  let html;
  try {
    if (route.name === 'projects') html = await renderProjectsWorkspace();
    else if (route.name === 'collection') html = await renderCollectionWorkspace();
    else if (route.name === 'scan') html = await renderScanWorkspace();
    else if (route.name === 'tasks') html = await renderTasksWorkspace();
    else if (route.name === 'task') html = await renderTaskDetailWorkspace(route.id || '');
    else if (route.name === 'findings-view') html = await renderFindingsWorkspace();
    else if (route.name === 'finding') html = await renderFindingDetailWorkspace(route.id || '');
    else if (route.name === 'dynamic') html = await renderDynamicWorkspace();
    else if (route.name === 'reverse') html = await renderReverseWorkspace();
    else if (route.name === 'permissions') html = await renderPermissionsWorkspace();
    else if (route.name === 'replay') html = await renderReplayWorkspace();
    else if (route.name === 'ai') html = await renderAiWorkspace();
    else if (route.name === 'corpus') html = await renderCorpusWorkspace();
  } catch (error) { html = workspaceFrame({ kicker: '实时资源', title: '读取失败', description: error.message, body: workspaceStatus(error.message, 'error') }); }
  if (requestId !== state.workspaceRequest) return;
  workspace.innerHTML = html || workspaceStatus('没有匹配的视图。', 'error');
  wireWorkspaceForms();
  if (route.name === 'findings-view') renderFindingRows(state.workspaceFindings || []);
  if (route.name === 'corpus') startCorpusPolling();
}

document.addEventListener('audit:navigate', (event) => {
  const { route, id, protocol } = event.detail || {};
  // 协议页的深链接带上链名，页面才能定位到那一张卡片。
  if (route === 'protocol') location.hash = protocol ? `#protocols/${encodeURIComponent(protocol)}` : '#protocols';
  if (route === 'finding' && id) location.hash = `#finding/${encodeURIComponent(id)}`;
});

/* ------------------------------------------------------------------
 * 启动段（放在文件末尾）。
 *
 * 顺序很重要：模块级常量（WORKSPACE_FLAG_* / WORKSPACE_STATE_KIND 等）
 * 必须先完成初始化，再触发首次路由渲染，否则 workspaceFrame() 会撞上
 * 暂时性死区（ReferenceError），模块求值中止，页面只剩静态 HTML，
 * 而后端接口与单元测试全绿，看起来一切正常。
 * ------------------------------------------------------------------ */
addEventListener('hashchange', routeWorkspace);
// 地址栏没有 hash 时默认就是首页：补成 #home，复制链接、刷新、前进后退才与页面一致。
// 用 replaceState 而不是改 location.hash，避免多一条历史记录让「后退」退不出首页。
if (!location.hash) history.replaceState(null, '', `${location.pathname}${location.search}#home`);
routeWorkspace();
