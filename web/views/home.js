// 首页：只回答三个问题 —— 现在是什么状态、下一步点哪里、哪些线索值得看。
//
// 分层原则（见 .cursor/rules/silent-wrong-value-review.mdc）：
//   - 数据层仍保留五级置信度（confidence.js），首页只展示三态：灰（待验证）、
//     黄（疑似）、红（已确认）。「非漏洞声明」与「无法判定」不进候选列表，
//     但数量必须以脚注给出，不能静默丢掉。
//   - 金额：只有 bounty.recorded 为 true 才显示金额；否则只写「暂无数据来源（不是 0）」。
//   - 链卡片状态：总开关关闭时一律「采集未开启」，不能出现「已就绪」。
//   - 采集不区分链，任何地方都不说某条链「正在扫」。
import { escapeHTML } from '../lib/format.js';
import { confidenceBadge, severityMeter } from '../lib/badges.js';
import { buildHomeModel, chainCardState, mergeChainSources, scopeAfterToggle } from '../lib/home-model.js';

const GUIDE_STORAGE_KEY = 'home.guide.dismissed.v1';

const STATE_ICONS = Object.freeze({
  live: '●',
  queued: '✓',
  paused: '⏸',
  error: '!',
  idle: '○',
});

const MOMENT_FORMAT = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
});

function count(value) {
  return Number.isFinite(value) ? String(value) : '未记录';
}

function usd(value) {
  if (!Number.isFinite(value)) return '未记录';
  return `$${Math.round(value).toLocaleString('en-US')}`;
}

/** 时间戳 → 「2026-10-25 08:36」。带年份，避免几天前的快照只显示月日。 */
function moment(value) {
  if (!value) return '未记录';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '未记录';
  return MOMENT_FORMAT.format(date).replace(/\//g, '-');
}

/* localStorage 可能被浏览器策略禁用，也可能根本没有这个全局对象。
   任何一种情况都只能影响「引导是否默认展开」，不能把整页渲染搞崩。 */
function guideDismissed() {
  try {
    if (typeof localStorage === 'undefined') return false;
    return localStorage.getItem(GUIDE_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function rememberGuideDismissed(dismissed) {
  try {
    if (typeof localStorage === 'undefined') return;
    if (dismissed) localStorage.setItem(GUIDE_STORAGE_KEY, '1');
    else localStorage.removeItem(GUIDE_STORAGE_KEY);
  } catch {
    // 存储不可用：引导下次仍然展开，但页面不能报错。
  }
}

/**
 * 控制面响应的形状归一化。
 *
 * 后端 GET /api/v1/chain-collection/status 直接返回状态对象本身
 * （enabled / running / state / stateLabel / availableChains …），
 * 也就是「顶层就是 status」。这里同时接受两种形状：
 *   - { enabled, running, … }              （真实响应）
 *   - { status: { enabled, running, … } }  （包一层）
 *
 * 形状认错时最糟的结果是「读到 200 却显示成读不到」，
 * 所以两种都认，认不出才报「不可用」。
 *
 * known 只在真的认出了控制面字段时才为 true。
 * 空对象 {} 会被读成「已知」，于是页面把一个读不到状态的开关显示成可点的 ——
 * 那就是「读到 200 却显示成读不到」的镜像错误：读到 200 却显示成读得到。
 * 所以这里额外要求至少有一个可识别的状态字段。
 */
export function normalizeControl(control) {
  if (!control || typeof control !== 'object' || Array.isArray(control)) {
    return { status: null, availableChains: [], availableChainIds: [], selectedChainIds: [], known: false };
  }
  const nested = control.status && typeof control.status === 'object' && !Array.isArray(control.status)
    ? control.status
    : null;
  const status = nested || control;
  const chains = Array.isArray(control.availableChains)
    ? control.availableChains
    : (Array.isArray(status.availableChains) ? status.availableChains : []);
  const selected = Array.isArray(control.selectedChainIds)
    ? control.selectedChainIds.map(String)
    : (Array.isArray(status.selectedChainIds) ? status.selectedChainIds.map(String) : []);
  const ids = Array.isArray(control.availableChainIds)
    ? control.availableChainIds.map(String)
    : (Array.isArray(status.availableChainIds)
      ? status.availableChainIds.map(String)
      : chains.map((chain) => String(chain?.chainId)));
  // 至少认出一个状态字段才算「读到了控制面」。
  const recognizable = typeof status.enabled === 'boolean'
    || typeof status.running === 'boolean'
    || typeof status.state === 'string'
    || chains.length > 0
    || ids.length > 0;
  if (!recognizable) {
    // 认不出就当没读到：status 必须是 null，不能塞一个空对象进去。
    // 下游靠 status 决定「已开启 / 已关闭」，空对象会被读成「已关闭」——
    // 那就是把「不知道」说成了「确定没开」。
    return { status: null, availableChains: [], availableChainIds: [], selectedChainIds: [], known: false };
  }
  return { status, availableChains: chains, availableChainIds: ids, selectedChainIds: selected, known: true };
}

/**
 * 采集状态行。优先用控制面（GET /api/v1/chain-collection/status）的字段，
 * 它才是「现在有没有任务在跑」的权威来源；读不到时退回快照里的采集报告。
 */
function collectionSummary(model, control) {
  const status = control.status;
  if (status && typeof status === 'object') {
    const label = typeof status.stateLabel === 'string' && status.stateLabel ? status.stateLabel : null;
    if (status.running === true) {
      return {
        running: true,
        enabled: status.enabled === true,
        text: '采集正在运行',
        sub: label ? `状态：${label}` : null,
        tone: 'live',
      };
    }
    if (status.enabled === true) {
      return {
        running: false,
        enabled: true,
        text: '当前没有任务在跑',
        sub: label ? `上一轮：${label}` : '开关已打开，等待下一轮',
        tone: 'idle',
      };
    }
    if (status.enabled === false) {
      return { running: false, enabled: false, text: '当前没有任务在跑', sub: '采集未开启', tone: 'paused' };
    }
    return { running: false, enabled: null, text: '当前没有任务在跑', sub: label ? `上一轮：${label}` : null, tone: 'idle' };
  }
  if (model.collection.running) {
    return { running: true, enabled: null, text: '采集正在运行', sub: model.collection.label || null, tone: 'live' };
  }
  return { running: false, enabled: null, text: '当前没有任务在跑', sub: model.collection.label || null, tone: 'idle' };
}

function freshnessLine(model) {
  const reported = model.lastReportAt ? `报告时间 ${moment(model.lastReportAt)}` : '报告时间未记录';
  if (model.report.historical === true) return `${reported} · 已是历史快照`;
  if (model.report.historical === null) return `${reported} · 无法判断是否过期`;
  return `${reported} · 24 小时内`;
}

function historyBanner(model) {
  if (model.report.historical !== true) return '';
  const days = Number.isFinite(model.report.ageDays) ? model.report.ageDays : 1;
  return `<div class="home-history" role="status"><span class="home-history-icon" aria-hidden="true">!</span>`
    + `<span>这是 ${days} 天前的历史快照，不代表当前状态</span></div>`;
}

/**
 * 心跳新鲜度说明。
 *
 * 心跳是采集进程自己写的，超过两分钟就不能当作「现在在跑」。
 * 只写「最近一次心跳：…」而不说它有多旧，等于把历史快照说成实时状态。
 */
function heartbeatAgeNote(status) {
  const age = Number(status?.heartbeatAgeMs);
  if (!Number.isFinite(age)) return '';
  if (age <= 120000) return '（新鲜）';
  const minutes = Math.floor(age / 60000);
  if (minutes < 60) return `（已过 ${minutes} 分钟，不代表现在在跑）`;
  const hours = Math.floor(minutes / 60);
  return `（已过 ${hours} 小时，不代表现在在跑）`;
}

function masterPanel(model, control) {
  const status = control.status;
  const known = Boolean(status);
  const enabled = known ? status.enabled === true : null;
  const running = known ? status.running === true : model.collection.running;
  const summary = collectionSummary(model, control);
  // 开关状态读不到时不能写「已关闭」——那是在宣称一个没读到的事实。
  const switchLabel = known
    ? (enabled ? '关闭链上采集' : '开启链上采集')
    : '链上采集开关状态未知';
  const switchTextLabel = known ? (enabled ? '已开启' : '已关闭') : '状态未知';
  const checked = enabled === true ? 'true' : 'false';
  const disabled = known ? '' : ' disabled title="采集控制面状态读取失败，总开关暂不可用"';
  const note = !known
    ? '采集控制面状态读取失败，总开关暂不可用。'
    : enabled
      ? (running
        ? '正在采集。只读取链上代码与已验证源码，不授权、不签名、不广播。'
        : '开关已打开，当前没有任务在跑。开启新一轮采集会立即启动一轮只读采集。')
      : '采集未开启。打开后会立即启动一轮只读采集，不授权、不签名、不广播。';
  const heartbeat = known && status.heartbeatAt
    ? `<p class="home-master-note">最近一次心跳：${escapeHTML(moment(status.heartbeatAt))}${escapeHTML(heartbeatAgeNote(status))}</p>`
    : '';
  const failure = known && (status.startFailed || status.stopFailed)
    ? `<p class="home-master-error" role="alert">${escapeHTML(status.startFailed
      ? `开启失败：${status.startError || '未知原因'}`
      : `停止失败：${status.stopError || '未知原因'}`)}</p>`
    : '';
  const lastError = known && status.lastError && !status.startFailed && !status.stopFailed
    ? `<p class="home-master-error" role="alert">${escapeHTML(String(status.lastError))}</p>`
    : '';
  return `<section class="home-master" aria-labelledby="home-master-title" data-master-enabled="${checked}" data-master-running="${running ? 'true' : 'false'}">`
    + `<div class="home-master-head">`
    + `<div class="home-master-copy"><span class="home-master-kicker">总开关</span>`
    + `<h2 id="home-master-title">链上采集</h2>`
    + `<p class="home-master-state"><span class="home-state-icon home-state-icon-${summary.tone}" aria-hidden="true">${STATE_ICONS[summary.tone] || STATE_ICONS.idle}</span>`
    + `<span data-master-status>${escapeHTML(summary.text)}</span>`
    + (summary.sub ? `<span class="home-master-sub">· ${escapeHTML(summary.sub)}</span>` : '')
    + `</p></div>`
    + `<button type="button" class="home-master-switch" role="switch" aria-checked="${checked}" aria-label="${escapeHTML(switchLabel)}" data-master-toggle${disabled}>`
    + `<span class="switch-track" aria-hidden="true"><span class="switch-knob"></span></span>`
    + `<span class="home-master-switch-text" data-master-switch-text>${escapeHTML(switchTextLabel)}</span></button>`
    + `</div>`
    + `<p class="home-master-note" data-master-note>${escapeHTML(note)}</p>`
    + heartbeat
    + failure
    + lastError
    + `<div class="home-confirm" data-master-confirm hidden>`
    + `<p class="home-confirm-text" data-confirm-text tabindex="-1"></p>`
    + `<div class="home-confirm-actions">`
    + `<button type="button" class="home-button home-button-primary" data-confirm-accept>确认</button>`
    + `<button type="button" class="home-button" data-confirm-cancel>取消</button>`
    + `</div></div>`
    + `</section>`;
}

function headline(model) {
  const { confirmed, pending, recorded } = model.headline;
  const bounty = model.bounty;
  // 首屏不再用金额当主角：「待处理线索 N 个」才是用户下一步要看的东西。
  // findings 读不到时是「未记录」，不是 0 —— 没读到不等于没有。
  const pendingText = pending === null ? '未记录' : `${count(pending)} 个`;
  const confirmedText = confirmed === null ? '未记录' : `${count(confirmed)} 个`;
  const bigText = `待处理线索 ${pendingText}`;
  // 金额只有在记录里真的带了金额字段时才显示。
  // 否则写「暂无数据来源（不是 0）」——渲染一个 $0 等于宣称我们查过且是零。
  const moneyNote = bounty.recorded
    ? `赏金估值：${usd(bounty.amountUsd)}`
    : '赏金估值：暂无数据来源（不是 0）';
  return `<section class="home-headline" aria-labelledby="home-headline-title">`
    + `<div class="home-headline-main">`
    + `<strong class="home-big" data-recorded="${recorded ? 'true' : 'false'}" data-pending-recorded="${pending === null ? 'false' : 'true'}">${escapeHTML(bigText)}</strong>`
    + `<span class="home-confirmed-tag" data-confirmed-tag data-confirmed-recorded="${confirmed === null ? 'false' : 'true'}">已确认 ${escapeHTML(confirmedText)}</span>`
    + `</div>`
    + `<p class="home-note" data-bounty-note data-bounty-recorded="${bounty.recorded ? 'true' : 'false'}">${escapeHTML(moneyNote)}</p>`
    + `<p class="home-note" data-report-time>${escapeHTML(freshnessLine(model))}。</p>`
    + `</section>`;
}

function guideBlock() {
  const open = guideDismissed() ? '' : ' open';
  return `<details class="home-guide" data-home-guide${open}>`
    + `<summary><span class="home-guide-icon" aria-hidden="true">?</span><span>3 步上手</span>`
    + `<span class="home-guide-hint">第一次来？照着这三步做</span></summary>`
    + `<ol class="home-guide-steps">`
    + `<li><span class="home-guide-num" aria-hidden="true">1</span><span><strong>打开采集开关</strong>在页面顶部打开「链上采集」。它会立即启动一轮只读采集，不授权、不签名、不广播。</span></li>`
    + `<li><span class="home-guide-num" aria-hidden="true">2</span><span><strong>看候选线索</strong>往下看「最值得看的候选」，优先处理已确认可复现的记录。</span></li>`
    + `<li><span class="home-guide-num" aria-hidden="true">3</span><span><strong>点进去看证据</strong>点候选卡片进入详情，看源码位置、证据与复现结果。</span></li>`
    + `</ol>`
    + `</details>`;
}

function advancedNav() {
  return `<nav class="home-advanced" aria-label="高级视图">`
    + `<span class="home-advanced-label">想看更细的数据？</span>`
    + `<a href="#map">风险地图</a><a href="#protocols">协议</a><a href="#execution">执行与复现</a><a href="#overview">旧版总览</a>`
    + `</nav>`;
}

function chainCards(model, control) {
  const chains = mergeChainSources(model.chains, control.availableChains);
  if (!chains.length) {
    return '<div class="audit-empty audit-empty-wide"><strong>暂无链数据</strong><span>读取到链之后，这里会显示各链状态。</span></div>';
  }
  const allIds = chains.map((item) => String(item.chainId));
  // 后端语义：未选任何链 = 覆盖全部链。所以空范围要当成「全部链」解读。
  const scope = control.selectedChainIds.length ? control.selectedChainIds : allIds;
  const usable = control.known;
  const enabled = usable ? control.status.enabled : undefined;
  const cards = chains.map((chain) => {
    const chainId = chain.chainId ?? '';
    const inScope = scope.includes(String(chainId));
    const state = chainCardState({ chainId, scope, status: control.status, enabled });
    // 只有快照里带来过统计的链才有「发现数」。控制面补进来的链没有元信息，
    // 写成「暂无记录」等于宣称我们查过且是 0——其实是从没查过。
    const hasMeta = typeof chain.total === 'number';
    const records = hasMeta ? `发现 ${count(chain.total)}` : '发现数未记录';
    const detail = hasMeta
      ? `候选 ${count(chain.candidates)} · 记录 ${count(chain.total)}${chain.tvlLabel ? ` · TVL 规模参考 ${chain.tvlLabel}（快照值）` : ''}`
      : '这条链没有随快照带来统计，完整列表在技术视图';
    const icon = STATE_ICONS[state.tone] || STATE_ICONS.idle;
    return `<article class="home-chain" data-chain-id="${escapeHTML(chainId)}" data-chain-state="${escapeHTML(state.tone)}">`
      + `<div class="home-chain-head"><strong>${escapeHTML(chain.name)}</strong>`
      + `<button type="button" class="home-chain-switch" role="switch" aria-checked="${inScope ? 'true' : 'false'}" aria-label="${escapeHTML(`切换 ${chain.name} 的采集`)}" data-chain-toggle="${escapeHTML(chainId)}"${usable ? '' : ' disabled title="采集控制面状态读取失败，开关暂不可用"'}>`
      + `<span class="switch-track" aria-hidden="true"><span class="switch-knob"></span></span></button></div>`
      + `<span class="home-chain-state"><span class="home-state-icon home-state-icon-${escapeHTML(state.tone)}" aria-hidden="true">${icon}</span>${escapeHTML(state.label)}</span>`
      + `<span class="home-chain-count">${escapeHTML(records)}</span>`
      + `<span class="home-chain-detail">${escapeHTML(detail)}</span>`
      + `</article>`;
  }).join('');
  const note = usable
    ? ''
    : '<p class="home-note">采集控制面状态读取失败，链卡片暂时只显示发现数，开关不可用。</p>';
  return `<div class="home-chain-grid">${cards}</div>${note}`;
}

function candidateRows(model) {
  // 脚注必须无条件出现。即使一条候选都没有，「无法判定」「采集记录」
  // 和「归不到链的记录」这几个数量也不能被吞掉——它们是模型里已经算出来的事实，
  // 少了就等于把「没有候选」说成「什么记录都没有」。
  const foot = `<p class="home-note">另有 ${count(model.tiers.indeterminate)} 条无法判定、${count(model.tiers.notApplicable)} 条为采集记录，未列入候选；完整分类在技术视图。</p>`;
  const unattributed = `<p class="home-note">另有 ${count(model.unattributed)} 条记录归不到具体链，没有分到链卡片上。</p>`;
  if (!model.candidates.length) {
    return '<div class="audit-empty audit-empty-wide"><strong>暂无候选</strong><span>没有处于待验证、异常待确认或已确认状态的记录。</span></div>'
      + `${unattributed}${foot}`;
  }
  const rows = model.candidates.map((item) => {
    const where = [item.chainName, item.subject].filter(Boolean).join(' · ');
    const plain = item.tier === 'confirmed' ? '已确认可复现' : item.tier === 'anomaly' ? '疑似，待验证' : '待进一步验证';
    const signals = `<span class="home-candidate-signals">${confidenceBadge(item.finding)}${severityMeter(item.finding)}</span>`;
    const body = `<span class="home-candidate-main"><strong>${escapeHTML(item.title)}</strong>`
      + `<span class="home-candidate-tier">${escapeHTML(plain)}${where ? ` · ${escapeHTML(where)}` : ''}</span></span>`
      + `${signals}`;
    // 有 id 才是真链接；没有 id 的记录显示「暂无详情页」，不渲染死链接。
    const row = item.id
      ? `<a class="home-candidate-card" href="#finding/${encodeURIComponent(item.id)}">${body}<span class="home-candidate-go" aria-hidden="true">→</span></a>`
      : `<span class="home-candidate-card home-candidate-card-static">${body}<span class="home-candidate-nolink">暂无详情页</span></span>`;
    return `<li class="home-candidate">${row}</li>`;
  }).join('');
  const more = model.candidateTotal > model.candidates.length
    ? `<p class="home-note">只显示前 ${model.candidates.length} 条，共 ${model.candidateTotal} 条；完整列表在「发现」。</p>`
    : '';
  return `<ul class="home-candidates">${rows}</ul>${more}${unattributed}${foot}`;
}

/**
 * @param {object} data  /api/status 快照
 * @param {number} now
 * @param {object|null} control  /api/v1/chain-collection/status 响应（可为 null）
 */
export function render(data = {}, now = Date.now(), control = null) {
  const model = buildHomeModel(data, now);
  const safeControl = normalizeControl(control);
  return `<div class="home-view">`
    + `<header class="home-intro">`
    + `<span class="home-eyebrow">区块链合约安全研究台</span>`
    + `<h1>先看状态，再看线索，最后看证据</h1>`
    + `<p>这里只做只读采集与线索整理：不会授权、不会签名、不会广播。标成「已确认」的记录都带有可复现证据；其余仍需人工复核。</p>`
    + `</header>`
    // 消息条放在顶部：操作结果与失败原因必须一眼看到，
    // 放在页面末尾等于把错误藏到需要滚动的地方。
    + `<p class="home-message" data-home-message data-tone="" role="status" aria-live="polite"></p>`
    + historyBanner(model)
    + masterPanel(model, safeControl)
    + headline(model)
    + guideBlock()
    + advancedNav()
    + `<section aria-labelledby="home-chains-title"><div class="home-section-head"><h2 id="home-chains-title">链开关</h2>`
    + `<span>点一下决定下一轮采集扫哪些链</span></div>${chainCards(model, safeControl)}`
    + `<p class="home-note">开关只影响下一轮采集：正在跑的这一轮不会被中断。采集不区分链，是全局任务，所以任何一条链都不会被单独标成「正在扫」。采集只读取链上代码与已验证源码，不授权、不签名、不广播。</p>`
    + `</section>`
    + `<section aria-labelledby="home-candidates-title"><div class="home-section-head"><h2 id="home-candidates-title">最值得看的候选</h2>`
    + `<span>已确认优先，其次疑似、待验证</span></div>${candidateRows(model)}`
    + `</section>`
    + `</div>`;
}

/**
 * 绑定首页交互。
 *
 * 交互契约：
 *   - 总开关 → 先弹行内二次确认，再 POST /switch { enabled }；
 *   - 链开关 → POST /switch { chainIds }，空范围按后端语义当「全部链」处理；
 *   - 后端拒绝时原样把错误交给调用方显示，不假装成功；
 *   - 按钮在请求期间禁用，避免重复提交。
 */
/**
 * 总开关的行内二次确认文案。
 *
 * 打开总开关会立刻启动一轮只读采集（后端 autoStart），所以点击前必须先问一句。
 * 关闭时的文案必须与打开时不同：一个是「你要开始跑了」，一个是「你要停下了」。
 *
 * 导出成纯函数是为了能直接测文案，不依赖 DOM。
 */
export function masterConfirmCopy(enabled) {
  return enabled === true
    ? {
      text: '确认开启？将立即启动一轮只读采集，不授权、不签名、不广播',
      accept: '确认开启',
      cancel: '取消',
    }
    : {
      text: '确认关闭？关闭后不会再自动启动新的只读采集，当前采集会被请求停止。',
      accept: '确认关闭',
      cancel: '取消',
    };
}

export function bind(root = null, handlers = {}) {
  // 没有 DOM 时 bind 必须是空操作，而不是抛 ReferenceError。
  // 默认值不能写 `document`：默认参数在无浏览器环境求值时就会抛错，
  // 根本走不到下面的判断。
  const scope = root ?? (typeof document === 'undefined' ? null : document);
  if (!scope || typeof scope.querySelectorAll !== 'function') return;

  const masterToggle = scope.querySelector('[data-master-toggle]');
  const confirmBox = scope.querySelector('[data-master-confirm]');
  const confirmText = scope.querySelector('[data-confirm-text]');
  const confirmAccept = scope.querySelector('[data-confirm-accept]');
  const confirmCancel = scope.querySelector('[data-confirm-cancel]');
  const switchText = scope.querySelector('[data-master-switch-text]');
  let pendingEnabled = null;

  const setConfirmVisible = (visible, enabled) => {
    if (!confirmBox) return;
    confirmBox.hidden = !visible;
    if (visible) {
      pendingEnabled = enabled;
      const copy = masterConfirmCopy(enabled);
      if (confirmText) confirmText.textContent = copy.text;
      if (confirmAccept) confirmAccept.textContent = copy.accept;
      if (confirmText && typeof confirmText.focus === 'function') confirmText.focus();
    } else {
      pendingEnabled = null;
    }
  };

  if (masterToggle && confirmBox) {
    masterToggle.addEventListener('click', () => {
      if (masterToggle.disabled) return;
      const enabled = masterToggle.getAttribute('aria-checked') !== 'true';
      setConfirmVisible(true, enabled);
    });
  }
  confirmCancel?.addEventListener('click', () => {
    setConfirmVisible(false);
    if (masterToggle && typeof masterToggle.focus === 'function') masterToggle.focus();
  });
  confirmAccept?.addEventListener('click', async () => {
    if (pendingEnabled === null) return;
    const enabled = pendingEnabled;
    const originalText = switchText ? switchText.textContent : '';
    // 总开关读不到控制面状态时按钮是禁用的。请求结束后必须恢复成原来的禁用态，
    // 不能因为一次点击就把「不可用」的开关变成可点的。
    const masterWasDisabled = masterToggle ? masterToggle.disabled : false;
    if (masterToggle) masterToggle.disabled = true;
    if (confirmAccept) confirmAccept.disabled = true;
    if (confirmCancel) confirmCancel.disabled = true;
    if (switchText) switchText.textContent = '处理中';
    if (masterToggle) masterToggle.setAttribute('aria-busy', 'true');
    let failed = false;
    try {
      await handlers.onMasterToggle?.({ enabled });
    } catch (error) {
      failed = true;
      const message = handlers.onError ? handlers.onError(error) : String(error?.message || error);
      // 失败原因留在确认框里：关掉确认框等于把错误藏起来，用户会以为开关没反应。
      if (message && confirmText) confirmText.textContent = message;
    } finally {
      if (masterToggle) {
        masterToggle.disabled = masterWasDisabled;
        masterToggle.removeAttribute('aria-busy');
      }
      if (confirmAccept) confirmAccept.disabled = false;
      if (confirmCancel) confirmCancel.disabled = false;
      // 失败时把「处理中」改回原样：不能因为请求失败就把开关写成「已开启」。
      if (switchText && failed) switchText.textContent = originalText;
      if (failed) {
        // 保持确认框展开，焦点移回错误文字。
        if (confirmBox) confirmBox.hidden = false;
        pendingEnabled = enabled;
        if (confirmText && typeof confirmText.focus === 'function') confirmText.focus();
      } else {
        setConfirmVisible(false);
      }
    }
  });

  for (const button of scope.querySelectorAll('[data-chain-toggle]')) {
    // 控制面状态读不到时按钮本来是禁用的，请求结束后要恢复禁用态。
    const wasDisabled = button.disabled;
    button.addEventListener('click', async () => {
      if (button.disabled) return;
      const chainId = button.dataset.chainToggle;
      const next = button.getAttribute('aria-checked') !== 'true';
      button.disabled = true;
      try {
        await handlers.onToggle?.({ chainId, enabled: next, button });
      } catch (error) {
        const message = handlers.onError ? handlers.onError(error) : String(error?.message || error);
        if (message) button.setAttribute('title', message);
      } finally {
        button.disabled = wasDisabled;
      }
    });
  }

  const guide = scope.querySelector('[data-home-guide]');
  if (guide) {
    // 浏览器在插入 <details> 时可能补一个 toggle 事件，那不是用户操作。
    // 记住上一次已知的 open 状态，只有真的翻转了才写存储：
    // 否则「用户刚关掉引导」这个动作会被浏览器的初始事件吃掉，
    // 用户的偏好就丢了。
    let lastOpen = guide.open;
    guide.addEventListener('toggle', () => {
      if (guide.open === lastOpen) return;
      lastOpen = guide.open;
      rememberGuideDismissed(!guide.open);
    });
  }
}

/** 供外部复用：算出一个链开关切换后的范围。 */
export { scopeAfterToggle };
