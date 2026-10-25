// 离线语料控制台视图（代号 LaneW）。
//
// 只做离线任务控制；链上采集启动按钮置灰，并由后端再次拒绝。
//
// 三条硬约束（与 .cursor/rules/silent-wrong-value-review.mdc 对齐）：
//   1. 读取失败必须如实显示「读取失败：原因」，并说明页面会自动重试；
//      不能用空卡片冒充「没有记录」。
//   2. 语料统计来自本地已保存内容，不是实时任务；心跳过期就显示「已过期」。
//   3. 暂停只在样本边界生效，停止才会终止子进程 —— 文案必须说清。
import { escapeHTML, formatDate } from '../lib/format.js';

const stateLabels = Object.freeze({
  idle: '空闲', running: '运行中', paused: '已暂停', pausing: '暂停中',
  completed: '已完成', failed: '失败', stopped: '已停止', interrupted: '已中断', unknown: '状态未知',
});

const stateKind = Object.freeze({
  idle: 'idle', running: 'running', paused: 'paused', pausing: 'paused',
  completed: 'done', failed: 'error', stopped: 'idle', interrupted: 'error', unknown: 'unknown',
});

const ACTION_LABELS = Object.freeze({
  start: '启动', pause: '暂停', resume: '继续', stop: '停止', 'rerun-failed': '重跑失败项',
});

function label(state) {
  return stateLabels[String(state || 'unknown')] || '状态未知';
}

function kind(state) {
  return stateKind[String(state || 'unknown')] || 'unknown';
}

function taskStateOf(task) {
  // 心跳不新鲜时后端会返回 state=unknown / stale=true，界面绝不显示“运行中”。
  if (task?.stale === true || task?.heartbeatStale === true) return 'unknown';
  return task?.state || 'unknown';
}

function laneCard(task, feedback) {
  const state = taskStateOf(task);
  const stale = task?.stale === true || task?.heartbeatStale === true;
  const running = state === 'running';
  const paused = state === 'paused' || state === 'pausing';
  const completed = Number.isInteger(task?.completedCount) ? task.completedCount : 0;
  const total = Number.isInteger(task?.totalCount) ? task.totalCount : 0;
  const summary = task?.itemSummary || {};
  const canStart = ['idle', 'completed', 'failed', 'stopped', 'interrupted'].includes(state);
  const canPause = running;
  const canResume = paused;
  const canStop = running || paused;
  const canRerun = (Number.isInteger(summary.failed) ? summary.failed : 0) > 0 && !running && !paused;
  const heartbeatText = task?.lastHeartbeatAt
    ? `${formatDate(task.lastHeartbeatAt)}${stale ? '（已过期）' : ''}`
    : '未记录';
  const heartbeatNote = stale
    ? '<span class="corpus-badge corpus-unknown">状态未知/已中断</span>'
    : '';
  const controls = [
    ['start', '启动', canStart],
    ['pause', '暂停', canPause],
    ['resume', '继续', canResume],
    ['stop', '停止', canStop],
    ['rerun-failed', '重跑失败项', canRerun],
  ].map(([action, text, enabled]) => `<button type="button" class="workspace-link corpus-action" data-corpus-lane="${escapeHTML(task.laneId)}" data-corpus-action="${action}" ${enabled ? '' : 'disabled'} title="${escapeHTML(`${text}这条泳道的离线任务（会修改本机任务状态）`)}">${escapeHTML(text)}</button>`).join('');
  const category = task?.filters?.category ? `类别过滤：${task.filters.category}` : '类别过滤：全部';
  const result = feedback && feedback.laneId === task.laneId
    ? `<span class="corpus-action-result" role="status" aria-live="polite" data-state="${escapeHTML(feedback.state)}">${escapeHTML(feedback.text)}</span>`
    : '<span class="corpus-action-result" role="status" aria-live="polite"></span>';
  return `<article class="workspace-card corpus-lane-card" data-corpus-lane-card="${escapeHTML(task.laneId)}">
    <div class="workspace-card-head"><h2>${escapeHTML(task.label || task.laneId)}</h2><span class="corpus-badge corpus-${kind(state)}">${escapeHTML(label(state))}</span></div>
    <dl class="workspace-definition">
      <div><dt>泳道 ID</dt><dd><code>${escapeHTML(task.laneId || '未提供')}</code></dd></div>
      <div><dt>已完成 / 总数</dt><dd>${escapeHTML(String(completed))} / ${escapeHTML(String(total))}</dd></div>
      <div><dt>开始时间</dt><dd>${escapeHTML(formatDate(task.startedAt))}</dd></div>
      <div><dt>最后心跳</dt><dd>${escapeHTML(heartbeatText)} ${heartbeatNote}</dd></div>
      <div><dt>当前阶段</dt><dd>${escapeHTML(task.currentStage || '未记录')}</dd></div>
      <div><dt>过滤条件</dt><dd>${escapeHTML(category)}</dd></div>
    </dl>
    <div class="corpus-actions">${controls}${result}</div>
    <p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>这些按钮会<b>修改本机离线任务的运行状态</b>，并写入 work/corpus-control/tasks.json。暂停只在样本边界生效（当前样本跑完才挂起）；只有停止会终止子进程。</span></p>
    ${task?.interpretation ? `<p class="corpus-note">${escapeHTML(task.interpretation)}</p>` : ''}
  </article>`;
}

export function render(payload = {}) {
  const data = payload?.data || payload || {};
  const tasks = Array.isArray(data.tasks) ? data.tasks : [];
  const corpus = data.corpus || {};
  const manifest = corpus.manifest || {};
  const layers = manifest.layers || {};
  const groundTruth = corpus.groundTruth || {};
  const shards = corpus.shards || {};
  const heartbeat = data.heartbeat || {};
  const chain = data.chainCollection || {};
  const categories = Array.isArray(data.categories) ? data.categories : [];
  const feedback = payload?.feedback || {};
  const selection = payload?.selection || {};
  const selectedCategory = String(selection.category || '');
  const selectedLane = String(selection.laneId || 'static');
  const readError = data.readError ? String(data.readError) : '';
  const categoryOptions = ['<option value="">全部类别</option>']
    .concat(categories.map((item) => `<option value="${escapeHTML(item.category || '')}"${item.category === selectedCategory ? ' selected' : ''}>${escapeHTML(item.category || '未命名')}（${escapeHTML(String(item.sampleCount ?? 0))}）</option>`))
    .join('');
  const laneOptions = [
    ['static', '静态分析'], ['dynamic', '动态复现'], ['decompiler', '反编译'],
    ['fetch', '离线抓取校验'], ['eval', '本地评测'],
  ].map(([value, text]) => `<option value="${value}"${value === selectedLane ? ' selected' : ''}>${text}</option>`).join('');
  const layerCounts = Object.entries(layers).map(([layer, counts]) => {
    const parts = Object.entries(counts || {}).map(([state, count]) => `${state} ${count}`).join(' · ');
    return `<div><dt>${escapeHTML(layer)}</dt><dd>${escapeHTML(parts || '未记录')}</dd></div>`;
  }).join('');
  const heartbeatNote = heartbeat.stale
    ? '<span class="corpus-badge corpus-unknown">心跳已过期</span>'
    : '<span class="corpus-badge corpus-done">心跳新鲜</span>';
  const filterResult = feedback?.filter
    ? `<span class="corpus-action-result" data-corpus-filter-result role="status" aria-live="polite" data-state="${escapeHTML(feedback.filter.state)}">${escapeHTML(feedback.filter.text)}</span>`
    : '<span class="corpus-action-result" data-corpus-filter-result role="status" aria-live="polite"></span>';
  const errorBanner = readError
    ? `<div class="workspace-status workspace-status-error"><strong>读取失败：${escapeHTML(readError)}</strong><br>下面的数字是本次没能读到的内容，不代表语料为空。页面每 4 秒自动重试一次；也可以切到别的页面再回来。</div>`
    : '';
  return `<div class="workspace-head ws-head">
    <div class="ws-head-main">
      <div class="eyebrow">离线 / 语料控制台</div>
      <h1>离线语料控制台</h1>
      <p class="ws-head-lead">这页管理本机的离线语料任务：静态分析、动态复现、反编译、离线抓取校验与本地评测。什么时候用：想在不连链、不花模型额度的前提下批量跑本地语料检查时。这里的统计来自本地已保存内容，不是实时任务。</p>
      <div class="ws-head-meta"><span class="ws-flag ws-flag-write"><i aria-hidden="true">✎</i>含写入操作 · 记录只读，按钮会改数据</span></div>
    </div>
    <div class="ws-head-side"><a class="workspace-back" href="#overview">返回安全总览</a></div>
  </div>
  <div class="workspace-body">
    ${errorBanner}
    <div class="workspace-grid-two">
      ${workspaceCardShim('语料概览', `<dl class="workspace-definition">
        <div><dt>样本总数</dt><dd>${escapeHTML(String(manifest.sampleCount ?? '未记录'))}</dd></div>
        <div><dt>来源指纹（SHA-256）</dt><dd><code>${escapeHTML(manifest.sha256 || '未记录')}</code></dd></div>
        <div><dt>清单生成时间</dt><dd>${escapeHTML(formatDate(manifest.generatedAt))}</dd></div>
        <div><dt>语料合并时间</dt><dd>${escapeHTML(formatDate(manifest.corpusMergedAt))}</dd></div>
        <div><dt>已合并分片数</dt><dd>${escapeHTML(String(shards.activeFileCount ?? '未记录'))}</dd></div>
        <div><dt>Ground-truth 指纹</dt><dd><code>${escapeHTML(groundTruth.fingerprint || '未记录')}</code></dd></div>
        <div><dt>基准文件数</dt><dd>${escapeHTML(String(groundTruth.fileCount ?? '未记录'))}</dd></div>
        <div><dt>心跳新鲜度</dt><dd>${heartbeatNote} 阈值 ${escapeHTML(String(heartbeat.staleAfterMs ?? '未记录'))} 毫秒</dd></div>
      </dl>
      <dl class="workspace-definition">${layerCounts}</dl>`)}
      ${workspaceCardShim('链上采集（离线阶段不开放）', `<div class="workspace-status workspace-status-empty">离线阶段不开放链上采集。campaign / defi-campaign / chain-scan 启动请求会被后端直接拒绝（错误码 ${escapeHTML(chain.code || 'chain_collection_disabled')}）。</div>
      <form class="workspace-form" data-corpus-chain-form>
        <div class="workspace-form-title">链上采集启动</div>
        <p class="workspace-form-note">该入口在离线阶段不可用：前端置灰只是提示，真正的拒绝在后端。</p>
        <button class="workspace-submit" type="button" disabled title="离线阶段不开放链上采集">启动链上采集（离线阶段不开放）</button>
        <span class="workspace-form-result" data-corpus-chain-result></span>
      </form>`)}
    </div>
    ${workspaceCardShim('离线语料任务', `<div class="corpus-lanes">${tasks.map((task) => laneCard(task, feedback?.action)).join('') || '<div class="ws-empty"><div class="ws-empty-title"><i aria-hidden="true">◌</i>这里还没有泳道任务记录</div><p class="ws-empty-text">控制面还没有创建过离线任务。用下面的「按类别创建任务」先建一个，任务状态会出现在这里。</p></div>'}</div>`)}
    ${workspaceCardShim('按类别创建离线任务', `<div class="corpus-filters">
      <label>漏洞类别<select data-corpus-category>${categoryOptions}</select></label>
      <label>应用到泳道<select data-corpus-filter-lane>${laneOptions}</select></label>
      <button type="button" class="workspace-link corpus-action" data-corpus-apply-filter title="按所选类别创建一条离线泳道任务">按类别创建任务</button>
      ${filterResult}
      <p class="ws-effect ws-effect-write"><i aria-hidden="true">✎</i><span>提交后会在本机<b>创建一条离线泳道任务</b>并登记类别过滤；只处理本地已保存的语料，不会启动任何链上扫描。</span></p>
    </div>`)}
  </div>`;
}

function workspaceCardShim(title, content) {
  return `<article class="workspace-card"><div class="workspace-card-head"><h2>${escapeHTML(title)}</h2></div>${content}</article>`;
}
