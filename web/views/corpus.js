// 离线语料控制台视图（代号 LaneW）。
// 只做离线任务控制；链上采集启动按钮置灰，并由后端再次拒绝。
import { escapeHTML, formatDate } from '../lib/format.js';

const stateLabels = Object.freeze({
  idle: '空闲', running: '运行中', paused: '已暂停', pausing: '暂停中',
  completed: '已完成', failed: '失败', stopped: '已停止', interrupted: '已中断', unknown: '状态未知',
});

const stateKind = Object.freeze({
  idle: 'idle', running: 'running', paused: 'paused', pausing: 'paused',
  completed: 'done', failed: 'error', stopped: 'idle', interrupted: 'error', unknown: 'unknown',
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

function laneCard(task) {
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
  ].map(([action, text, enabled]) => `<button type="button" class="workspace-link corpus-action" data-corpus-lane="${escapeHTML(task.laneId)}" data-corpus-action="${action}" ${enabled ? '' : 'disabled'}>${escapeHTML(text)}</button>`).join('');
  const category = task?.filters?.category ? `类别过滤：${task.filters.category}` : '类别过滤：全部';
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
    <div class="corpus-actions">${controls}<span class="corpus-action-result" role="status" aria-live="polite"></span></div>
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
  const categoryOptions = ['<option value="">全部类别</option>']
    .concat(categories.map((item) => `<option value="${escapeHTML(item.category || '')}">${escapeHTML(item.category || '未命名')}（${escapeHTML(String(item.sampleCount ?? 0))}）</option>`))
    .join('');
  const layerCounts = Object.entries(layers).map(([layer, counts]) => {
    const parts = Object.entries(counts || {}).map(([state, count]) => `${state} ${count}`).join(' · ');
    return `<div><dt>${escapeHTML(layer)}</dt><dd>${escapeHTML(parts || '未记录')}</dd></div>`;
  }).join('');
  const heartbeatNote = heartbeat.stale
    ? '<span class="corpus-badge corpus-unknown">心跳已过期</span>'
    : '<span class="corpus-badge corpus-done">心跳新鲜</span>';
  return `<div class="workspace-head"><div><div class="eyebrow">离线 / 语料控制台</div><h1>离线语料控制台</h1><p>只做本地离线任务控制：静态、动态、反编译、抓取校验与基准评测。暂停只在样本边界生效，停止才会终止子进程。</p></div><a class="workspace-back" href="#overview">返回安全总览</a></div>
  <div class="workspace-body">
    <div class="workspace-grid-two">
      ${workspaceCardShim('语料概览', `<dl class="workspace-definition">
        <div><dt>样本总数</dt><dd>${escapeHTML(String(manifest.sampleCount ?? '未记录'))}</dd></div>
        <div><dt>Manifest SHA-256</dt><dd><code>${escapeHTML(manifest.sha256 || '未记录')}</code></dd></div>
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
    ${workspaceCardShim('离线语料任务', `<div class="corpus-lanes">${tasks.map(laneCard).join('') || '<div class="workspace-status workspace-status-empty">没有泳道任务记录。</div>'}</div>`)}
    ${workspaceCardShim('漏洞类别过滤', `<div class="corpus-filters">
      <label>漏洞类别<select data-corpus-category>${categoryOptions}</select></label>
      <label>应用到泳道<select data-corpus-filter-lane>
        <option value="static">静态分析</option>
        <option value="dynamic">动态复现</option>
        <option value="decompiler">反编译</option>
        <option value="fetch">离线抓取校验</option>
        <option value="eval">本地评测</option>
      </select></label>
      <button type="button" class="workspace-link corpus-action" data-corpus-apply-filter>创建过滤任务</button>
      <span class="corpus-action-result" data-corpus-filter-result role="status" aria-live="polite"></span>
    </div>`)}
  </div>`;
}

function workspaceCardShim(title, content) {
  return `<article class="workspace-card"><div class="workspace-card-head"><h2>${escapeHTML(title)}</h2></div>${content}</article>`;
}
