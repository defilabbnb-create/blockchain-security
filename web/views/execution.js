import { escapeHTML, formatDate, stateLabel, value } from '../lib/format.js';

const EXECUTION_STATE = {
  passed: { label: '通过', tone: 'ok', icon: '✓', hint: '规则在本地运行中成立。' },
  violated: { label: '被违反', tone: 'danger', icon: '!', hint: '规则在本地运行中被打破，仍需人工复核。' },
  unavailable: { label: '不可用', tone: 'warn', icon: '·', hint: '环境或适配器没准备好，这次没跑起来。' },
  timeout: { label: '超时', tone: 'warn', icon: '·', hint: '本地运行超时，没有拿到结果。' },
  not_performed: { label: '未执行', tone: 'muted', icon: '–', hint: '这条合约还没有对应的本地测试环境。' },
};

function badge(tone, icon, label, title = '') {
  return `<span class="status-badge tone-${tone}"${title ? ` title="${escapeHTML(title)}"` : ''}>`
    + `<span class="status-badge-icon" aria-hidden="true">${icon}</span>`
    + `<span class="status-badge-text">${escapeHTML(label)}</span></span>`;
}

function resultCard(result) {
  const state = String(result.state || 'unavailable');
  const info = EXECUTION_STATE[state] || { label: stateLabel(state), tone: 'muted', icon: '–', hint: '' };
  const command = result.command || result.runCommand;
  const reason = result.reason ? String(result.reason) : '';
  return `<article class="execution-result"><div class="execution-result-head">`
    + `<div><span class="audit-kicker">${escapeHTML(result.mode || 'local')}</span>`
    + `<h2>${escapeHTML(result.invariantId || result.name || '本地运行结果')}</h2></div>`
    + `${badge(info.tone, info.icon, info.label, info.hint)}</div>`
    + `<p class="execution-result-hint">${escapeHTML(info.hint)}</p>`
    + `<p>证据指纹：<code>${escapeHTML(value(result.evidenceSha256))}</code></p>`
    + `<small>区块锚点：${escapeHTML(value(result.blockAnchor))} · gas：${escapeHTML(value(result.gasUsed))}</small>`
    + (command ? `<div class="execution-command"><code>${escapeHTML(command)}</code>`
      + `<button type="button" data-copy="${escapeHTML(command)}" aria-label="复制运行命令">复制命令</button></div>` : '')
    + (reason ? `<p class="adapter-hint">${escapeHTML(reason)}</p>` : '')
    + `</article>`;
}

export function render(data = {}) {
  const results = Array.isArray(data.dynamicResults) ? data.dynamicResults : [];
  const findings = Array.isArray(data.findings) ? data.findings.filter((item) => item.pocState || item.status === 'invariant_violated') : [];
  const pending = findings.filter((finding) => !['confirmed', 'poc_confirmed'].includes(String(finding.pocState || finding.status)));
  const confirmed = findings.filter((finding) => ['confirmed', 'poc_confirmed'].includes(String(finding.pocState || finding.status)));

  const cards = results.length
    ? results.map(resultCard).join('')
    : '<div class="audit-empty audit-empty-wide"><strong>这里还没有本地运行结果</strong>'
      + '<span>本地运行是指在自己的测试环境里跑一遍合约，看安全规则还成不成立。<br>'
      + '现在还没有记录 —— 先去「发现」挑一条线索，再回到这里看有没有跑过。</span>'
      + '<a class="audit-link finding-open" href="#discoveries">去发现页挑一条线索 →</a></div>';

  const pendingList = pending.length
    ? pending.map((finding) => {
      const id = finding.id || finding.findingId || '';
      const link = id
        ? `<a href="#finding/${encodeURIComponent(id)}">打开完整证据 →</a>`
        : '<span class="execution-no-detail">暂无详情</span>';
      return `<div class="execution-finding"><strong>${escapeHTML(finding.title || finding.check || '未命名发现')}</strong>`
        + `${badge('muted', '–', stateLabel(finding.pocState || finding.status))}${link}</div>`;
    }).join('')
    : '<div class="audit-empty audit-empty-wide"><strong>没有待复现的线索</strong>'
      + '<span>所有带执行记录的线索都已有复现结果，或还没有任何本地运行记录。</span></div>';

  return `<div class="audit-head"><div><span class="eyebrow">04 / 执行与复现</span><h1>执行与复现</h1>`
    + `<p>这里只显示已经跑过的本地运行结果和复现记录。页面不会替你签名、授权或往链上发交易。</p></div>`
    + `<span class="audit-updated">快照时间 ${escapeHTML(formatDate(data.generatedAt))}</span></div>`
    + `<div class="audit-guide"><strong>这一页在看什么</strong><ol>`
    + `<li><b>本地运行</b>：在自己的测试环境里跑一遍合约，看「安全规则」还成不成立。</li>`
    + `<li><b>通过 / 被违反 / 不可用</b>：分别代表规则成立、规则被打破、以及这次根本没跑起来 —— 不可用不是「没问题」。</li>`
    + `<li>结果必须绑定证据指纹才能算数；没有指纹的结果只是记录，不是证据。</li>`
    + `</ol></div>`
    + `<div class="execution-banner"><strong>只读执行边界</strong>`
    + `<span>只在本地测试环境和固定区块副本里运行 · 结果必须绑定证据指纹 · 不签名、不授权、不广播</span></div>`
    + `<div class="protocol-summary"><span><b>${results.length}</b> 条运行结果</span>`
    + `<span><b>${confirmed.length}</b> 条已复现</span>`
    + `<span><b>${pending.length}</b> 条待复现</span></div>`
    + `<section class="execution-grid"><div class="audit-panel"><div class="audit-panel-head"><div><h2>本地运行结果</h2>`
    + `<p>通过、被违反和不可用分别显示。</p></div><span>${results.length} 条</span></div>`
    + `<div class="execution-result-list">${cards}</div></div>`
    + `<div class="audit-panel"><div class="audit-panel-head"><div><h2>待复现的线索</h2>`
    + `<p>从线索进入完整证据。</p></div><span>${pending.length} 条</span></div>`
    + `<div class="execution-pending-list">${pendingList}</div></div></section>`
    + `<p class="audit-note">本地运行只说明「在这套环境里规则不成立了」。它不等于漏洞已确认，还需要复核执行模式、前置条件和部署合约。</p>`;
}

export function bind(root = document) {
  root.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
    const original = button.textContent;
    try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = '已复制'; }
    catch { button.textContent = '请手动复制'; }
    window.setTimeout(() => { if (button.isConnected) button.textContent = original; }, 1600);
  }));
}
