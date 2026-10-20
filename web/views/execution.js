import { escapeHTML, formatDate, stateLabel, value } from '../lib/format.js';

export function render(data = {}) {
  const results = Array.isArray(data.dynamicResults) ? data.dynamicResults : [];
  const findings = Array.isArray(data.findings) ? data.findings.filter((item) => item.pocState || item.status === 'invariant_violated') : [];
  const cards = results.map((result) => `<article class="execution-result"><div><span class="audit-kicker">${escapeHTML(result.mode || 'local')}</span><h2>${escapeHTML(result.invariantId || result.name || '动态结果')}</h2></div><strong class="execution-state state-${escapeHTML(result.state || 'unavailable')}">${escapeHTML(stateLabel(result.state))}</strong><p>证据指纹：<code>${escapeHTML(value(result.evidenceSha256))}</code></p><small>区块锚点：${escapeHTML(value(result.blockAnchor))} · gas：${escapeHTML(value(result.gasUsed))}</small></article>`).join('');
  return `<div class="audit-head"><div><span class="eyebrow">04 / 执行与复现</span><h1>执行与复现</h1><p>集中查看本地模拟、固定区块 fork 和 PoC 结果。页面只展示证据，不执行签名、授权或链上广播。</p></div><span class="audit-updated">快照 ${escapeHTML(formatDate(data.generatedAt))}</span></div><div class="execution-banner">执行入口：本地 EVM / 固定区块 fork · 结果必须绑定证据 SHA-256。</div><section class="execution-grid"><div class="audit-panel"><div class="audit-panel-head"><h2>动态结果</h2><span>${results.length} 条</span></div>${cards || '<div class="audit-empty">暂无动态执行结果。</div>'}</div><div class="audit-panel"><div class="audit-panel-head"><h2>待复现发现</h2><span>${findings.length} 条</span></div>${findings.map((finding) => `<div class="execution-finding"><strong>${escapeHTML(finding.title || finding.check || '未命名发现')}</strong><span>${escapeHTML(stateLabel(finding.pocState || finding.status))}</span><a href="#finding/${encodeURIComponent(finding.id || finding.findingId || '')}">打开证据链</a></div>`).join('') || '<div class="audit-empty">暂无待复现发现。</div>'}</div></section>`;
}

export function bind(root = document) {}
