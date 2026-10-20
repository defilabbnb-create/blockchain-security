import { escapeHTML, formatDate, stateLabel, value } from '../lib/format.js';
import { severityLabel, severityOf, sortBySeverity } from '../lib/severity.js';

export function render(data = {}) {
  const findings = sortBySeverity(data.findings || []);
  const rows = findings.map((finding) => {
    const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
    const evidenceHTML = evidence.length ? `<details><summary>证据 ${evidence.length} 条</summary>${evidence.map((item) => `<div class="audit-evidence"><code>${escapeHTML(value(item.file))} · L${escapeHTML(value(item.lineStart))}–L${escapeHTML(value(item.lineEnd))}</code><blockquote>${escapeHTML(item.quote || '')}</blockquote></div>`).join('')}</details>` : '<small>未记录证据行</small>';
    const conditions = Array.isArray(finding.conditions) ? finding.conditions : [];
    const testPlan = finding.localTestPlan ? `<div class="audit-test-plan"><b>本地测试计划</b><span>${escapeHTML(finding.localTestPlan)}</span></div>` : '';
    const conditionList = conditions.length ? `<ul class="audit-conditions">${conditions.map((condition) => `<li>${escapeHTML(condition)}</li>`).join('')}</ul>` : '';
    return `<article class="audit-finding severity-${escapeHTML(severityOf(finding))}"><div class="audit-finding-main"><span class="audit-severity">${escapeHTML(severityLabel(finding))}</span><h2>${escapeHTML(finding.title || finding.check || '未命名观察')}</h2><p>${escapeHTML(finding.protocol || '未知协议')} · ${escapeHTML(finding.chain || '未知链')} · ${escapeHTML(finding.address || '地址未记录')}</p></div><span class="audit-status">${escapeHTML(stateLabel(finding.status || finding.state))}</span><div class="audit-finding-evidence">${evidenceHTML}${conditionList}${testPlan}</div><button type="button" class="audit-link" data-finding-id="${escapeHTML(finding.id || finding.findingId || '')}">查看证据链</button></article>`;
  }).join('');
  return `<div class="audit-head"><div><span class="eyebrow">03 / 发现</span><h1>发现与证据链</h1><p>按严重度排序，展开每条记录查看行号、引文和来源；状态不会把静态线索写成已确认漏洞。</p></div><span class="audit-updated">快照 ${escapeHTML(formatDate(data.generatedAt))}</span></div><div class="finding-toolbar"><span>${findings.length} 条发现</span><span>来源：${findings.filter((item) => item.origin === 'campaign').length} 条 campaign 证据</span></div><section class="audit-findings">${rows || '<div class="audit-empty">当前没有可展示的发现。</div>'}</section>`;
}

export function bind(root = document) {
  root.querySelectorAll('[data-finding-id]').forEach((button) => button.addEventListener('click', () => root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'finding', id: button.dataset.findingId } }))));
}
