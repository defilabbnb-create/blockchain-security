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
    const status = String(finding.status || finding.state || 'unconfirmed_observation');
    const statusClass = /confirmed|passed/.test(status) ? 'state-passed' : /adapter/.test(status) ? 'state-adapter' : /excluded|fixed|rejected/.test(status) ? 'state-excluded' : 'state-unverified';
    const source = finding.source?.sha256 || finding.sourceSha256;
    return `<article class="audit-finding severity-${escapeHTML(severityOf(finding))}"><div class="audit-finding-main"><span class="audit-severity">${escapeHTML(severityLabel(finding))}</span><h2>${escapeHTML(finding.title || finding.check || '未命名观察')}</h2><p>${escapeHTML(finding.protocol || '未知协议')} · ${escapeHTML(finding.chain || '未知链')} · ${escapeHTML(finding.address || '地址未记录')}</p></div><span class="audit-status state-badge ${statusClass}">${escapeHTML(stateLabel(status))}</span><div class="audit-finding-evidence"><div class="evidence-chain" aria-label="证据链"><span>不变量</span><i>→</i><span>执行</span><i>→</i><span>PoC</span><b>${finding.confirmedVulnerability === true ? '已绑定' : '待验证'}</b></div>${evidenceHTML}${conditionList}${testPlan}${source ? `<div class="evidence-hash"><span>来源 SHA-256</span><code>${escapeHTML(source)}</code><button type="button" class="copy-hash" data-copy="${escapeHTML(source)}" aria-label="复制来源 SHA-256">复制</button></div>` : ''}</div><button type="button" class="audit-link" data-finding-id="${escapeHTML(finding.id || finding.findingId || '')}">打开完整证据</button></article>`;
  }).join('');
  return `<div class="audit-head"><div><span class="eyebrow">03 / 发现</span><h1>发现与证据链</h1><p>先看严重度和状态，再展开证据。静态线索不会自动变成已确认漏洞。</p></div><span class="audit-updated">快照 ${escapeHTML(formatDate(data.generatedAt))}</span></div><div class="finding-toolbar"><label class="finding-filter">筛选发现 <input type="search" data-finding-filter placeholder="协议、标题或地址" aria-label="筛选发现"></label><span>${findings.length} 条发现 · 来源：${findings.filter((item) => item.origin === 'campaign').length} 条 campaign 证据</span></div><section class="audit-findings">${rows || '<div class="audit-empty audit-empty-wide"><strong>暂无发现记录</strong><span>完成静态或动态检查后，记录会出现在这里。</span></div>'}</section>`;
}

export function bind(root = document) {
  root.querySelectorAll('[data-finding-id]').forEach((button) => button.addEventListener('click', () => root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'finding', id: button.dataset.findingId } }))));
  root.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', async () => { try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = '已复制'; } catch { button.textContent = '请手动复制'; } window.setTimeout(() => { if (button.isConnected) button.textContent = '复制'; }, 1600); }));
  const filter = root.querySelector('[data-finding-filter]');
  if (filter) filter.addEventListener('input', () => root.querySelectorAll('.audit-finding').forEach((row) => { row.hidden = !row.textContent.toLowerCase().includes(filter.value.trim().toLowerCase()); }));
}
