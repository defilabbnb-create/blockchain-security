import { escapeHTML, formatDate, value } from '../lib/format.js';

export function render(data = {}) {
  const chains = Array.isArray(data.chains) ? data.chains : [];
  const contracts = [...(data.contracts || []), ...(data.campaignContracts || [])];
  const seenContracts = new Set();
  const uniqueContracts = contracts.filter((item) => {
    const key = `${item.chainId || item.chain}:${item.address || item.input?.address}`.toLowerCase();
    if (!item.address && !item.input?.address || seenContracts.has(key)) return false;
    seenContracts.add(key);
    return true;
  });
  const invariants = Array.isArray(data.invariants) ? data.invariants : [];
  const findings = (data.findings || []).slice(0, 8);
  const rows = chains.map((chain) => `<tr><td><strong>${escapeHTML(chain.name || '未知链')}</strong><small>#${escapeHTML(chain.chainId || '--')}</small></td><td>${escapeHTML(value(chain.currentTvlLabel || chain.peakTvlLabel))}</td><td>${escapeHTML(value(chain.status || chain.transferability))}</td><td>${escapeHTML(value(chain.rpc?.ok ? '已验证' : '待复核'))}</td><td><button class="audit-link" type="button" data-protocol-detail="${escapeHTML(chain.name || chain.chainId)}">查看协议</button></td></tr>`).join('');
  const contractRows = uniqueContracts.map((item) => `<tr><td><strong>${escapeHTML(value(item.protocol || item.name || item.input?.protocolId))}</strong><small>${escapeHTML(value(item.chain || item.chainId || item.input?.chainId))}</small></td><td><code>${escapeHTML(value(item.address || item.input?.address))}</code></td><td>${escapeHTML(value(item.originProxy || item.proxy?.implementation || item.implementationAddress))}</td></tr>`).join('');
  const invariantRows = invariants.map((item) => `<li><strong>${escapeHTML(value(item.invariantId || item.id || item.name))}</strong><span>${escapeHTML(value(item.status || item.state))}</span><p>${escapeHTML(value(item.description || item.template || item.name))}</p></li>`).join('');
  const findingRows = findings.map((item) => `<li><a href="#finding/${encodeURIComponent(item.id || item.findingId || '')}">${escapeHTML(value(item.title || item.check))}</a><span>${escapeHTML(value(item.status || item.state))}</span></li>`).join('');
  return `<div class="audit-head"><div><span class="eyebrow">02 / 协议</span><h1>协议清单与关系</h1><p>集中查看链、合约地址、已记录代理关系、不变量和关联发现。</p></div><span class="audit-updated">数据更新时间 ${escapeHTML(formatDate(data.generatedAt))}</span></div><div class="protocol-layout"><section class="audit-panel"><div class="audit-panel-head"><h2>协议 / 链清单</h2><span>${chains.length} 条记录</span></div><div class="audit-table-wrap"><table class="audit-table"><thead><tr><th>协议</th><th>资产规模</th><th>状态</th><th>链节点</th><th>详情</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="audit-empty">暂无协议记录。</td></tr>'}</tbody></table></div></section><section class="audit-panel"><div class="audit-panel-head"><h2>代理关系图</h2><span>只读</span></div><pre class="mermaid">graph LR\n  Protocol[协议] --> Implementation[实现合约]\n  Protocol --> Evidence[证据记录]\n  Implementation --> Runtime[链上代码]</pre><p class="audit-note">关系图只表达已记录的关联，未记录的实现关系不会被推测。</p></section></div><div class="protocol-layout protocol-lower"><section class="audit-panel"><div class="audit-panel-head"><h2>合约清单</h2><span>${uniqueContracts.length} 条记录</span></div><div class="audit-table-wrap"><table class="audit-table"><thead><tr><th>协议 / 链</th><th>地址</th><th>代理实现</th></tr></thead><tbody>${contractRows || '<tr><td colspan="3" class="audit-empty">当前没有合约或代理记录。</td></tr>'}</tbody></table></div></section><section class="audit-panel"><div class="audit-panel-head"><h2>业务不变量</h2><span>${invariants.length} 条记录</span></div><ul class="protocol-list">${invariantRows || '<li class="audit-empty">当前没有已保存的不变量。</li>'}</ul></section></div><section class="audit-panel protocol-related-findings"><div class="audit-panel-head"><h2>关联发现</h2><span>最近 ${findingRows ? findings.length : 0} 条</span></div><ul class="protocol-list">${findingRows || '<li class="audit-empty">当前没有关联发现。</li>'}</ul></section>`;
}

export async function bind(root = document) {
  root.querySelectorAll('[data-protocol-detail]').forEach((button) => button.addEventListener('click', () => root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'protocol', protocol: button.dataset.protocol } }))));
  const diagram = root.querySelector('pre.mermaid');
  if (diagram) {
    try {
      const { default: mermaid } = await import('https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs');
      mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'strict' });
      await mermaid.run({ nodes: [diagram] });
    } catch {
      diagram.dataset.renderState = 'text-fallback';
    }
  }
}
