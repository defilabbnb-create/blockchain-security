import { escapeHTML, formatDate, value } from '../lib/format.js';
import { riskBand } from './overview.js';

const CHAIN_STATUS = {
  ready: { label: '可深挖', tone: 'ok', icon: '✓', hint: '链节点身份核对通过，可以看合约代码。' },
  candidate: { label: '候选', tone: 'info', icon: 'i', hint: '资产规模过线，等采集轮到这个链。' },
  queued: { label: '排队中', tone: 'muted', icon: '–', hint: '排在队列里，还没轮到。' },
};

const INVARIANT_STATE = {
  passed: { label: '通过', tone: 'ok', icon: '✓' },
  violated: { label: '被违反', tone: 'danger', icon: '!' },
  failed: { label: '被违反', tone: 'danger', icon: '!' },
  adapter_required: { label: '需要补充适配', tone: 'warn', icon: '·' },
  unverified: { label: '未验证', tone: 'muted', icon: '–' },
};

function badge(tone, icon, label, title = '') {
  return `<span class="status-badge tone-${tone}"${title ? ` title="${escapeHTML(title)}"` : ''}>`
    + `<span class="status-badge-icon" aria-hidden="true">${icon}</span>`
    + `<span class="status-badge-text">${escapeHTML(label)}</span></span>`;
}

function chainCard(chain) {
  const name = chain.name || '未知链';
  const status = CHAIN_STATUS[String(chain.status || '').toLowerCase()]
    || { label: String(chain.status || '未记录'), tone: 'muted', icon: '–', hint: '' };
  const band = riskBand(chain.priorityScore);
  const rpcOk = chain.rpc?.ok === true;
  const riskLabel = `风险指数 ${band.score === null ? '未记录' : band.score}`;
  // 链节点核对失败时如实写「待复核」，不把它显示成已验证。
  const rpcHint = rpcOk
    ? '链节点身份核对通过。'
    : (chain.rpc?.error ? `链节点待复核：${chain.rpc.error}` : '链节点待复核：还没有核验记录。');
  return `<article class="protocol-card" data-protocol-detail="${escapeHTML(name)}">`
    + `<div class="protocol-card-head">`
    + `<a class="protocol-card-name" href="#protocols/${encodeURIComponent(name)}" title="定位到 ${escapeHTML(name)}">${escapeHTML(name)}</a>`
    + `<span class="protocol-card-id">#${escapeHTML(String(chain.chainId || '--'))}</span></div>`
    + `<div class="protocol-card-badges">${badge(status.tone, status.icon, status.label, status.hint)}`
    + `${badge(rpcOk ? 'ok' : 'warn', rpcOk ? '✓' : '·', rpcOk ? '链节点已核对' : '链节点待复核', rpcHint)}`
    + `${badge(band.tone === 'danger' ? 'danger' : band.tone === 'warn' ? 'warn' : 'muted', '◆', riskLabel, band.hint)}</div>`
    + `<p class="protocol-card-scale">当前资产规模 ${escapeHTML(value(chain.currentTvlLabel || chain.peakTvlLabel))}</p>`
    + `<p class="protocol-card-hint">${escapeHTML(status.hint || band.hint)}</p>`
    + `<a class="protocol-card-link" href="#discoveries">看这条链的线索 →</a>`
    + `</article>`;
}

function contractRow(item) {
  return `<li class="protocol-contract"><div><strong>${escapeHTML(value(item.protocol || item.name || item.input?.protocolId))}</strong>`
    + `<small>${escapeHTML(value(item.chain || item.chainId || item.input?.chainId))}</small></div>`
    + `<code>${escapeHTML(value(item.address || item.input?.address))}</code>`
    + `<span class="protocol-contract-proxy">代理实现：${escapeHTML(value(item.originProxy || item.proxy?.implementation || item.implementationAddress))}</span></li>`;
}

function invariantRow(item) {
  const state = String(item.status || item.state || 'unverified').toLowerCase();
  const info = INVARIANT_STATE[state] || { label: state || '未验证', tone: 'muted', icon: '–' };
  const assertion = item.assertion || item.code || item.generatedCode;
  return `<li class="invariant-row"><div><strong>${escapeHTML(value(item.name || item.template || item.invariantId || item.id))}</strong>`
    + `<p>${escapeHTML(value(item.description || item.template || '未提供说明'))}</p></div>`
    + `${badge(info.tone, info.icon, info.label, state)}`
    + (assertion ? `<details class="invariant-code"><summary>展开规则代码</summary><pre><code>${escapeHTML(assertion)}</code></pre></details>` : '')
    + (state === 'adapter_required'
      ? `<small class="adapter-hint">${escapeHTML(value(item.reason || item.adapterReason || '缺少协议适配器，这条规则暂时没法本地执行。'))}</small>` : '')
    + `</li>`;
}

export function render(data = {}) {
  const chains = Array.isArray(data.chains) ? data.chains : [];
  const contracts = [...(data.contracts || []), ...(data.campaignContracts || [])];
  const seen = new Set();
  const uniqueContracts = contracts.filter((item) => {
    const key = `${item.chainId || item.chain}:${item.address || item.input?.address}`.toLowerCase();
    if (!item.address && !item.input?.address || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const invariants = Array.isArray(data.invariants) ? data.invariants : [];
  const findings = (data.findings || []).slice(0, 8);

  const chainCards = chains.length
    ? chains.map(chainCard).join('')
    : '<div class="audit-empty audit-empty-wide"><strong>还没有链记录</strong><span>采集一轮之后，这里会列出每条链并标明它现在的状态。</span></div>';
  const contractList = uniqueContracts.length
    ? uniqueContracts.map(contractRow).join('')
    : '<div class="audit-empty audit-empty-wide"><strong>还没有合约记录</strong><span>采集到合约地址后，这里会显示协议、地址和代理实现。</span></div>';
  const invariantList = invariants.length
    ? invariants.map(invariantRow).join('')
    : '<div class="audit-empty audit-empty-wide"><strong>还没有安全规则</strong>'
      + '<span>安全规则（也写作「不变量」）是「这条合约必须一直成立」的一句话。<br>规则生成后，这里会显示每条规则的状态。</span></div>';
  const findingList = findings.length
    ? findings.map((item) => `<li><a href="#finding/${encodeURIComponent(item.id || item.findingId || '')}">${escapeHTML(value(item.title || item.check))}</a>`
      + `<span>${escapeHTML(value(item.status || item.state))}</span></li>`).join('')
    : '<li class="audit-empty">当前没有关联线索。</li>';

  return `<div class="audit-head"><div><span class="eyebrow">02 / 协议</span><h1>协议与链</h1>`
    + `<p>这里按链整理合约、安全规则和线索。每条链都写清现在能做什么、还差什么。</p></div>`
    + `<span class="audit-updated">数据更新时间 ${escapeHTML(formatDate(data.generatedAt))}</span></div>`
    + `<div class="audit-guide"><strong>这一页在看什么</strong><ol>`
    + `<li><b>链卡片</b>：每条链现在能不能看代码、风险指数多少、资产规模多大。</li>`
    + `<li><b>合约清单</b>：抓到了哪些合约地址，以及它们的代理实现指向哪里。</li>`
    + `<li><b>安全规则</b>（也写作「不变量」）：一条「必须一直成立」的话。没验证过就如实写没验证过。</li>`
    + `</ol></div>`
    + `<div class="protocol-summary"><span><b>${chains.length}</b> 条链</span>`
    + `<span><b>${uniqueContracts.length}</b> 个合约</span>`
    + `<span><b>${invariants.length}</b> 条安全规则</span>`
    + `<span><b>${findings.length}</b> 条关联线索</span></div>`
    + `<section class="audit-panel"><div class="audit-panel-head"><div><h2>链清单</h2>`
    + `<p>点链名可以定位到这条链；点「看这条链的线索」会跳到发现页。</p></div><span>${chains.length} 条记录</span></div>`
    + `<div class="protocol-card-grid">${chainCards}</div></section>`
    + `<div class="protocol-layout protocol-lower">`
    + `<section class="audit-panel"><div class="audit-panel-head"><div><h2>合约清单</h2>`
    + `<p>地址、所属链和代理实现。</p></div><span>${uniqueContracts.length} 条记录</span></div>`
    + `<ul class="protocol-list protocol-contract-list">${contractList}</ul></section>`
    + `<section class="audit-panel"><div class="audit-panel-head"><div><h2>安全规则</h2>`
    + `<p>展开可以看规则代码和适配限制。</p></div><span>${invariants.length} 条记录</span></div>`
    + `<ul class="protocol-list">${invariantList}</ul></section></div>`
    + `<section class="audit-panel protocol-related-findings"><div class="audit-panel-head"><div><h2>关联线索</h2>`
    + `<p>点进去看完整证据。</p></div><span>最近 ${findings.length} 条</span></div>`
    + `<ul class="protocol-list">${findingList}</ul></section>`
    + `<section class="audit-panel"><div class="audit-panel-head"><div><h2>关系示意</h2>`
    + `<p>只画已经记录下来的关系，没记录的不推测。</p></div><span>只读</span></div>`
    + `<pre class="mermaid">graph LR\n  Protocol[链 / 协议] --> Contract[合约地址]\n  Protocol --> Rule[安全规则]\n  Contract --> Evidence[证据记录]\n  Rule --> Execution[本地运行结果]</pre>`
    + `<p class="audit-note">这条关系图只说明「记录之间的关联」，不代表任何漏洞成立。</p></section>`;
}

export async function bind(root = document) {
  const diagram = root.querySelector('pre.mermaid');
  if (diagram) {
    try {
      const { default: mermaid } = await import('https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs');
      mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'strict' });
      await mermaid.run({ nodes: [diagram] });
    } catch {
      // CDN 取不到时保留文字版关系，不假装图已经画出来。
      diagram.dataset.renderState = 'text-fallback';
    }
  }
}
