import { escapeHTML, formatDate, value } from '../lib/format.js';

export function render(data = {}) {
  const chains = Array.isArray(data.chains) ? data.chains : [];
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const top = chains.slice(0, 12);
  const maxAssets = Math.max(1, ...top.map((chain) => Number(chain.currentTvlUsd || chain.peakTvlUsd || 0)));
  const blocks = top.length ? top.map((chain) => { const heat = Math.max(.16, Math.min(1, Number(chain.currentTvlUsd || chain.peakTvlUsd || 0) / maxAssets)); const score = Number(chain.priorityScore); const label = Number.isFinite(score) && score >= .7 ? '高风险' : Number.isFinite(score) && score >= .35 ? '待复核' : '未评分'; const dot = label === '高风险' ? 'danger' : label === '待复核' ? 'warn' : ''; return `<button class="map-protocol" type="button" aria-label="打开 ${escapeHTML(chain.name || '未知链')} 协议详情" data-protocol="${escapeHTML(chain.name || chain.chainId)}" style="--heat:${heat}"><span class="map-protocol-index">${escapeHTML(String(chain.chainId || '--'))}</span><strong>${escapeHTML(chain.name || '未知链')}</strong><span>${escapeHTML(value(chain.currentTvlLabel || chain.peakTvlLabel))}</span><small><i class="status-dot ${dot}"></i>${label} · ${escapeHTML(value(chain.priorityScore ?? '未评分'))}</small></button>`; }).join('') : '<div class="audit-empty audit-empty-wide"><strong>暂无协议地图</strong><span>采集到协议或链数据后，这里会显示可点击的风险卡片。</span></div>';
  const attention = findings.filter((item) => ['critical', 'high'].includes(String(item.severity || item.impact || '').toLowerCase())).length;
  return `<div class="audit-head"><div><span class="eyebrow">01 / 作战地图</span><h1>协议风险作战地图</h1><p>先按资产规模找到重点，再点击协议查看合约、不变量和证据。所有状态来自已保存证据。</p></div><span class="audit-updated">更新于 ${escapeHTML(formatDate(data.generatedAt))}</span></div><div class="audit-kpis"><div><span>协议 / 链</span><b>${chains.length}</b><small>可点击查看详情</small></div><div><span>待核验发现</span><b class="${attention ? 'kpi-alert' : ''}">${findings.length}</b><small>${attention ? `${attention} 条高优先级` : '没有高优先级记录'}</small></div><div><span>执行边界</span><b>只读</b><small>不签名、不授权、不广播</small></div></div><section class="protocol-map" aria-label="协议风险热力图">${blocks}</section><div class="audit-legend" aria-label="风险图例"><span><i class="status-dot danger"></i>高风险</span><span><i class="status-dot warn"></i>待复核</span><span><i class="status-dot"></i>未评分</span></div><div class="audit-note">资产规模仅用于排序，不代表资产可取回；静态线索和模型观察仍需本地证据确认。</div>`;
}

export function bind(root = document) {
  root.querySelectorAll('[data-protocol]').forEach((button) => button.addEventListener('click', () => root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'protocol', protocol: button.dataset.protocol } }))));
}
