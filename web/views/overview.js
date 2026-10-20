import { escapeHTML, formatDate, value } from '../lib/format.js';

export function render(data = {}) {
  const chains = Array.isArray(data.chains) ? data.chains : [];
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const top = chains.slice(0, 12);
  const maxAssets = Math.max(1, ...top.map((chain) => Number(chain.currentTvlUsd || chain.peakTvlUsd || 0)));
  const blocks = top.length ? top.map((chain) => `<button class="map-protocol" type="button" data-protocol="${escapeHTML(chain.name || chain.chainId)}" style="--heat:${Math.max(.16, Math.min(1, Number(chain.currentTvlUsd || chain.peakTvlUsd || 0) / maxAssets))}"><strong>${escapeHTML(chain.name || '未知链')}</strong><span>${escapeHTML(value(chain.currentTvlLabel || chain.peakTvlLabel))}</span><small>风险 ${escapeHTML(value(chain.priorityScore ?? '未评分'))}</small></button>`).join('') : '<div class="audit-empty">当前没有协议地图记录。</div>';
  return `<div class="audit-head"><div><span class="eyebrow">01 / 作战地图</span><h1>协议风险作战地图</h1><p>按可达资产规模展示协议热度，颜色代表当前风险排序；所有状态来自已保存证据。</p></div><span class="audit-updated">更新于 ${escapeHTML(formatDate(data.generatedAt))}</span></div><div class="audit-kpis"><div><span>协议 / 链</span><b>${chains.length}</b></div><div><span>待核验发现</span><b>${findings.length}</b></div><div><span>只读模式</span><b>开启</b></div></div><section class="protocol-map" aria-label="协议风险热力图">${blocks}</section><div class="audit-note">资产规模仅用于排序，不代表资产可取回；静态线索和模型观察仍需本地证据确认。</div>`;
}

export function bind(root = document) {
  root.querySelectorAll('[data-protocol]').forEach((button) => button.addEventListener('click', () => root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'protocol', protocol: button.dataset.protocol } }))));
}
