import { escapeHTML, formatDate, value } from '../lib/format.js';

// 风险指数（后端字段名 priorityScore）来自筛选快照：
//   历史热度 50% + 当前资产规模 25% + 跨链连接 25%，三项各自封顶 100。
// 所以分数范围是 0–100，0 表示「三项加起来几乎为 0」。
//
// 诚实性约束：0 不等于「这条链没有风险」，只等于「没有记录到热度、规模和连接证据」。
// 因此没有评分时显示「未评分」，不把它显示成 0 分。
const RISK_BANDS = [
  { min: 60, key: 'high', label: '优先查看', tone: 'danger', hint: '风险指数偏高，建议先看这条链的合约与线索。' },
  { min: 30, key: 'mid', label: '值得一看', tone: 'warn', hint: '风险指数中等，等有具体线索时再深入。' },
  { min: 0.01, key: 'low', label: '暂不优先', tone: 'none', hint: '风险指数较低，或这条链的采集记录很少。' },
];

const STATUS_HINTS = {
  candidate: '候选：资产规模过线，等采集轮到这个链。',
  ready: '可深挖：链节点身份核对通过，可以看合约代码。',
  queued: '排队中：排在队列里，还没轮到。',
};

/** 把风险指数分档。缺少评分时如实说「未评分」，不假装是 0。 */
export function riskBand(score) {
  const numeric = Number(score);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return { key: 'none', label: '未评分', tone: 'none', hint: '这条链还没有记录到风险指数。', score: null };
  }
  const band = RISK_BANDS.find((item) => numeric >= item.min) || RISK_BANDS[RISK_BANDS.length - 1];
  return { ...band, score: numeric };
}

function chainCard(chain) {
  const name = chain.name || '未知链';
  const band = riskBand(chain.priorityScore);
  const scale = value(chain.currentTvlLabel || chain.peakTvlLabel);
  // 热度只影响底色深浅，用来排序和提示；分档仍然只看风险指数本身。
  const heat = Math.max(0.08, Math.min(1, Number(chain.currentTvlUsd || chain.peakTvlUsd || 0) / 400000000));
  const hint = STATUS_HINTS[String(chain.status || '').toLowerCase()] || '';
  return `<button class="map-protocol" type="button" data-protocol="${escapeHTML(name)}"`
    + ` aria-label="查看 ${escapeHTML(name)} 的协议与线索" style="--heat:${heat.toFixed(3)}">`
    + `<span class="map-protocol-index">#${escapeHTML(String(chain.chainId || '--'))}</span>`
    + `<strong>${escapeHTML(name)}</strong>`
    + `<span class="map-protocol-scale">当前资产规模 ${escapeHTML(scale)}</span>`
    + `<span class="map-protocol-risk"><i class="status-dot ${band.tone}"></i>`
    + `<b>风险指数 ${band.score === null ? '未记录' : band.score}</b>`
    + `<em class="map-protocol-band band-${band.key}">${escapeHTML(band.label)}</em></span>`
    + `<small class="map-protocol-hint">${escapeHTML(hint || band.hint)}</small>`
    + `</button>`;
}

export function render(data = {}) {
  const chains = Array.isArray(data.chains) ? data.chains : [];
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const attention = findings.filter((item) => ['critical', 'high'].includes(String(item.severity || item.impact || '').toLowerCase())).length;
  const cards = chains.length
    ? chains.slice(0, 12).map(chainCard).join('')
    : '<div class="audit-empty audit-empty-wide"><strong>还没有链数据</strong><span>采集一轮之后，这里会列出每条链并按风险指数排序。</span></div>';

  return `<div class="audit-head"><div><span class="eyebrow">01 / 风险地图</span><h1>风险地图</h1>`
    + `<p>先看哪条链值得优先看，再点开看它的合约、安全规则和线索。数字越大越值得先看。</p></div>`
    + `<span class="audit-updated">数据更新时间 ${escapeHTML(formatDate(data.generatedAt))}</span></div>`
    + `<div class="audit-guide"><strong>怎么看这张图</strong><ol>`
    + `<li>每张卡片是一条链，卡片上的<em>风险指数</em>是 0–100 的分：<em>数字越大越值得先看</em>。</li>`
    + `<li>点击任意一张卡片，会跳到「协议」页并自动定位到这条链。</li>`
    + `<li>资产规模只用来参考规模，不代表里面的钱一定能取回来，也不代表这条链有漏洞。</li>`
    + `</ol></div>`
    + `<div class="audit-kpis"><div><span>已收录的链</span><b>${chains.length}</b><small>点击卡片查看详情</small></div>`
    + `<div><span>待核验线索</span><b class="${attention ? 'kpi-alert' : ''}">${findings.length}</b><small>${attention ? `其中 ${attention} 条高危，优先看` : '没有高危线索'}</small></div>`
    + `<div><span>执行边界</span><b>只读</b><small>不签名、不授权、不广播</small></div></div>`
    + `<section class="protocol-map" aria-label="风险地图：按风险指数排序的链卡片">${cards}</section>`
    + `<div class="audit-legend" aria-label="风险图例"><span><i class="status-dot danger"></i>优先查看（风险指数 ≥ 60）</span>`
    + `<span><i class="status-dot warn"></i>值得一看（30–60）</span>`
    + `<span><i class="status-dot"></i>暂不优先或未评分</span></div>`
    + `<p class="audit-note">风险指数来自已保存的筛选快照（历史热度 + 当前资产规模 + 跨链连接）。静态线索和模型观察仍需要本地证据确认，不能直接当成已确认漏洞。</p>`;
}

export function bind(root = document) {
  root.querySelectorAll('[data-protocol]').forEach((button) => button.addEventListener('click', () => {
    // 深链接带上链名，协议页才能定位到具体那张卡片。
    root.dispatchEvent(new CustomEvent('audit:navigate', { bubbles: true, detail: { route: 'protocol', protocol: button.dataset.protocol } }));
  }));
}
