// 置信度徽章与严重度刻度。两者故意用不同的视觉语言，不能互相借用：
//   置信度：颜色 + 形状 + 图标 + 文字（confidence.js 的五级）
//   严重度：文字 + 四格长度条，不使用任何色相（颜色只留给置信度）
// 单靠颜色的信息一律不要：每个徽章都带文字标签，形状也各不相同，色盲和灰度显示下仍可区分。
import { escapeHTML } from './format.js';
import { CONFIDENCE_TIERS, confidenceTier } from './confidence.js';
import { severityLabels } from './severity.js';

const SVG_OPEN = '<svg class="conf-icon" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">';

// 五个等级的外形互不相同：实心圆、实心三角、空心圆、虚线圆、方框。
const ICONS = Object.freeze({
  confirmed: `${SVG_OPEN}<circle cx="8" cy="8" r="7" fill="currentColor"/><path class="ink" d="M4.6 8.3l2.3 2.3 4.5-4.9" stroke="#0b1117" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  anomaly: `${SVG_OPEN}<path d="M8 1.4L15.2 14H0.8z" fill="currentColor" stroke="currentColor" stroke-width="1" stroke-linejoin="round"/><path class="ink" d="M8 6v4" stroke="#0b1117" fill="none" stroke-width="1.8" stroke-linecap="round"/><circle class="ink-dot" cx="8" cy="12" r="1" fill="#0b1117"/></svg>`,
  unverified: `${SVG_OPEN}<circle cx="8" cy="8" r="6.4" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M6.1 6.4a2 2 0 1 1 2.9 1.8c-.6.3-1 .7-1 1.4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="11.7" r=".9" fill="currentColor"/></svg>`,
  indeterminate: `${SVG_OPEN}<circle cx="8" cy="8" r="6.4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="2.6 2.2"/><path d="M5.2 8h5.6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  not_applicable: `${SVG_OPEN}<rect x="2" y="2" width="12" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M5 6h6M5 8.5h6M5 11h3.5" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
});

export const CONFIDENCE_ICONS = ICONS;

export function confidenceBadge(finding) {
  const verdict = confidenceTier(finding);
  const tier = CONFIDENCE_TIERS[verdict.tier];
  const title = `${tier.meaning}（依据：${verdict.reason}）`;
  return `<span class="conf-badge conf-${verdict.tier}" data-tier="${verdict.tier}" data-reason="${escapeHTML(verdict.reason)}" title="${escapeHTML(title)}">${ICONS[verdict.tier]}<span class="conf-label">${escapeHTML(tier.label)}</span></span>`;
}

export function confidenceLegend() {
  const rows = Object.entries(CONFIDENCE_TIERS).sort((a, b) => a[1].rank - b[1].rank).map(([key, tier]) =>
    `<li class="conf-legend-row"><span class="conf-badge conf-${key}" data-tier="${key}">${ICONS[key]}<span class="conf-label">${escapeHTML(tier.label)}</span></span><span class="conf-legend-meaning">${escapeHTML(tier.meaning)}</span></li>`);
  return `<ul class="conf-legend">${rows.join('')}</ul>`;
}

// 严重度刻度：已知取值映射到 0–4 格；缺失或无法识别时显示“未分级”，不落到“提示”。
const SEVERITY_BARS = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });
const SEVERITY_ALIASES = Object.freeze({ informational: 'info' });
const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

export function severityReading(finding) {
  const raw = finding !== null && typeof finding === 'object' ? (finding.severity ?? finding.impact) : undefined;
  if (typeof raw !== 'string' || !raw.trim()) return Object.freeze({ key: 'unrated', bars: 0, reason: 'severity_missing' });
  const lowered = raw.trim().toLowerCase();
  const key = has(SEVERITY_ALIASES, lowered) ? SEVERITY_ALIASES[lowered] : lowered;
  if (!has(SEVERITY_BARS, key)) return Object.freeze({ key: 'unrated', bars: 0, reason: 'severity_unrecognized' });
  return Object.freeze({ key, bars: SEVERITY_BARS[key], reason: 'severity_field' });
}

export function severityMeter(finding) {
  const reading = severityReading(finding);
  const label = reading.key === 'unrated' ? '未分级' : severityLabels[reading.key];
  const bars = [1, 2, 3, 4].map((position) => `<i${position <= reading.bars ? ' class="on"' : ''}></i>`).join('');
  return `<span class="sev-meter sev-${reading.key}" data-severity="${reading.key}" data-reason="${reading.reason}"><span class="sev-bars" aria-hidden="true">${bars}</span><span class="sev-text">${escapeHTML(label)}</span></span>`;
}

// 两者并排但各带说明文字，中间有分隔线，避免被当成同一套系统。
export function findingSignals(finding) {
  return `<div class="signal-pair"><div class="signal-cell"><span class="signal-caption">严重度</span>${severityMeter(finding)}</div><div class="signal-cell"><span class="signal-caption">置信度</span>${confidenceBadge(finding)}</div></div>`;
}
