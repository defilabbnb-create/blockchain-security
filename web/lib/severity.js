export const severityOrder = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 });
export const severityLabels = Object.freeze({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示', informational: '提示' });
export function severityOf(item) { return String(item?.severity || item?.impact || 'info').toLowerCase(); }
export function severityLabel(item) { return severityLabels[severityOf(item)] || '提示'; }
export function sortBySeverity(items = []) { return [...items].sort((a, b) => (severityOrder[severityOf(a)] ?? 9) - (severityOrder[severityOf(b)] ?? 9)); }
