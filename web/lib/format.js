export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

export function formatDate(value) {
  if (!value) return '未记录';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '未记录';
  return new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
}

export function value(value, max = 180) {
  if (value === undefined || value === null || value === '') return '未提供';
  const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function stateLabel(valueToFormat) {
  return ({ poc_confirmed: 'PoC 已确认', static_signal: '静态信号', unconfirmed_observation: '未确认观察', poc_failed: 'PoC 未复现', invariant_violated: '不变量被打破', passed: '通过', violated: '违反', unavailable: '不可用', timeout: '超时' })[String(valueToFormat)] || valueToFormat || '未提供';
}
