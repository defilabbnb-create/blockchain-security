export async function getJSON(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', ...options, signal: options.signal || AbortSignal.timeout(12000) });
  let payload = null;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) throw new Error(payload?.error?.message || payload?.error || `服务返回状态 ${response.status}`);
  return payload || {};
}

export function items(payload) { return Array.isArray(payload?.items) ? payload.items : []; }

export async function optional(path) {
  try { return { ok: true, path, data: await getJSON(path) }; }
  catch (error) { return { ok: false, path, error }; }
}
