import { setTimeout as sleep } from 'node:timers/promises';

export function integer(value, name, min, max) {
  if (!/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`${name} 必须是整数`);
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`${name} 范围必须为 ${min}–${max}`);
  return n;
}
export function quantity(value, name = 'RPC quantity') {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) throw new Error(`${name} 格式无效`);
  return BigInt(value);
}
export function createRpc(url, { timeout = 15000, retries = 2, fetchImpl = fetch, delay = sleep } = {}) {
  let endpoint;
  try { endpoint = new URL(url); } catch { throw new Error('请设置有效的 RPC_URL'); }
  if (!['http:', 'https:'].includes(endpoint.protocol)) throw new Error('RPC_URL 必须使用 HTTP(S)');
  integer(timeout, 'timeout', 1, 120000); integer(retries, 'retries', 0, 5);
  let sequence = 0;
  return async (method, params = []) => {
    const id = ++sequence;
    for (let attempt = 0; ; attempt++) {
      let transient = false;
      let message = `${method}: 网络连接失败或超时`;
      try {
        let response;
        try {
          response = await fetchImpl(endpoint, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
            signal: AbortSignal.timeout(timeout), redirect: 'error',
          });
        } catch { transient = true; throw new Error(message); }
        if (!response.ok) {
          transient = response.status === 429 || response.status >= 500;
          message = `${method}: HTTP ${response.status}`;
          throw new Error(message);
        }
        let data;
        try { data = await response.json(); } catch { message = `${method}: 响应不是 JSON`; throw new Error(message); }
        if (!data || data.jsonrpc !== '2.0' || data.id !== id) { message = `${method}: JSON-RPC 响应不匹配`; throw new Error(message); }
        if (data.error) {
          transient = [-32005, -32016].includes(data.error.code);
          message = `${method}: RPC 错误 ${Number(data.error.code)}`;
          throw new Error(message);
        }
        if (!Object.hasOwn(data, 'result')) { message = `${method}: 响应缺少 result`; throw new Error(message); }
        return data.result;
      } catch {
        if (!transient || attempt >= retries) throw new Error(message);
        await delay(Math.min(250 * 2 ** attempt, 4000));
      }
    }
  };
}
