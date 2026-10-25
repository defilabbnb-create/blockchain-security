import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, createGunzip } from 'node:zlib';

// 免口令模式的回归测试。
//
// 用户要求公网地址直接打开、不要口令弹窗。这条改动落在 deploy/tunnel/proxy-server.mjs，
// 而 work/ 被 .gitignore 排除，不在版本控制里 —— 所以测试要按文件是否真的存在
// 决定跳不跳过，而不是让测试在干净克隆上假失败。
//
// 这里固定的行为：
//   - TUNNEL_REQUIRE_AUTH=0  -> 无认证请求直接放行（200）
//   - TUNNEL_REQUIRE_AUTH=1  -> 无认证请求 401，带正确口令 200
//   - 不设该变量              -> 默认要口令（防止误配导致公网裸奔）
//   - 免口令模式下不读口令文件，口令文件缺失也能启动
//
// 按 .cursor/rules/silent-wrong-value-review.mdc：边界输入必须诚实失败。
// 要求口令但口令文件缺失时，代理必须明确报错退出，而不是悄悄放行或用空口令。
//
// 注意两个易踩的坑：
//   1. 跳过必须条件式。无条件传 { skip } 会让测试永远不执行 —— 绿灯并不代表
//      行为被验证过，属于「状态合法但语义错误」。
//   2. 不用 fetch。它的 keep-alive 连接池会让测试进程不退出（挂住但不报错）。
//      这里用 http.get + agent:false，连接用完即关。

// 不能用 new URL(...).pathname —— 仓库路径含中文「区块链安全」，
// URL 会把它百分号编码，得到的路径找不到文件，测试会假跳过。
const PROXY = fileURLToPath(new URL('../deploy/tunnel/proxy-server.mjs', import.meta.url));

const SKIP = existsSync(PROXY)
  ? {}
  : { skip: 'deploy/tunnel/proxy-server.mjs 不存在' };

async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function startUpstream() {
  const sockets = new Set();
  // 造一份体积够大、重复度高的 JSON：压缩路径只有在响应体超过阈值时才会走到，
  // 太小的话测了也等于没测。
  const bulky = { ok: true, findings: Array.from({ length: 500 }, (_, i) => ({ id: i, name: `finding-${i}-repeated-content` })) };
  const server = createServer((req, res) => {
    const path = (req.url || '').split('?')[0];
    if (path === '/api/events') {
      // SSE：必须流式，不能被代理缓冲成定长。
      res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' });
      res.write('retry: 3000\n\n');
      res.write(`event: snapshot\nid: 1\ndata: ${JSON.stringify(bulky)}\n\n`);
      return;
    }
    // 与真实上游一致：所有响应都带 no-store，由代理决定哪些可以放行缓存。
    if (path === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end('<!doctype html><title>x</title>');
      return;
    }
    if (path.includes('missing')) {
      res.writeHead(404, { 'content-type': 'text/javascript', 'cache-control': 'no-store' });
      res.end('not found');
      return;
    }
    if (path.endsWith('.js') || path.endsWith('.css')) {
      res.writeHead(200, {
        'content-type': path.endsWith('.css') ? 'text/css' : 'text/javascript',
        'cache-control': 'no-store',
      });
      res.end(`/* ${path} */`);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(bulky));
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    server,
    port: server.address().port,
    stop: () => new Promise((resolve) => {
      for (const socket of sockets) socket.destroy();
      server.close(() => resolve());
    }),
  };
}

async function startProxy(env) {
  const port = await freePort();
  const child = spawn(process.execPath, [PROXY], {
    env: { ...process.env, TUNNEL_PROXY_PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  let err = '';
  child.stdout.on('data', (chunk) => { out += chunk; });
  child.stderr.on('data', (chunk) => { err += chunk; });

  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`代理启动超时: out=${out} err=${err}`)),
      10000,
    );
    const check = () => {
      if (out.includes('listening')) { clearTimeout(timer); resolve(); }
    };
    child.stdout.on('data', check);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`代理退出 code=${code}: ${err || out}`));
    });
  });
  await ready;

  return {
    port,
    output: () => out,
    errorOutput: () => err,
    // 子进程可能已经退出；那时 on('exit') 不会再触发，必须直接 resolve，
    // 否则清理会永久挂起。
    stop: () => new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) { resolve(); return; }
      child.on('exit', () => resolve());
      child.kill('SIGTERM');
    }),
  };
}

function request(port, { auth } = {}) {
  return requestRaw(port, { auth }).then((response) => ({
    status: response.status,
    body: response.text,
  }));
}

// 原始请求：保留响应头和原始字节，供压缩相关断言使用。
function requestRaw(port, { auth, acceptEncoding, path = '/api/health' } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (auth) headers.authorization = `Basic ${Buffer.from(`sec:${auth}`).toString('base64')}`;
    if (acceptEncoding) headers['accept-encoding'] = acceptEncoding;
    const req = http.get(
      { host: '127.0.0.1', port, path, headers, agent: false },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw: buffer,
            text: buffer.toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(new Error('请求超时')); });
  });
}

// SSE 读取：流式响应永远不结束，不能等 'end' 事件。
// 读到第一帧完整事件就主动中止连接 —— 这样测的才是「首帧能否及时送达」，
// 而不是「服务端什么时候关闭连接」。
function readSseFirstFrame(port, { acceptEncoding } = {}) {
  return new Promise((resolve, reject) => {
    const headers = acceptEncoding ? { 'accept-encoding': acceptEncoding } : {};
    const req = http.get(
      { host: '127.0.0.1', port, path: '/api/events', headers, agent: false },
      (res) => {
        const chunks = [];
        const gunzip = createGunzip();
        const decoded = [];
        gunzip.on('data', (chunk) => {
          decoded.push(chunk);
          const text = Buffer.concat(decoded).toString('utf8');
          // 一帧完整 SSE 事件以空行结尾。
          if (text.includes('\n\n')) {
            req.destroy();
            resolve({
              status: res.statusCode,
              headers: res.headers,
              text,
              raw: Buffer.concat(chunks),
            });
          }
        });
        res.on('data', (chunk) => {
          chunks.push(chunk);
          gunzip.write(chunk);
        });
        gunzip.on('error', reject);
      },
    );
    req.on('error', (error) => {
      // req.destroy() 是我们主动中止的，不算失败。
      if (error.code !== 'ECONNRESET' && error.message !== 'socket hang up') reject(error);
    });
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('SSE 首帧等待超时')); });
  });
}

async function passFileWith(value) {
  const dir = await mkdtemp(join(tmpdir(), 'proxy-auth-'));
  const file = join(dir, 'pass');
  await writeFile(file, value, 'utf8');
  return { file, dir };
}

test('免口令模式：无认证请求直接放行', SKIP, async (t) => {
  const upstream = await startUpstream();
  const { file, dir } = await passFileWith('secret-pass');
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '0',
    TUNNEL_PASS_FILE: file,
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); await rm(dir, { recursive: true, force: true }); });

  const noAuth = await request(proxy.port);
  assert.equal(noAuth.status, 200, '免口令模式必须放行无认证请求');

  const withAuth = await request(proxy.port, { auth: 'secret-pass' });
  assert.equal(withAuth.status, 200, '免口令模式下带口令也应放行');
});

test('免口令模式：口令文件缺失也能启动（不静默失败）', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '0',
    TUNNEL_PASS_FILE: join(tmpdir(), 'definitely-missing-pass-file'),
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  const response = await request(proxy.port);
  assert.equal(response.status, 200);
});

test('需要口令模式：无认证请求 401，带正确口令 200', SKIP, async (t) => {
  const upstream = await startUpstream();
  const { file, dir } = await passFileWith('secret-pass');
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '1',
    TUNNEL_PASS_FILE: file,
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); await rm(dir, { recursive: true, force: true }); });

  const noAuth = await request(proxy.port);
  assert.equal(noAuth.status, 401, '要口令时必须拒绝无认证请求');

  const wrongPass = await request(proxy.port, { auth: 'wrong' });
  assert.equal(wrongPass.status, 401, '错误口令必须被拒');

  const rightPass = await request(proxy.port, { auth: 'secret-pass' });
  assert.equal(rightPass.status, 200);
});

test('默认要口令：不设 TUNNEL_REQUIRE_AUTH 时不得裸奔', SKIP, async (t) => {
  const upstream = await startUpstream();
  const { file, dir } = await passFileWith('secret-pass');
  const env = {
    TUNNEL_PASS_FILE: file,
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  };
  delete env.TUNNEL_REQUIRE_AUTH;
  const proxy = await startProxy(env);
  t.after(async () => { await proxy.stop(); await upstream.stop(); await rm(dir, { recursive: true, force: true }); });

  const noAuth = await request(proxy.port);
  assert.equal(noAuth.status, 401, '默认值必须是要求口令，防止误配导致公网裸奔');
});

test('要求口令但口令文件缺失：明确报错退出，不能静默放行', SKIP, async (t) => {
  const upstream = await startUpstream();
  t.after(async () => { await upstream.stop(); });

  let proxy = null;
  let startError = null;
  try {
    proxy = await startProxy({
      TUNNEL_REQUIRE_AUTH: '1',
      TUNNEL_PASS_FILE: join(tmpdir(), 'definitely-missing-pass-file'),
      TUNNEL_UPSTREAM_PORT: String(upstream.port),
    });
  } catch (error) {
    startError = error;
  }

  // 期望代理启动失败（明确报错退出），而不是带着空口令放行。
  if (startError) {
    assert.match(startError.message, /退出|口令/, '应明确报出退出原因');
    return;
  }
  t.after(async () => { await proxy.stop(); });
  const response = await request(proxy.port);
  assert.equal(response.status, 401, '口令文件缺失时不得放行任何请求');
  assert.match(proxy.errorOutput(), /口令文件/, '应明确指出找不到口令文件');
});

// 代理层 gzip 的回归测试。
//
// 为什么要压缩：实测公网隧道有效带宽只有 60–100 KB/s，而 /api/status 的完整
// 快照是 1.36 MB，SSE 每 15 秒推一份。服务端 sendEvent 有 writableLength > 512KB
// 的守卫（防慢客户端无限堆积），隧道慢到写不完时连接被销毁，浏览器按 retry:3000
// 重连，重连又立刻推一份全量快照 —— 形成「推不完 → 断开 → 重连 → 再推」的风暴。
// 代理层压缩把隧道段（cloudflared → 边缘）也压掉，才能从根上避免触发那个守卫。
test('代理层 gzip：客户端接受 gzip 时压缩响应并声明 content-encoding', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '0',
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  const plain = await requestRaw(proxy.port);
  const compressed = await requestRaw(proxy.port, { acceptEncoding: 'gzip, deflate, br' });

  assert.equal(compressed.status, 200);
  assert.equal(compressed.headers['content-encoding'], 'gzip', '接受 gzip 时必须声明 content-encoding');
  assert.match(String(compressed.headers.vary || ''), /accept-encoding/i, '必须声明 vary: accept-encoding（否则缓存会串味）');

  const decompressed = gunzipSync(compressed.raw);
  assert.equal(decompressed.length, plain.raw.length, '解压后内容长度必须与未压缩时一致');
  assert.equal(decompressed.toString('utf8'), plain.text, '解压后内容必须与未压缩时逐字节一致');
  assert.ok(compressed.raw.length < plain.raw.length, `压缩后应更小：${compressed.raw.length} >= ${plain.raw.length}`);
});

test('代理层 gzip：客户端不接受 gzip 时返回原始内容且不声明 content-encoding', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '0',
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  const response = await requestRaw(proxy.port);
  assert.equal(response.status, 200);
  assert.equal(response.headers['content-encoding'], undefined, '客户端没接受 gzip 时不能声明 content-encoding');
  assert.doesNotThrow(() => JSON.parse(response.text), '未压缩时必须仍是可直接解析的 JSON');
});

test('代理层 gzip：Accept-Encoding 显式 q=0 时不压缩', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '0',
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  const response = await requestRaw(proxy.port, { acceptEncoding: 'gzip;q=0' });
  assert.equal(response.headers['content-encoding'], undefined, '客户端明确拒绝 gzip 时不能压缩');
  assert.doesNotThrow(() => JSON.parse(response.text));
});

test('代理层 gzip：SSE 保持流式且可解压（不能被缓冲成定长）', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '0',
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  const response = await readSseFirstFrame(proxy.port, { acceptEncoding: 'gzip' });
  assert.equal(response.status, 200);
  assert.equal(response.headers['content-encoding'], 'gzip', 'SSE 也应压缩（隧道段最吃带宽的就是它）');
  assert.equal(response.headers['content-length'], undefined, 'SSE 不能有 content-length（那会变成定长响应，破坏流式）');

  assert.match(response.text, /^retry: 3000/, 'SSE 必须保留 retry 指令');
  assert.match(response.text, /^event: snapshot/m, 'SSE 必须保留事件类型');
  assert.match(response.text, /^data: /m, 'SSE 必须保留事件数据');
});

// 静态文件边缘缓存的回归测试。
//
// 应用对所有响应写 no-store，Cloudflare 因此每个静态文件都 BYPASS，页面要把十几个
// 模块逐个走隧道。代理对白名单内的前端静态文件改写为 s-maxage=60。
// 缓存错位是静默错值：/api 被缓存时页面照常渲染，数字却是旧的；口令模式被缓存时
// 边缘副本会绕过 Basic Auth。所以这里正反两个方向都要断言。
test('边缘缓存：白名单静态文件放行 s-maxage，浏览器仍每次校验', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({ TUNNEL_REQUIRE_AUTH: '0', TUNNEL_UPSTREAM_PORT: String(upstream.port) });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  for (const path of ['/app.js', '/styles.css', '/views/overview.js', '/lib/format.js']) {
    const response = await requestRaw(proxy.port, { path });
    assert.equal(response.status, 200, path);
    const cacheControl = String(response.headers['cache-control']);
    assert.match(cacheControl, /s-maxage=60/, `${path} 应允许边缘缓存`);
    assert.match(cacheControl, /max-age=0/, `${path} 浏览器必须每次回源校验，否则改前端后用户长时间看旧版`);
    assert.doesNotMatch(cacheControl, /no-store/, `${path} 不应再是 no-store`);
  }
});

test('边缘缓存：/api、首页、非白名单路径、非 200 保持 no-store（反方向）', SKIP, async (t) => {
  const upstream = await startUpstream();
  const proxy = await startProxy({ TUNNEL_REQUIRE_AUTH: '0', TUNNEL_UPSTREAM_PORT: String(upstream.port) });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  const mustStayNoStore = [
    ['/api/health', 200],
    ['/api/status', 200],
    ['/', 200],
    ['/views/missing.js', 404],
    ['/views/../api/health', 200],
    ['/views/sub/deep.js', 200],
    ['/other.js', 200],
  ];
  for (const [path, status] of mustStayNoStore) {
    const response = await requestRaw(proxy.port, { path });
    assert.equal(response.status, status, path);
    assert.equal(response.headers['cache-control'], 'no-store', `${path} 不得被放行缓存`);
  }
});

test('边缘缓存：口令模式下静态文件也保持 no-store（防止缓存副本绕过鉴权）', SKIP, async (t) => {
  const upstream = await startUpstream();
  const { file, dir } = await passFileWith('secret-pass');
  const proxy = await startProxy({
    TUNNEL_REQUIRE_AUTH: '1',
    TUNNEL_PASS_FILE: file,
    TUNNEL_UPSTREAM_PORT: String(upstream.port),
  });
  t.after(async () => { await proxy.stop(); await upstream.stop(); await rm(dir, { recursive: true, force: true }); });

  const response = await requestRaw(proxy.port, { path: '/app.js', auth: 'secret-pass' });
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'no-store', '口令模式不得发出 public 缓存头');
});

// SSE 生命周期回归：代理必须把「上游中途断开」和「客户端断开」都传导到另一端。
//
// 修复前的两个静默故障（接口与单元测试都绿，只有长时间运行才暴露）：
//   1. 上游 SSE 被掐断/重启时，pipe 不结束下游，浏览器连接一直挂着，
//      EventSource 不重连，页面停在旧数据上且没有任何报错。
//   2. 客户端断开后上游连接不释放；上游 SSE 有 16 个连接上限，泄漏会把名额占满。
// 上游断开必须以「正常结束」（chunked 结束块 / gzip 尾部）收尾，
// 否则浏览器记 net::ERR_INCOMPLETE_CHUNKED_ENCODING。
async function startDyingSseUpstream({ dieAfterMs }) {
  const state = { open: 0, started: 0 };
  const server = createServer((req, res) => {
    state.open++; state.started++;
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' });
    res.write('retry: 3000\n\n');
    res.on('close', () => { state.open--; });
    if (dieAfterMs !== null) setTimeout(() => res.socket.destroy(), dieAfterMs);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    state,
    port: server.address().port,
    stop: () => new Promise((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

function waitForStreamEnd(port, { acceptEncoding = 'identity', timeoutMs = 3000 } = {}) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { request.destroy(); resolve({ how: 'hang' }); }, timeoutMs);
    const settle = (value) => { clearTimeout(timer); resolve(value); };
    const request = http.get({ host: '127.0.0.1', port, path: '/api/events', agent: false, headers: { 'accept-encoding': acceptEncoding } }, (response) => {
      response.resume();
      response.on('end', () => settle({ how: 'end', complete: response.complete === true }));
      response.on('aborted', () => settle({ how: 'aborted' }));
      response.on('error', (error) => settle({ how: `error:${error.message}` }));
    });
    request.on('error', (error) => settle({ how: `request-error:${error.message}` }));
  });
}

for (const acceptEncoding of ['identity', 'gzip']) {
  test(`SSE 代理（${acceptEncoding}）：上游中途断开时下游正常结束，不挂死也不半截`, SKIP, async (t) => {
    const upstream = await startDyingSseUpstream({ dieAfterMs: 200 });
    const proxy = await startProxy({ TUNNEL_REQUIRE_AUTH: '0', TUNNEL_UPSTREAM_PORT: String(upstream.port) });
    t.after(async () => { await proxy.stop(); await upstream.stop(); });

    const result = await waitForStreamEnd(proxy.port, { acceptEncoding });
    assert.equal(result.how, 'end', `上游断开后下游应正常结束，实际是 ${result.how}`);
    assert.equal(result.complete, true, '下游应读到完整收尾的流');
  });
}

test('SSE 代理：客户端断开后立即释放上游连接', SKIP, async (t) => {
  const upstream = await startDyingSseUpstream({ dieAfterMs: null });
  const proxy = await startProxy({ TUNNEL_REQUIRE_AUTH: '0', TUNNEL_UPSTREAM_PORT: String(upstream.port) });
  t.after(async () => { await proxy.stop(); await upstream.stop(); });

  for (let index = 0; index < 5; index++) {
    await new Promise((resolve) => {
      const request = http.get({ host: '127.0.0.1', port: proxy.port, path: '/api/events', agent: false }, (response) => {
        response.once('data', () => { request.destroy(); resolve(); });
      });
      request.on('error', () => {});
    });
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.equal(upstream.state.started, 5, '5 次连接都应到达上游');
  assert.equal(upstream.state.open, 0, '客户端全部断开后，上游不应残留 SSE 连接');
});
