// 区块链安全 Web 端 —— 公网隧道代理（自建，替代 Caddy）
//
// 为什么需要这一层：
//   1. src/web-server.js 内置「只允许本机访问」校验：Host 与 Origin 必须落在
//      loopback 集合内，直接把 8788 暴露到公网会全站 403。
//   2. 应用以 Transfer-Encoding: chunked 返回 JSON；实测隧道（localtunnel /
//      serveo / pinggy）遇到 chunked 响应会丢弃响应体（状态码 200 但
//      content-length: 0）。对照实验：同样响应体改为 Content-Length 后隧道
//      可完整转发。
//
// 因此本代理做四件事：
//   - 重写 Host / Origin，满足应用的 loopback 校验
//   - 校验 Basic Auth（口令从 deploy/tunnel/.plainpass 读取，该文件被 gitignore）
//   - 除 SSE（/api/events）外缓冲完整响应，改用 Content-Length 定长返回；
//     SSE 保持流式不缓冲
//   - 对可压缩响应做 gzip（见下方「为什么在代理层压缩」）
//
// 为什么在代理层压缩：
//   实测公网隧道有效带宽只有 60–100 KB/s，而 /api/status 的完整快照是 1.36 MB
//   （findings 占 61%，vulnerabilityLibrary 占 16%）。SSE 每 15 秒推一份全量快照。
//   Cloudflare 只压缩「边缘 → 浏览器」这一段；cloudflared → 边缘的隧道段
//   仍是原始 1.36 MB。实测浏览器里那条 SSE 连接累计传输了 84 MB ——
//   服务端 sendEvent 有 writableLength > 512KB 的守卫（防止慢客户端无限堆积），
//   隧道慢到写不完时连接被销毁，浏览器按 retry:3000 重连，重连又立刻推一份
//   全量快照，于是形成「推不完 → 断开 → 重连 → 再推」的风暴。
//   在代理层压缩能把 1.36 MB 降到约 200 KB，隧道段和边缘段同时受益，
//   从根上避免触发那个 512KB 守卫。
//
// 免口令模式（TUNNEL_REQUIRE_AUTH=0）：
//   用户要求公网地址直接打开、不要口令弹窗。设 TUNNEL_REQUIRE_AUTH=0 即可关闭
//   Basic Auth 校验，行为是「跳过鉴权」而不是「删掉鉴权代码」——
//   一行环境变量就能回退到有口令的状态，不用改代码、不用重启改配置。
//   默认值是 1（要口令），避免误配导致公网裸奔。
//   注意：关闭口令后，任何能访问该域名的人都能调用本机的全部 /api 路由
//   （含 /api/ask 的模型调用、/api/tasks 的任务下发）。这是用户明确要求的状态，
//   状态展示里会如实写明当前是「免口令公开访问」。
//
// 不修改任何项目源码，Web 服务与采集任务不受影响。
import http from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import { createGzip, constants as zlibConstants, gzipSync } from 'node:zlib';

const PORT = Number(process.env.TUNNEL_PROXY_PORT || 8789);
const UPSTREAM = { host: '127.0.0.1', port: Number(process.env.TUNNEL_UPSTREAM_PORT || 8788) };
const PASS_FILE = process.env.TUNNEL_PASS_FILE
  || '/Users/d288/Desktop/区块链安全/deploy/tunnel/.plainpass';
const SSE_PATH = '/api/events';

// 压缩阈值：太小的响应压缩反而变大（gzip 头 + 字典开销）。
const COMPRESS_MIN_BYTES = 1024;

// 是否要求 Basic Auth。默认要口令；只有显式设为 0/false/no/off 才免口令。
const REQUIRE_AUTH = !['0', 'false', 'no', 'off'].includes(
  String(process.env.TUNNEL_REQUIRE_AUTH ?? '1').trim().toLowerCase(),
);

// 免口令模式下没有口令文件也要能启动，所以口令只在需要鉴权时才读。
let expectedBuf = null;
if (REQUIRE_AUTH) {
  if (!existsSync(PASS_FILE)) {
    console.error(`找不到口令文件: ${PASS_FILE}（或设 TUNNEL_REQUIRE_AUTH=0 免口令）`);
    process.exit(1);
  }
  expectedBuf = Buffer.from(readFileSync(PASS_FILE, 'utf8').trim(), 'utf8');
}

function authorized(header) {
  if (!REQUIRE_AUTH) return true;
  if (!header || !header.startsWith('Basic ')) return false;
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const idx = decoded.indexOf(':');
  if (idx < 0) return false;
  const user = Buffer.from(decoded.slice(0, idx), 'utf8');
  const pass = Buffer.from(decoded.slice(idx + 1), 'utf8');
  // 用户名固定为 sec；口令用定时安全比较，避免时序侧信道。
  const userOk = user.length === 3 && timingSafeEqual(user, Buffer.from('sec'));
  if (!userOk) return false;
  if (pass.length !== expectedBuf.length) return false;
  return timingSafeEqual(pass, expectedBuf);
}

function unauthorized(res) {
  res.writeHead(401, {
    'www-authenticate': 'Basic realm="security-web"',
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify({ error: '需要访问口令' }));
}

function acceptsGzip(req) {
  const header = String(req.headers['accept-encoding'] || '').toLowerCase();
  // 明确写了 gzip;q=0 的不接受；没写 accept-encoding 也不压缩。
  return header.split(',').some((part) => {
    const [name, ...params] = part.trim().split(';');
    if (name.trim() !== 'gzip') return false;
    return !params.some((p) => /^\s*q\s*=\s*0(\.0+)?\s*$/i.test(p));
  });
}

// 前端静态文件的边缘缓存。
//
// 问题：应用对所有响应都写 cache-control: no-store，Cloudflare 因此对每个静态文件
// 都 BYPASS，页面打开要把 10 个模块 + CSS 逐个走一遍隧道（实测每个 0.7–1.2 秒）。
// 做法：只对白名单内的前端静态文件改写为 s-maxage=60 —— 边缘缓存 60 秒，
// 浏览器仍然 max-age=0 每次回源校验（命中边缘时很快），改前端后最多 60 秒生效。
//
// 边界（见 .cursor/rules/silent-wrong-value-review.mdc，缓存错位是静默错值）：
//   - 只放行白名单路径；/api/*、/ (index.html) 保持上游的 no-store，
//     否则状态数据会过期而页面照常显示，看起来正常但数值是旧的。
//   - 口令模式不缓存：public 缓存副本会让未带口令的请求直接命中边缘，绕过 Basic Auth。
//   - 只缓存 200 的 GET/HEAD，404/500 不入缓存。
const STATIC_ASSET_RE = /^\/(?:app\.js|styles\.css|(?:views|lib)\/[\w.-]+\.js)$/;
const STATIC_CACHE_CONTROL = 'public, max-age=0, s-maxage=60';

function isEdgeCacheable(req, statusCode) {
  if (REQUIRE_AUTH) return false;
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  if (statusCode !== 200) return false;
  return STATIC_ASSET_RE.test((req.url || '').split('?')[0]);
}

function isCompressibleType(contentType) {
  const type = String(contentType || '').toLowerCase();
  return /json|text\/|javascript|xml|svg|wasm/.test(type);
}

const server = http.createServer((req, res) => {
  if (!authorized(req.headers.authorization)) return unauthorized(res);

  const isSse = (req.url || '').split('?')[0] === SSE_PATH;
  const gzip = acceptsGzip(req);
  const headers = {
    ...req.headers,
    host: `${UPSTREAM.host}:${UPSTREAM.port}`,
    origin: `http://${UPSTREAM.host}:${UPSTREAM.port}`,
    'x-forwarded-proto': 'https',
    // 关键：让上游不要自己声明 chunked 之外的长度语义，这里保留上游头，
    // 由本代理在缓冲后统一写 Content-Length。
    connection: 'close',
  };

  const upstreamReq = http.request(
    { host: UPSTREAM.host, port: UPSTREAM.port, method: req.method, path: req.url, headers },
    (upstreamRes) => {
      const contentType = upstreamRes.headers['content-type'];
      const compressible = gzip && isCompressibleType(contentType);

      if (isSse) {
        // 生命周期两头都要接上，否则会出现两种「看起来正常」的故障：
        //   1. 客户端断开后上游连接不释放 —— 上游 SSE 有 16 个连接上限，泄漏会挤占名额；
        //   2. 上游中途死掉（重启/被掐断）时 pipe 不会结束下游 —— 浏览器连接一直挂着，
        //      EventSource 不重连，页面停在旧数据上却没有任何报错。
        // 上游异常结束时用 end() 正常收尾（补 chunked 结束块），浏览器会按 retry 重连；
        // 用 destroy() 会变成 net::ERR_INCOMPLETE_CHUNKED_ENCODING。
        res.on('close', () => upstreamReq.destroy());
        let closeDownstream = () => { if (!res.writableEnded && !res.destroyed) res.end(); };
        upstreamRes.on('error', () => {});
        upstreamRes.on('close', () => { if (!upstreamRes.complete) closeDownstream(); });
        // SSE：实时推送，不缓冲。压缩时用流式 gzip，并在每帧后立即 flush，
        // 保证浏览器能及时收到事件（不为了压缩率牺牲实时性）。
        if (compressible) {
          const outHeaders = { ...upstreamRes.headers };
          delete outHeaders['content-length'];
          delete outHeaders['transfer-encoding'];
          outHeaders['content-encoding'] = 'gzip';
          outHeaders.vary = outHeaders.vary ? `${outHeaders.vary}, accept-encoding` : 'accept-encoding';
          res.writeHead(upstreamRes.statusCode || 502, outHeaders);
          const gzipStream = createGzip({ flush: zlibConstants.Z_SYNC_FLUSH });
          gzipStream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
          res.on('close', () => gzipStream.destroy());
          // 经过 gzip 时必须先结束压缩流，才会写出 gzip 尾部并关闭下游。
          closeDownstream = () => { if (!gzipStream.writableEnded && !gzipStream.destroyed) gzipStream.end(); };
          upstreamRes.pipe(gzipStream).pipe(res);
        } else {
          res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
          upstreamRes.pipe(res);
        }
        return;
      }

      const chunks = [];
      upstreamRes.on('data', (c) => chunks.push(c));
      upstreamRes.on('end', () => {
        let body = Buffer.concat(chunks);
        const outHeaders = { ...upstreamRes.headers };
        delete outHeaders['transfer-encoding'];
        if (compressible && body.length >= COMPRESS_MIN_BYTES) {
          const compressed = gzipSync(body);
          // 压缩后反而更大就不压，保持原样。
          if (compressed.length < body.length) {
            body = compressed;
            outHeaders['content-encoding'] = 'gzip';
            outHeaders.vary = outHeaders.vary ? `${outHeaders.vary}, accept-encoding` : 'accept-encoding';
          }
        }
        outHeaders['content-length'] = String(body.length);
        if (isEdgeCacheable(req, upstreamRes.statusCode)) outHeaders['cache-control'] = STATIC_CACHE_CONTROL;
        res.writeHead(upstreamRes.statusCode || 502, outHeaders);
        res.end(body);
      });
      upstreamRes.on('error', () => {
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: '上游不可用' }));
      });
    },
  );

  upstreamReq.on('error', () => {
    // 响应头已发出（例如 SSE 中途断开）时不能再往流里追加 JSON，否则会污染事件流。
    if (res.headersSent) { if (!res.writableEnded && !res.destroyed) res.end(); return; }
    res.writeHead(502, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: '上游不可用' }));
  });

  req.pipe(upstreamReq);
});

server.listen(PORT, '127.0.0.1', () => {
  const mode = REQUIRE_AUTH ? '需要口令' : '免口令（公网公开访问）';
  console.log(`tunnel proxy listening on 127.0.0.1:${PORT} -> 127.0.0.1:${UPSTREAM.port} [${mode}]`);
});
