#!/usr/bin/env node
import { mkdir, rename, unlink, writeFile, open, copyFile } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { runtimeFingerprint } from '../src/runtime-fingerprint.js';
import { boundedSingleFlight } from '../src/bounded-work.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
export function options(args = process.argv.slice(2)) {
  const config = { durationMs: 10800000, intervalMs: 30000, timeoutMs: 7000, output: join(ROOT, 'work/soak-3h.json'), baseUrl: process.env.SOAK_BASE_URL || 'http://127.0.0.1:8788', events: true, sourceCheck: true };
  const keys = { '--duration-ms': 'durationMs', '--interval-ms': 'intervalMs', '--ask-every': 'askEvery', '--timeout-ms': 'timeoutMs' };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--once') config.durationMs = 0;
    else if (arg === '--output') config.output = resolve(args[++i]);
    else if (arg === '--base-url') config.baseUrl = args[++i];
    else if (keys[arg]) { const value = Number(args[++i]); if (!Number.isFinite(value) || value < 1) throw new Error(`无效参数 ${arg}`); config[keys[arg]] = value; }
    else throw new Error(`未知参数 ${arg}`);
  }
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(new URL(config.baseUrl).hostname)) throw new Error('soak 仅允许本机 URL');
  return config;
}
export function validate(path, data) {
  if (!data || typeof data !== 'object') return 'invalid JSON response';
  if (path === '/api/health') return data.status !== 'ok' ? `health ${data.status}` : !data.instanceId || !Number.isFinite(data.memory?.rss) ? 'invalid health schema' : null;
  if (path === '/api/status') return !data.syncVersion || !Array.isArray(data.chains) || !Array.isArray(data.vulnerabilityChains) ? 'invalid status schema' : !Number.isFinite(Date.parse(data.generatedAt)) || Math.abs(Date.now() - Date.parse(data.generatedAt)) > 60000 ? 'snapshot stale' : null;
  if (path === '/api/sync') return !data.syncVersion || !data.consumers?.includes('dsh') || !data.consumers?.includes('dhlsh') ? 'invalid sync schema' : null;
  if (path === '/api/ask') return !data.answer ? 'empty answer' : null;
  return null;
}
function compact(path, data) {
  if (path === '/api/health') return data;
  if (path === '/api/status') return { generatedAt: data.generatedAt, syncVersion: data.syncVersion, totals: data.totals };
  if (path === '/api/sync') return { generatedAt: data.generatedAt, syncVersion: data.syncVersion, consumers: data.consumers };
  if (path === '/api/ask') return { mode: data.mode, provider: data.provider, model: data.model, reason: data.reason, answer: data.answer?.slice(0, 350) };
  return null;
}
async function atomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${randomUUID()}.tmp`;
  try { await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }); await rename(temp, path); }
  finally { await unlink(temp).catch(() => {}); }
}
export async function runSoak(config, signal = new AbortController().signal) {
  const started = Date.now();
  const startedMono = performance.now();
  const elapsed = () => performance.now() - startedMono;
  const fingerprint = boundedSingleFlight(runtimeFingerprint);
  const sourceFingerprint = config.sourceCheck ? await fingerprint() : null;
  const controller = new AbortController();
  const linkedSignal = AbortSignal.any([signal, controller.signal]);
  const runId = randomUUID();
  const samples = [];
  const events = { frames: 0, lastAt: null, maxGapMs: 0, error: null };
  let lastEventMono = startedMono;
  const eventTask = config.events ? (async () => {
    try {
      const response = await fetch(`${config.baseUrl}/api/events`, { signal: linkedSignal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      let buffer = '';
      const decoder = new TextDecoder();
      for await (const chunk of response.body) {
        buffer += decoder.decode(chunk, { stream: true });
        if (buffer.length > 2 * 1024 * 1024) throw new Error('SSE frame too large');
        let boundary;
        while ((boundary = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
          if (frame.startsWith('event: snapshot\n')) {
            const data = JSON.parse(frame.split('\ndata: ')[1]);
            const error = validate('/api/status', data);
            if (error) throw new Error(error);
            const gap = performance.now() - lastEventMono;
            events.maxGapMs = Math.max(events.maxGapMs, gap);
            if (gap > 45000) events.error ||= 'SSE gap exceeded 45 seconds';
            lastEventMono = performance.now();
            events.frames++; events.lastAt = new Date().toISOString();
          } else if (frame.startsWith('event: snapshot-error')) throw new Error('SSE snapshot failed');
        }
      }
      if (!linkedSignal.aborted) throw new Error('SSE disconnected');
    } catch (error) { if (!linkedSignal.aborted) events.error = error.message; }
  })() : Promise.resolve();
  async function request(path) {
    const start = performance.now();
    try {
      const response = await fetch(`${config.baseUrl}${path}`, {
        signal: AbortSignal.any([linkedSignal, AbortSignal.timeout(config.timeoutMs)]),
        ...(path === '/api/ask' ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: '当前服务状态？', useModel: false }) } : {}),
      });
      const data = await response.json();
      const error = response.ok ? validate(path, data) : `HTTP ${response.status}`;
      return { path, ok: !error, status: response.status, latencyMs: Math.round(performance.now() - start), error, data: compact(path, data) };
    } catch (error) { return { path, ok: false, latencyMs: Math.round(performance.now() - start), error: error.name }; }
  }
  let firstInstance = null;
  let maxGapMs = 0;
  let previousAt = startedMono;
  let maxClockDriftMs = 0;
  let runError = null;
  function report(state, reason = null) {
    const checks = samples.flatMap((sample) => sample.checks);
    const failed = checks.filter((check) => !check.ok);
    const latency = checks.filter((check) => check.path.startsWith('/') && check.path !== '/api/events').map((check) => check.latencyMs).filter(Number.isFinite).sort((a, b) => a - b);
    return { schemaVersion: 3, runId, pid: process.pid, state, completionReason: reason, sourceFingerprint,
      validation: { events: config.events, sourceCheck: config.sourceCheck, cloudReviewProbe: false }, instanceId: firstInstance,
      startedAt: new Date(started).toISOString(), updatedAt: new Date().toISOString(), plannedEndAt: new Date(started + config.durationMs).toISOString(), finishedAt: state === 'running' ? null : new Date().toISOString(),
      durationMs: Math.floor(elapsed()), wallDurationMs: Date.now() - started, targetDurationMs: config.durationMs, intervalMs: config.intervalMs, maxGapMs, maxClockDriftMs,
      sampleCount: samples.length, checks: checks.length, failures: failed.length,
      latencyMs: { p50: latency[Math.floor(latency.length * .5)] ?? null, p95: latency[Math.floor(latency.length * .95)] ?? null, max: latency.at(-1) ?? null },
      events: { ...events }, failureDetails: failed.slice(-20), samples,
      caveat: '仅观测本机 HTTP、SSE、同步与源码指纹；不调用任何 AI 模型，也不代表源码安全审查已完成。休眠或心跳中断不能算稳定通过。' };
  }
  await atomic(config.output, report('running'));
  try {
    while (!signal.aborted) {
      const sampleStart = performance.now();
      const clockDriftMs = Math.abs(Date.now() - started - elapsed());
      maxClockDriftMs = Math.max(maxClockDriftMs, clockDriftMs);
      maxGapMs = Math.max(maxGapMs, sampleStart - previousAt);
      const checks = await Promise.all(['/api/status', '/api/sync', '/api/health'].map((path) => request(path)));
      const status = checks.find((check) => check.path === '/api/status')?.data;
      const sync = checks.find((check) => check.path === '/api/sync')?.data;
      checks.push({ path: 'snapshot-consistency', ok: Boolean(status?.syncVersion && status.syncVersion === sync?.syncVersion), latencyMs: 0 });
      const health = checks.find((check) => check.path === '/api/health')?.data;
      if (firstInstance && health?.instanceId !== firstInstance) checks.push({ path: 'server-continuity', ok: false, error: 'server restarted or unavailable', latencyMs: 0 });
      if (health?.instanceId) firstInstance ||= health.instanceId;
      if (samples.length && sampleStart - previousAt > Math.max(config.intervalMs * 2.5, 90000)) checks.push({ path: 'sampling-continuity', ok: false, error: 'sampling gap / suspend', latencyMs: 0 });
      if (clockDriftMs > 2000) checks.push({ path: 'clock-continuity', ok: false, error: 'wall and monotonic clocks diverged', latencyMs: 0 });
      if (config.sourceCheck) {
        let current = null;
        try { current = await fingerprint(); } catch {}
        checks.push({ path: 'source-continuity', ok: current === sourceFingerprint && health?.sourceFingerprint === sourceFingerprint, error: current === sourceFingerprint && health?.sourceFingerprint === sourceFingerprint ? null : 'source changed or server is running an older build', latencyMs: 0 });
      }
      checks.push(await request('/api/ask'));
      if (config.events) checks.push({ path: '/api/events', ok: !events.error && Boolean(events.lastAt) && performance.now() - lastEventMono < 45000, latencyMs: 0, error: events.error, frames: events.frames });
      samples.push({ iteration: samples.length, at: new Date().toISOString(), checks });
      console.log(`${new Date().toISOString()} sample=${samples.length} failures=${checks.filter((check) => !check.ok).length}`);
      await atomic(config.output, report('running'));
      previousAt = sampleStart;
      if (!config.durationMs || elapsed() >= config.durationMs) break;
      const wait = Math.max(1, Math.min(config.intervalMs - (performance.now() - sampleStart), config.durationMs - elapsed()));
      await delay(wait, undefined, { signal }).catch((error) => { if (!signal.aborted) throw error; });
    }
  } catch (error) {
    runError = String(error.message);
    samples.push({ iteration: samples.length, at: new Date().toISOString(), checks: [{ path: 'runner', ok: false, error: runError, latencyMs: 0 }] });
  } finally { controller.abort(); await eventTask; }
  if (events.error && !samples.some((sample) => sample.checks.some((check) => check.path === '/api/events' && !check.ok))) {
    samples.push({ iteration: samples.length, at: new Date().toISOString(), checks: [{ path: '/api/events', ok: false, error: events.error, latencyMs: 0 }] });
  }
  const provisional = report('running');
  const completed = !signal.aborted && provisional.durationMs >= config.durationMs;
  const final = report(runError ? 'failed' : !completed ? 'interrupted' : provisional.failures ? 'failed' : 'completed', runError || (!completed ? 'signal / incomplete duration' : 'requested observation window ended'));
  await atomic(config.output, final);
  console.log(JSON.stringify({ output: config.output, state: final.state, sampleCount: final.sampleCount, failures: final.failures }));
  return final;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  const config = options();
  // All outputs share one project lock; preserve every previous report verbatim.
  const lockPath = join(ROOT, 'work/soak.lock');
  await mkdir(dirname(lockPath), { recursive: true });
  let lock;
  try { lock = await open(lockPath, 'wx', 0o600); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    throw new Error('已有 soak 锁。先核对 work/soak.lock 的 PID；确认进程退出后才能归档该锁并重启。');
  }
  try {
    await lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString(), output: config.output }));
    try { await copyFile(config.output, `${config.output}.${Date.now()}.previous.json`, 1); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const report = await runSoak(config, controller.signal);
    process.exitCode = report.state === 'completed' ? 0 : 1;
  } finally { await lock.close(); await unlink(lockPath); }
}
