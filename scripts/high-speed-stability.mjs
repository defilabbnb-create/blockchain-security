#!/usr/bin/env node
import { mkdir, rename, unlink, writeFile, open, copyFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';

import { runtimeFingerprint } from '../src/runtime-fingerprint.js';
import { boundedSingleFlight } from '../src/bounded-work.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
export const MAX_STABILITY_DURATION_MS = 72 * 60 * 60 * 1000;

export function options(args = process.argv.slice(2)) {
  const config = {
    durationMs: 180000,
    concurrency: 8,
    intervalMs: 250,
    requestTimeoutMs: 2500,
    readinessTimeoutMs: 30000,
    baseUrl: process.env.SOAK_BASE_URL || 'http://127.0.0.1:8788',
    output: resolve(ROOT, 'work/high-speed-stability.json'),
  };
  const keys = {
    '--duration-ms': 'durationMs', '--concurrency': 'concurrency', '--interval-ms': 'intervalMs',
    '--request-timeout-ms': 'requestTimeoutMs',
    '--readiness-timeout-ms': 'readinessTimeoutMs',
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--output') config.output = resolve(args[++index]);
    else if (arg === '--base-url') config.baseUrl = args[++index];
    else if (keys[arg]) {
      const value = Number(args[++index]);
      if (!Number.isInteger(value) || value < 1) throw new Error(`无效参数 ${arg}`);
      config[keys[arg]] = value;
    } else throw new Error(`未知参数 ${arg}`);
  }
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(new URL(config.baseUrl).hostname)) throw new Error('仅允许本机 URL');
  if (config.concurrency > 16 || config.intervalMs < 100 || config.durationMs > MAX_STABILITY_DURATION_MS || config.readinessTimeoutMs > 120000) throw new Error('并发需 ≤16、间隔需 ≥100ms、时长需 ≤72h、预检超时需 ≤120s');
  return config;
}

async function atomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  } finally { await unlink(temp).catch(() => {}); }
}

export function histogram() {
  const bins = new Uint32Array(60002); let count = 0, max = 0;
  return { add(value) { const ms = Math.max(0, Math.ceil(value)); bins[Math.min(ms, 60001)]++; count++; max = Math.max(max, ms); }, summary() {
    const percentile = (p) => { if (!count) return null; let total = 0; const target = Math.ceil(count * p); for (let i = 0; i < bins.length; i++) { total += bins[i]; if (total >= target) return i; } };
    return { count, p50: percentile(.5), p95: percentile(.95), p99: percentile(.99), max: count ? max : null, resolutionMs: 1 };
  } };
}

function validate(path, data) {
  if (!data || typeof data !== 'object') return 'invalid JSON';
  if (path === '/api/health') return data.status !== 'ok' || !data.instanceId || !Number.isFinite(data.memory?.rss) ? `health ${data.status || 'invalid'}` : null;
  if (path === '/api/status') return !data.syncVersion || !Array.isArray(data.chains) || !Number.isFinite(Date.parse(data.generatedAt)) ? 'invalid status' : null;
  if (path === '/api/sync') return !data.syncVersion || !data.consumers?.includes('dsh') || !data.consumers?.includes('dhlsh') ? 'invalid sync' : null;
  if (path === '/api/ask') return !data.answer ? 'empty answer' : null;
  return null;
}

const READINESS_PATHS = ['/api/status', '/api/sync', '/api/health'];
const MAX_SNAPSHOT_AGE_MS = 60000;

function freshTimestamp(value, now) {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && Math.abs(now - timestamp) <= MAX_SNAPSHOT_AGE_MS;
}

export async function readinessPreflight(config, dependencies = {}) {
  const fetchImpl = dependencies.fetchImpl || fetch;
  const fingerprintFn = dependencies.fingerprint || runtimeFingerprint;
  const nowFn = dependencies.now || Date.now;
  const sleep = dependencies.sleep || ((ms) => delay(ms));
  const timeoutMs = config.readinessTimeoutMs ?? 30000;
  const retryMs = config.readinessRetryMs ?? 250;
  const requestTimeoutMs = config.requestTimeoutMs ?? 2500;
  const deadline = performance.now() + timeoutMs;
  let expectedSourceFingerprint;
  try { expectedSourceFingerprint = await fingerprintFn(); }
  catch (error) { throw new Error(`readiness preflight could not fingerprint local source: ${error.message || error}`); }
  if (performance.now() > deadline) throw new Error(`readiness preflight exceeded ${timeoutMs}ms while fingerprinting local source`);

  let attempts = 0;
  let lastError = 'no readiness probe completed';
  let previous = null;
  let stableSamples = 0;
  while (performance.now() < deadline) {
    attempts++;
    try {
      const data = {};
      // /api/health reports the server's latest snapshot but does not force a
      // refresh. Read status and sync first so health observes that same build.
      for (const path of READINESS_PATHS) {
        const remainingMs = Math.ceil(deadline - performance.now());
        if (remainingMs <= 0) throw new Error(`readiness deadline reached during ${path}`);
        const signal = AbortSignal.timeout(Math.max(1, Math.min(requestTimeoutMs, remainingMs)));
        const response = await fetchImpl(`${config.baseUrl}${path}`, { signal, headers: { accept: 'application/json' } });
        if (!response.ok) throw new Error(`${path} HTTP ${response.status}`);
        data[path] = await response.json();
      }
      const now = nowFn();
      const status = data['/api/status'];
      const sync = data['/api/sync'];
      const health = data['/api/health'];
      const currentSourceFingerprint = await fingerprintFn();
      if (currentSourceFingerprint !== expectedSourceFingerprint) throw new Error('local source changed during readiness preflight');
      const statusError = validate('/api/status', status);
      if (statusError) throw new Error(`/api/status ${statusError}`);
      if (!freshTimestamp(status.generatedAt, now)) throw new Error('/api/status snapshot is stale or has an invalid generatedAt');
      const syncError = validate('/api/sync', sync);
      if (syncError) throw new Error(`/api/sync ${syncError}`);
      if (sync.syncVersion !== status.syncVersion) throw new Error('/api/status and /api/sync syncVersion mismatch');
      const healthError = validate('/api/health', health);
      if (healthError) throw new Error(`/api/health ${healthError}`);
      if (health.snapshots?.stale !== false || !freshTimestamp(health.snapshots?.lastBuiltAt, now)) throw new Error('/api/health snapshot is stale or has no fresh build timestamp');
      if (health.snapshots?.lastError !== null) throw new Error('/api/health reports a snapshot error');
      if (!freshTimestamp(health.now, now)) throw new Error('/api/health response timestamp is stale');
      if (!health.sourceFingerprint || health.sourceFingerprint !== expectedSourceFingerprint) throw new Error('/api/health source fingerprint does not match local source');
      if (health.dsh?.syncVersion !== status.syncVersion) throw new Error('/api/health and status snapshot versions mismatch or health version is missing');
      if (sync.updatedAt && !freshTimestamp(sync.updatedAt, now)) throw new Error('/api/sync payload is stale');

      const candidate = {
        instanceId: health.instanceId,
        sourceFingerprint: health.sourceFingerprint,
        syncVersion: status.syncVersion,
      };
      if (previous && previous.instanceId === candidate.instanceId
        && previous.sourceFingerprint === candidate.sourceFingerprint) stableSamples++;
      else stableSamples = 1;
      previous = candidate;
      if (stableSamples >= 2) {
        return {
          passed: true,
          attempts,
          readyAt: new Date(nowFn()).toISOString(),
          instanceId: candidate.instanceId,
          sourceFingerprint: candidate.sourceFingerprint,
          expectedSourceFingerprint,
          syncVersion: candidate.syncVersion,
          statusGeneratedAt: status.generatedAt,
          healthObservedAt: health.now || null,
        };
      }
      lastError = 'waiting for a second matching readiness sample';
    } catch (error) {
      previous = null;
      stableSamples = 0;
      const message = String(error?.message || error);
      if (!message.startsWith('readiness deadline reached')) lastError = message;
    }
    const waitMs = Math.min(retryMs, Math.max(0, deadline - performance.now()));
    if (waitMs > 0) await sleep(waitMs);
  }
  throw new Error(`readiness preflight failed after ${attempts} attempt(s) within ${timeoutMs}ms: ${lastError}`);
}

export async function runHighSpeed(config, suppliedReadiness = null) {
  const readiness = suppliedReadiness || await readinessPreflight(config);
  if (readiness.passed !== true || !readiness.instanceId || !readiness.expectedSourceFingerprint) throw new Error('readiness preflight result is invalid; measured run not started');
  if (await runtimeFingerprint() !== readiness.expectedSourceFingerprint) throw new Error('local source changed after readiness preflight; measured run not started');
  const startedAtMs = Date.now();
  const startedMono = performance.now();
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  const linkedSignal = AbortSignal.any([controller.signal]);
  let requestCount = 0, failureCount = 0, healthCount = 0, sampleCount = 0;
  const runId = randomUUID();
  const fingerprint = boundedSingleFlight(runtimeFingerprint);
  const expectedSource = readiness.expectedSourceFingerprint;
  let firstRss = null, peakRss = 0, lastRss = null, firstHeapUsed = null, peakHeapUsed = 0, lastHeapUsed = null;
  let lastHealth = null, writeError = null, maxClockDriftMs = 0, maxSamplingGapMs = 0;
  let stopping = false, writes = Promise.resolve();
  const journal = `${config.output}.samples.jsonl`;
  await mkdir(dirname(config.output), {recursive:true});
  const journalHandle = await open(journal, 'ax', 0o600);
  const log = (value) => { writes = writes.then(() => journalHandle.write(JSON.stringify(value) + '\n')).catch((error) => { writeError ||= error.message; controller.abort(); }); return writes; };
  const fail = (record) => { failureCount++; if (failures.length < 100) failures.push(record); void log({type:'failure', at:new Date().toISOString(), ...record}); };
  await log({type:'start', runId, pid:process.pid, startedAt:new Date(startedAtMs).toISOString(), config, expectedSource, readiness});
  const failures = [];
  const endpointCounts = new Map();
  const statusCounts = new Map();
  const latencies = histogram();
  let consistencyFailures = 0;
  let baseline = { instanceId: readiness.instanceId, sourceFingerprint: readiness.sourceFingerprint };
  const sse = { frames: 0, error: null, maxGapMs: 0, lastAt: null };
  let lastFrameMono = performance.now();

  const request = async (path, { method = 'GET', body = null } = {}) => {
    const started = performance.now();
    const record = { path };
    requestCount++; endpointCounts.set(path, (endpointCounts.get(path) || 0) + 1);
    try {
      const response = await fetch(`${config.baseUrl}${path}`, {
        method,
        headers: body ? { 'content-type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.any([linkedSignal, AbortSignal.timeout(config.requestTimeoutMs)]),
      });
      const data = await response.json();
      record.status = response.status;
      record.latencyMs = Math.round(performance.now() - started);
      statusCounts.set(String(response.status), (statusCounts.get(String(response.status)) || 0) + 1);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const error = validate(path, data);
      if (error) throw new Error(error);
      if (path === '/api/health') {
        healthCount++;
        lastHealth = {at:new Date().toISOString(), memory:data.memory, requests:data.requests, snapshots:data.snapshots, instanceId:data.instanceId};
        firstRss ??= data.memory.rss; lastRss = data.memory.rss; peakRss = Math.max(peakRss, lastRss);
        firstHeapUsed ??= data.memory.heapUsed; lastHeapUsed = data.memory.heapUsed; peakHeapUsed = Math.max(peakHeapUsed, lastHeapUsed);
        if (!baseline) baseline = { instanceId: data.instanceId, sourceFingerprint: data.sourceFingerprint };
        if (baseline.instanceId !== data.instanceId) throw new Error('server instance changed');
        if (baseline.sourceFingerprint !== data.sourceFingerprint || data.sourceFingerprint !== expectedSource) throw new Error('source fingerprint changed');
      }
      if (path === '/api/status' || path === '/api/sync') record.syncVersion = data.syncVersion || null;
      return record;
    } catch (error) {
      record.latencyMs = Math.round(performance.now() - started);
      record.error = String(error.message || error);
      fail(record);
      return record;
    } finally { latencies.add(performance.now() - started); }
  };

  const sseTask = (async () => {
    try {
      const response = await fetch(`${config.baseUrl}/api/events`, { signal: linkedSignal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      let buffer = '';
      const decoder = new TextDecoder();
      for await (const chunk of response.body) {
        buffer += decoder.decode(chunk, { stream: true });
        if (buffer.length > 2 * 1024 * 1024) throw new Error('oversized SSE frame');
        let boundary;
        while ((boundary = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          if (frame.startsWith('event: snapshot-error')) throw new Error('SSE snapshot failed');
          if (!frame.startsWith('event: snapshot\n')) continue;
          const gap = performance.now() - lastFrameMono;
          sse.maxGapMs = Math.max(sse.maxGapMs, gap);
          if (gap > 45000) sse.error ||= 'SSE gap exceeded 45 seconds';
          lastFrameMono = performance.now();
          sse.frames += 1;
          sse.lastAt = new Date().toISOString();
          const data = JSON.parse(frame.split('\ndata: ')[1]); if (validate('/api/status', data) || Math.abs(Date.now() - Date.parse(data.generatedAt)) > 60000) throw new Error('invalid or stale SSE snapshot');
        }
      }
      if (!controller.signal.aborted) throw new Error('SSE disconnected');
    } catch (error) { if (!controller.signal.aborted) sse.error = String(error.message || error); }
  })();

  const paths = ['/api/health', '/api/status', '/api/chains', '/api/findings', '/api/vulnerability-chains', '/api/tasks', '/api/sync'];
  const worker = async (workerId) => {
    while (!controller.signal.aborted && performance.now() - startedMono < config.durationMs) {
      const roundStarted = performance.now();
      const batch = paths.map((path) => request(path));
      batch.push(request('/api/ask', { method: 'POST', body: { question: '当前状态', useModel: false } }));
      const results = await Promise.all(batch);
      const status = results.find((item) => item.path === '/api/status');
      const sync = results.find((item) => item.path === '/api/sync');
      if (status?.syncVersion && sync?.syncVersion && status.syncVersion !== sync.syncVersion) {
        consistencyFailures += 1;
        fail({ path: 'snapshot-consistency', error: 'status/sync version mismatch', latencyMs: 0 });
      }
      const waitMs = config.intervalMs - (performance.now() - roundStarted);
      if (waitMs > 0) await delay(waitMs, undefined, { signal: controller.signal }).catch(() => {});
    }
  };

  function report(state = 'running') {
    const durationMs = Math.floor(performance.now() - startedMono);
    return {schemaVersion:2, kind:'high-speed-stability', runId, pid:process.pid, state, verdict:state === 'completed' ? 'passed' : state,
      startedAt:new Date(startedAtMs).toISOString(), updatedAt:new Date().toISOString(), plannedEndAt:new Date(startedAtMs+config.durationMs).toISOString(), finishedAt:state === 'running' ? null : new Date().toISOString(),
      durationMs, wallDurationMs:Date.now()-startedAtMs, configuredDurationMs:config.durationMs, targetDurationMs:config.durationMs,
      readiness:{passed:readiness.passed,attempts:readiness.attempts,readyAt:readiness.readyAt,instanceId:readiness.instanceId,syncVersion:readiness.syncVersion,statusGeneratedAt:readiness.statusGeneratedAt},
      concurrency:config.concurrency, maxHttpConcurrency:config.concurrency*8, intervalMs:config.intervalMs, requestTimeoutMs:config.requestTimeoutMs,
      baseline, expectedSourceFingerprint:expectedSource, requests:requestCount, requestsPerSecond:durationMs ? requestCount/durationMs*1000 : 0, failures:failureCount, sampleCount,
      endpointCounts:Object.fromEntries(endpointCounts), statusCounts:Object.fromEntries(statusCounts), latencyMs:latencies.summary(),
      memory:{firstRss,peakRss,lastRss,firstHeapUsed,peakHeapUsed,lastHeapUsed,runner:process.memoryUsage()}, healthSamples:healthCount, consistencyFailures, sse:{...sse}, maxClockDriftMs, maxSamplingGapMs,
      failureDetails:failures, journalPath:journal, validation:{readinessPreflight:true,cloudReviewProbe:false,events:true,sourceCheck:true},
      caveat:'本机 HTTP、SSE、同步与结构化状态接口压测；不调用云端 AI，也不把云端配置状态当作稳定性证据。'};
  }
  async function checkpoint() {
    sampleCount++;
    if (performance.now()-lastFrameMono > 45000 && !sse.error) sse.error = 'SSE silent beyond 45 seconds';
    const drift = Math.abs(Date.now()-startedAtMs-(performance.now()-startedMono)); maxClockDriftMs = Math.max(maxClockDriftMs, drift);
    if (drift > 2000) fail({path:'clock-continuity',error:'wall and monotonic clocks diverged'});
    try { if (await fingerprint() !== expectedSource) fail({path:'source-continuity',error:'source changed'}); } catch (e) { fail({path:'source-continuity',error:e.message}); }
    const value = report(); await log({type:'checkpoint', ...value, health:lastHealth}); await atomic(config.output,value);
    console.log(JSON.stringify({at:value.updatedAt,elapsedMs:value.durationMs,requests:requestCount,failures:failureCount,sseFrames:sse.frames}));
  }
  await atomic(config.output, report());
  const progress = (async () => { let previous = performance.now(); while (!stopping && !controller.signal.aborted) {
    await delay(10000,undefined,{signal:controller.signal}).catch(()=>{}); if (stopping || controller.signal.aborted) break;
    const gap=performance.now()-previous; maxSamplingGapMs=Math.max(maxSamplingGapMs,gap); previous=performance.now();
    if(gap>30000) fail({path:'sampling-continuity',error:'checkpoint gap exceeds 30 seconds'});
    await checkpoint();
  } })().catch(error=>{writeError ||= error.message;controller.abort();});
  await Promise.all(Array.from({ length: config.concurrency }, (_, index) => worker(index)));
  stopping = true;
  const interrupted = controller.signal.aborted || performance.now()-startedMono < config.durationMs;
  controller.abort(); await progress; await sseTask;
  await checkpoint();
  if (sse.error || sse.frames < 2) fail({path:'/api/events',error:sse.error || 'fewer than two SSE frames'});
  if (writeError) fail({path:'journal',error:writeError});
  const result = report(interrupted ? 'interrupted' : failureCount ? 'failed' : 'completed');
  await log({type:'final',...result}); await writes; await journalHandle.sync(); await journalHandle.close();
  await atomic(config.output,result);
  process.removeListener('SIGINT', stop);
  process.removeListener('SIGTERM', stop);
  console.log(JSON.stringify({state:result.state,requests:result.requests,failures:result.failures,output:config.output}));
  return result;
}

export async function startHighSpeedRun(config, dependencies = {}) {
  const readiness = await readinessPreflight(config, dependencies);
  for (const path of [config.output, `${config.output}.samples.jsonl`]) {
    try { await copyFile(path, `${path}.${Date.now()}.previous`, 1); if (path.endsWith('.jsonl')) await unlink(path); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return runHighSpeed(config, readiness);
}

async function main() {
  const config=options(), lockPath=resolve(ROOT,'work/high-speed.lock');
  await mkdir(dirname(lockPath),{recursive:true});
  const lock=await open(lockPath,'wx',0o600).catch(e=>{throw new Error(e.code==='EEXIST' ? '已有高速测试锁，核对 PID 后处理，不重复启动' : e.message);});
  try {
    await lock.writeFile(JSON.stringify({pid:process.pid,startedAt:new Date().toISOString(),output:config.output}));
    const result=await startHighSpeedRun(config);process.exitCode=result.state==='completed'?0:1;
  } finally {await lock.close();await unlink(lockPath);}
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error=>{console.error(error);process.exitCode=1;});
