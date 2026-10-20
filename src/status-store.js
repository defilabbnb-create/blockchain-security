import { readFile, stat, mkdir, writeFile, rename, unlink, readdir, realpath } from 'node:fs/promises';
import { join, resolve, relative, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHash } from 'node:crypto';
import { buildVulnerabilityChains } from './vulnerability-chain.js';
import { readCampaignState, campaignAnswer, campaignProgress } from './campaign-status.js';

const PROJECT_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const REPORT_DIR = join(PROJECT_ROOT, 'flare-scan', 'reports');
const WORK_DIR = join(PROJECT_ROOT, 'work');
const SYNC_FILE = join(WORK_DIR, 'dsh-sync.json');
const STATUS_FILE = join(WORK_DIR, 'dsh-status.json');
const SNAPSHOT_CACHE_MS = Number(process.env.DSH_SNAPSHOT_CACHE_MS || 1200);


const severityOrder = ['High', 'Medium', 'Low', 'Informational'];
const campaignEvidenceNames = ['cloud-review-evidence.json', 'runtime-bytecode-analysis.json', 'dependency-trace.json'];

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function isSha256(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
}

function findingSeverity(value, kind) {
  const normalized = String(value || '').toLowerCase();
  if (['high', 'medium', 'low', 'info'].includes(normalized)) return normalized;
  if (normalized === 'informational') return 'info';
  return kind === 'risk_hypothesis' ? 'medium' : 'info';
}

function safeEvidenceFile(value) {
  if (typeof value !== 'string' || !value.trim() || value.includes('\\') || value.startsWith('/')) return null;
  const parts = value.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..')) return null;
  return parts.join('/');
}

function confidenceValue(value) {
  const normalized = String(value || '').toLowerCase();
  if (['high', 'medium', 'low'].includes(normalized)) return normalized;
  if (normalized === '高') return 'high';
  if (normalized === '中') return 'medium';
  if (normalized === '低') return 'low';
  return 'low';
}

function makeCampaignFinding({ sourceSha256, kind, title, severity = 'info', confidence = 'low', status = 'unconfirmed_observation', protocol, chain, address, evidence, conditions = [], localTestPlan = null, runId, observedAt }) {
  const first = evidence[0];
  const id = sha256(`${sourceSha256}${kind}${first?.lineStart ?? 0}${first?.lineEnd ?? 0}`);
  return { id, kind, title, severity, confidence: confidenceValue(confidence), status, protocol, chain, address,
    evidence, conditions, localTestPlan, sourceSha256, runId, observedAt, origin: 'campaign' };
}

function safeObservedAt(...values) {
  for (const value of values) {
    const parsed = isoOrNull(value);
    if (parsed) return parsed;
  }
  return new Date(0).toISOString();
}

async function readContractContext(contractDir) {
  const [record, review, cloudReview] = await Promise.all([
    readJson(join(contractDir, 'evidence.json')),
    readJson(join(contractDir, 'review.json')),
    readJson(join(contractDir, 'cloud-review-evidence.json')),
  ]);
  const embeddedReview = record?.review;
  return {
    record: record && typeof record === 'object' ? record : {},
    review: review && typeof review === 'object' ? review : embeddedReview && typeof embeddedReview === 'object' ? embeddedReview : {},
    cloudReview: cloudReview && typeof cloudReview === 'object' ? cloudReview : {},
  };
}

async function scanCampaignEvidence(workDir = WORK_DIR, generatedAt = new Date().toISOString()) {
  let campaignRoot;
  try { campaignRoot = await realpath(resolve(workDir, 'defi-campaign')); } catch { return []; }
  let runEntries;
  try { runEntries = await readdir(campaignRoot, { withFileTypes: true }); } catch { return []; }
  const findings = [];
  for (const runEntry of runEntries) {
    if (!runEntry.isDirectory() || runEntry.name === '.' || runEntry.name === '..') continue;
    const runDir = join(campaignRoot, runEntry.name);
    let canonicalRun;
    try { canonicalRun = await realpath(runDir); } catch { continue; }
    const runRelative = relative(campaignRoot, canonicalRun);
    if (!runRelative || runRelative.startsWith(`..${sep}`) || runRelative === '..') continue;
    const contractsDir = join(canonicalRun, 'contracts');
    let contractEntries;
    try { contractEntries = await readdir(contractsDir, { withFileTypes: true }); } catch { continue; }
    for (const contractEntry of contractEntries) {
      if (!contractEntry.isDirectory()) continue;
      const contractDir = join(contractsDir, contractEntry.name);
      let canonicalContract;
      try { canonicalContract = await realpath(contractDir); } catch { continue; }
      const contractRelative = relative(contractsDir, canonicalContract);
      if (!contractRelative || contractRelative.startsWith(`..${sep}`) || contractRelative === '..') continue;
      const { record, review, cloudReview } = await readContractContext(canonicalContract);
      const protocol = String(record.protocol || '未知协议');
      const chain = String(record.chain || record.chainId || '未知链');
      const address = String(record.address || '');
      const sourceSha256 = isSha256(record.source?.sha256) ? record.source.sha256 : null;
      const reportValues = await Promise.all(campaignEvidenceNames.map(async (name) => ({ name, value: await readJson(join(canonicalContract, name)) })));
      const reconciliation = await readJson(join(canonicalContract, 'ir-reconciliation.json'));
      const dynamicResult = await readJson(join(canonicalContract, 'dynamic-result.json'));
      const pocResult = await readJson(join(canonicalContract, 'poc-result.json'));
      if (Array.isArray(review.observations)) {
        const manifestFiles = new Map((review.excerptManifest || []).filter((item) => item && typeof item.file === 'string' && isSha256(item.sourceSha256)).map((item) => [item.file, item.sourceSha256]));
        for (const observation of review.observations) {
          if (!observation || typeof observation !== 'object') continue;
          const evidence = (Array.isArray(observation.evidence) ? observation.evidence : []).flatMap((item) => {
            const file = safeEvidenceFile(item?.file);
            const lineStart = Number(item?.lineStart);
            const lineEnd = Number(item?.lineEnd);
            if (!file || !Number.isSafeInteger(lineStart) || lineStart < 1 || !Number.isSafeInteger(lineEnd) || lineEnd < lineStart || typeof item.quote !== 'string') return [];
            return [{ file, lineStart, lineEnd, quote: item.quote.slice(0, 1200), sourceSha256: manifestFiles.get(item.file) || null }];
          });
          if (!evidence.length) continue;
          const sourceHash = sourceSha256 || evidence.find((item) => isSha256(item.sourceSha256))?.sourceSha256;
          if (!sourceHash) continue;
          const confidence = confidenceValue(observation.confidence);
          const kind = String(observation.kind || 'campaign_review_observation').slice(0, 100);
          findings.push(makeCampaignFinding({ sourceSha256: sourceHash, kind,
            title: String(observation.title || '采集审查观察').slice(0, 300), severity: findingSeverity(observation.severity, kind),
            confidence, status: 'unconfirmed_observation', protocol, chain, address, evidence,
            conditions: [observation.conditions, observation.missingEvidence].filter((item) => typeof item === 'string' && item.trim()).map((item) => item.slice(0, 1000)),
            localTestPlan: typeof observation.localTestPlan === 'string' ? observation.localTestPlan.slice(0, 1500) : null,
            runId: runEntry.name, observedAt: safeObservedAt(record.finishedAt, cloudReview.retrievedAt, generatedAt) }));
        }
      }
      for (const { name, value } of reportValues) {
        if (!value || typeof value !== 'object' || name === 'cloud-review-evidence.json') continue;
        const bytecodeHash = isSha256(value.bytecodeSha256) ? value.bytecodeSha256 : null;
        const deploymentBlockHash = typeof value.blockHash === 'string' && /^0x[a-f0-9]{64}$/i.test(value.blockHash) ? value.blockHash : null;
        const inputHash = sourceSha256 || bytecodeHash || (isSha256(value.manifestSha256) ? value.manifestSha256 : null);
        if (!inputHash) continue;
        const quote = name === 'runtime-bytecode-analysis.json'
          ? `bytecodeSha256=${bytecodeHash || '未记录'}; blockHash=${deploymentBlockHash || '未记录'}; instructionCount=${Number.isSafeInteger(value.instructionCount) ? value.instructionCount : '未记录'}`
          : `依赖追踪状态=${String(value.state || '未记录')}; blockHash=${deploymentBlockHash || '未记录'}`;
        findings.push(makeCampaignFinding({ sourceSha256: inputHash, kind: name === 'runtime-bytecode-analysis.json' ? 'runtime_bytecode_analysis' : 'dependency_trace',
          title: name === 'runtime-bytecode-analysis.json' ? '运行时字节码分析记录' : '依赖关系追踪记录', severity: 'info', confidence: 'low',
          status: 'unconfirmed_observation', protocol, chain: String(record.chain || value.chainId || record.chainId || '未知链'),
          address: String(record.address || value.address || ''), evidence: [{ file: name, lineStart: 0, lineEnd: 0, quote,
            ...(bytecodeHash ? { bytecodeSha256: bytecodeHash } : {}), ...(deploymentBlockHash ? { blockHash: deploymentBlockHash } : {}) }],
          conditions: ['该记录本身不证明可达性、语义或漏洞。'], localTestPlan: null, runId: runEntry.name,
          observedAt: safeObservedAt(value.generatedAt, record.finishedAt, generatedAt) }));
      }
      if (reconciliation && Array.isArray(reconciliation.bytecodeOnlyFunctions) && reconciliation.bytecodeOnlyFunctions.length && sourceSha256) {
        const functions = reconciliation.bytecodeOnlyFunctions.slice(0, 40);
        const evidence = functions.map((item) => ({ file: 'ir-reconciliation.json', lineStart: 0, lineEnd: 0,
          quote: `selector=${String(item.selector || '未知')}; riskHints=${Array.isArray(item.riskHints) ? item.riskHints.join(',') : '无'}` }));
        findings.push(makeCampaignFinding({ sourceSha256, kind: 'source_bytecode_divergence',
          title: '源码与运行时字节码存在未对齐函数候选', severity: functions.some((item) => Array.isArray(item.riskHints) && item.riskHints.length) ? 'medium' : 'info',
          confidence: 'low', status: 'static_signal', protocol, chain, address, evidence,
          conditions: ['selector 与 opcode 仅为静态候选；需核验代理实现、编译设置及运行时可达性。'],
          localTestPlan: null, runId: runEntry.name,
          observedAt: safeObservedAt(record.finishedAt, reconciliation.generatedAt, generatedAt) }));
      }
      if (dynamicResult?.state === 'violated' && typeof dynamicResult.invariantId === 'string' && sourceSha256) {
        const evidenceHash = isSha256(dynamicResult.evidenceSha256) ? dynamicResult.evidenceSha256 : null;
        findings.push(makeCampaignFinding({ sourceSha256, kind: 'invariant_violated',
          title: '本地执行观察到不变量被打破', severity: 'medium', confidence: 'medium',
          status: 'invariant_violated', protocol, chain, address,
          evidence: [{ file: 'dynamic-result.json', lineStart: 0, lineEnd: 0,
            quote: `invariantId=${dynamicResult.invariantId}; mode=${String(dynamicResult.mode || 'unknown')}; state=violated`,
            ...(evidenceHash ? { evidenceSha256: evidenceHash } : {}) }],
          conditions: ['不变量被打破不等于漏洞已确认；需复核 harness、执行模式和复现前置条件。'],
          localTestPlan: null, runId: runEntry.name,
          observedAt: safeObservedAt(record.finishedAt, dynamicResult.observedAt, generatedAt) }));
      }
      if (pocResult && typeof pocResult.findingId === 'string'
          && isSha256(pocResult.sourceSha256) && pocResult.sourceSha256 === sourceSha256
          && isSha256(pocResult.pocEvidenceSha256) && isSha256(pocResult.evidenceSha256)) {
        const finding = findings.find((item) => item.id === pocResult.findingId);
        if (finding) {
          finding.pocState = ['confirmed', 'unconfirmed', 'error'].includes(pocResult.pocState) ? pocResult.pocState : 'unconfirmed';
          finding.pocArtifactPath = typeof pocResult.pocArtifactPath === 'string' ? pocResult.pocArtifactPath : null;
          finding.minCapitalRequiredWei = typeof pocResult.minCapitalRequiredWei === 'string' && /^\d+$/.test(pocResult.minCapitalRequiredWei)
            ? pocResult.minCapitalRequiredWei : null;
          finding.severityFactors = pocResult.severityFactors && typeof pocResult.severityFactors === 'object' ? pocResult.severityFactors : null;
          finding.severityScore = Number.isFinite(pocResult.severityScore) && pocResult.severityScore >= 0 ? pocResult.severityScore : null;
          finding.pocEvidenceSha256 = pocResult.pocEvidenceSha256;
          if (pocResult.pocState === 'confirmed' && pocResult.confirmedVulnerability === true) {
            finding.status = 'poc_confirmed';
            finding.confirmedVulnerability = true;
          }
        }
      }
    }
  }
  const unique = new Map();
  for (const finding of findings) if (!unique.has(finding.id)) unique.set(finding.id, finding);
  return [...unique.values()];
}

export async function writeFindingIndex(workDir = WORK_DIR, generatedAt = new Date().toISOString()) {
  const findings = await scanCampaignEvidence(workDir, generatedAt);
  const index = { schemaVersion: 1, generatedAt, findings };
  await writeAtomic(join(workDir, 'finding-index.json'), index);
  return index;
}

function countValueOrNotRecorded(counts, key) {
  if (!Object.hasOwn(counts, key) || counts[key] === null || counts[key] === '') return '未记录';
  const count = Number(counts[key]);
  return Number.isInteger(count) && count >= 0 ? count : '未记录';
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

async function fileMeta(path) {
  try {
    const info = await stat(path);
    return { path: relative(PROJECT_ROOT, path), mtime: info.mtime.toISOString(), size: info.size };
  } catch {
    return null;
  }
}

function isoOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function numberOrZero(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function formatUsd(value) {
  const amount = numberOrZero(value);
  if (amount >= 1e9) return `$${(amount / 1e9).toFixed(2)}B`;
  if (amount >= 1e6) return `$${(amount / 1e6).toFixed(1)}M`;
  if (amount >= 1e3) return `$${(amount / 1e3).toFixed(0)}K`;
  return `$${amount.toFixed(0)}`;
}

function dedupeRoutes(routes = []) {
  const seen = new Set();
  return routes.filter((route) => {
    if (!route || typeof route !== 'object') return false;
    const key = JSON.stringify([
      route.toChainId,
      route.routeVerification,
      route.tool,
      route.quotedFromAmount,
      route.quotedToAmount,
    ]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeChain(chain, ready, selected) {
  const routes = dedupeRoutes(chain.crossChain);
  const quoteRoutes = routes.filter((route) => route.routeVerification === 'quote_verified');
  const connectionRoutes = routes.filter((route) => route.routeVerification === 'connection_only');
  const isReady = ready.has(chain.name) || chain.selection?.readyForDeepDive === true;
  const isSelected = selected.has(chain.name) || chain.selection?.candidateForDeepDive === true;
  const status = isReady ? 'ready' : isSelected ? 'candidate' : chain.selection?.prefilterSkipped ? 'prefiltered' : 'queued';
  return {
    name: chain.name,
    chainId: chain.chainId,
    llamaName: chain.llamaName,
    status,
    currentTvlUsd: numberOrZero(chain.currentTvlUsd),
    currentTvlLabel: formatUsd(chain.currentTvlUsd),
    peakTvlUsd: numberOrZero(chain.historicalHeat?.peakTvlUsd),
    peakTvlLabel: formatUsd(chain.historicalHeat?.peakTvlUsd),
    peakAt: isoOrNull(chain.historicalHeat?.peakAt),
    historicalPoints: numberOrZero(chain.historicalHeat?.points),
    currentToPeakRatio: numberOrZero(chain.score?.currentToPeakRatio),
    priorityScore: numberOrZero(chain.score?.priorityScore),
    historicalHeatScore: numberOrZero(chain.score?.historicalHeatScore),
    currentValueScore: numberOrZero(chain.score?.currentValueScore),
    crossChainScore: numberOrZero(chain.score?.crossChainScore),
    transferability: chain.transferability || 'unavailable',
    rpc: {
      ok: chain.rpc?.ok === true,
      blockNumber: chain.rpc?.blockNumber ?? null,
      observedChainId: chain.rpc?.observedChainId ?? null,
      url: chain.rpc?.url || null,
      error: chain.rpc?.error || null,
    },
    routes,
    quoteRoutes,
    connectionRoutes,
    connectionCount: routes.reduce((total, route) => total + numberOrZero(route.connectionCount), 0),
    selectedForDeepDive: isSelected,
    readyForDeepDive: isReady,
    prefilterSkipped: chain.selection?.prefilterSkipped === true,
    errors: Array.isArray(chain.errors) ? chain.errors : [],
    caveats: Array.isArray(chain.caveats) ? chain.caveats : [],
  };
}

function extractFindings(reports) {
  const findings = [];
  for (const report of reports) {
    const detectors = report?.results?.detectors;
    if (!Array.isArray(detectors)) continue;
    for (const detector of detectors) {
      const element = Array.isArray(detector.elements) ? detector.elements[0] : null;
      findings.push({
        id: detector.id,
        check: detector.check || 'unknown',
        impact: detector.impact || 'Informational',
        confidence: detector.confidence || 'Unknown',
        target: report.target?.name || 'unknown',
        contract: element?.type_specific_fields?.parent?.name || element?.name || 'unknown',
        source: detector.first_markdown_element || null,
        markdown: String(detector.markdown || '').trim(),
        origin: 'static-report',
      });
    }
  }
  return findings.sort((a, b) => {
    const severity = severityOrder.indexOf(a.impact) - severityOrder.indexOf(b.impact);
    return severity || (a.confidence === 'High' ? -1 : 1);
  });
}

function readCloudModelProfile() {
  const baseUrl = process.env.DEFI_CLOUD_AI_BASE_URL?.trim() || '';
  const apiKey = process.env.DEFI_CLOUD_AI_API_KEY?.trim() || '';
  const model = process.env.DEFI_CLOUD_AI_MODEL?.trim() || '';
  let parsedUrl = null;
  try { parsedUrl = new URL(baseUrl); } catch {}
  const validUrl = parsedUrl?.protocol === 'https:' && !parsedUrl.username && !parsedUrl.password && !parsedUrl.search && !parsedUrl.hash;
  return {
    provider: 'external_cloud_ai',
    configured: Boolean(validUrl && apiKey && model),
    baseUrlHost: validUrl ? parsedUrl.hostname : null,
    model: model || null,
    participatesInSecurityAnalysis: true,
    role: 'cloud-review',
  };
}

async function buildSnapshotFresh() {
  const { campaign, rpcPool } = await readCampaignState(PROJECT_ROOT);
  const [screen, flare, summary, config, model, testReport, soakReport, findingIndex] = await Promise.all([
    readJson(join(REPORT_DIR, 'chain-screen.json')),
    readJson(join(REPORT_DIR, 'flare-screen.json')),
    readJson(join(REPORT_DIR, 'summary.json')),
    readJson(join(PROJECT_ROOT, 'flare-scan', 'chains.json')),
    Promise.resolve(readCloudModelProfile()),
    readJson(join(WORK_DIR, 'security-test-report.json')),
    readJson(join(WORK_DIR, 'soak-3h.json')),
    writeFindingIndex(WORK_DIR).then(() => readJson(join(WORK_DIR, 'finding-index.json'))),
  ]);
  for (const report of [screen, flare]) {
    for (const chain of report?.chains || []) {
      chain.crossChain = (chain.crossChain || []).map((route) => ({ ...route, observedAt: report.generatedAt, evidenceScope: 'historical_quote_or_connection' }));
    }
  }
  const screenChains = Array.isArray(screen?.chains) ? screen.chains : [];
  const fallbackChains = Array.isArray(flare?.chains) ? flare.chains : [];
  const chainsByName = new Map(screenChains.map((chain) => [chain.name, chain]));
  for (const chain of fallbackChains) {
    const existing = chainsByName.get(chain.name);
    if (!existing) {
      chainsByName.set(chain.name, chain);
      continue;
    }
    // The broad run probes compatibility; a focused run may carry a real quote.
    // Keep both evidence sets so the UI never downgrades an already verified route.
    const existingRoutes = Array.isArray(existing.crossChain) ? existing.crossChain : [];
    const focusedRoutes = Array.isArray(chain.crossChain) ? chain.crossChain : [];
    existing.crossChain = [...existingRoutes, ...focusedRoutes];
    if (!existing.rpc?.ok && chain.rpc?.ok) existing.rpc = chain.rpc;
    if (chain.transferability === 'quote_verified') existing.transferability = 'quote_verified';
  }
  const ready = new Set(screen?.ready || flare?.ready || []);
  const selected = new Set(screen?.selected || flare?.selected || []);
  const chains = [...chainsByName.values()].map((chain) => normalizeChain(chain, ready, selected));
  const configured = Array.isArray(config?.chains) ? config.chains : [];
  const known = new Set(chains.map((chain) => chain.name));
  for (const chain of configured) {
    if (known.has(chain.name)) continue;
    chains.push({
      name: chain.name,
      chainId: chain.chainId,
      llamaName: chain.llamaName || chain.name,
      status: chain.selectedForDeepDive ? 'queued' : 'queued',
      currentTvlUsd: numberOrZero(chain.currentDefiTvlUsdSnapshot),
      currentTvlLabel: formatUsd(chain.currentDefiTvlUsdSnapshot),
      peakTvlUsd: 0,
      peakTvlLabel: '$0',
      peakAt: null,
      historicalPoints: 0,
      currentToPeakRatio: 0,
      priorityScore: 0,
      historicalHeatScore: 0,
      currentValueScore: 0,
      crossChainScore: 0,
      transferability: 'not_checked',
      rpc: { ok: false, blockNumber: null, observedChainId: null, url: chain.rpc || null, error: null },
      routes: [], quoteRoutes: [], connectionRoutes: [], connectionCount: 0,
      selectedForDeepDive: chain.selectedForDeepDive === true, readyForDeepDive: false,
      prefilterSkipped: true, errors: [], caveats: [chain.status || '尚未进入筛选快照'],
    });
  }
  chains.sort((a, b) => b.priorityScore - a.priorityScore || a.name.localeCompare(b.name));

  const reportFiles = await Promise.all([
    fileMeta(join(REPORT_DIR, 'chain-screen.json')),
    fileMeta(join(REPORT_DIR, 'flare-screen.json')),
    fileMeta(join(REPORT_DIR, 'summary.json')),
  ]);
  const detailPaths = [
    'firelight-cover-allocator.json', 'firelight-incidents.json', 'firelight-cover-nft.json',
    'firelight-fasset-proxy.json', 'firelight-fasset.json', 'firelight-legacy-vault.json',
    'firelight-rewards.json', 'firelight-oracle.json', 'firelight-vault.json', 'morpho-blue.json',
  ];
  const detailReports = (await Promise.all(detailPaths.map((file) => readJson(join(REPORT_DIR, file))))).filter(Boolean);
  const staticReports = extractFindings(detailReports);
  const campaignFindings = Array.isArray(findingIndex?.findings) ? findingIndex.findings : [];
  const findings = [...staticReports, ...campaignFindings];
  const vulnerabilityChains = await buildVulnerabilityChains({ projectRoot: PROJECT_ROOT, reports: detailReports, testReport });
  const severityCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const finding of staticReports) severityCounts[finding.impact] = (severityCounts[finding.impact] || 0) + 1;
  const campaignSeverityCounts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of campaignFindings) campaignSeverityCounts[finding.severity] = (campaignSeverityCounts[finding.severity] || 0) + 1;
  const generatedAt = [screen?.generatedAt, flare?.generatedAt, summary?.generatedAt].map(isoOrNull).filter(Boolean).sort().at(-1) || null;
  const readyChains = chains.filter((chain) => chain.readyForDeepDive);
  const candidateChains = chains.filter((chain) => chain.selectedForDeepDive);
  const quoteRoutes = chains.flatMap((chain) => chain.quoteRoutes.map((route) => ({ ...route, fromChain: chain.name, fromChainId: chain.chainId })));
  const active = readyChains[0] || candidateChains[0] || chains.find((chain) => chain.status === 'queued') || chains[0] || null;
  const unifiedIR = campaign?.unifiedIR || { documentCount: 0, documents: [], semanticsProven: false, comparison: { state: 'not_performed', reason: 'No unified IR references are present in the campaign snapshot.' } };
  const progress = campaign?.progress || campaignProgress(campaign);
  const snapshot = {
    schemaVersion: 2,
    syncVersion: randomUUID(),
    generatedAt: new Date().toISOString(),
    lastReportAt: generatedAt,
    campaign, progress, rpcPool,
    activeTask: campaign ? { id: 'defi-source-campaign', label: '合约采集与真实源码审查', status: campaign.observedState, lastRunAt: campaign.updatedAt, scope: '按协议在目标链 TVL ≥ $10,000 初筛；多类型轮换、RPC 核验、源码审查与待验证线索分别计数。' } : {
      id: 'chain-screen',
      label: '冷门 EVM 链筛选与逐链深挖',
      status: screen ? 'snapshot_ready' : 'waiting_for_report',
      lastRunAt: generatedAt,
      scope: '历史热度、剩余 TVL、RPC 身份与跨链报价证据。队列来自最近报告，不代表后台正在扫描。',
    },
    activeChain: active ? { name: active.name, chainId: active.chainId, status: active.status, role: 'snapshot_priority' } : null,
    queue: chains.map((chain, index) => ({ position: index + 1, name: chain.name, chainId: chain.chainId, status: chain.status, priorityScore: chain.priorityScore })),
    chains,
    candidates: candidateChains.map((chain) => chain.name),
    readyChains: readyChains.map((chain) => chain.name),
    routes: quoteRoutes,
    findings,
    staticReports: staticReports.slice(0, 80),
    findingIndex: { schemaVersion: findingIndex?.schemaVersion || 1, generatedAt: findingIndex?.generatedAt || null, findingCount: campaignFindings.length },
    highPriorityFindings: findings.filter((finding) => finding.impact === 'High' || (finding.impact === 'Medium' && finding.confidence === 'High')).slice(0, 16),
    vulnerabilityChains,
    staticAnalysis: {
      complete: summary?.complete === true,
      unifiedIR,
      targetCount: Array.isArray(summary?.targets) ? summary.targets.length : detailReports.length,
      analyzedContracts: (summary?.targets || []).reduce((total, target) => total + numberOrZero(target.analyzedContracts), 0),
      findingCount: staticReports.length,
      campaignFindingCount: campaignFindings.length,
      severityCounts,
      campaignSeverityCounts,
      targets: Array.isArray(summary?.targets) ? summary.targets.map((target) => ({
        name: target.target?.name || 'unknown', success: target.success === true, findingCount: numberOrZero(target.findingCount), severityCounts: target.severityCounts || {}, analyzedContracts: numberOrZero(target.analyzedContracts),
      })) : [],
      localSecurityTests: testReport ? {
        generatedAt: testReport.generatedAt,
        complete: testReport.complete === true && vulnerabilityChains.every((chain) => chain.localTest.sourceMatches),
        requiredComplete: testReport.requiredComplete === true && vulnerabilityChains.every((chain) => chain.localTest.sourceMatches),
        sourceMatches: vulnerabilityChains.every((chain) => chain.localTest.sourceMatches),
        missingSuites: Array.isArray(testReport.missingSuites) ? testReport.missingSuites : [],
        suites: Array.isArray(testReport.suites) ? testReport.suites.map((suite) => ({ id: suite.id, label: suite.label, status: suite.status, durationMs: suite.durationMs })) : [],
        caveat: testReport.caveat || null,
      } : null,
    },
    soak: soakReport ? {
      runId: soakReport.runId, state: soakReport.state || 'interrupted',
      startedAt: soakReport.startedAt, updatedAt: soakReport.updatedAt || soakReport.finishedAt,
      finishedAt: soakReport.finishedAt, plannedEndAt: soakReport.plannedEndAt,
      durationMs: soakReport.durationMs, targetDurationMs: soakReport.targetDurationMs,
      sampleCount: soakReport.sampleCount, failures: soakReport.failures, latencyMs: soakReport.latencyMs,
      maxGapMs: soakReport.maxGapMs, completionReason: soakReport.completionReason,
      stale: Date.now() - Date.parse(soakReport.updatedAt || soakReport.finishedAt) > 120000 && soakReport.state === 'running',
    } : null,
    model,
    sources: {
      reports: reportFiles.filter(Boolean),
      quoteSafety: screen?.quoteSafety || flare?.quoteSafety || '报价只读，不签名、不授权、不广播。',
      reportPaths: detailPaths.map((file) => join('flare-scan', 'reports', file)),
    },
    totals: {
      configuredChains: configured.length,
      screenedChains: screenChains.length,
      candidates: candidateChains.length,
      ready: readyChains.length,
      quoteVerified: quoteRoutes.length,
      connectionOnly: chains.reduce((total, chain) => total + chain.connectionRoutes.length, 0),
      rpcHealthy: chains.filter((chain) => chain.rpc.ok).length,
      high: severityCounts.High || 0,
      medium: severityCounts.Medium || 0,
      testedChains: vulnerabilityChains.filter((chain) => chain.status === 'tested').length,
      highSignalChains: vulnerabilityChains.filter((chain) => chain.confidence === 'high_signal').length,
    },
  };
  return snapshot;
}

// Requests from the dashboard and SSE stream often arrive together. Reuse one
// fresh snapshot and one in-flight build so disk reads do not multiply.
export function createSnapshotStore(stateDir = WORK_DIR) {
  let cachedSnapshot = null;
  let cachedAt = 0;
  let snapshotPromise = null;
  return async function buildSnapshot({ force = false } = {}) {
    if (!force && cachedSnapshot && Date.now() - cachedAt < SNAPSHOT_CACHE_MS) return cachedSnapshot;
    if (snapshotPromise) return snapshotPromise;
    snapshotPromise = buildSnapshotFresh().then(async (snapshot) => {
      if (stateDir) await writeSyncFiles(snapshot, stateDir);
      cachedSnapshot = snapshot;
      cachedAt = Date.now();
      return snapshot;
    }).finally(() => { snapshotPromise = null; });
    return snapshotPromise;
  };
}
export const buildSnapshot = createSnapshotStore();

async function writeAtomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  } finally {
    await unlink(temp).catch(() => {});
  }
}

async function writeSyncFiles(snapshot, stateDir) {
  const statusFile = join(stateDir, 'dsh-status.json');
  const syncFile = join(stateDir, 'dsh-sync.json');
  const sync = {
    schemaVersion: 1,
    syncVersion: snapshot.syncVersion,
    updatedAt: snapshot.generatedAt,
    consumers: ['dsh', 'dhlsh'],
    intendedConsumers: ['dsh', 'dhlsh'],
    consumptionVerified: false,
    consumerAcknowledgements: { dsh: null, dhlsh: null },
    activeChain: snapshot.activeChain,
    activeTask: snapshot.activeTask,
    queue: snapshot.queue,
    lastReportAt: snapshot.lastReportAt,
    progress: snapshot.progress,
    model: snapshot.model,
    totals: snapshot.totals,
    sourceReports: snapshot.sources.reports,
    unifiedIR: snapshot.staticAnalysis.unifiedIR,
    localSecurityTests: snapshot.staticAnalysis.localSecurityTests,
    soak: snapshot.soak,
    campaign: snapshot.campaign,
    rpcPool: snapshot.rpcPool,
    contract: {
      statusFile: relative(PROJECT_ROOT, statusFile),
      api: '/api/status',
      ask: '/api/ask',
      events: '/api/events',
      readOnly: true,
    },
  };
  await writeAtomic(statusFile, snapshot);
  await writeAtomic(syncFile, sync);
}

export function answerQuestion(snapshot, question) {
  const text = String(question || '').trim();
  const reply = (answer, evidence = []) => ({ mode: 'structured', answer, evidence });
  const chains = snapshot.chains || [];
  const chain = snapshot.activeChain;
  const top = chains.find((item) => item.status === 'ready') || chains.find((item) => item.status === 'candidate');
  const named = chains.find((item) => text.toLowerCase().includes(item.name.toLowerCase()) || (item.llamaName && text.toLowerCase().includes(item.llamaName.toLowerCase())));
  if (/动态分析|反编译|反汇编|字节码|decompil|disassembl/i.test(text)) {
    const counts = snapshot.campaign?.counts || {};
    const dynamic = counts.dynamicTestsPerformed ?? counts.localTestsPerformed ?? 0;
    const suites = counts.dynamicTestSuites ?? counts.localTestSuites ?? 0;
    const disassemblies = countValueOrNotRecorded(counts, 'runtimeBytecodeAnalyses');
    const unavailable = countValueOrNotRecorded(counts, 'runtimeBytecodeAnalysisUnavailable');
    const partials = countValueOrNotRecorded(counts, 'runtimeBytecodeAnalysisPartials');
    const decompilationKeys = ['runtimeBytecodeDecompilations','runtimeBytecodeDecompilationsNotRequested','runtimeBytecodeDecompilationsIncomplete'];
    const hasDecompilationCounts = decompilationKeys.some((key) => Object.hasOwn(counts, key));
    const decompilationSummary = hasDecompilationCounts
      ? `Heimdall 伪码产物 ${countValueOrNotRecorded(counts, 'runtimeBytecodeDecompilations')} 份，未请求 ${countValueOrNotRecorded(counts, 'runtimeBytecodeDecompilationsNotRequested')} 份，不完整 ${countValueOrNotRecorded(counts, 'runtimeBytecodeDecompilationsIncomplete')} 份；伪码是启发式推断，不是已验证源码。`
      : '当前采集未记录 Heimdall 伪码产物计数。';
    const graphs = counts.staticCallGraphs || 0;
    const graphPaths = counts.staticCallGraphPaths || 0;
    const bytecodeSummary = Object.hasOwn(counts, 'runtimeBytecodeAnalyses')
      ? `反汇编 ${disassemblies} 份`
      : '反汇编份数未记录';
    const unavailableSummary = Object.hasOwn(counts, 'runtimeBytecodeAnalysisUnavailable')
      ? `不可用 ${unavailable} 份`
      : '不可用计数未记录';
    const partialSummary = Object.hasOwn(counts, 'runtimeBytecodeAnalysisPartials')
      ? `字节码部分结果 ${partials} 份`
      : '字节码部分结果计数未记录';
    return { ...reply(`支持隔离 EVM 本地动态测试（当前采集 ${dynamic} 项 / ${suites} 个套件）、链上运行时代码（${bytecodeSummary}；${unavailableSummary}；${partialSummary}）和源码级结构化调用图（${graphs} 份 / ${graphPaths} 条入口到状态写入或外部调用的候选路径）。${decompilationSummary}反汇编会记录 opcode、选择器候选、外部调用/存储位置和代理槽线索；调用图与路径是静态过近似，不代表完整控制流或漏洞。动态测试目前只对有专用目标夹具的合约运行，其它对象会明确标为未运行。`, [`采集状态：${snapshot.campaign?.observedState || '当前没有活动采集报告'}`, `证据目录：${snapshot.campaign?.evidenceDirectory || '无'}`, '默认使用本地隔离 EVM；只有显式配置固定区块 fork 且完成边界校验时才使用 fork；始终不使用用户资产、不签名、不广播。']), authoritative: true };
  }
  if (/rpc|节点|备用|轮换/i.test(text)) {
    const pool = snapshot.rpcPool;
    if (!pool) return reply('尚无多 RPC 验证报告。');
    const rows = named ? pool.chains.filter(c => c.chainId === named.chainId) : pool.chains;
    return { ...reply(`最近验证：${rows.filter(c => c.healthyCount > 0).length} 条链有可用 RPC，${rows.filter(c => c.redundant).length} 条链有多个通过共同区块核对的节点，总计 ${rows.reduce((n,c) => n+c.healthyCount,0)} 个。运行中按负载轮换，失败切换并冷却；限流退避。未通过验证的节点不进入采集池。`, [`RPC 验证时间：${pool.generatedAt}`, ...rows.map(c => `${c.name}：${c.healthyCount} 个可用节点`)]), authoritative: true };
  }
  if (/三小时|3小时|保活|稳定|soak/i.test(text)) {
    const run = snapshot.soak;
    if (!run) return reply('尚无三小时稳定性测试报告。');
    const state = run.stale ? '心跳已过期，不能视为仍在运行' : ({ running: '运行中', completed: '已完成', failed: '存在失败', interrupted: '已中断' }[run.state] || '未验证');
    return reply(`稳定性测试：${state}，已记录 ${run.sampleCount || 0} 轮，失败 ${run.failures || 0} 次。已观测 ${Math.floor((run.durationMs || 0) / 60000)} 分钟；目标 ${Math.round((run.targetDurationMs || 10800000) / 60000)} 分钟。`, [`观测更新时间：${run.updatedAt}`, `当前快照时间：${snapshot.generatedAt}`, '检查范围：本地服务、状态同步、实时连接与结构化状态接口；不调用云端 AI，也不是链上安全证明。']);
  }
  if (/测试|复现|foundry|hardhat/i.test(text)) {
    const test = snapshot.staticAnalysis.localSecurityTests;
    if (!test) return reply('尚无本地安全测试报告。');
    return reply(`本地 Hardhat 必要套件${test.requiredComplete ? '通过' : '未完成或源码已变化'}；全套测试${test.complete ? '通过' : '不完整'}。${test.missingSuites?.length ? `未通过或未运行：${test.missingSuites.join('、')}。` : ''}本地回归通过不代表已确认漏洞，也不代表已验证部署字节码。`, test.suites.map((suite) => `${suite.label}：${suite.status}`));
  }
  if (/漏洞链路|攻击链|链路分析/.test(text)) {
    return { ...reply(`当前建模 ${(snapshot.vulnerabilityChains || []).length} 条风险路径；本地测试匹配 ${snapshot.totals.testedChains} 条，已确认可利用 0 条。`, (snapshot.vulnerabilityChains || []).map((path) => `${path.title}：${path.interpretation}；状态 ${path.status}`)), authoritative: true };
  }
  if (/跨链|转移|quote|报价/i.test(text)) {
    const quote = named ? snapshot.routes.find((route) => route.fromChainId === named.chainId) : snapshot.routes[0];
    if (!quote) return reply(`${named?.name || '当前报告'}没有 quote_verified 报价。connection_only 只表示兼容性，不能证明当前可转移。`, ['不执行授权、签名或广播。']);
    return reply(`${quote.fromChain} → chain ID ${quote.toChainId} 曾取得 quote_verified（${quote.tool || '未知工具'}）：预计输出 ${quote.quotedToAmount}，最低 ${quote.quotedToAmountMin}，单位为代币最小单位。这是报价采集时刻的只读证据，需重新报价才能判断当前可转移性；不执行授权、签名或广播。`, [`报价采集时间：${quote.observedAt || snapshot.lastReportAt}`, `当前快照时间：${snapshot.generatedAt}`]);
  }
  if (/风险|告警|漏洞|high|medium/i.test(text)) {
    const high = snapshot.highPriorityFindings || [];
    return { ...reply(`静态分析产生 ${snapshot.staticAnalysis.findingCount} 条线索，其中 High ${snapshot.totals.high} 条、Medium ${snapshot.totals.medium} 条。自动检测不是已确认漏洞；优先复核权限、资金流与状态回滚。`, high.slice(0, 3).map((item) => `${item.target}/${item.check} (${item.impact})`)), authoritative: true };
  }
  if (/哪条|优先|值得|先看|深挖/.test(text)) {
    return reply(top ? `快照建议优先 ${top.name}：历史峰值 ${top.peakTvlLabel}，当前 TVL 代理 ${top.currentTvlLabel}，跨链证据 ${top.transferability}。这是研究排序，不代表已完成资金可转移性验证。` : '尚无达到筛选门槛的链。', [`当前快照时间：${snapshot.generatedAt}`, `源报告时间：${snapshot.lastReportAt}`]);
  }
  if (/同步|dhlsh|模型/i.test(text)) return reply(`DSH / DHLsh 使用同一状态版本 ${snapshot.syncVersion}。云端审查通道${snapshot.model.configured ? '已配置' : '未配置'}；状态文件存在不代表两个客户端都已确认消费。`, ['权威快照：work/dsh-status.json', '同步索引：work/dsh-sync.json']);
  if (/采集|一小时|1小时|高速|合约|金额|门槛|TVL|当前|正在|进度|状态/i.test(text) && snapshot.campaign) {
    return { ...reply(campaignAnswer(snapshot.campaign), [`采集更新时间：${snapshot.campaign.updatedAt}`, `证据目录：${snapshot.campaign.evidenceDirectory}`, `实时任务：${(snapshot.campaign.active || []).map(x => `${x.chain}/${x.protocol} · ${x.stage}`).join('；') || '暂无正在处理的对象'}`]), authoritative: /采集|一小时|1小时|高速|金额|门槛|TVL/i.test(text) };
  }
  if (!text || /当前|正在|分析什么|进度|状态|报告|扫描/.test(text)) return reply(`当前快照覆盖 ${snapshot.totals.screenedChains} 条 EVM 链，${snapshot.totals.candidates} 条候选、${snapshot.totals.ready} 条 ready。快照优先链 ${chain?.name || '未确定'}；源码深挖与本地测试目前覆盖 Flare / Firelight 的 3 条路径。没有运行任务证据时，不应把队列说成正在扫描。`, [`当前快照时间：${snapshot.generatedAt}`, `源报告时间：${snapshot.lastReportAt}`, `同步版本：${snapshot.syncVersion}`]);
  return { ...reply('我能依据当前快照回答：链筛选、跨链报价、漏洞链路、本地测试、三小时稳定性和同步情况。'), unknown: true };
}

export { PROJECT_ROOT, REPORT_DIR, SYNC_FILE, STATUS_FILE, formatUsd };
