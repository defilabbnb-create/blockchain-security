import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

function finiteCount(value) {
  if (value === null || value === '' || typeof value === 'boolean') return null;
  const number = Number(value);
  return Number.isInteger(number) && number >= 0 ? number : null;
}

function countLabel(source, key) {
  if (!Object.hasOwn(source, key) || source[key] === null || source[key] === '') return '未记录';
  return finiteCount(source[key]) ?? '未记录';
}

function countLabelAny(source, keys) {
  for (const key of keys) {
    if (Object.hasOwn(source, key) && source[key] !== null && source[key] !== '') {
      return finiteCount(source[key]) ?? '未记录';
    }
  }
  return '未记录';
}

function roundedPercent(numerator, denominator) {
  const value = finiteCount(numerator);
  const total = finiteCount(denominator);
  if (value === null || total === null || total <= 0) return null;
  return Math.max(0, Math.min(100, Math.round((value / total) * 1000) / 10));
}

function progressStage(id, label, numerator, denominator, basis) {
  return {
    id,
    label,
    numerator: finiteCount(numerator),
    denominator: finiteCount(denominator),
    percent: roundedPercent(numerator, denominator),
    basis,
  };
}

/**
 * Convert the campaign counters into bounded, auditable progress signals.
 * Each stage keeps its own denominator because a bytecode check, source
 * review, and isolated test are different kinds of work.  The overview is a
 * simple average of recorded stage percentages and is deliberately labelled
 * as an evidence overview rather than an audit completion claim.
 */
export function campaignProgress(run) {
  const counts = run?.counts && typeof run.counts === 'object' ? run.counts : {};
  const qualified = finiteCount(run?.qualifiedProtocolChains) ?? finiteCount(counts.qualifiedProtocolChains);
  const attempted = finiteCount(counts.protocolChainsAttempted);
  const candidates = finiteCount(counts.contractCandidates);
  const deployed = finiteCount(counts.deployedContracts);
  const source = finiteCount(counts.verifiedSourceBundles);
  const reviews = finiteCount(counts.cloudReviewCompletions);
  const historicalLocalReviews = finiteCount(counts.sourceReviews);
  const staticAnalyses = finiteCount(counts.staticAnalyses);
  const runtime = finiteCount(counts.runtimeBytecodeAnalyses);
  const dynamic = finiteCount(counts.dynamicTestsPerformed ?? counts.localTestsPerformed);
  const decompilationRecorded = Object.hasOwn(counts, 'runtimeBytecodeDecompilations');
  const decompilation = decompilationRecorded ? finiteCount(counts.runtimeBytecodeDecompilations) : null;

  const stages = [
    progressStage('discovery', '目标初筛', attempted, qualified, '已尝试的协议 / 链 ÷ 达到门槛的协议 / 链'),
    progressStage('runtime', '运行时代码读取', runtime, deployed, '已读取运行时代码 ÷ 核实有部署代码的目标'),
    progressStage('source', '验证源码获取', source, deployed, '已取得验证源码 ÷ 核实有部署代码的目标'),
    progressStage('review', '云端审查证据', reviews, deployed, '有调用证据的云端审查 ÷ 核实有部署代码的目标'),
    progressStage('static', '静态检查', staticAnalyses, source, '已完成静态检查 ÷ 已取得验证源码的目标'),
    progressStage('dynamic', '隔离动态检查', dynamic, deployed, '已运行动态检查 ÷ 核实有部署代码的目标'),
  ];
  const codeStages = stages.filter((stage) => ['runtime', 'source', 'review', 'static'].includes(stage.id));
  const recorded = stages.filter((stage) => stage.percent !== null);
  const average = (items) => items.length ? Math.round((items.reduce((sum, item) => sum + item.percent, 0) / items.length) * 10) / 10 : null;
  const windowNumerator = finiteCount(run?.durationMs);
  const windowDenominator = finiteCount(run?.targetDurationMs);
  const window = progressStage('window', '采集窗口', windowNumerator, windowDenominator, '已记录时间 ÷ 计划采集时间');
  return {
    schemaVersion: 1,
    state: run?.observedState || run?.state || 'not_started',
    window,
    code: {
      percent: codeStages.every((stage) => stage.percent !== null) ? average(codeStages) : null,
      stages: codeStages,
      omittedStages: codeStages.filter((stage) => stage.percent === null).map((stage) => stage.id),
      basis: '运行时代码、源码获取、云端审查证据、静态检查四类比例的平均值；不是代码质量评分。',
    },
    overall: {
      percent: average(recorded),
      stages: recorded,
      omittedStages: stages.filter((stage) => stage.percent === null).map((stage) => stage.id),
      formula: '已记录阶段百分比的简单平均；不同阶段分母不同，只用于进度概览，不代表审计完成度。',
    },
    decompilation: {
      state: decompilationRecorded ? 'recorded' : 'not_recorded',
      percent: roundedPercent(decompilation, runtime ?? deployed),
      numerator: decompilation,
      denominator: runtime ?? deployed,
      basis: decompilationRecorded ? '已生成伪码 ÷ 已完成运行时代码读取' : '报告未记录伪码产物计数，不能当作零。',
    },
    inputs: { qualified, attempted, candidates, deployed, source, reviews, historicalLocalReviews, staticAnalyses, runtime, dynamic, decompilation },
  };
}

function collectUnifiedIR(raw) {
  const documents = new Map();
  const recent = Array.isArray(raw?.recent) ? raw.recent : [];
  const channels = [
    ['staticAnalysis', 'static'],
    ['dynamicAnalysis', 'dynamic'],
    ['runtimeBytecodeAnalysis', 'bytecode'],
  ];
  for (const item of recent) {
    if (!item || typeof item !== 'object') continue;
    for (const [field, kind] of channels) {
      const ir = item[field]?.unifiedIR;
      if (!ir || typeof ir !== 'object' || typeof ir.documentId !== 'string' || !ir.documentId.trim()) continue;
      const documentId = ir.documentId.trim();
      const report = typeof ir.report === 'string' && ir.report.trim() ? ir.report.trim() : null;
      const key = `${documentId}\u0000${report || ''}`;
      let document = documents.get(key);
      if (!document) {
        document = {
          state: typeof ir.state === 'string' ? ir.state : 'unknown',
          documentId,
          report,
          source: typeof ir.source === 'string' ? ir.source : kind,
          functionCount: finiteCount(ir.functionCount),
          operationCount: finiteCount(ir.operationCount),
          linkCount: finiteCount(ir.linkCount),
          semanticsProven: false,
          evidenceKinds: [],
          targets: [],
        };
        documents.set(key, document);
      }
      if (!document.evidenceKinds.includes(kind)) document.evidenceKinds.push(kind);
      const target = { chain: item.chain || null, address: item.address || null };
      if (!document.targets.some((entry) => entry.chain === target.chain && entry.address === target.address)) document.targets.push(target);
    }
  }
  const rows = [...documents.values()].sort((a, b) => a.documentId.localeCompare(b.documentId) || String(a.report).localeCompare(String(b.report)));
  return {
    documentCount: rows.length,
    recorded: rows.length > 0,
    documents: rows,
    semanticsProven: false,
    comparison: { state: 'not_performed', reason: 'IR references are evidence indexes; semantic equivalence is not established.' },
  };
}

export function normalizeCampaign(raw, now = Date.now(), alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } }) {
  if (!raw || raw.kind !== 'defi-source-campaign') return null;
  const active = ['initializing', 'running', 'waiting_for_new_candidates', 'draining'].includes(raw.state);
  const lease = raw.lease && typeof raw.lease === 'object' ? raw.lease : null;
  const heartbeatAt = lease?.heartbeatAt || raw.heartbeatAt || raw.updatedAt;
  const heartbeatAge = now - Date.parse(heartbeatAt);
  const ttlSec = Number(lease?.ttlSec);
  const ttlMs = Number.isFinite(ttlSec) && ttlSec >= 1 && ttlSec <= 3600 ? ttlSec * 1000 : 45000;
  const expiresAt = lease ? Date.parse(lease.expiresAt) : NaN;
  const leaseInvalid = lease && (
    lease.runId !== raw.runId ||
    Number(lease.pid) !== Number(raw.pid) ||
    !Number.isFinite(expiresAt) ||
    now > expiresAt + 5000 ||
    !Number.isFinite(heartbeatAge) || heartbeatAge > ttlMs + 5000 || heartbeatAge < -5000
  );
  const stale = active && (Boolean(leaseInvalid) || !Number.isFinite(heartbeatAge) || heartbeatAge > ttlMs + 5000 || heartbeatAge < -5000 || !Number.isInteger(raw.pid) || !alive(raw.pid));
  const legacyReviewCount = finiteCount(raw.counts?.sourceReviews);
  const { localModel: _removedLegacyModel, ...savedAnalysisMode } = raw.analysisMode || {};
  const analysisMode = {
    ...savedAnalysisMode,
    cloudAI: { state: 'unavailable', reason: 'cloud-adapter-not-configured', completedCalls: 0, evidenceCount: 0, ...savedAnalysisMode.cloudAI },
    history: savedAnalysisMode.history || { legacySourceReviewCount: legacyReviewCount, source: legacyReviewCount ? 'legacy-source-review-counter; not cloud evidence' : 'no legacy review counter' },
  };
  const normalized = { ...raw, analysisMode, unifiedIR: collectUnifiedIR(raw), stale, observedState: stale ? 'stale' : raw.state, completionMeaning: 'completed 仅表示采集窗口结束；不是所有合约已审计或漏洞已确认。' };
  return { ...normalized, progress: campaignProgress(normalized) };
}

export async function readCampaignState(root) {
  const read = async (name) => { try { return JSON.parse(await readFile(join(root, 'work', name), 'utf8')); } catch { return null; } };
  const [raw, rpc] = await Promise.all([read('defi-campaign.json'), read('rpc-pool.json')]);
  const rpcPool = rpc ? { generatedAt: rpc.generatedAt, sources: rpc.sources, policy: rpc.policy, chains: (rpc.chains || []).map(c => ({ chainId: c.chainId, name: c.name, healthyCount: c.healthyCount, redundant: c.redundant, assurance: c.assurance, endpoints: c.endpoints.map(e => ({ url: e.url, healthy: e.healthy, latencyMs: e.latencyMs, blockAgeSec: e.blockAgeSec, observedAt: e.observedAt, error: e.error })) })) } : null;
  if (rpcPool) for (const chain of rpcPool.chains) for (const node of chain.endpoints) node.runtime = raw?.rpc?.runtime?.nodes?.[node.url] || null;
  return { campaign: normalizeCampaign(raw), rpcPool };
}

export function campaignAnswer(run) {
  if (!run) return '一小时合约采集分析尚未启动。';
  const counts = run.counts || {};
  const status = {initializing:'准备中',running:'运行中',waiting_for_new_candidates:'候选已处理完，等待新候选（没有重复分析充数）',draining:'正在结束已发出的请求',completed:'采集窗口已结束',queue_exhausted:'当前队列已处理完，提前停止',interrupted:'已中断',invalidated:'源码发生变化，本窗口作废并保留证据',failed:'运行失败',stale:'心跳过期或进程已退出，不能视为仍在运行'}[run.observedState || run.state] || '未验证';
  const unifiedIRCount = run.unifiedIR?.recorded === true ? countLabel(run.unifiedIR, 'documentCount') : '未记录';
  const decompilations = `Heimdall 伪码产物 ${countLabel(counts, 'runtimeBytecodeDecompilations')} 份，未请求 ${countLabel(counts, 'runtimeBytecodeDecompilationsNotRequested')} 份，不完整 ${countLabel(counts, 'runtimeBytecodeDecompilationsIncomplete')} 份（启发式推断，不是已验证源码）`;
  const bytecodePartials = countLabel(counts, 'runtimeBytecodeAnalysisPartials');
  const progress = run.progress || campaignProgress(run);
  const percent = (value) => value == null ? '未记录' : `${value}%`;
  const legacyReviews = finiteCount(counts.sourceReviews);
  const reviewHistory = legacyReviews === null ? '历史来源审查数未记录' : `旧版来源审查 ${legacyReviews} 份（来源未核验，不计云端审查证据）`;
  const cloudAttempts = finiteCount(counts.cloudReviewAttempts);
  const cloudCompletions = finiteCount(counts.cloudReviewCompletions);
  const cloudState = run.analysisMode?.cloudAI?.state;
  const cloudStatus = (cloudCompletions !== null && cloudCompletions > 0) || cloudState === 'available_with_recorded_calls'
    ? `有调用证据的云端审查 ${cloudCompletions === null ? '未记录' : cloudCompletions} 份`
    : (cloudAttempts !== null && cloudAttempts > 0) || cloudState === 'failed'
      ? `云端审查未形成完成证据（尝试 ${cloudAttempts === null ? '未记录' : cloudAttempts} 次）`
      : cloudState === 'configured_not_called'
        ? '云端审查已配置但尚未调用'
        : '云端审查未配置';
  const durationMs = finiteCount(run.durationMs);
  const targetDurationMs = finiteCount(run.targetDurationMs);
  const duration = durationMs === null ? '未记录' : `${Math.floor(durationMs / 60000)} 分钟`;
  const targetDuration = targetDurationMs === null ? '未记录' : `${Math.round(targetDurationMs / 60000)} 分钟`;
  const qualified = Object.hasOwn(run, 'qualifiedProtocolChains')
    ? countLabel(run, 'qualifiedProtocolChains')
    : countLabel(counts, 'qualifiedProtocolChains');
  return `合约采集分析：${status}。代码检查进度约 ${percent(progress.code.percent)}，总体证据进度约 ${percent(progress.overall.percent)}；采集窗口 ${percent(progress.window.percent)}（均按页面显示公式计算，不代表审计完成度）。已记录 ${duration}，目标 ${targetDuration}。按协议在该链 TVL ≥ $10,000 初筛 ${qualified} 项；尝试 ${countLabel(counts, 'protocolChainsAttempted')} 项，核实有代码的合约 ${countLabel(counts, 'deployedContracts')} 个，获取源码 ${countLabel(counts, 'verifiedSourceBundles')} 份，${reviewHistory}，${cloudStatus}，Slither 完成 ${countLabel(counts, 'staticAnalyses')} 份。结构化调用图 ${countLabel(counts, 'staticCallGraphs')} 份（报告 ${countLabel(counts, 'staticCallGraphPaths')} 条入口到状态写入或外部调用的候选路径，均需复核）；统一 IR 文档 ${unifiedIRCount} 份（仅证据索引，语义未证明）；字节码反汇编 ${countLabel(counts, 'runtimeBytecodeAnalyses')} 份（不是高层反编译，字节码部分结果 ${bytecodePartials} 份）；${decompilations}。本地动态测试 ${countLabelAny(counts, ['dynamicTestsPerformed', 'localTestsPerformed'])} 项，测试套件 ${countLabelAny(counts, ['dynamicTestSuites', 'localTestSuites'])} 个（失败 ${countLabelAny(counts, ['dynamicTestsFailed', 'localTestsFailed'])}）。其它合约没有专用本地测试时会标为未运行。已确认漏洞 ${countLabel(counts, 'confirmedVulnerabilities')} 项。发现阶段阻塞 ${countLabel(counts, 'discoveryBlocked')} 项，合约阶段阻塞 ${countLabel(counts, 'contractBlocked')} 项。TVL 不代表单合约余额；接口请求量不算分析量。`;
}

export { collectUnifiedIR };
