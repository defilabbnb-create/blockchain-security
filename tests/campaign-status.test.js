import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeCampaign, campaignAnswer, collectUnifiedIR, campaignProgress} from '../src/campaign-status.js';
import {answerQuestion} from '../src/status-store.js';

test('running campaign is not advertised as completed and uses minutes',()=>{
  const run={kind:'defi-source-campaign',state:'running',updatedAt:'2026-10-17T00:00:00Z',pid:123,durationMs:600000,targetDurationMs:3600000,counts:{sourceReviews:3}};
  const normalized=normalizeCampaign(run,Date.parse(run.updatedAt),()=>true);
  assert.match(campaignAnswer(normalized),/运行中.*10 分钟.*60 分钟/);
  assert.match(campaignAnswer(normalized),/旧版来源审查 3 份/);
  assert.doesNotMatch(campaignAnswer(normalized),/已完成一小时|已通过/);
});
test('stale heartbeat and dead process cannot be counted as running',()=>{
  const raw={kind:'defi-source-campaign',state:'running',updatedAt:'2026-10-17T00:00:00Z',pid:123};
  assert.equal(normalizeCampaign(raw,Date.parse(raw.updatedAt)+60000,()=>true).observedState,'stale');
  assert.equal(normalizeCampaign(raw,Date.parse(raw.updatedAt),()=>false).observedState,'stale');
});
test('explicit lease expiry and identity are enforced while terminal states stay terminal',()=>{
  const now=Date.parse('2026-10-17T00:00:00Z');
  const base={kind:'defi-source-campaign',state:'running',updatedAt:'2026-10-16T23:59:59Z',pid:123,runId:'run-1',lease:{runId:'run-1',pid:123,heartbeatAt:'2026-10-17T00:00:00Z',expiresAt:'2026-10-17T00:00:45Z',ttlSec:45}};
  assert.equal(normalizeCampaign(base,now+40000,()=>true).observedState,'running');
  assert.equal(normalizeCampaign(base,now+50001,()=>true).observedState,'stale');
  assert.equal(normalizeCampaign({...base,lease:{...base.lease,runId:'other'}},now+1000,()=>true).observedState,'stale');
  assert.equal(normalizeCampaign({...base,state:'completed',lease:{...base.lease,expiresAt:'2026-10-16T23:00:00Z'}},now+600000,()=>false).observedState,'completed');
});
test('unified IR references are indexed without upgrading semantic evidence',()=>{
  const raw={kind:'defi-source-campaign',state:'completed',updatedAt:'2026-10-17T00:00:00Z',recent:[
    {chain:'Flare',address:'0xabc',staticAnalysis:{unifiedIR:{state:'available',documentId:'doc-1',report:'work/a/unified-ir.json',functionCount:2,operationCount:3,linkCount:4,semanticsProven:true}}},
    {chain:'Flare',address:'0xabc',dynamicAnalysis:{unifiedIR:{state:'available',documentId:'doc-1',report:'work/a/unified-ir.json'}}},
    {chain:'Celo',address:'0xdef',runtimeBytecodeAnalysis:{unifiedIR:{documentId:'doc-2',report:'work/b/unified-ir.json',functionCount:1}}},
    {chain:'ignored',address:'0x0',staticAnalysis:{unifiedIR:{report:'work/invalid.json'}}},
  ]};
  const index=collectUnifiedIR(raw);
  assert.equal(index.documentCount,2);
  assert.equal(index.semanticsProven,false);
  assert.equal(index.comparison.state,'not_performed');
  const first=index.documents.find((item)=>item.documentId==='doc-1');
  assert.deepEqual(first.evidenceKinds,['static','dynamic']);
  assert.deepEqual(first.targets,[{chain:'Flare',address:'0xabc'}]);
  assert.equal(first.functionCount,2);
  assert.equal(first.semanticsProven,false);
});
test('dynamic analysis questions expose evidence counts and the decompilation gap',()=>{
  const snapshot={campaign:{observedState:'failed',counts:{dynamicTestsPerformed:10,dynamicTestSuites:2,runtimeBytecodeAnalyses:7,runtimeBytecodeAnalysisUnavailable:1,runtimeBytecodeDecompilations:2,runtimeBytecodeDecompilationsNotRequested:4,runtimeBytecodeDecompilationsIncomplete:1}}};
  const result=answerQuestion(snapshot,'当前有没有动态分析或者反编译？');
  assert.equal(result.authoritative,true);
  assert.match(result.answer,/10 项 \/ 2 个套件/);
  assert.match(result.answer,/反汇编 7 份/);
  assert.match(result.answer,/不可用 1 份/);
  assert.match(result.answer,/Heimdall 伪码产物 2 份，未请求 4 份，不完整 1 份/);
  assert.match(result.answer,/不是已验证源码/);
  assert.match(result.evidence.join(' '),/failed/);
});
test('dynamic analysis questions describe the opt-in fixed-block fork boundary',()=>{
  const result=answerQuestion({campaign:{observedState:'interrupted',counts:{dynamicTestsPerformed:1}}},'当前有没有动态分析？');
  const evidence=result.evidence.join(' ');
  assert.match(evidence,/默认使用本地隔离 EVM/);
  assert.match(evidence,/显式配置固定区块 fork/);
  assert.match(evidence,/完成边界校验/);
  assert.match(evidence,/不使用用户资产、不签名、不广播/);
  assert.doesNotMatch(evidence,/不连接 fork/);
});
test('campaign without decompilation counters is not misreported as zero output',()=>{
  const snapshot={campaign:{observedState:'interrupted',counts:{runtimeBytecodeAnalyses:7}}};
  const result=answerQuestion(snapshot,'当前有没有动态分析或者反编译？');
  assert.match(result.answer,/未记录 Heimdall 伪码产物计数/);
  assert.match(result.answer,/不可用计数未记录/);
});
test('dynamic analysis question preserves an explicitly recorded zero unavailable count',()=>{
  const snapshot={campaign:{observedState:'completed',counts:{runtimeBytecodeAnalyses:7,runtimeBytecodeAnalysisUnavailable:0}}};
  const result=answerQuestion(snapshot,'当前字节码反汇编情况？');
  assert.match(result.answer,/反汇编 7 份/);
  assert.match(result.answer,/不可用 0 份/);
});
test('campaign and model agree on partial bytecode analysis', () => {
    const counts = { runtimeBytecodeAnalysisPartials: 1 };
    const campaignText = campaignAnswer({ state: 'interrupted', counts });
    const modelText = answerQuestion({ campaign: { observedState: 'interrupted', counts } }, '当前字节码反汇编情况？').answer;
    assert.match(campaignText, /字节码部分结果 1 份/);
    assert.match(modelText, /字节码部分结果 1 份/);
});
test('dynamic bytecode partial count distinguishes missing from recorded zero', () => {
  const missing = answerQuestion({ campaign: { counts: { runtimeBytecodeAnalyses: 7 } } }, '当前字节码反编译情况？').answer;
  assert.match(missing, /字节码部分结果计数未记录/);
  const zero = answerQuestion({ campaign: { counts: { runtimeBytecodeAnalyses: 7, runtimeBytecodeAnalysisPartials: 0 } } }, '当前字节码反编译情况？').answer;
  assert.match(zero, /字节码部分结果 0 份/);
});

test('campaign progress keeps stage denominators and does not invent decompilation zeros', () => {
  const progress = campaignProgress({
    state: 'interrupted', durationMs: 1_735_619, targetDurationMs: 3_600_000,
    qualifiedProtocolChains: 253,
    counts: {
      protocolChainsAttempted: 169, deployedContracts: 204,
      verifiedSourceBundles: 85, sourceReviews: 77, staticAnalyses: 68,
      runtimeBytecodeAnalyses: 204, dynamicTestsPerformed: 10,
    },
  });
  assert.equal(progress.window.percent, 48.2);
  assert.equal(progress.code.stages.find((item) => item.id === 'source').percent, 41.7);
  assert.equal(progress.code.percent, null);
  assert.deepEqual(progress.code.omittedStages, ['review']);
  assert.equal(progress.decompilation.state, 'not_recorded');
  assert.equal(progress.decompilation.percent, null);
  assert.equal(progress.overall.stages.length, 5);
  assert.deepEqual(progress.overall.omittedStages, ['review']);
  assert.match(progress.overall.formula, /不同阶段分母不同/);
});

test('campaign progress preserves explicit zero as a measured value', () => {
  const progress = campaignProgress({ counts: { deployedContracts: 4, runtimeBytecodeAnalyses: 4, runtimeBytecodeDecompilations: 0 } });
  assert.equal(progress.decompilation.state, 'recorded');
  assert.equal(progress.decompilation.percent, 0);
});

test('code progress preserves an explicit zero cloud review count', () => {
  const progress = campaignProgress({ counts: {
    deployedContracts: 4,
    runtimeBytecodeAnalyses: 4,
    verifiedSourceBundles: 4,
    staticAnalyses: 4,
    cloudReviewCompletions: 0,
  } });
  assert.equal(progress.code.percent, 75);
  assert.deepEqual(progress.code.omittedStages, []);
});

test('legacy source review counts are not cloud review evidence or review progress', () => {
  const now = Date.parse('2026-10-17T00:00:00Z');
  const normalized = normalizeCampaign({
    kind: 'defi-source-campaign',
    state: 'running',
    updatedAt: new Date(now).toISOString(),
    pid: process.pid,
    counts: { deployedContracts: 4, sourceReviews: 3 },
    analysisMode: { localModel: { enabled: false }, cloudAI: { state: 'unavailable' } },
  }, now, () => true);

  assert.equal(Object.hasOwn(normalized.analysisMode, 'localModel'), false);
  assert.equal(normalized.analysisMode.history.legacySourceReviewCount, 3);
  assert.equal(normalized.analysisMode.cloudAI.state, 'unavailable');
  assert.equal(normalized.analysisMode.cloudAI.completedCalls, 0);
  assert.equal(normalized.progress.code.stages.find((stage) => stage.id === 'review').percent, null);
  assert.ok(normalized.progress.overall.omittedStages.includes('review'));
});

test('ordinary campaign answer reports decompilation counters and distinguishes missing fields from zero',()=>{
  const legacy=campaignAnswer({state:'interrupted',counts:{runtimeBytecodeAnalyses:7}});
  assert.match(legacy,/伪码产物 未记录 份，未请求 未记录 份，不完整 未记录 份/);
  assert.match(legacy,/部分结果 未记录 份/);

  const current=campaignAnswer({state:'completed',counts:{
    runtimeBytecodeAnalyses:7,
    runtimeBytecodeAnalysisPartials:0,
    runtimeBytecodeDecompilations:0,
    runtimeBytecodeDecompilationsNotRequested:0,
    runtimeBytecodeDecompilationsIncomplete:0,
  }});
  assert.match(current,/伪码产物 0 份，未请求 0 份，不完整 0 份/);
  assert.match(current,/部分结果 0 份/);
});

test('campaign answer keeps missing counters distinct from explicit zero', () => {
  const missing = campaignAnswer({ state: 'interrupted', counts: {} });
  assert.match(missing, /已记录 未记录，目标 未记录/);
  assert.match(missing, /初筛 未记录 项；尝试 未记录 项，核实有代码的合约 未记录 个/);
  assert.match(missing, /Slither 完成 未记录 份/);
  assert.match(missing, /统一 IR 文档 未记录 份/);
  assert.match(missing, /本地动态测试 未记录 项，测试套件 未记录 个（失败 未记录）/);
  assert.match(missing, /已确认漏洞 未记录 项/);
  const failedCloud = campaignAnswer({ state: 'failed', analysisMode: { cloudAI: { state: 'failed' } }, counts: {} });
  assert.match(failedCloud, /云端审查未形成完成证据（尝试 未记录 次）/);

  const zero = campaignAnswer({ state: 'completed', durationMs: 0, targetDurationMs: 0,
    qualifiedProtocolChains: 0,
    counts: {
      protocolChainsAttempted: 0, deployedContracts: 0, verifiedSourceBundles: 0,
      staticAnalyses: 0, staticCallGraphs: 0, staticCallGraphPaths: 0,
      runtimeBytecodeAnalyses: 0, dynamicTestsPerformed: 0, dynamicTestSuites: 0,
      dynamicTestsFailed: 0, confirmedVulnerabilities: 0,
      discoveryBlocked: 0, contractBlocked: 0,
    },
    unifiedIR: { recorded: true, documentCount: 0 },
  });
  assert.match(zero, /已记录 0 分钟，目标 0 分钟/);
  assert.match(zero, /初筛 0 项；尝试 0 项，核实有代码的合约 0 个/);
  assert.match(zero, /统一 IR 文档 0 份/);
  assert.match(zero, /本地动态测试 0 项，测试套件 0 个（失败 0）/);
  assert.match(zero, /已确认漏洞 0 项/);
});

test('campaign answer uses legacy local counter only when the preferred dynamic counter is absent', () => {
  const text = campaignAnswer({ state: 'interrupted', counts: { localTestsPerformed: 4, localTestSuites: 2, localTestsFailed: 1 } });
  assert.match(text, /本地动态测试 4 项，测试套件 2 个（失败 1）/);
});
test('active campaigns preserve specific test routing and structured status interpretation',()=>{
  const snapshot={campaign:{state:'running',counts:{sourceReviews:3}},staticAnalysis:{localSecurityTests:{requiredComplete:true,complete:true,suites:[]}}};
  assert.match(answerQuestion(snapshot,'当前测试情况').answer,/Hardhat/);
  const current=answerQuestion(snapshot,'当前情况');
  assert.match(current.answer,/旧版来源审查 3 份/);
  assert.equal(current.authoritative,false);
  assert.equal(answerQuestion(snapshot,'一小时采集情况').authoritative,true);
});
