#!/usr/bin/env node
// Executes in an isolated Hardhat EVM. A fixed-block fork is opt-in and must
// pass the boundary probe; no transaction is ever sent to the upstream RPC.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = process.env.CAMPAIGN_PROJECT_ROOT || path.resolve(__dirname, '..');
const { LOCAL_CHAIN_ID, parseForkConfig, publicBoundary } = require('./dynamic-execution-boundary.cjs');
const forkConfig = parseForkConfig(process.env);
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
const hre = require(path.join(deps, 'hardhat'));
const { BrowserProvider, ContractFactory, Interface } = require(path.join(deps, 'ethers'));
const solc = require(path.join(root, 'flare-scan/tools/solc-0828/node_modules/solc')).setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const {runtimeLocations,effectSiteId}=require('./evm-source-map.cjs');
const {createTraceSampler,markTraceSampleComplete,traceSummaryEvidenceState,traceSourceAttributionEvidenceState,installHardhatFrameIdentityCapture,alignTraceFrameIdentities,stableHash,summarizeTraceSteps,traceEvidenceState,createTransactionEvidenceTracker,captureTraceSafely,traceSupportHash,MAX_TRACE_STEPS}=require('./dynamic-trace-support.cjs');
const mocks = `pragma solidity >=0.8.17 <0.9.0;
contract TestToken {
  uint8 public constant decimals=6;
  mapping(address=>uint256) public balanceOf;
  mapping(address=>mapping(address=>uint256)) public allowance;
  bool public fee; address public reenter; bool public reentryBlocked;
  function mint(address to,uint n) external {balanceOf[to]+=n;}
  function setFee(bool b) external {fee=b;}
  function setReenter(address a) external {reenter=a;}
  function approve(address to,uint n) external returns(bool) {allowance[msg.sender][to]=n;return true;}
  function transfer(address to,uint n) external returns(bool) {_move(msg.sender,to,n);return true;}
  function transferFrom(address from,address to,uint n) external returns(bool) {
    allowance[from][msg.sender]-=n;
    if(reenter!=address(0)) { (bool ok,)=reenter.call(abi.encodeWithSignature("mintChip(address,uint256)",from,1)); require(!ok,"REENTRY_UNEXPECTEDLY_SUCCEEDED"); reentryBlocked=true; }
    _move(from,to,n); return true;
  }
  function _move(address from,address to,uint n) internal {balanceOf[from]-=n;balanceOf[to]+=fee?n-1:n;}
}
contract TestRegistry {
  address public handler;
  function setHandler(address a) external {handler=a;}
  function validBurnHandlerForChip(address) external view returns(address) {return handler;}
  function getValidSpenderTargetForChipByRole(address,string calldata) external pure returns(address) {return address(0);}
}
contract DenyController {
  function isPoolMintController() external pure returns(bool){return true;}
  function isPoolBurnController() external pure returns(bool){return true;}
  function informMintRequest(address,address,uint,uint) external pure returns(bool){return false;}
  function informBurnRequest(address,address,uint,uint) external pure returns(bool){return false;}
}
contract RevertingHandler {
  function handleBurn(address,uint,uint,bytes calldata) external payable {revert("TEST_HANDLER_FAILURE");}
}
interface ILocalAMTPool { function deposit(uint256,string calldata) external payable returns(uint256); }
contract LocalAMTConfig {
  mapping(bytes32=>address) private entries;
  function setContract(bytes32 key,address value) external {entries[key]=value;}
  function getContract(bytes32 key) external view returns(address){return entries[key];}
}
contract LocalArtMetis {
  uint256 public totalSupply; mapping(address=>uint256) public balanceOf;
  function mint(address to,uint256 amount) external {totalSupply+=amount;balanceOf[to]+=amount;}
  function burn(address from,uint256 amount) external {balanceOf[from]-=amount;totalSupply-=amount;}
}
contract LocalRewardPool {
  address public pool; uint256 public reward; uint256 public reentryValue; bool public reenter; bool private entered; bool private claimed;
  function configure(address p,uint256 r,uint256 value,bool enabled) external {pool=p;reward=r;reentryValue=value;reenter=enabled;entered=false;claimed=false;}
  function claimReward() external returns(uint256) {
    if(reenter&&!entered&&!claimed) {entered=true;ILocalAMTPool(pool).deposit{value:reentryValue}(0,"callback");entered=false;claimed=true;(bool ok,)=msg.sender.call{value:reward}("");require(ok,"reward transfer failed");return reward;}
    if(!reenter&&!claimed&&reward>0) {claimed=true;(bool ok,)=msg.sender.call{value:reward}("");require(ok,"reward transfer failed");return reward;}
    return 0;
  }
  receive() external payable {}
}
contract LocalAMTProxy {
  bytes32 private constant SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  constructor(address implementation,bytes memory initData) payable {assembly{sstore(SLOT,implementation)}(bool ok,bytes memory reason)=implementation.delegatecall(initData);require(ok,string(reason));}
  fallback() external payable {assembly {let implementation := sload(SLOT) calldatacopy(0,0,calldatasize()) let ok := delegatecall(gas(),implementation,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize()) switch ok case 0 {revert(0,returndatasize())} default {return(0,returndatasize())}}}
  receive() external payable {}
}
contract LocalReenteringFeeReceiver {
  address public pool; uint256 public depositValue; bool private entered; uint256 public callbacks;
  constructor(address p,uint256 value) payable {pool=p;depositValue=value;}
  receive() external payable {callbacks++;if(!entered){entered=true;ILocalAMTPool(pool).deposit{value:depositValue}(0,"fee-callback");entered=false;}}
}`;

(async () => {
  const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const target = process.argv[3];
  const args=process.argv.slice(4);let extraPath=null,sourceAliases={};
  for(let i=0;i<args.length;i++){if(args[i]==='--dependency')extraPath=args[++i];else if(args[i]==='--source-aliases')sourceAliases=JSON.parse(fs.readFileSync(args[++i],'utf8'));else throw Error(`Unknown harness option ${args[i]}`);}
  let rewardTarget=null;
  if(extraPath){
    const extra=JSON.parse(fs.readFileSync(extraPath,'utf8')),extraSources=extra.sources||{},variants=new Map();
    for(const [file,source] of Object.entries(extraSources))if(input.sources[file]&&input.sources[file].content!==source.content)variants.set(file,`__verified_variants__/${crypto.createHash('sha256').update(file).digest('hex').slice(0,16)}.sol`);
    const mappedFiles=new Map(Object.keys(input.sources).map(file=>[file,file]));
    for(const file of Object.keys(extraSources))mappedFiles.set(file,variants.get(file)||file);
    const rewriteImports=(file,mappedFile,content)=>content.replace(/\bimport\s+(?:[^;]*?\bfrom\s+)?([\"'])([^\"']+)\1/g,(whole,quote,spec)=>{
      const resolved=spec.startsWith('.')?path.posix.normalize(path.posix.join(path.posix.dirname(file),spec)):spec;
      const replacement=mappedFiles.get(resolved);if(!replacement)return whole;
      let rel=path.posix.relative(path.posix.dirname(mappedFile),replacement);if(!rel.startsWith('.'))rel='./'+rel;
      return whole.replace(spec,rel);
    });
    for(const [file,source] of Object.entries(extraSources)){const mapped=variants.get(file)||file;input.sources[mapped]={content:rewriteImports(file,mapped,source.content)};}
    const targets=extra.metadata?.settings?.compilationTarget||{},targetEntry=Object.entries(targets).find(([,name])=>name==='AMTRewardPool');
    rewardTarget=targetEntry?(variants.get(targetEntry[0])||targetEntry[0]):null;
    if(!rewardTarget||!input.sources[rewardTarget])throw Error('Additional verified source is not an AMTRewardPool compilation target');
  }
  const targetContent=target&&input.sources[target]?.content;
  const engineTarget=typeof targetContent==='string'&&targetContent.includes('contract EngineChip ');
  const amtTarget=typeof targetContent==='string'&&targetContent.includes('contract AMTDepositPool ');
  if (!engineTarget&&!amtTarget) throw Error('Unsupported local test target');
  const sourceHash = stableHash(input.sources);
  input.sources['__local_tests__/Mocks.sol'] = {content:mocks};
  input.settings ||= {};
  const outputSelection={'*':{'*':['abi','evm.bytecode.object']}};
  outputSelection[target]={[engineTarget?'EngineChip':'AMTDepositPool']:['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.sourceMap']};
  if(rewardTarget)outputSelection[rewardTarget]={AMTRewardPool:['abi','evm.bytecode.object']};
  input.settings.outputSelection=outputSelection;
  const compiled=JSON.parse(solc.compile(JSON.stringify(input)));
  const errors=(compiled.errors || []).filter(x=>x.severity==='error');
  if(errors.length) throw Error(errors.map(x=>x.formattedMessage).join('\n'));
  if (!forkConfig.valid) throw Error(`execution boundary configuration invalid: ${forkConfig.reason}`);
  const hardhatFork = hre.network.config.forking;
  if (forkConfig.configured !== Boolean(hardhatFork)) throw Error('execution boundary configuration was not applied by Hardhat');
  if (hre.network.name !== 'hardhat' || hre.network.config.url) throw Error('Unsupported dynamic EVM network configuration');
  const provider=new BrowserProvider(hre.network.provider);
  const observedChainId=Number((await provider.getNetwork()).chainId);
  if (observedChainId !== LOCAL_CHAIN_ID) throw Error('Unexpected local chain');
  let forkProbe={state:'not_performed',reason:'fork_not_requested'},forkBlockHash=null;
  if (forkConfig.configured) {
    const blockTag=`0x${forkConfig.blockNumber.toString(16)}`;
    const first=await provider.send('eth_getBlockByNumber',[blockTag,false]);
    const second=await provider.send('eth_getBlockByNumber',[blockTag,false]);
    if (!first || !second || first.hash !== second.hash || first.number?.toLowerCase() !== blockTag.toLowerCase()) {
      throw Error('fixed fork block probe failed or was not stable');
    }
    forkBlockHash=first.hash;
    forkProbe={state:'verified',method:'eth_getBlockByNumber',blockNumber:forkConfig.blockNumber,blockHash:first.hash,repeatHashMatch:true,readOnly:true};
  }
  const executionBoundary=publicBoundary(forkConfig,{chainId:observedChainId,
    forkState:forkConfig.configured?'verified':'not_performed',forkProbe,blockHash:forkBlockHash});
  provider.pollingInterval=10;
  const targetArtifact=compiled.contracts[target][engineTarget?'EngineChip':'AMTDepositPool'];
  const targetInterface=new Interface(targetArtifact.abi);
  const rawSourceLocations=runtimeLocations(targetArtifact.evm.deployedBytecode.object,targetArtifact.evm.deployedBytecode.sourceMap,compiled.sources,input.sources);
  const sourceLocations=new Map([...rawSourceLocations].map(([pc,loc])=>[pc,{...loc,file:sourceAliases[loc.file]||loc.file}]));
  const traces=[],traceSampling=[],sourceCoverage=new Map(),traceSampler=createTraceSampler(),transactionEvidence=createTransactionEvidenceTracker(),sampledSelectors=new Set(),dynamicTargets=new Map();
  const frameIdentityCapture=installHardhatFrameIdentityCapture(hre.network.provider,(tx)=>typeof tx?.to==='string'&&dynamicTargets.has(tx.to.toLowerCase()));
  const traceStats = {requested:0, valid:0, invalid:0, skipped:0, truncated:0, stepLimited:0, unknownOpcodeCount:0, unknownOpcodes:new Set(), totalSteps:0, processedSteps:0, reportedEffects:0, totalEffects:0, targetEffects:0, unmappedTargetEffects:0, nonTargetEffects:0, mappedEffects:0, unmappedEffects:0, frameIdentityAvailable:0, frameIdentityPartial:0, frameIdentityUnavailable:0, targetCodeStepCount:0, targetFrameDepthMismatchCount:0};
  async function traceTransaction(receipt,targetAddress,transactionId=null){
    const sample={scenario:activeScenario,transactionId:typeof transactionId==='string'?transactionId:null,transactionHash:receipt?.hash||null,selector:null,method:null,outcome:null,calldata:null};
    const evidence=await captureTraceSafely(receipt?.hash, async()=>{
      if(typeof receipt?.hash!=='string'||!receipt.hash)throw Error('transaction hash unavailable for trace lookup');
      const txData=await provider.getTransaction(receipt.hash);
      if(!txData)throw Error('transaction unavailable for selector lookup');
      const calldata=txData.data||'0x';
      sample.calldata=calldata;
      const selector=calldata.length>=10?calldata.slice(0,10):'<fallback>',targetName=engineTarget?'EngineChip':'AMTDepositPool';
      let fragment=null;
      if(selector!=='<fallback>'){
        try{fragment=targetInterface.getFunction(selector);}catch{}
      }
      sample.selector=selector;sample.method=fragment?fragment.format('sighash'):selector==='\u003cfallback\u003e'?'fallback':'unknown';
      const receiptOutcome=receipt.status===0||receipt.status===0n||receipt.status==='0x0'?'reverted':
        receipt.status===1||receipt.status===1n||receipt.status==='0x1'?'committed':null;
      sample.outcome=receiptOutcome;
      if(receiptOutcome&&traceSampler.has(targetName,selector,receiptOutcome==='reverted')){traceStats.skipped++;sample.state='skipped';sample.reason='selector_outcome_sample_limit';frameIdentityCapture.discard(receipt.hash);return null;}
      const target=dynamicTargets.get(targetAddress.toLowerCase());
      if(!target||!Number.isInteger(target.depth)||target.depth<1)throw Error('target trace frame configuration unavailable');
      traceStats.requested++;
      const trace=await hre.network.provider.send('debug_traceTransaction',[receipt.hash,{disableMemory:true,disableStorage:true,disableStack:true}]);
      const actualOutcome=trace.failed?'reverted':'committed';
      if(receiptOutcome&&receiptOutcome!==actualOutcome)throw Error('trace outcome does not match transaction receipt');
      if(!receiptOutcome&&traceSampler.has(targetName,selector,trace.failed)){traceStats.skipped++;sample.outcome=trace.failed?'reverted':'committed';sample.state='skipped';sample.reason='selector_outcome_sample_limit';frameIdentityCapture.discard(receipt.hash);return null;}
      sample.outcome=trace.failed?'reverted':'committed';
      const frameIdentity=alignTraceFrameIdentities(trace,frameIdentityCapture.take(receipt.hash));
      const summary=summarizeTraceSteps(trace,target.depth,sourceLocations,sourceCoverage,undefined,undefined,{...frameIdentity,targetCodeAddress:target.codeAddress});
      sampledSelectors.add(selector);
      traceStats.valid++;traceStats.totalSteps+=summary.steps;traceStats.processedSteps+=summary.processedSteps;traceStats.totalEffects+=summary.effectCount;traceStats.reportedEffects+=summary.effects.length;if(summary.effectsTruncated||summary.stepsTruncated)traceStats.truncated++;if(summary.stepsTruncated)traceStats.stepLimited++;
      traceStats.targetEffects+=summary.targetEffectCount;traceStats.unmappedTargetEffects+=summary.unmappedTargetEffects;traceStats.nonTargetEffects+=summary.nonTargetEffects;traceStats.mappedEffects+=summary.mappedEffects;traceStats.unmappedEffects+=summary.unmappedEffects;traceStats.targetCodeStepCount+=summary.targetCodeStepCount;traceStats.targetFrameDepthMismatchCount+=summary.targetFrameDepthMismatchCount;if(summary.frameIdentityState==='available')traceStats.frameIdentityAvailable++;else if(summary.frameIdentityState==='partial')traceStats.frameIdentityPartial++;else traceStats.frameIdentityUnavailable++;traceStats.unknownOpcodeCount+=summary.unknownOpcodeCount;for(const opcode of summary.unknownOpcodes)traceStats.unknownOpcodes.add(opcode);
      const evidence={transactionHash:receipt.hash,targetAddress,targetDepth:target.depth,targetCodeAddress:target.codeAddress,scenario:sample.scenario,selector,method:sample.method,state:traceSummaryEvidenceState(summary),traceValid:true,failed:trace.failed,gas:trace.gas,...summary,reportedEffectCount:summary.effects.length,sourceScope:engineTarget?'depth-1 target runtime; frame code address verified':'depth-2 delegatecalled implementation runtime; implementation code address verified; proxy dispatch is outside the mapped target'};
      markTraceSampleComplete(traceSampler,targetName,selector,trace.failed,evidence);
      sample.state='sampled';sample.traceState=evidence.state;
      return evidence;
    },()=>{traceStats.invalid++;frameIdentityCapture.discard(receipt?.hash);});
    if(sample.state==='skipped'){
      transactionEvidence.skipped(sample.selector, sample.scenario,{transactionId:sample.transactionId,calldata:sample.calldata});
      traceSampling.push(sample);
      return null;
    }
    transactionEvidence.trace(sample.selector, evidence, sample.scenario,{transactionId:sample.transactionId,calldata:sample.calldata});
    if(evidence?.traceValid===true)traceSampling.push({...sample});
    else if(evidence)traceSampling.push({...sample,state:'unavailable',reason:evidence.reason||'invalid_trace'});
    return evidence;
  }
  const admin=await provider.getSigner(0), user=await provider.getSigner(1), adminAddress=await admin.getAddress(), userAddress=await user.getAddress();
  async function deploy(file,name,args=[],overrides={}) {
    const a=compiled.contracts[file][name];
    const c=await new ContractFactory(a.abi,a.evm.bytecode.object,admin).deploy(...args,{gasLimit:12000000,...overrides});
    await c.waitForDeployment(); return c;
  }
  async function tx(p) {
    const sent=await p,targetAddress=sent.to;
    const targetCall=typeof targetAddress==='string'&&dynamicTargets.has(targetAddress.toLowerCase());
    let outcomeRecorded=false;
    const transactionEvidenceId=targetCall?transactionEvidence.submitted(activeScenario,{transactionHash:sent.hash,from:sent.from,to:sent.to,value:sent.value,calldata:sent.data,sequenceId:activeScenario}):null;
    const receiptMetadata=async(receipt)=>{
      if (!receipt || typeof receipt !== 'object') return {};
      const metadata={
        blockNumber:receipt.blockNumber,
        blockHash:receipt.blockHash,
        events:receipt.logs,
      };
      try {
        if (receipt.blockNumber !== undefined) {
          const block=await provider.getBlock(receipt.blockNumber);
          if (block && block.timestamp !== undefined) metadata.blockTime=block.timestamp;
        }
      } catch {}
      return metadata;
    };
    const recordOutcome=async(receipt)=>{
      if(!targetCall||outcomeRecorded)return;
      const status=receipt?.status;
      const committed=status===1||status===1n||status==='0x1';
      const reverted=status===0||status===0n||status==='0x0';
      const metadata={transactionId:transactionEvidenceId,...await receiptMetadata(receipt)};
      transactionEvidence.outcome(committed?'committed':reverted?'reverted':'unknown',metadata);
      outcomeRecorded=true;
    };
    let receipt;
    try {
      receipt=await sent.wait();
      await recordOutcome(receipt);
    } catch(error) {
      await recordOutcome(error.receipt||null);
      if(targetCall){const trace=await traceTransaction(error.receipt||{hash:sent.hash},targetAddress,transactionEvidenceId);if(trace)traces.push(trace);}
      throw error;
    }
    if(targetCall){const trace=await traceTransaction(receipt,targetAddress,transactionEvidenceId);if(trace)traces.push(trace);}
    return receipt;
  }
  async function engineFixture(){
    const token=await deploy('__local_tests__/Mocks.sol','TestToken'), registry=await deploy('__local_tests__/Mocks.sol','TestRegistry');
    const chip=await deploy(target,'EngineChip',[await registry.getAddress(),'Local Test Chip','LTC',await token.getAddress()]);
    const address=await chip.getAddress();dynamicTargets.set(address.toLowerCase(),{depth:1,codeAddress:address.toLowerCase()});
    await tx(token.mint(userAddress,100000000n));
    await tx(token.connect(user).approve(await chip.getAddress(),100000000n));
    return {token,registry,chip,address};
  }
  const results=[];
  let deterministicFuzz=null;
  let activeScenario='fixture_setup';
  const unavailableFailureField=(reason)=>({state:'unavailable',reason});
  const availableFailureField=(value)=>({state:'available',value});
  function buildFailureEvidence(snapshot,failedResults,traceRows) {
    if(!Array.isArray(failedResults)||failedResults.length===0)return {schemaVersion:1,state:'not_performed',samples:[],reason:'no_failed_scenario_assertions'};
    const dimensions=['seed','caller','role','parameters','value','transactionSequence','blockTime','initialState','dependencyCodeHashes','trace','stateDiff','events','assetChanges','permissionChanges','profit','cost','minimumSequence','replayCommand'];
    const seed=deterministicFuzz?.seed;
    const replayAvailable=typeof process.argv[2]==='string'&&fs.existsSync(process.argv[2])&&typeof process.env.CAMPAIGN_SOLJSON==='string'&&process.env.CAMPAIGN_SOLJSON.length>0;
    return {schemaVersion:1,state:'partial',scope:'failed local harness assertions; captured transaction and trace references only; no exploitability inference',samples:failedResults.map(row=>{
      const scenario=typeof row.name==='string'&&row.name?row.name:'unknown_scenario';
      const txs=(snapshot.transactions||[]).filter(tx=>tx?.scenario===scenario||tx?.sequenceId===scenario);
      const hashes=new Set(txs.map(tx=>tx?.transactionHash).filter(x=>typeof x==='string'));
      const boundTraces=(traceRows||[]).filter(trace=>hashes.has(trace?.transactionHash)).map(trace=>({transactionHash:trace.transactionHash,state:trace.state,traceValid:trace.traceValid}));
      const fields=Object.fromEntries(dimensions.map(name=>[name,unavailableFailureField('not_captured_by_dynamic_harness')]));
      if(seed!==undefined&&seed!==null&&(/sequence|fuzz|序列/i.test(scenario)))fields.seed=availableFailureField(seed);
      if(txs.length){
        const callers=[...new Set(txs.map(tx=>tx?.from).filter(x=>typeof x==='string'))].sort();
        fields.caller=callers.length?availableFailureField(callers):unavailableFailureField('caller_not_recorded');
        fields.value=txs.every(tx=>typeof tx?.value==='string')?availableFailureField(txs.map(tx=>tx.value)):unavailableFailureField('transaction_value_not_fully_recorded');
        fields.parameters=availableFailureField(txs.map(tx=>({selector:tx.selector,rawCalldata:tx.rawCalldata,rawCalldataState:tx.rawCalldataState})));
        fields.transactionSequence=availableFailureField(txs);
        const blockTimes=txs.map(tx=>tx?.blockTime);
        fields.blockTime=blockTimes.length&&blockTimes.every(value=>typeof value==='string')
          ?availableFailureField(blockTimes):unavailableFailureField('block_time_not_recorded_for_every_transaction');
        const eventRows=txs.map(tx=>tx?.events);
        fields.events=txs.length&&txs.every(tx=>tx?.eventsState==='available')
          ?availableFailureField(eventRows):unavailableFailureField('receipt_events_not_recorded_for_every_transaction');
        const assetChanges=txs.flatMap(tx=>Array.isArray(tx?.assetChanges)?tx.assetChanges:[]);
        fields.assetChanges=txs.every(tx=>['available','not_observed'].includes(tx?.assetChangesState))
          ?(assetChanges.length?availableFailureField({source:'receipt_event',stateAuthority:'not_balance_diff',events:assetChanges}):unavailableFailureField('no_standard_erc20_transfer_events_observed'))
          :unavailableFailureField('receipt_events_not_recorded_for_every_transaction');
      }else fields.transactionSequence=unavailableFailureField('no_transactions_bound_to_failed_scenario');
      fields.trace=boundTraces.length?availableFailureField(boundTraces):unavailableFailureField('no_trace_bound_to_failed_scenario');
      if(replayAvailable)fields.replayCommand=availableFailureField({argv:['node',...process.argv.slice(1)],cwd:root,env:{CAMPAIGN_SOLJSON:process.env.CAMPAIGN_SOLJSON||null}});
      return {scenario,failure:{state:'observed',message:String(row.error||'scenario assertion failed').slice(0,500)},confirmedVulnerability:false,fields};
    })};
  }
  async function check(name,body,setup=engineFixture){const start=Date.now();activeScenario=name;try {await body(await setup()); results.push({name,state:'passed',durationMs:Date.now()-start});}catch(e){results.push({name,state:'failed',error:e.message.slice(0,500),durationMs:Date.now()-start});}finally{activeScenario='fixture_setup';}}
  const expectRevert=async(p)=>assert.rejects(async()=>tx(p));
  if(engineTarget){
  const fixture=engineFixture;
  await check('非管理员不能暂停铸币',async({chip})=>{await expectRevert(chip.connect(user).setIsMintingPaused(true,{gasLimit:1000000})); assert.equal(await chip.isMintingPaused(),false);assert.equal(await chip.admin(),adminAddress);});
  await check('6位精度资产铸造赎回资金守恒',async({chip,token,address})=>{const before=await token.balanceOf(userAddress);await tx(chip.connect(user).mintChip(userAddress,1234567n));assert.equal(await chip.totalSupply(),1234567000000000000n);await tx(chip.connect(user).burnChip(userAddress,await chip.balanceOf(userAddress)));assert.equal(await chip.totalSupply(),0n);assert.equal(await token.balanceOf(address),0n);assert.equal(await token.balanceOf(userAddress),before);});
  await check('转账扣费资产被拒绝且余额回滚',async({chip,token,address})=>{await tx(token.setFee(true));const before=await token.balanceOf(userAddress);await expectRevert(chip.connect(user).mintChip(userAddress,10000n,{gasLimit:1000000}));assert.equal(await chip.totalSupply(),0n);assert.equal(await token.balanceOf(address),0n);assert.equal(await token.balanceOf(userAddress),before);});
  await check('无 ABI 原始 calldata 未知 selector 执行并回滚',async({chip,token,address})=>{
    const rawCalldata='0xdeadbeef00';
    await expectRevert(user.sendTransaction({to:address,data:rawCalldata,gasLimit:1000000}));
    assert.equal(await chip.totalSupply(),0n);
    assert.equal(await token.balanceOf(address),0n);
    const row=transactionEvidence.snapshot().transactions.find(tx=>tx.scenario==='无 ABI 原始 calldata 未知 selector 执行并回滚'&&tx.rawCalldata===rawCalldata);
    assert.ok(row,'raw calldata transaction should be retained without ABI decoding');
    assert.equal(row.selector,rawCalldata.slice(0,10));
    assert.equal(row.rawCalldataState,'available');
    assert.equal(row.outcome,'reverted');
  });
  await check('暂停阻止铸币但保留赎回',async({chip,token})=>{await tx(chip.connect(user).mintChip(userAddress,10000n));await tx(chip.setIsMintingPaused(true));await expectRevert(chip.connect(user).mintChip(userAddress,10000n,{gasLimit:1000000}));await tx(chip.connect(user).burnChip(userAddress,await chip.balanceOf(userAddress)));assert.equal(await chip.totalSupply(),0n);assert.equal(await token.balanceOf(userAddress),100000000n);});
  await check('铸币控制器拒绝时已转入资金回滚',async({chip,token,address})=>{const ctrl=await deploy('__local_tests__/Mocks.sol','DenyController');await tx(chip.setMintController(await ctrl.getAddress()));await expectRevert(chip.connect(user).mintChip(userAddress,10000n,{gasLimit:1000000}));assert.equal(await token.balanceOf(address),0n);assert.equal(await token.balanceOf(userAddress),100000000n);assert.equal(await chip.totalSupply(),0n);});
  await check('赎回控制器拒绝时份额与抵押不变',async({chip,token,address})=>{await tx(chip.connect(user).mintChip(userAddress,10000n));const before=await chip.totalSupply(),ctrl=await deploy('__local_tests__/Mocks.sol','DenyController');await tx(chip.setBurnController(await ctrl.getAddress()));await expectRevert(chip.connect(user).burnChip(userAddress,before,{gasLimit:1000000}));assert.equal(await chip.balanceOf(userAddress),before);assert.equal(await chip.totalSupply(),before);assert.equal(await token.balanceOf(address),10000n);});
  await check('代币转账回调重入被拒绝',async({chip,token,address})=>{await tx(token.setReenter(address));await tx(chip.connect(user).mintChip(userAddress,10000n,{gasLimit:1000000}));assert.equal(await token.reentryBlocked(),true);assert.equal(await chip.totalSupply(),10000000000000000n);assert.equal(await token.balanceOf(address),10000n);});
  await check('赎回后处理器失败时整笔操作回滚',async({chip,token,registry,address})=>{const h=await deploy('__local_tests__/Mocks.sol','RevertingHandler');await tx(registry.setHandler(await h.getAddress()));await tx(chip.setBurnHandler(await h.getAddress()));await tx(chip.connect(user).mintChip(userAddress,10000n));const before=await chip.totalSupply();await expectRevert(chip.connect(user).burnChipAndCall(before,'0x',{gasLimit:1000000}));assert.equal(await chip.totalSupply(),before);assert.equal(await chip.balanceOf(userAddress),before);assert.equal(await token.balanceOf(address),10000n);assert.equal(await token.balanceOf(await h.getAddress()),0n);});
  const fuzzSeed=0x5ec0a11;
  await check('确定性状态序列：总供应量、持有人份额与抵押余额守恒',async({chip,token,address})=>{
    const other=await provider.getSigner(2),otherAddress=await other.getAddress(),scale=10n**12n;
    await tx(token.mint(otherAddress,100000000n));
    await tx(token.connect(other).approve(address,100000000n));
    const actors=[{signer:user,address:userAddress},{signer:other,address:otherAddress}];
    const expected=new Map(actors.map(x=>[x.address,0n]));
    let state=fuzzSeed>>>0,operations=0,invariantChecks=0,actionCounts={mint:0,transfer:0,burn:0};
    const random=()=>{state=(Math.imul(1664525,state)+1013904223)>>>0;return state;};
    for(let i=0;i<64;i++){
      let index=random()%actors.length,actor=actors[index],recipient=actors[1-index],balance=expected.get(actor.address),action=['mint','transfer','burn'][i%3];
      if(action!=='mint'&&balance===0n){index=1-index;actor=actors[index];recipient=actors[1-index];balance=expected.get(actor.address);}
      if(action==='mint'){
        const raw=BigInt(1+random()%10000);
        if(await token.balanceOf(actor.address)>=raw){
          await tx(chip.connect(actor.signer).mintChip(actor.address,raw,{gasLimit:1000000}));
          expected.set(actor.address,balance+raw*scale);operations++;actionCounts.mint++;
        }
      }else if(action==='transfer'){
        const units=balance/scale;
        if(units>0n){const shares=BigInt(1+random()%Number(units))*scale;await tx(chip.connect(actor.signer).transfer(recipient.address,shares));expected.set(actor.address,balance-shares);expected.set(recipient.address,expected.get(recipient.address)+shares);operations++;actionCounts.transfer++;}
      }else{
        const units=balance/scale;
        if(units>0n){const shares=BigInt(1+random()%Number(units))*scale;await tx(chip.connect(actor.signer).burnChip(actor.address,shares));expected.set(actor.address,balance-shares);operations++;actionCounts.burn++;}
      }
      const total=[...expected.values()].reduce((sum,value)=>sum+value,0n);
      assert.equal(await chip.totalSupply(),total,`totalSupply invariant at step ${i}`);
      for(const holder of actors)assert.equal(await chip.balanceOf(holder.address),expected.get(holder.address),`holder balance invariant at step ${i}`);
      assert.equal((await token.balanceOf(address))*scale,total,`collateral invariant at step ${i}`);
      invariantChecks++;
    }
    assert.equal(actionCounts.mint>0,true);assert.equal(actionCounts.transfer>0,true);assert.equal(actionCounts.burn>0,true);
    deterministicFuzz={seed:`0x${fuzzSeed.toString(16)}`,requestedOperations:64,executedOperations:operations,actionCounts,invariantChecks,properties:['totalSupply equals tracked holder balances','each holder balance matches the reference model','underlying collateral equals scaled share supply']};
  });
  } else {
    const amount=(x)=>BigInt(x)*10n**18n;
    async function amtFixture({actualReward=false,feeReceiver=adminAddress}={}){
      const config=await deploy('__local_tests__/Mocks.sol','LocalAMTConfig'),art=await deploy('__local_tests__/Mocks.sol','LocalArtMetis'),impl=await deploy(target,'AMTDepositPool');
      const iface=new (require(path.join(deps,'ethers')).Interface)(compiled.contracts[target].AMTDepositPool.abi);
      const init=iface.encodeFunctionData('initialize',[await config.getAddress()]);
      const proxy=await deploy('__local_tests__/Mocks.sol','LocalAMTProxy',[await impl.getAddress(),init]);
      dynamicTargets.set((await proxy.getAddress()).toLowerCase(),{depth:2,codeAddress:(await impl.getAddress()).toLowerCase()});
      const pool=new (require(path.join(deps,'ethers')).Contract)(await proxy.getAddress(),compiled.contracts[target].AMTDepositPool.abi,admin);
      const ethers=require(path.join(deps,'ethers'));await tx(config.setContract(ethers.keccak256(ethers.toUtf8Bytes('ART_METIS')),await art.getAddress()));
      let reward;
      if(actualReward){
        if(!rewardTarget)throw Error('Missing chain-verified AMTRewardPool sources');
        const rewardImpl=await deploy(rewardTarget,'AMTRewardPool'),rewardAbi=compiled.contracts[rewardTarget].AMTRewardPool.abi;
        const rewardInit=new ethers.Interface(rewardAbi).encodeFunctionData('initialize',[await config.getAddress(),feeReceiver,5n*10n**17n]);
        const rewardProxy=await deploy('__local_tests__/Mocks.sol','LocalAMTProxy',[await rewardImpl.getAddress(),rewardInit]);
        reward=new ethers.Contract(await rewardProxy.getAddress(),rewardAbi,admin);
        await tx(config.setContract(ethers.keccak256(ethers.toUtf8Bytes('AMT_REWARD_POOL')),await reward.getAddress()));
        await tx(config.setContract(ethers.keccak256(ethers.toUtf8Bytes('AMT_DEPOSIT_POOL')),await pool.getAddress()));
      }else{
        reward=await deploy('__local_tests__/Mocks.sol','LocalRewardPool');
        await tx(config.setContract(ethers.keccak256(ethers.toUtf8Bytes('AMT_REWARD_POOL')),await reward.getAddress()));
        await tx(reward.configure(await pool.getAddress(),0,0,false));
      }
      await tx(pool.connect(user).deposit(0,'seed',{value:amount(100)}));
      return {config,art,reward,pool};
    }
    await check(rewardTarget?'Metis 实际部署源码：普通手续费收款时正常分账':'Metis 存款池：无回调时正常质押与奖励顺序',async({art,reward,pool})=>{
      if(rewardTarget){await tx(admin.sendTransaction({to:await reward.getAddress(),value:amount(100)}));await tx(pool.connect(user).deposit(0,'normal',{value:amount(1)}));assert.equal(await art.balanceOf(userAddress),amount(100)+amount(100)/150n);assert.equal(await pool.totalDeposits(),amount(151));assert.equal(await provider.getBalance(await reward.getAddress()),0n);return;}
      await tx(admin.sendTransaction({to:await reward.getAddress(),value:amount(100)}));
      await tx(reward.configure(await pool.getAddress(),amount(100),amount(100),false));
      await tx(pool.connect(user).deposit(0,'normal',{value:amount(1)}));
      assert.equal(await art.balanceOf(userAddress),amount(100)+(amount(1)*amount(100)/amount(200)));
      assert.equal(await art.balanceOf(userAddress),amount(100)+amount(0)+500000000000000000n);
      assert.equal(await pool.totalDeposits(),amount(201));
    },()=>amtFixture({actualReward:!!rewardTarget}));
    await check(rewardTarget?'Metis 实际部署源码：费用收款回调导致操作回滚':'Metis 存款池：模拟奖励池回调时检查份额定价偏差',async({art,reward,pool})=>{
      if(rewardTarget){
        const receiver=await deploy('__local_tests__/Mocks.sol','LocalReenteringFeeReceiver',[await pool.getAddress(),amount(1)],{value:amount(1)});
        await tx(reward.setFeeReceiver(await receiver.getAddress()));await tx(admin.sendTransaction({to:await reward.getAddress(),value:amount(100)}));
        await assert.rejects(async()=>tx(pool.connect(user).deposit(0,'outer',{value:amount(1),gasLimit:5000000})),/TransferHelper: Sending ETH failed/);
        assert.equal(await art.balanceOf(await receiver.getAddress()),0n);
        assert.equal(await art.balanceOf(userAddress),amount(100));
        assert.equal(await pool.totalDeposits(),amount(100));
        assert.equal(await provider.getBalance(await reward.getAddress()),amount(100));
        assert.equal(await provider.getBalance(await pool.getAddress()),amount(100));
        assert.equal(await receiver.callbacks(),0n);
        return;
      }
      await tx(admin.sendTransaction({to:await reward.getAddress(),value:amount(200)}));
      await tx(reward.configure(await pool.getAddress(),amount(100),amount(100),true));
      await tx(pool.connect(user).deposit(0,'outer',{value:amount(1)}));
      const callbackShares=await art.balanceOf(await reward.getAddress());
      const fairShares=amount(50);
      assert.equal(callbackShares,amount(100),'callback deposit shares under the pre-reward exchange rate');
      assert.equal(callbackShares-fairShares,amount(50),'conditional mock over-mint relative to reward-first pricing');
      assert.equal(await pool.totalDeposits(),amount(301));
      assert.equal(await art.totalSupply(),amount(200)+(amount(1)*amount(200)/amount(300)));
    },()=>amtFixture({actualReward:!!rewardTarget}));
  }
  const transactionSnapshot=transactionEvidence.snapshot();
  const assertionState=results.length>0&&results.every(x=>x.state==='passed')?'passed':'failed';
  const failureEvidence=buildFailureEvidence(transactionSnapshot,results.filter(x=>x.state==='failed'),traces);
  // A passing assertion suite is not complete execution evidence when a
  // target trace was unavailable or sampling had to be skipped. Preserve both
  // states so callers cannot promote an incomplete run to a full pass.
  const reportState=assertionState!=='passed'?'failed':
    transactionSnapshot.state==='not_performed'?'unavailable':
    transactionSnapshot.state==='unavailable'?'unavailable':
    transactionSnapshot.state==='partial'?'partial':'passed';
  const report={
    state:reportState,
    assertionState,
    evidenceState:transactionSnapshot.state,
    suite:engineTarget?'EngineChip isolated defensive invariants':rewardTarget?'Metis contracts actual verified source integration':'AMTDepositPool reward callback hypothesis reproduction',
    analysisType:engineTarget?'target-specific deterministic invariant sequence with sampled opcode traces':'target-specific isolated EVM scenarios with sampled opcode traces',
    sourceHash,compiler:solc.version(),target,additionalVerifiedTarget:rewardTarget,
    network:forkConfig.configured?'in-process Hardhat 31337 fixed-block fork; no external transactions':'in-process Hardhat 31337 isolated EVM; no external transactions',
    externalTransactions:false,externalSigning:false,
    executionBoundary,
    transactionEvidence:transactionSnapshot,
    failureEvidence,
    deterministicFuzz,tests:results.length,passed:results.filter(x=>x.state==='passed').length,
    failed:results.filter(x=>x.state==='failed').length,results,traces,traceSampling,
    frameIdentityCapture:{state:frameIdentityCapture.supported?'available':'unavailable',source:'Hardhat 2.22.19 private provider._node._vm.evm.events path / locked EDR 0.8.0 transaction-time beforeMessage and step events',scope:'selected target eth_sendTransaction requests; captured step sequence is aligned with debug_traceTransaction pc/depth/op before attribution'},
    traceEvidence:{state:traceEvidenceState(traceStats),sourceAttributionState:traceSourceAttributionEvidenceState(traceStats),
      traceCount:traces.length,requestedTraceCount:traceStats.requested,validTraceCount:traceStats.valid,
      invalidTraceCount:traceStats.invalid,skippedTraceCount:traceStats.skipped,truncatedTraceCount:traceStats.truncated,
      totalEffectCount:traceStats.totalEffects,reportedEffectCount:traceStats.reportedEffects,
      mappedEffectCount:traceStats.mappedEffects,unmappedEffectCount:traceStats.unmappedEffects,
      frameIdentityAvailableTraceCount:traceStats.frameIdentityAvailable,frameIdentityPartialTraceCount:traceStats.frameIdentityPartial,
      frameIdentityUnavailableTraceCount:traceStats.frameIdentityUnavailable,targetCodeStepCount:traceStats.targetCodeStepCount,
      targetFrameDepthMismatchCount:traceStats.targetFrameDepthMismatchCount,
      scope:'debug_traceTransaction opcode samples; source attribution also requires the active EDR frame codeAddress to match compiled target runtime; one committed and one reverted sample per selector; not exhaustive execution coverage'},
    sourceCoverage:{scope:engineTarget?'sampled depth-1 target runtime source spans with matching frame code address':'sampled delegatecalled implementation source spans with matching frame code address; proxy dispatch excluded',spans:[...sourceCoverage.values()],sampledSelectors:[...sampledSelectors].sort()},
    confirmedVulnerabilities:0,
    limitations:engineTarget?['Mock 6-decimal underlying, registry and controllers; not deployed state','Deterministic invariant sequence is bounded to the listed fixture and seed','Sampled traces do not provide exhaustive branch coverage or prove deployed reachability','Tests do not prove absence of vulnerabilities']:
      rewardTarget?['Proxy, config, and reward pool fixture use local mock deployments; reward implementation logic and source are chain-verified','Reentrant fee receiver is intentionally adversarial; actual configured fee receiver behavior is not established','A reverted transaction leaves local state unchanged; this is a conditional denial-of-service reproduction, not a confirmed exploitable vulnerability']:
      ['RewardPool is an intentionally reentrant local mock; actual configured reward pool behavior was not established','No live chain or user assets used; conditional reproduction is not proof of an exploitable deployed vulnerability','No live chain or user assets used; conditional reproduction is not proof of an exploitable deployed vulnerability'],
  };
  report.traceEvidence={...report.traceEvidence,stepLimitedTraceCount:traceStats.stepLimited,unknownOpcodeCount:traceStats.unknownOpcodeCount,unknownOpcodes:[...traceStats.unknownOpcodes].sort(),totalStepCount:traceStats.totalSteps,processedStepCount:traceStats.processedSteps,totalEffectCount:traceStats.stepLimited?null:traceStats.totalEffects,observedEffectCount:traceStats.totalEffects,effectCountComplete:traceStats.stepLimited===0,targetEffectCount:traceStats.targetEffects,unmappedTargetEffectCount:traceStats.unmappedTargetEffects,nonTargetEffectCount:traceStats.nonTargetEffects,stepLimit:MAX_TRACE_STEPS,scope:`${report.traceEvidence.scope}; each summary processes at most ${MAX_TRACE_STEPS} steps and reports truncation; unknown opcodes are retained but make evidence partial; mapped/unmapped target counts exclude effects at other call depths`};
  report.sourceCoverage={scope:engineTarget?'sampled target runtime source spans with matching frame code address':'sampled delegatecalled implementation spans with matching frame code address; proxy dispatch excluded',spans:[...sourceCoverage.values()],sampledSelectors:[...sampledSelectors].sort()};
  report.staticCorrelation={state:'awaiting_static_call_graph_join',matchedEffectCount:0,scope:'source-location correlation performed by the static analysis driver'};
  report.traces=traces;
  report.harnessHash=crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex');
  report.harnessSupportHash=traceSupportHash(__dirname);
frameIdentityCapture.dispose();console.log(JSON.stringify(report));if(!['passed','partial'].includes(report.state))process.exitCode=1;await provider.destroy();
})().catch(e=>{
  // Keep execution-boundary failures machine-readable. The parent review
  // driver can then preserve an unavailable result instead of treating a
  // missing or malformed fork probe as a local pass.
  const message=String(e?.message||e).slice(0,500);
  const boundary=publicBoundary(forkConfig,{forkState:'unavailable',forkProbe:{state:'unavailable',reason:message}});
  console.log(JSON.stringify({state:'unavailable',reason:'dynamic_execution_boundary_failed',executionBoundary:boundary,confirmedVulnerabilities:0,externalTransactions:false,externalSigning:false}));
  console.error(message);process.exitCode=1;
});
