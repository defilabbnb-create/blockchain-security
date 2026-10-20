#!/usr/bin/env node
// Reviewed idle-vault fixture. All deployments and transactions stay in-process.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
process.env.HARDHAT_CONFIG = path.join(root, 'scripts/local-test-hardhat.cjs');
const deps = path.join(root, 'flare-scan/contracts/firelight-core/node_modules');
const hre = require(path.join(deps, 'hardhat'));
const {BrowserProvider, ContractFactory, MaxUint256} = require(path.join(deps, 'ethers'));
const solc = require(path.join(root, 'flare-scan/tools/solc-0828/node_modules/solc')).setupMethods(require(process.env.CAMPAIGN_SOLJSON));
const {runtimeLocations}=require('./evm-source-map.cjs');
const {createTraceSampler,markTraceSampleComplete,traceSummaryEvidenceState,stableHash,summarizeTraceSteps,traceEvidenceState,traceSourceAttributionEvidenceState,installHardhatFrameIdentityCapture,alignTraceFrameIdentities,captureTraceSafely,traceSupportHash,MAX_TRACE_STEPS}=require('./dynamic-trace-support.cjs');
const serialize = x => JSON.stringify(x, (_, value) => typeof value === 'bigint' ? value.toString() : value);
const hash = stableHash;
const tokenSource = `pragma solidity >=0.8.24 <0.9.0;
contract LocalVaultAsset {
 uint8 public constant decimals=6; uint public totalSupply; bool public rejectTransfer;
 mapping(address=>uint) public balanceOf; mapping(address=>mapping(address=>uint)) public allowance;
 function mint(address a,uint n) external {balanceOf[a]+=n;totalSupply+=n;}
 function setRejectTransfer(bool value) external {rejectTransfer=value;}
 function approve(address a,uint n) external returns(bool){allowance[msg.sender][a]=n;return true;}
 function transfer(address a,uint n) external returns(bool){require(!rejectTransfer,"LOCAL_TOKEN_REJECTED");balanceOf[msg.sender]-=n;balanceOf[a]+=n;return true;}
 function transferFrom(address a,address b,uint n) external returns(bool){require(!rejectTransfer,"LOCAL_TOKEN_REJECTED");if(allowance[a][msg.sender]!=type(uint).max)allowance[a][msg.sender]-=n;balanceOf[a]-=n;balanceOf[b]+=n;return true;}
}`;
const stateReaderSource = `pragma solidity >=0.8.24 <0.9.0;
interface IVaultRead {
 function totalSupply() external view returns(uint256);
 function totalAssets() external view returns(uint256);
 function _totalAssets() external view returns(uint256);
 function lastUpdate() external view returns(uint256);
 function balanceOf(address) external view returns(uint256);
 function allowance(address,address) external view returns(uint256);
}
interface ITokenRead {
 function balanceOf(address) external view returns(uint256);
 function totalSupply() external view returns(uint256);
 function rejectTransfer() external view returns(bool);
 function allowance(address,address) external view returns(uint256);
}
contract LocalVaultStateReader {
 function read(address vaultAddress,address tokenAddress,address[] calldata actors) external view returns(
  uint256 supply,uint256 assets,uint256 storedAssets,uint256 lastUpdate,uint256 collateral,uint256 assetSupply,bool rejectTransfer,
  uint256 vaultNative,uint256[] memory holders,uint256[] memory wallets,uint256[] memory allowances,uint256[] memory assetAllowances,uint256[] memory actorNative
 ) {
  IVaultRead vault=IVaultRead(vaultAddress);ITokenRead token=ITokenRead(tokenAddress);
  supply=vault.totalSupply();assets=vault.totalAssets();storedAssets=vault._totalAssets();lastUpdate=vault.lastUpdate();
  collateral=token.balanceOf(vaultAddress);assetSupply=token.totalSupply();rejectTransfer=token.rejectTransfer();
  vaultNative=vaultAddress.balance;
  uint256 count=actors.length;holders=new uint256[](count);wallets=new uint256[](count);actorNative=new uint256[](count);
  allowances=new uint256[](count*count);assetAllowances=new uint256[](count);
  for(uint256 i=0;i<count;i++){
   holders[i]=vault.balanceOf(actors[i]);wallets[i]=token.balanceOf(actors[i]);actorNative[i]=actors[i].balance;
   assetAllowances[i]=token.allowance(actors[i],vaultAddress);
   for(uint256 j=0;j<count;j++)allowances[i*count+j]=vault.allowance(actors[i],actors[j]);
  }
 }
}`;

async function run(input, target, name, sourceAliases={}) {
  if (hre.network.name !== 'hardhat' || hre.network.config.url || hre.network.config.forking) throw Error('Isolated in-process EVM required');
  const provider = new BrowserProvider(hre.network.provider);
  let frameIdentityCapture = null;
  provider.pollingInterval = 10;
  try {
    if ((await provider.getNetwork()).chainId !== 31337n) throw Error('Unexpected local chain');
    const sourceHash = hash(input.sources);
    const settings = input.settings || {};
    const compilerSettingsHash = hash(settings);
    if (input.sources['__local_vault__/Asset.sol']) throw Error('Reserved fixture source collision');
    if (input.sources['__local_vault__/StateReader.sol']) throw Error('Reserved state reader source collision');
    input.sources['__local_vault__/Asset.sol'] = {content: tokenSource};
    input.sources['__local_vault__/StateReader.sol'] = {content: stateReaderSource};
    input.settings = {...settings, outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.sourceMap']}}};
    const compiled = JSON.parse(solc.compile(JSON.stringify(input)));
    const errors = (compiled.errors || []).filter(e => e.severity === 'error');
    if (errors.length) throw Error(errors.map(e => e.formattedMessage).join('\n'));
    const artifact = compiled.contracts?.[target]?.[name];
    if (!artifact?.evm?.bytecode?.object) throw Error('Missing deployable target');
    const rawSourceLocations=runtimeLocations(artifact.evm.deployedBytecode.object,artifact.evm.deployedBytecode.sourceMap,compiled.sources,input.sources);
    const sourceLocations=new Map([...rawSourceLocations].map(([pc,loc])=>[pc,{...loc,file:sourceAliases[loc.file]||loc.file}]));
    const constructor = artifact.abi.find(x => x.type === 'constructor');
    if (serialize(constructor?.inputs?.map(x => x.type)) !== '["address","address"]') throw Error('Fixture requires reviewed (owner, asset) constructor');
    const methods = new Set(artifact.abi.filter(x => x.type === 'function').map(x => `${x.name}(${x.inputs.map(a => a.type)})`));
    for (const method of ['deposit(uint256,address)','mint(uint256,address)','withdraw(uint256,address,address)','redeem(uint256,address,address)','virtualShares()']) {
      if (!methods.has(method)) throw Error(`Unsupported idle-vault fixture: ${method}`);
    }
    const actors = await Promise.all([0,1,2].map(async index => { const signer=await provider.getSigner(index); return {signer,address:await signer.getAddress()}; }));
    const deploy = async (a, args) => { const c=await new ContractFactory(a.abi,a.evm.bytecode.object,actors[0].signer).deploy(...args,{gasLimit:16000000}); await c.waitForDeployment(); return c; };
    const token = await deploy(compiled.contracts['__local_vault__/Asset.sol'].LocalVaultAsset, []);
    const vault = await deploy(artifact, [actors[0].address, await token.getAddress()]);
    const stateReader = await deploy(compiled.contracts['__local_vault__/StateReader.sol'].LocalVaultStateReader, []);
    const address = await vault.getAddress(), initial = 1000000000n;
    const assetAddress=await token.getAddress();
    frameIdentityCapture=installHardhatFrameIdentityCapture(hre.network.provider,
      tx=>typeof tx?.to==='string'&&tx.to.toLowerCase()===address.toLowerCase());
    const rawTx = async p => (await p).wait();
    for (const a of actors) { await rawTx(token.mint(a.address,initial)); await rawTx(token.connect(a.signer).approve(address,MaxUint256)); }
    let baseline = await hre.network.provider.send('evm_snapshot');
    const results = [], sequences = [], traces = [], traceSampling = [], coverage = new Set(), tracedMethods=new Set(), tracedOutcomes=new Set(), sourceCoverage=new Map();
    const traceSampler=createTraceSampler();
    const traceStats = {requested:0, valid:0, invalid:0, skipped:0, truncated:0, stepLimited:0, unknownOpcodeCount:0, unknownOpcodes:new Set(), totalSteps:0, processedSteps:0, reportedEffects:0, totalEffects:0, targetEffects:0, unmappedTargetEffects:0, nonTargetEffects:0, mappedEffects:0, unmappedEffects:0, frameIdentityAvailable:0, frameIdentityPartial:0, frameIdentityUnavailable:0, targetCodeStepCount:0, targetFrameDepthMismatchCount:0};
    const stateDiffStats = {operations:0, complete:0, missing:0};
    const actionExecutionStats = new Map();
    let latestStateSnapshot = null;
    let stateSnapshotReadCount = 0;
    const fuzzActions=new Map(), fuzzTransitions=new Map();
    let activeSequence=[], activeScenario='fixture_setup', lastHash=null, lastTarget=false, lastMethod='unknown', lastFailed=false, lastTraceIndex=null;
    const selectorFor = method => { try { return vault.interface.getFunction(method)?.selector || null; } catch { return null; } };
    const trace = async (transactionHash,targetRuntime=true,method='unknown',expectedFailed=null) => {
      if (!transactionHash) {
        if(targetRuntime)traceSampling.push({scenario:activeScenario,transactionHash:null,method,selector:selectorFor(method),outcome:expectedFailed===null?null:expectedFailed?'reverted':'committed',state:'unavailable',reason:'transaction_hash_unavailable'});
        return null;
      }
      const sample=targetRuntime?{scenario:activeScenario,transactionHash,method,selector:selectorFor(method),outcome:expectedFailed===null?null:expectedFailed?'reverted':'committed',state:'requested',reason:null}:null;
      if(sample)traceSampling.push(sample);
      if (targetRuntime&&expectedFailed!==null&&traceSampler.has('VaultV2',method,expectedFailed)) {traceStats.skipped++;sample.state='skipped';sample.reason='selector_outcome_sample_limit';frameIdentityCapture.discard(transactionHash);return null;}
      traceStats.requested++;
      const evidence=await captureTraceSafely(transactionHash,async()=>{
        const t = await hre.network.provider.send('debug_traceTransaction',[transactionHash,{disableMemory:true,disableStorage:true,disableStack:true}]);
        if (expectedFailed!==null&&t.failed!==expectedFailed) throw Error('trace outcome does not match transaction result');
        const frameIdentity=targetRuntime?alignTraceFrameIdentities(t,frameIdentityCapture.take(transactionHash)):null;
        // null keeps non-target token traces in the accounting stream without
        // attributing their depth-1 opcodes to the Vault source map.
        const summary=summarizeTraceSteps(t,targetRuntime?1:null,sourceLocations,sourceCoverage,120,undefined,
          targetRuntime?{...frameIdentity,targetCodeAddress:address.toLowerCase()}:null);
        traceStats.valid++;traceStats.totalSteps+=summary.steps;traceStats.processedSteps+=summary.processedSteps;traceStats.totalEffects+=summary.effectCount;traceStats.reportedEffects+=summary.effects.length;if(summary.effectsTruncated||summary.stepsTruncated)traceStats.truncated++;if(summary.stepsTruncated)traceStats.stepLimited++;
        traceStats.targetEffects+=summary.targetEffectCount;traceStats.unmappedTargetEffects+=summary.unmappedTargetEffects;traceStats.nonTargetEffects+=summary.nonTargetEffects;traceStats.mappedEffects+=summary.mappedEffects;traceStats.unmappedEffects+=summary.unmappedEffects;traceStats.unknownOpcodeCount+=summary.unknownOpcodeCount;for(const opcode of summary.unknownOpcodes)traceStats.unknownOpcodes.add(opcode);
        if(targetRuntime){
          traceStats.targetCodeStepCount+=summary.targetCodeStepCount;traceStats.targetFrameDepthMismatchCount+=summary.targetFrameDepthMismatchCount;
          if(summary.frameIdentityState==='available')traceStats.frameIdentityAvailable++;else if(summary.frameIdentityState==='partial')traceStats.frameIdentityPartial++;else traceStats.frameIdentityUnavailable++;
          sample.frameIdentityState=summary.frameIdentityState;
          tracedMethods.add(method);
          tracedOutcomes.add(`${method}:${t.failed?'reverted':'committed'}`);
        }
        const evidence={transactionHash,state:traceSummaryEvidenceState(summary),traceValid:true,failed:t.failed,targetDepth:targetRuntime?1:null,targetCodeAddress:targetRuntime?address.toLowerCase():null,gas:t.gas,...summary,reportedEffectCount:summary.effects.length,sourceScope:targetRuntime?'depth-1 target runtime with matching EDR frame code address; nested token and generated compiler locations are not attributed':'non-target runtime; no target source mapping'};
        if(targetRuntime) markTraceSampleComplete(traceSampler,'VaultV2',method,t.failed,evidence);
        return evidence;
      },error=>{traceStats.invalid++;frameIdentityCapture.discard(transactionHash);if(sample){sample.state='unavailable';sample.reason=(error instanceof Error?error.message:String(error)).slice(0,200);}});
      if(sample){
        if(evidence?.traceValid===true){sample.state='sampled';sample.outcome=evidence.failed?'reverted':'committed';sample.traceState=evidence.state;}
        else if(evidence){sample.state='unavailable';sample.reason=evidence.reason||sample.reason||'invalid_trace';}
      }
      return evidence;
    };
    const stateDiff = (before, after) => {
      const changed = {};
      for (const key of Object.keys(before || {}).filter(key=>!['vaultNative','actorNative'].includes(key))) {
        const left = serialize(before[key]), right = serialize(after?.[key]);
        if (left !== right) changed[key] = {before: JSON.parse(left), after: JSON.parse(right)};
      }
      return {schemaVersion:1, complete:true, changed, changedFieldCount:Object.keys(changed).length};
    };
    const recordStateDiff = (txData,before,after) => {
      txData.stateDiff=stateDiff(before,after);
      stateDiffStats.complete++;
    };
    const markStateDiffMissing = (txData,reason) => {
      txData.stateDiff={schemaVersion:1,complete:false,reason};
      stateDiffStats.missing++;
    };
    const send = async (contract,actor,method,args=[],knownBefore=null) => {
      const txData = {contract:await contract.getAddress(),actor:actor.address,method,args:args.map(String)};
      activeSequence.push(txData); coverage.add(`${contract===vault?'vault':'asset'}:${method}`);
      const actionKey=`${contract===vault?'vault':'asset'}:${method}`;
      let actionStats=actionExecutionStats.get(actionKey);
      if(!actionStats)actionExecutionStats.set(actionKey,actionStats={attempted:0,committed:0,reverted:0,unconfirmed:0,notSubmitted:0});
      actionStats.attempted++;
      lastHash=null;lastTarget=contract===vault;lastMethod=method;lastFailed=false;lastTraceIndex=null;
      stateDiffStats.operations++;
      let before=null;
      try {before=knownBefore===null?await state():knownBefore;}catch{markStateDiffMissing(txData,'before_state_unavailable');}
      let sent=null,receipt,gasFee=null;
      try {
        txData.executionState='pending';
        sent=await contract.connect(actor.signer)[method](...args,{gasLimit:3000000});
        lastHash=sent.hash;txData.transactionHash=sent.hash;
        receipt=await sent.wait();
        txData.gasUsed=receipt.gasUsed.toString();
        let effectiveGasPrice=receipt.effectiveGasPrice??receipt.gasPrice;
        if(effectiveGasPrice===undefined||effectiveGasPrice===null)try{effectiveGasPrice=(await provider.getTransaction(sent.hash))?.gasPrice;}catch{}
        if(effectiveGasPrice!==null&&effectiveGasPrice!==undefined){gasFee=receipt.gasUsed*BigInt(effectiveGasPrice);txData.gasFee=gasFee.toString();}
        txData.executionState='committed';
        actionStats.committed++;
        lastFailed=false;
      } catch(e) {
        lastHash=sent?.hash||e.transactionHash||e.receipt?.hash||e.data?.transactionHash||e.info?.error?.data?.transactionHash||lastHash;
        let failedReceipt=e.receipt||e.info?.error?.receipt;
        if(lastHash)try{failedReceipt=await provider.getTransactionReceipt(lastHash)||failedReceipt;}catch{}
        const reverted=failedReceipt?.status===0||failedReceipt?.status===0n||failedReceipt?.status==='0x0';
        const failedGasPrice=failedReceipt?.effectiveGasPrice??failedReceipt?.gasPrice;
        if(failedReceipt?.gasUsed!==undefined&&failedGasPrice!==undefined){gasFee=BigInt(failedReceipt.gasUsed)*BigInt(failedGasPrice);txData.gasUsed=String(failedReceipt.gasUsed);txData.gasFee=gasFee.toString();}
        txData.reverted=reverted;
        txData.executionState=reverted?'reverted':lastHash?'unconfirmed':'not_submitted';
        if(reverted)actionStats.reverted++;else if(lastHash)actionStats.unconfirmed++;else actionStats.notSubmitted++;
        txData.error=(e.shortMessage||e.message).slice(0,250);lastFailed=reverted;
        if(lastHash)txData.transactionHash=lastHash;
        if(before!==null)try{const after=await state();recordStateDiff(txData,before,after);recordAssetBalanceDiff(txData,before,after,actor.address,gasFee);latestStateSnapshot=after;}catch{markStateDiffMissing(txData,'after_state_unavailable');txData.assetBalanceDiff={state:'unavailable',reason:'after_state_unavailable'};latestStateSnapshot=null;}
        else if(!txData.stateDiff)markStateDiffMissing(txData,'before_state_unavailable');
        if(contract===vault&&lastHash&&reverted){const evidence=await trace(lastHash,true,method,true);if(evidence){traces.push(evidence);lastTraceIndex=traces.length-1;txData.traceIndex=lastTraceIndex;}}
        throw e;
      }
      if(before!==null)try{const after=await state();recordStateDiff(txData,before,after);recordAssetBalanceDiff(txData,before,after,actor.address,gasFee);latestStateSnapshot=after;}catch{markStateDiffMissing(txData,'after_state_unavailable');txData.assetBalanceDiff={state:'unavailable',reason:'after_state_unavailable'};latestStateSnapshot=null;}
      else if(!txData.stateDiff)markStateDiffMissing(txData,'before_state_unavailable');
      if(contract===vault){const evidence=await trace(sent.hash,true,method,false);if(evidence){traces.push(evidence);lastTraceIndex=traces.length-1;txData.traceIndex=lastTraceIndex;}}
      return receipt;
    };
    const state = async () => {
      stateSnapshotReadCount++;
      const [supply,assets,storedAssets,lastUpdate,collateral,assetSupply,rejectTransfer,vaultNative,holders,wallets,allowances,assetAllowances,actorNative]=
        await stateReader.read(address,assetAddress,actors.map(actor=>actor.address));
      const snapshot={supply,assets,storedAssets,lastUpdate,collateral,assetSupply,rejectTransfer,
        holders:[...holders],wallets:[...wallets],allowances:[...allowances],assetAllowances:[...assetAllowances]};
      Object.defineProperties(snapshot,{vaultNative:{value:vaultNative},actorNative:{value:[...actorNative]}});
      return snapshot;
    };
    const recordAssetBalanceDiff = (txData,before,after,sender,gasFee) => {
      const rows=[];
      const row=(kind,asset,holder,left,right,fee=0n)=>({kind,asset,holder,before:left.toString(),after:right.toString(),rawDelta:(right-left).toString(),
        gasFee:fee===null?null:fee.toString(),transactionDelta:fee===null?null:(right-left+fee).toString(),transactionDeltaState:fee===null?'unavailable':'available'});
      rows.push(row('native','native',address,before.vaultNative,after.vaultNative,0n));
      actors.forEach((item,index)=>rows.push(row('native','native',item.address,before.actorNative[index],after.actorNative[index],
        item.address.toLowerCase()===sender.toLowerCase()?gasFee:0n)));
      rows.push(row('erc20',assetAddress,address,before.collateral,after.collateral));
      actors.forEach((item,index)=>rows.push(row('erc20',assetAddress,item.address,before.wallets[index],after.wallets[index])));
      txData.assetBalanceDiff={schemaVersion:1,state:'available',source:'isolated_local_evm_state_reader',stateAuthority:'queried_before_after_balances',
        nativeFeeAdjustment:gasFee===null?'unavailable':'available',gasFee:gasFee===null?null:gasFee.toString(),balances:rows,
        scope:'vault and three fixture actors only; native sender delta is adjusted by receipt gas fee when available; ERC20 balances are queried directly, not inferred from events'};
    };
    const assertBalanceDelta = (txData,kind,holder,expectedDelta,field='rawDelta') => {
      const row=txData?.assetBalanceDiff?.balances?.find(item=>item.kind===kind&&item.holder.toLowerCase()===holder.toLowerCase());
      assert.ok(row,`${kind} balance evidence missing for ${holder}`);
      assert.equal(row[field],String(expectedDelta),`${kind} observed ${field} mismatch for ${holder}`);
      return row;
    };
    const invariant = async (expected,unaccountedAssets=0n,snapshot=latestStateSnapshot) => {
      const s=snapshot||await state();assert.deepEqual(s.holders,expected,'tracked shares differ from reference ledger');
      assert.equal(s.supply,expected.reduce((a,b)=>a+b,0n),'share supply does not equal holder sum');
      assert.equal(s.assetSupply,initial*3n,'underlying token total supply changed');
      assert.equal(s.collateral-s.assets,unaccountedAssets,'idle fixture accounting differs from independently tracked collateral');
      assert.equal(s.wallets.reduce((a,b)=>a+b,s.collateral),initial*3n,'underlying token conservation');
      return s;
    };
    const reverts = async operation => {
      try {await operation();}catch(e){
        const message=[e.message,e.shortMessage,e.info?.error?.message].filter(Boolean).join(' ');
        if (e.code==='CALL_EXCEPTION'||/revert|panic|VM Exception/.test(message)) {
          const txData=activeSequence.at(-1);
          assert.equal(txData?.executionState,'reverted','expected a mined transaction with a reverted receipt');
          assert.equal(txData.stateDiff?.complete,true,'reverted operation must have a complete state diff');
          assert.equal(txData.stateDiff.changedFieldCount,0,'reverted operation must not change tracked state');
          assert.equal(txData.assetBalanceDiff?.state,'available','reverted operation must retain queried asset balances');
          assert.ok(txData.assetBalanceDiff.balances.filter(row=>row.kind==='erc20').every(row=>row.rawDelta==='0'),'reverted operation changed an ERC20 balance');
          const nativeRows=txData.assetBalanceDiff.balances.filter(row=>row.kind==='native');
          const senderRow=nativeRows.find(row=>row.holder.toLowerCase()===txData.actor.toLowerCase());
          assert.equal(senderRow?.transactionDeltaState,'available','mined reverted transaction must report its fee-adjusted sender native balance');
          assert.equal(senderRow?.transactionDelta,'0','reverted transaction native delta must contain only its gas fee');
          assert.ok(nativeRows.filter(row=>row!==senderRow).every(row=>row.rawDelta==='0'&&row.transactionDelta===row.rawDelta),
            'reverted operation changed Vault or non-sender native balance');
          return;
        }
        throw e;
      }
      assert.fail('operation succeeded without required authorization or rollback');
    };
    const check = async (id,propertyIds,body) => {
      assert.equal(await hre.network.provider.send('evm_revert',[baseline]),true,'fixture snapshot restore failed');baseline=await hre.network.provider.send('evm_snapshot');
      activeSequence=[];lastHash=null;lastTarget=false;lastMethod='unknown';lastFailed=false;lastTraceIndex=null;latestStateSnapshot=null;const start=Date.now();
      const previousScenario=activeScenario;activeScenario=id;
      try {
        try {await body();results.push({id,state:'passed',propertyIds,durationMs:Date.now()-start,operations:activeSequence.length});}
        catch(e){const outcomeKnown=['committed','reverted'].includes(activeSequence.at(-1)?.executionState);const evidence=lastTarget&&outcomeKnown?await trace(lastHash,lastTarget,lastMethod,lastFailed):null;if(evidence){traces.push(evidence);lastTraceIndex=traces.length-1;}results.push({id,state:'failed',propertyIds:[],targetPropertyIds:propertyIds,error:e.message.slice(0,800),durationMs:Date.now()-start,operations:activeSequence.length,traceIndex:lastTraceIndex});}
        sequences.push({id,operations:activeSequence});
      } finally {activeScenario=previousScenario;}
    };
    await check('idle-vault-rounding-and-roundtrip',['accounting.rounding_direction','accounting.share_conservation','accounting.asset_conservation'],async()=>{
      const scale=await vault.virtualShares();assert.ok(scale>0n);
      for(const shares of [1n,scale-1n,scale,scale+1n]){
        const before=await state(),assets=(shares*(before.assets+1n)+before.supply+scale-1n)/(before.supply+scale);
        assert.equal(await vault.previewMint(shares),assets,'mint must round required assets up');
        await send(vault,actors[1],'mint',[shares,actors[1].address]);
        const mintTx=activeSequence.at(-1);
        assertBalanceDelta(mintTx,'erc20',actors[1].address,-assets);
        assertBalanceDelta(mintTx,'erc20',address,assets);
        const nativeSender=assertBalanceDelta(mintTx,'native',actors[1].address,0n,'transactionDelta');
        assert.equal(nativeSender.transactionDeltaState,'available','sender native delta should be gas-adjusted');
        for(const nativeRow of mintTx.assetBalanceDiff.balances.filter(row=>row.kind==='native'&&row.holder.toLowerCase()!==actors[1].address.toLowerCase())){
          assert.equal(nativeRow.gasFee,'0','non-sender native balance must not receive a transaction fee adjustment');
          assert.equal(nativeRow.transactionDelta,nativeRow.rawDelta,'non-sender native net delta must equal its observed balance delta');
          assert.equal(nativeRow.transactionDeltaState,'available');
        }
        const after=await state();assert.equal(after.supply-before.supply,shares);assert.equal(before.wallets[1]-after.wallets[1],assets);
        const redeemAssets=shares*(after.assets+1n)/(after.supply+scale);
        assert.equal(await vault.previewRedeem(shares),redeemAssets,'redeem must round paid assets down');
        await send(vault,actors[1],'redeem',[shares,actors[1].address,actors[1].address]);
        const redeemTx=activeSequence.at(-1);
        assertBalanceDelta(redeemTx,'erc20',actors[1].address,redeemAssets);
        assertBalanceDelta(redeemTx,'erc20',address,-redeemAssets);
        const end=await state();assert.ok(end.wallets[1]<=before.wallets[1],'round-trip creates unearned assets');
        await invariant([0n,0n,0n]);
      }
    });
    await check('idle-vault-unauthorized-redemption-and-allowance',['authorization.redemption','settlement.receiver_exact','rollback.atomicity','accounting.share_conservation','accounting.asset_conservation'],async()=>{
      await send(vault,actors[1],'deposit',[10000n,actors[1].address]);
      const before=await state(),shares=before.holders[1]/2n;
      await reverts(()=>send(vault,actors[2],'redeem',[shares,actors[2].address,actors[1].address]));
      assert.deepEqual(await state(),before,'rejected redemption changed balances or allowances');
      await send(vault,actors[1],'approve',[actors[2].address,shares]);
      const beforeRedeem=await state(),expectedAssets=await vault.previewRedeem(shares);
      assert.ok(expectedAssets>0n,'authorized redemption must have a positive preview');
      await send(vault,actors[2],'redeem',[shares,actors[2].address,actors[1].address]);
      const afterRedeem=await state();
      assert.equal(afterRedeem.wallets[2]-beforeRedeem.wallets[2],expectedAssets,'redeemed assets must be paid to receiver');
      assert.equal(afterRedeem.wallets[1],beforeRedeem.wallets[1],'share owner must not receive redemption assets');
      assert.equal(await vault.allowance(actors[1].address,actors[2].address),0n,'finite allowance was not consumed');
      await invariant([0n,beforeRedeem.holders[1]-shares,0n]);
    });
    await check('idle-vault-role-separated-redemption-revocation',['authorization.redemption','authorization.revocation','settlement.receiver_exact','settlement.payer_owner_separation','rollback.atomicity','accounting.share_conservation','accounting.asset_conservation'],async()=>{
      const scale=await vault.virtualShares(),depositAssets=21001n;
      const initialState=await state(),mintedShares=depositAssets*(initialState.supply+scale)/(initialState.assets+1n);
      // Payer, share owner, redemption caller and receiver must be modeled independently.
      await send(vault,actors[0],'deposit',[depositAssets,actors[1].address]);
      const funded=await invariant([0n,mintedShares,0n]);
      assert.equal(initialState.wallets[0]-funded.wallets[0],depositAssets,'deposit charged the wrong payer');
      assert.equal(funded.wallets[1],initialState.wallets[1],'share recipient paid for another actor deposit');
      const shares=mintedShares/3n;
      await send(vault,actors[1],'approve',[actors[2].address,shares]);
      await send(vault,actors[1],'approve',[actors[2].address,0n]);
      const revoked=await state();
      await reverts(()=>send(vault,actors[2],'redeem',[shares,actors[0].address,actors[1].address]));
      assert.deepEqual(await state(),revoked,'revoked redemption changed state');
      await send(vault,actors[1],'approve',[actors[2].address,shares]);
      const before=await state(),assets=shares*(before.assets+1n)/(before.supply+scale);
      assert.ok(assets>0n);
      await send(vault,actors[2],'redeem',[shares,actors[0].address,actors[1].address]);
      const after=await invariant([0n,mintedShares-shares,0n]);
      assert.equal(after.wallets[0]-before.wallets[0],assets,'redemption did not settle exactly to receiver distinct from caller and owner');
      assert.equal(after.wallets[1],before.wallets[1],'redemption paid share owner instead of receiver');
      assert.equal(after.wallets[2],before.wallets[2],'redemption paid caller instead of receiver');
      assert.equal(await vault.allowance(actors[1].address,actors[2].address),0n,'restored finite allowance was not consumed');
      await reverts(()=>send(vault,actors[2],'redeem',[shares,actors[0].address,actors[1].address]));
      assert.deepEqual(await state(),after,'exhausted allowance changed state');
      await send(vault,actors[1],'approve',[actors[2].address,MaxUint256]);
      const beforeWithdraw=await state(),withdrawAssets=7n,burnedShares=(withdrawAssets*(beforeWithdraw.supply+scale)+beforeWithdraw.assets)/(beforeWithdraw.assets+1n);
      await send(vault,actors[2],'withdraw',[withdrawAssets,actors[0].address,actors[1].address]);
      const end=await invariant([0n,mintedShares-shares-burnedShares,0n]);
      assert.equal(end.wallets[0]-beforeWithdraw.wallets[0],withdrawAssets,'withdraw did not settle exactly to separate receiver');
      assert.equal(end.wallets[1],beforeWithdraw.wallets[1]);assert.equal(end.wallets[2],beforeWithdraw.wallets[2]);
      assert.equal(await vault.allowance(actors[1].address,actors[2].address),MaxUint256,'reviewed unlimited allowance convention changed');
    });
    await check('idle-vault-share-transferFrom-allowance-ledger',['authorization.revocation','rollback.atomicity','accounting.share_conservation','accounting.asset_conservation'],async()=>{
      const ownerIndex=1,spenderIndex=2,recipientIndex=0;
      const owner=actors[ownerIndex],spender=actors[spenderIndex],recipient=actors[recipientIndex];
      const depositAssets=21001n,scale=await vault.virtualShares(),beforeDeposit=await state();
      const mintedShares=depositAssets*(beforeDeposit.supply+scale)/(beforeDeposit.assets+1n);
      assert.equal(await vault.previewDeposit(depositAssets),mintedShares,'deposit share reference model mismatch');
      assert.ok(mintedShares>8n,'fixture needs enough shares for allowance boundary checks');
      const expected=[0n,mintedShares,0n];
      const expectedAllowances=Array.from({length:3},()=>Array(3).fill(0n));
      const assertLedger=async()=>{
        const actual=await invariant(expected);
        assert.deepEqual(actual.allowances,expectedAllowances.flat(),'share allowance matrix differs from reference ledger');
        return actual;
      };
      const assertNoUnderlyingChange=(before,after,operation)=>{
        assert.equal(after.assets,before.assets,`${operation} changed managed assets`);
        assert.equal(after.storedAssets,before.storedAssets,`${operation} changed stored assets`);
        assert.equal(after.lastUpdate,before.lastUpdate,`${operation} changed the accounting timestamp`);
        assert.equal(after.collateral,before.collateral,`${operation} changed vault collateral`);
        assert.equal(after.assetSupply,before.assetSupply,`${operation} changed underlying token total supply`);
        assert.deepEqual(after.wallets,before.wallets,`${operation} moved underlying tokens`);
        assert.deepEqual(after.assetAllowances,before.assetAllowances,`${operation} changed underlying token allowances`);
      };
      const approve=async amount=>{
        const before=await assertLedger();
        await send(vault,owner,'approve',[spender.address,amount]);
        expectedAllowances[ownerIndex][spenderIndex]=amount;
        const after=await assertLedger();
        assert.deepEqual(after.holders,before.holders,'approve changed share balances');
        assertNoUnderlyingChange(before,after,'approve');
        return after;
      };
      const transferFrom=async(caller,amount,consumeAllowance=true)=>{
        const before=await assertLedger();
        await send(vault,caller,'transferFrom',[owner.address,recipient.address,amount]);
        expected[ownerIndex]-=amount;
        expected[recipientIndex]+=amount;
        if(consumeAllowance&&expectedAllowances[ownerIndex][spenderIndex]!==MaxUint256){
          expectedAllowances[ownerIndex][spenderIndex]-=amount;
        }
        const after=await assertLedger();
        assertNoUnderlyingChange(before,after,'transferFrom');
      };

      await send(vault,actors[0],'deposit',[depositAssets,owner.address]);
      await assertLedger();

      const finiteAllowance=mintedShares/2n;
      assert.ok(finiteAllowance>2n);
      await approve(finiteAllowance);
      const firstTransfer=finiteAllowance/2n;
      await transferFrom(spender,firstTransfer);
      const remainingAllowance=expectedAllowances[ownerIndex][spenderIndex];
      assert.ok(remainingAllowance>0n);
      const beforeInsufficient=await state();
      await reverts(()=>send(vault,spender,'transferFrom',[owner.address,recipient.address,remainingAllowance+1n]));
      assert.deepEqual(await state(),beforeInsufficient,'insufficient allowance failure changed full vault state');
      await assertLedger();
      await transferFrom(spender,remainingAllowance);
      assert.equal(expectedAllowances[ownerIndex][spenderIndex],0n,'finite allowance was not fully consumed');

      await approve(finiteAllowance);
      await transferFrom(spender,1n);
      const beforeRevoked=await approve(0n);
      await reverts(()=>send(vault,spender,'transferFrom',[owner.address,recipient.address,1n]));
      assert.deepEqual(await state(),beforeRevoked,'revoked allowance failure changed full vault state');
      await assertLedger();

      await approve(MaxUint256);
      await transferFrom(spender,1n);
      assert.equal(expectedAllowances[ownerIndex][spenderIndex],MaxUint256,'unlimited allowance was decremented');

      await approve(0n);
      await transferFrom(owner,1n,false);
      assert.equal(expectedAllowances[ownerIndex][spenderIndex],0n,'owner-initiated transferFrom changed allowance');
    });
    await check('idle-vault-donation-zero-rate-consistency',['accounting.donation_consistency','accounting.share_conservation','accounting.asset_conservation','accounting.rounding_direction'],async()=>{
      // VaultV2 explicitly caps donation recognition; zero maxRate means donations remain unaccounted.
      // This is a reviewed VaultV2 convention, not an ERC-4626-wide donation guarantee.
      assert.equal(await vault.maxRate(),0n,'donation oracle requires constructor default zero rate');
      assert.equal(await vault.performanceFee(),0n);assert.equal(await vault.managementFee(),0n);
      const donation=50000n,scale=await vault.virtualShares(),before=await state();
      await send(token,actors[2],'transfer',[address,donation]);
      const donated=await invariant([0n,0n,0n],donation);
      assert.equal(donated.assets,0n,'zero-rate unsolicited donation was recognized as managed assets');
      assert.equal(donated.wallets[2],before.wallets[2]-donation);
      const depositAssets=10000n,shares=depositAssets*scale;
      assert.equal(await vault.previewDeposit(depositAssets),shares,'donation silently diluted a new depositor');
      await send(vault,actors[1],'deposit',[depositAssets,actors[1].address]);
      const funded=await invariant([0n,shares,0n],donation);assert.equal(funded.assets,depositAssets);
      await send(vault,actors[1],'redeem',[shares,actors[1].address,actors[1].address]);
      const redeemed=await invariant([0n,0n,0n],donation);
      assert.equal(redeemed.wallets[1],before.wallets[1],'zero-rate deposit/redeem lost assets after donation');
      assert.equal(redeemed.collateral,donation,'redemption extracted unrecognized donated collateral');
      assert.equal(redeemed.assets,0n);
      // Re-enter at the one-asset boundary after the prior holder has fully exited.
      assert.equal(await vault.previewDeposit(1n),scale);
      await send(vault,actors[0],'deposit',[1n,actors[0].address]);await invariant([scale,0n,0n],donation);
      await send(vault,actors[0],'redeem',[scale,actors[0].address,actors[0].address]);
      const end=await invariant([0n,0n,0n],donation);assert.equal(end.wallets[0],before.wallets[0]);
    });
    await check('idle-vault-token-failure-rolls-back-state',['rollback.atomicity','liveness.failure_recovery','settlement.receiver_exact','accounting.share_conservation','accounting.asset_conservation'],async()=>{
      await send(vault,actors[1],'deposit',[10000n,actors[1].address]);
      const scale=await vault.virtualShares(),funded=await state(),shares=(funded.supply+scale+funded.assets)/(funded.assets+1n);
      await send(vault,actors[1],'approve',[actors[2].address,shares]);
      await send(token,actors[0],'setRejectTransfer',[true]);
      assert.deepEqual(activeSequence.at(-1).stateDiff.changed.rejectTransfer,{before:false,after:true},'enabled token failure must appear in state diff');
      const before=await state();
      await reverts(()=>send(vault,actors[2],'withdraw',[1n,actors[0].address,actors[1].address]));
      assert.deepEqual(await state(),before,'token rejection left a partial withdrawal');
      await reverts(()=>send(vault,actors[2],'deposit',[1n,actors[1].address]));
      assert.deepEqual(await state(),before,'token rejection left a partial deposit');
      await send(token,actors[0],'setRejectTransfer',[false]);
      assert.deepEqual(activeSequence.at(-1).stateDiff.changed.rejectTransfer,{before:true,after:false},'cleared token failure must appear in state diff');
      await send(vault,actors[2],'withdraw',[1n,actors[0].address,actors[1].address]);
      const recovered=await invariant([0n,funded.holders[1]-shares,0n]);
      assert.equal(recovered.wallets[0]-before.wallets[0],1n,'withdraw did not recover after transient token failure');
      assert.equal(await vault.allowance(actors[1].address,actors[2].address),0n,'recovery consumed the wrong allowance');
      const depositAssets=7n,newShares=depositAssets*(recovered.supply+scale)/(recovered.assets+1n);
      await send(vault,actors[2],'deposit',[depositAssets,actors[1].address]);
      const end=await invariant([0n,recovered.holders[1]+newShares,0n]);
      assert.equal(recovered.wallets[2]-end.wallets[2],depositAssets,'deposit did not recover after transient token failure');
    });
    const seeds=[0x5ec0a11,0x1badb002,0xc0ffee];
    for(const seed of seeds)await check(`idle-vault-state-sequence-${seed.toString(16)}`,['accounting.share_conservation','accounting.asset_conservation','accounting.rounding_direction','settlement.receiver_exact'],async()=>{
      let randomState=seed>>>0;const random=()=>randomState=(Math.imul(randomState,1664525)+1013904223)>>>0;
      const expected=[0n,0n,0n],scale=await vault.virtualShares();let before=await state(),previousAction=null;
      for(let i=0;i<48;i++){
        const idx=random()%3,a=actors[idx],other=actors[(idx+1)%3],action=i%5;
        if(action===0||expected[idx]===0n){const assets=BigInt(1+random()%10000),shares=assets*(before.supply+scale)/(before.assets+1n);assert.equal(await vault.previewDeposit(assets),shares);await send(vault,a,'deposit',[assets,a.address],before);expected[idx]+=shares;}
        else if(action===1){const shares=BigInt(1+random()%10000)*scale+BigInt(random()%7),assets=(shares*(before.assets+1n)+before.supply+scale-1n)/(before.supply+scale);assert.equal(await vault.previewMint(shares),assets);await send(vault,a,'mint',[shares,a.address],before);expected[idx]+=shares;assert.equal(before.wallets[idx]-(await token.balanceOf(a.address)),assets);}
        else if(action===2){const shares=expected[idx]/2n;await send(vault,a,'transfer',[other.address,shares],before);expected[idx]-=shares;expected[(idx+1)%3]+=shares;}
        else if(action===3){const shares=expected[idx]/3n,assets=shares*(before.assets+1n)/(before.supply+scale);assert.equal(await vault.previewRedeem(shares),assets);await send(vault,a,'redeem',[shares,a.address,a.address],before);expected[idx]-=shares;assert.equal((await token.balanceOf(a.address))-before.wallets[idx],assets);}
        else {const assets=expected[idx]*(before.assets+1n)/(before.supply+scale)/4n,shares=(assets*(before.supply+scale)+before.assets)/(before.assets+1n);assert.equal(await vault.previewWithdraw(assets),shares);await send(vault,a,'withdraw',[assets,a.address,a.address],before);expected[idx]-=shares;assert.equal((await token.balanceOf(a.address))-before.wallets[idx],assets);}
        const actualAction=activeSequence.at(-1).method;
        fuzzActions.set(actualAction,(fuzzActions.get(actualAction)||0)+1);
        if(previousAction!==null){const transition=`${previousAction}->${actualAction}`;fuzzTransitions.set(transition,(fuzzTransitions.get(transition)||0)+1);}
        previousAction=actualAction;before=await invariant(expected);
      }
      const t=await trace(lastHash,true,lastMethod,lastFailed);if(t)traces.push(t);
    });
    const sortedCounts=counts=>Object.fromEntries([...counts].sort(([a],[b])=>a.localeCompare(b)));
    const stateDiffComplete=stateDiffStats.operations>0&&stateDiffStats.missing===0&&stateDiffStats.complete===stateDiffStats.operations;
    const expectedRevertedMethods=[...new Set(sequences.flatMap(sequence=>sequence.operations.filter(operation=>operation.reverted).map(operation=>operation.method)))].sort();
    const sampledRevertedMethods=[...tracedOutcomes].filter(outcome=>outcome.endsWith(':reverted')).map(outcome=>outcome.slice(0,-':reverted'.length)).sort();
    const missingRevertedTraceMethods=expectedRevertedMethods.filter(method=>!sampledRevertedMethods.includes(method));
    const traceState=traceEvidenceState(traceStats);
    return {
      state:results.length>0&&results.every(x=>x.state==='passed')?'passed':'failed',
      suite:'ERC-4626 idle VaultV2 reference-model invariants',
      analysisType:'multi-seed local state sequences with independent accounting and opcode traces',
      sourceHash,compilerSettingsHash,fixtureHash:hash({tokenSource,stateReaderSource}),harnessHash:hash(fs.readFileSync(__filename,'utf8')),
      harnessSupportHash:traceSupportHash(__dirname),compiler:solc.version(),target,contract:name,
      network:'in-process Hardhat 31337; no fork or external transactions',externalTransactions:false,externalSigning:false,
      tests:results.length,passed:results.filter(x=>x.state==='passed').length,failed:results.filter(x=>x.state==='failed').length,
      propertyIds:[...new Set(results.flatMap(x=>x.propertyIds))].sort(),results,sequences,traces,traceSampling,
      traceEvidence:{
        state:traceState==='available'&&missingRevertedTraceMethods.length>0?'partial':traceState,
        sourceAttributionState:traceSourceAttributionEvidenceState(traceStats),
        frameIdentityAvailableTraceCount:traceStats.frameIdentityAvailable,frameIdentityPartialTraceCount:traceStats.frameIdentityPartial,
        frameIdentityUnavailableTraceCount:traceStats.frameIdentityUnavailable,targetCodeStepCount:traceStats.targetCodeStepCount,
        targetFrameDepthMismatchCount:traceStats.targetFrameDepthMismatchCount,
        traceCount:traces.length,requestedTraceCount:traceStats.requested,validTraceCount:traceStats.valid,
        invalidTraceCount:traceStats.invalid,skippedTraceCount:traceStats.skipped,truncatedTraceCount:traceStats.truncated,
        stepLimitedTraceCount:traceStats.stepLimited,unknownOpcodeCount:traceStats.unknownOpcodeCount,
        unknownOpcodes:[...traceStats.unknownOpcodes].sort(),totalStepCount:traceStats.totalSteps,
        processedStepCount:traceStats.processedSteps,totalEffectCount:traceStats.stepLimited?null:traceStats.totalEffects,
        observedEffectCount:traceStats.totalEffects,effectCountComplete:traceStats.stepLimited===0,
        targetEffectCount:traceStats.targetEffects,unmappedTargetEffectCount:traceStats.unmappedTargetEffects,
        nonTargetEffectCount:traceStats.nonTargetEffects,
        stepLimit:MAX_TRACE_STEPS,reportedEffectCount:traceStats.reportedEffects,
        mappedEffectCount:traceStats.mappedEffects,unmappedEffectCount:traceStats.unmappedEffects,
        sampledMethodOutcomes:[...tracedOutcomes].sort(),
        expectedRevertedMethods,sampledRevertedMethods,missingRevertedTraceMethods,
        scope:'debug_traceTransaction samples; target source attribution additionally requires EDR frame codeAddress to match the Vault runtime; at most one committed and one reverted sample per method; every target trace attempt is identified in traceSampling by scenario, method, selector, and outcome, including skipped or unavailable attempts; each summary processes at most the configured step limit and reports truncation; not exhaustive coverage; SELFDESTRUCT is an opcode observation, not proof of account deletion',
      },
      frameIdentityCapture:{state:frameIdentityCapture.supported?'available':'unavailable',source:'Hardhat 2.22.19 private provider._node._vm.evm.events path / locked EDR 0.8.0 transaction-time beforeMessage and step events',scope:'selected Vault eth_sendTransaction requests; captured steps are aligned with debug_traceTransaction pc/depth/op before source attribution'},
      stateDiff:{
        schemaVersion:1,
        scope:'queried top-level Vault, ERC20, and fixture actor fields compared around every recorded in-process transaction; native balances are recorded separately under assetBalanceDiff',
        operationCount:stateDiffStats.operations,completeOperationCount:stateDiffStats.complete,
        missingOperationCount:stateDiffStats.missing,stateSnapshotReadCount,complete:stateDiffComplete,
      },
      suiteActionCoverage:[...coverage].sort(),
      suiteActionCoverageScope:'attempted methods; mined execution outcomes are counted separately',
      suiteActionExecutionCoverage:[...actionExecutionStats].sort(([a],[b])=>a.localeCompare(b)).map(([action,counts])=>({action,...counts})),
      sourceCoverage:{
        scope:'sampled depth-1 target runtime source spans with matching EDR frame code address; not exhaustive branch coverage',
        spans:[...sourceCoverage.values()],sampledMethods:[...tracedMethods].sort(),
        sampledMethodOutcomes:[...tracedOutcomes].sort(),
      },
      deterministicFuzz:{
        seeds:seeds.map(x=>'0x'+x.toString(16)),requestedOperations:seeds.length*48,
        executedOperations:sequences.filter(x=>x.id.includes('state-sequence')).reduce((n,x)=>n+x.operations.length,0),
        actionCoverage:[...fuzzActions.keys()].sort(),actionCounts:sortedCounts(fuzzActions),
        transitionCoverage:[...fuzzTransitions.keys()].sort(),transitionCounts:sortedCounts(fuzzTransitions),
        transitionScope:'Adjacent actual successful actions within each seeded sequence; no cross-seed transitions, no claim of exhaustive branch or state coverage.',
      },
      confirmedVulnerabilities:0,
      limitations:[
        'Reviewed idle VaultV2 fixture: standard six-decimal asset; no adapters, fees, gates or live state.',
        'Donation oracle covers the reviewed constructor-default zero maxRate; positive-rate timing and configured fees are not covered.',
        'Fixed seeded sequences cover action adjacency, not all economically distinct states or adversarial transactions.',
        'Source and constructor shape alone do not establish deployment-equivalent configuration.',
        'State diffs cover queried top-level fixture fields and do not prove storage-slot completeness; native and fixture ERC20 balance rows cover only the Vault and three known actors, not arbitrary dependencies or token holders.',
        'No claim of exhaustive paths, exploitability, live-contract safety or new vulnerability discovery',
      ],
      references:['https://eips.ethereum.org/EIPS/eip-4626','https://v2.hardhat.org/hardhat-network/docs/reference'],
    };
  } finally {frameIdentityCapture?.dispose();await provider.destroy();}
}
if (require.main === module){const args=process.argv.slice(4);let name=null,aliases={};for(let i=0;i<args.length;i++){if(args[i]==='--contract')name=args[++i];else if(args[i]==='--source-aliases')aliases=JSON.parse(fs.readFileSync(args[++i],'utf8'));else throw Error(`Unknown harness option ${args[i]}`);}run(JSON.parse(fs.readFileSync(process.argv[2],'utf8')),process.argv[3],name,aliases).then(x=>{console.log(serialize(x));if(x.state!=='passed')process.exitCode=1;}).catch(e=>{console.log(serialize({state:'unavailable',reason:'vault_harness_execution_error',error:e.message.slice(0,2000),confirmedVulnerabilities:0}));process.exitCode=1;});}
module.exports={run};
