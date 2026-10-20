#!/usr/bin/env python3
"""Timed read-only DeFi collection with deterministic evidence and cloud review handoff."""
import argparse
import collections
import concurrent.futures
import copy
import fcntl
import hashlib
import json
import os
import posixpath
import re
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings
from pathlib import Path

try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=NotOpenSSLWarning)
except ImportError:
    pass

from rpc_pool import ROOT, RpcPool, atomic, json_http, now, rpc
from data_provenance import archive_bytes
from bytecode_analysis import analyze_runtime_bytecode
from decompiler_crosscheck import attach_opcode_cross_validation
from decompiler_adapter import run_heimdall
from unified_ir import from_bytecode_report
from ir_reconcile import reconcile as reconcile_ir
from invariant_gen import generate_invariants
from cloud_review import CloudReviewError, run_staged_review
from proxy_history import resolve_proxy_at_block, proxy_history

ALIASES = {'Gnosis':'xDai','Rootstock':'RSK'}
ADAPTER_KEYS = {14:'flare',19:'songbird',250:'fantom',1285:'moonriver',9001:'evmos',1666600000:'harmony',1284:'moonbeam',7700:'canto',1313161554:'aurora',2222:'kava',288:'boba',122:'fuse',40:'telos',1088:'metis',592:'astar',30:'rsk',25:'cronos',100:'xdai',42220:'celo'}
GROUPS = {'Lending':'借贷','CDP':'借贷','Dexs':'DEX','DEX Aggregator':'DEX','Yield':'收益金库','Yield Aggregator':'收益金库','Liquidity Manager':'收益金库','Farm':'收益金库','Leveraged Farming':'收益金库','Onchain Capital Allocator':'收益金库','Liquid Staking':'质押','Liquid Restaking':'质押','Bridge':'桥','Cross Chain Bridge':'桥','Dual-Token Stablecoin':'稳定币','Algo-Stables':'稳定币','Synthetics':'衍生品','Derivatives':'衍生品','Insurance':'保险'}
IMPL_SLOT='0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
BEACON_SLOT='0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
ADDRESS=re.compile(r'^0x[0-9a-fA-F]{40}$')
CAMPAIGN_LEASE_TTL_SEC=45
MAX_RAW_ARCHIVE_BYTES=2*1024*1024*1024
MAX_HTTP_RESPONSE_BYTES=24_000_000

class _RejectCloudRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _rpc_result(parsed):
    """Return a JSON-RPC result while keeping malformed/error envelopes untrusted."""
    if isinstance(parsed, dict) and 'result' in parsed and 'error' not in parsed:
        return parsed['result']
    return None

def _rpc_quantity(value):
    """Decode a JSON-RPC quantity, returning None for tags and malformed values."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r'0x[0-9a-fA-F]+', value):
        try:
            return int(value, 16)
        except ValueError:
            pass
    return None

def _rpc_address(value):
    """Normalize only exact 20-byte addresses; never infer from arbitrary data."""
    if isinstance(value, str) and ADDRESS.fullmatch(value):
        return value.lower()
    return None

def _rpc_code_hash(value):
    """Hash deployed code bytes, excluding the JSON-RPC hex encoding."""
    if not isinstance(value, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', value):
        return None
    try:
        return hashlib.sha256(bytes.fromhex(value[2:])).hexdigest()
    except ValueError:
        return None

def initial_proxy_review_completeness(proxy):
    if not isinstance(proxy, dict) or proxy.get('error'):
        return 'proxy_metadata_unavailable'
    if proxy.get('eip1967Implementation') or proxy.get('beaconImplementation'):
        return 'proxy_only_pending_implementation'
    if proxy.get('eip1967Beacon'):
        return 'proxy_only_implementation_unavailable'
    return 'verified_source_reviewed'

def _rpc_archive_provenance(method, params, parsed):
    """Extract explicit chain identity from one raw RPC response.

    This intentionally leaves fields null when a block tag is symbolic or the
    response does not carry an unambiguous identity.  The raw request remains
    in ``source_ref`` so callers can inspect unsupported cases without treating
    inferred values as observations.
    """
    result = _rpc_result(parsed)
    params = params if isinstance(params, list) else []
    block_number = None
    block_hash = None
    contract_address = None
    code_hash = None

    if isinstance(result, dict):
        block_number = _rpc_quantity(result.get('blockNumber') or result.get('number'))
        candidate_hash = result.get('blockHash') or result.get('hash')
        if isinstance(candidate_hash, str) and re.fullmatch(r'0x[0-9a-fA-F]{64}', candidate_hash):
            block_hash = candidate_hash.lower()
        if method == 'eth_getTransactionReceipt':
            contract_address = _rpc_address(result.get('contractAddress'))

    # Most read methods carry a block tag as their final parameter.  Preserve
    # numeric tags even when the provider returns a scalar result.
    block_param = None
    if method == 'eth_getBlockByNumber' and params:
        block_param = params[0]
    elif method in ('eth_getCode', 'eth_getStorageAt', 'eth_call',
                    'eth_getBalance', 'eth_getProof') and len(params) >= 2:
        block_param = params[-1]
    elif method == 'eth_getBlockReceipts' and params:
        block_param = params[0]
    if block_number is None:
        block_number = _rpc_quantity(block_param)

    address_param = None
    if method in ('eth_getCode', 'eth_getStorageAt', 'eth_getBalance', 'eth_getProof') and params:
        address_param = params[0]
    elif method == 'eth_call' and params and isinstance(params[0], dict):
        address_param = params[0].get('to')
    if contract_address is None:
        contract_address = _rpc_address(address_param)

    if method == 'eth_getCode':
        code_hash = _rpc_code_hash(result)
    return {
        'blockNumber': block_number,
        'blockHash': block_hash,
        'contractAddress': contract_address,
        'codeHash': code_hash,
    }

def code_only(text):
    """Remove comments without changing line numbers or string literals."""
    tokens=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
    return tokens.sub(lambda m: re.sub(r'[^\n]',' ',m.group()) if m.group().startswith(('//','/*')) else m.group(),text)

def run_bounded(command,timeout,**kwargs):
    """Reap the entire compiler process group, including solc children."""
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,**kwargs)
    try:
        out,err=proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=proc.communicate()
        raise subprocess.TimeoutExpired(command,timeout,output=out,stderr=err)
    return subprocess.CompletedProcess(command,proc.returncode,out,err)

def _run_heimdall(code,*,engine,output_dir,timeout_seconds,hardfork='latest'):
    raw=bytes.fromhex(code[2:])
    input_hash=hashlib.sha256(raw).hexdigest()
    if engine is None:
        return {'state':'not_performed','engine':None,'inputSha256':input_hash,'confidence':None,
                'hardfork':hardfork,
                'sourceVerified':False,'highLevelSemanticsRecovered':False,'outputKind':'not_requested',
                'reason':'decompiler_not_requested','artifacts':[],'artifactOverflowCount':0,
                'artifactOmittedCount':0,'artifactInventoryComplete':True,
                'crossValidation':{'state':'not_performed','reason':'decompiler_not_requested'}}
    if engine!='heimdall':raise ValueError('unsupported runtime decompiler')
    try:
        return run_heimdall(code,binary=ROOT/'work/tools/heimdall/heimdall',output_dir=output_dir,
                            timeout_seconds=timeout_seconds,hardfork=hardfork)
    except Exception as error:
        return {'state':'failed','engine':'heimdall-rs','toolVersion':None,'inputSha256':input_hash,
                'hardfork':hardfork,
                'confidence':'heuristic','sourceVerified':False,'highLevelSemanticsRecovered':False,
                'outputKind':'inferred_pseudocode_not_verified_source','command':[],'exitCode':None,
                'timedOut':False,'artifacts':[],'artifactOverflowCount':0,
                'artifactOmittedCount':0,'artifactInventoryComplete':False,
                'crossValidation':{'state':'not_performed','reason':'single_decompiler_engine_configured'},
                'error':f'{type(error).__name__}: {str(error)[:500]}'}

def static_analysis_environment(base=None):
    """Make Slither hash-based candidate ordering reproducible across runs."""
    env=dict(os.environ if base is None else base)
    env['PYTHONHASHSEED']='0'
    return env

def build_excerpts(sources, targets, max_chars=32000):
    ordered=list(sources);target_set=set(targets);target_files=[n for n in ordered if n in target_set]
    numbered={name:[f'{i+1}: {line}' for i,line in enumerate(sources[name].splitlines())] for name in ordered}
    selected={name:set() for name in ordered};remaining=max_chars
    def add(name,indices,limit=None):
        nonlocal remaining
        added=0
        for i in sorted(set(indices)):
            if i<0 or i>=len(numbered[name]) or i in selected[name]:continue
            cost=len(numbered[name][i])+1
            if cost>remaining or (limit is not None and added+cost>limit):continue
            selected[name].add(i);remaining-=cost;added+=cost
        return added
    # Preserve contract identity, compiler directives and immediate file context.
    prefix_budget=round(max_chars*.20)
    for name in target_files+ [n for n in ordered if n not in target_set]:
        if prefix_budget<=0:break
        spent=add(name,range(min(12,len(numbered[name]))),prefix_budget)
        prefix_budget-=spent
    candidates=[]
    function_re=re.compile(r'\b(function|modifier|constructor|fallback|receive)\s*([A-Za-z0-9_]*)\s*\(')
    for order,name in enumerate(ordered):
        lines=sources[name].splitlines();structural=re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/',lambda m:re.sub(r'[^\n]',' ',m.group()),sources[name]).splitlines()
        for i,line in enumerate(structural):
            match=function_re.search(line)
            if not match:continue
            depth=0;opened=False;end=i
            for j in range(i,len(structural)):
                depth+=structural[j].count('{')-structural[j].count('}')
                if '{' in structural[j]:opened=True
                if opened and depth<=0:end=j;break
                if not opened and ';' in structural[j]:end=j;break
            if not opened:continue
            namepart=match.group(2).lower();chunk='\n'.join(lines[i:end+1]);lower=chunk.lower()
            rank=1
            if re.search(r'\b(public|external)\b',chunk):rank+=2
            if re.search(r'deposit|withdraw|redeem|borrow|repay|liquidat|swap|mint|burn|transfer|harvest|execute|claim|bridge|callback|upgrade|initialize|flash|settle',namepart):rank+=10
            if re.search(r'call\s*\{|delegatecall|transferfrom|safetransfer|sendvalue',lower):rank+=3
            if re.search(r'onlyowner|onlyadmin|accesscontrol|reentrancyguard',lower):rank+=1
            if name in target_set:rank+=3
            candidates.append((rank,-order,i,end,name))
    for _,__,first,last,name in sorted(candidates,reverse=True):add(name,range(first,last+1))
    # Complete remaining small modules and use the balance on target functions/files.
    for name in target_files+[n for n in ordered if n not in target_set]:add(name,range(len(numbered[name])))
    excerpts=[];submitted={}
    for name in ordered:
        if not selected[name]:continue
        text='\n'.join(numbered[name][i] for i in sorted(selected[name]))
        submitted[name]=selected[name]
        excerpts.append({'file':name,'numberedSource':text,'truncated':len(selected[name])<len(numbered[name]),'sourceSha256':digest(sources[name]),'submittedLineRanges':ranges_from_set(selected[name])})
    return excerpts,{name:sources[name] for name in ordered},submitted

def ranges_from_set(values):
    out=[]
    for n in sorted(values):
        if not out or n>out[-1][1]+1:out.append([n,n])
        else:out[-1][1]=n
    return out

def historical_revisions(commits):
    revisions=[]
    for entry in commits if isinstance(commits,list) else []:
        for sha in [entry.get('sha'),*((entry.get('parents') or [{}])[0].get('sha'),)]:
            if isinstance(sha,str) and re.fullmatch(r'[0-9a-f]{40}',sha) and sha not in revisions:revisions.append(sha)
    return revisions

def source_identity(data):
    sources,targets,missing=reachable_sources(data)
    settings=((data.get('stdJsonInput') or {}).get('settings') or (data.get('compilation') or {}).get('compilerSettings') or {}).copy()
    settings.pop('outputSelection',None)
    return digest({'sources':sources,'targets':(data.get('metadata') or {}).get('settings',{}).get('compilationTarget',{}),'compiler':(data.get('compilation') or {}).get('compilerVersion'),'settings':settings,'unresolvedImports':missing})

def digest(data):
    return hashlib.sha256((data if isinstance(data,str) else json.dumps(data,sort_keys=True,separators=(',',':'))).encode()).hexdigest()

def resolve_source_import(importer,spec,remappings,sources):
    relative=spec.startswith('.')
    candidate=posixpath.normpath(posixpath.join(posixpath.dirname(importer),spec)) if relative else spec
    if not relative:
        applicable=[]
        for index,rule in enumerate(remappings if isinstance(remappings,list) else []):
            if not isinstance(rule,str) or '=' not in rule:continue
            left,target=rule.split('=',1)
            context,prefix=(left.rsplit(':',1) if ':' in left else ('',left))
            if context and not importer.startswith(context):continue
            if prefix and candidate.startswith(prefix):applicable.append((len(context),len(prefix),index,target+candidate[len(prefix):]))
        if applicable:
            # Solidity uses longest context, then longest prefix, then the last
            # declaration when both lengths tie.
            return max(applicable,key=lambda row:(row[0],row[1],row[2]))[3]
    if candidate in sources:return candidate
    matches=[x for x in sources if x.endswith('/'+candidate)]
    if len(matches)==1:return matches[0]
    return candidate

def reachable_sources(data):
    sources={k:v['content'] for k,v in data.get('sources',{}).items() if isinstance(v,dict) and isinstance(v.get('content'),str)}
    targets=list(((data.get('metadata') or {}).get('settings') or {}).get('compilationTarget',{}))
    if not targets or any(x not in sources for x in targets):raise ValueError('deployment compilation target missing from source bundle')
    remappings=((data.get('stdJsonInput') or {}).get('settings') or {}).get('remappings',[])
    queue=targets[:];seen=set();ordered=[];missing=[]
    while queue:
        name=queue.pop(0)
        if name in seen:continue
        seen.add(name);ordered.append(name)
        clean=code_only(sources[name])
        for match in re.finditer(r'\bimport\s+(?:[^;]*?\bfrom\s+)?[\"\']([^\"\']+)[\"\']\s*;',clean):
            imp=match.group(1);candidate=resolve_source_import(name,imp,remappings,sources)
            if candidate in sources:queue.append(candidate)
            else:missing.append({'importer':name,'import':imp,'resolvedPath':candidate})
    return {k:sources[k] for k in ordered},targets,missing

def build_queue(protocols, chains, threshold=10000):
    buckets=collections.defaultdict(list)
    for p in protocols:
        group=GROUPS.get(p.get('category'))
        if not group: continue
        for c in chains:
            alias=ALIASES.get(c['llamaName'],c['llamaName']); tvl=p.get('chainTvls',{}).get(alias)
            if type(tvl) not in (float,int) or not threshold<=tvl<float('inf'): continue
            key=(group,c['chainId'])
            buckets[key].append({'protocol':p['name'],'slug':p['slug'],'category':p['category'],'group':group,'chain':c['name'],'chainId':c['chainId'],'llamaChain':alias,'tvlUsd':tvl,'module':p.get('module'),'tvlScope':'protocol-on-this-chain; initial screening only','adapterKey':ADAPTER_KEYS[c['chainId']]})
    # Round-robin both category and chain; total protocol TVL is never used.
    groups=list(dict.fromkeys(GROUPS.values())); queue=[]; positions=collections.Counter()
    for b in buckets.values(): b.sort(key=lambda x:(-x['tvlUsd'],x['slug']))
    while any(buckets.values()):
        for group in groups:
            for offset in range(len(chains)):
                index=(positions[group]+offset)%len(chains);c=chains[index]
                b=buckets[(group,c['chainId'])]
                if b:
                    queue.append(b.pop(0));positions[group]=(index+1)%len(chains);break
    return queue

def validate_review(review, sources, submitted_lines=None):
    accepted=[]; rejected=[]
    for item in review.get('observations',[])[:12] if isinstance(review.get('observations'),list) else []:
        if not isinstance(item,dict): continue
        evidence=item.get('evidence',[]); valid=[]
        for e in evidence if isinstance(evidence,list) else []:
            if not isinstance(e,dict): continue
            file=e.get('file'); a=e.get('lineStart'); b=e.get('lineEnd'); quote=e.get('quote')
            if file not in sources or type(a)!=int or type(b)!=int or not 1<=a<=b<=len(sources[file].splitlines()) or b-a>60 or not isinstance(quote,str) or len(quote.strip())<8: continue
            if submitted_lines is not None and (file not in submitted_lines or not set(range(a-1,b)).issubset(submitted_lines[file])):continue
            snippet='\n'.join(sources[file].splitlines()[a-1:b])
            if re.sub(r'\s+','',quote) not in re.sub(r'\s+','',snippet): continue
            # Strip comments from the full file so mid-comment excerpts remain comments.
            code='\n'.join(code_only(sources[file]).splitlines()[a-1:b]).strip()
            quoted_code=code_only(quote).strip()
            if not quoted_code or not re.search(r'[;{}()]',quoted_code) or re.sub(r'\s+','',quoted_code) not in re.sub(r'\s+','',code):continue
            valid.append(e)
        kind=item.get('kind') if item.get('kind') in ('risk_hypothesis','security_control','coverage_gap') else 'unclassified_observation'
        item={**item,'kind':kind,'status':'unconfirmed_review_observation','confirmed':False,'evidence':valid}
        if valid: accepted.append(item)
        else: rejected.append(item)
    return {'summary':str(review.get('summary',''))[:3000],'role':str(review.get('role',''))[:500],'observations':accepted,'rejectedUnsupportedObservations':rejected,'limits':review.get('limits',[]),'confirmedVulnerabilities':0,'localReproduction':'not performed for newly collected contracts'}

class Campaign:
    def __init__(self,duration,output,workers=3,decompiler=None,decompiler_timeout=30,decompiler_hardfork='latest',review_budget_usd=None):
        self.id=str(uuid.uuid4());self.start=time.monotonic();self.wall=time.time();self.duration=duration;self.output=Path(output)
        self.run=ROOT/'work/defi-campaign'/self.id;self.run.mkdir(parents=True)
        self.stop=threading.Event();self.lock=threading.RLock();self.net_lock=threading.Lock()
        self.host_next={};self.host_block={};self.cache={};self.seen=set();self.source_seen={};self.source_locks={};self.workers=workers
        self.journal=(self.run/'events.jsonl').open('a',buffering=1);self.counts=collections.Counter();self.recent=[];self.active={};self.failures=[]
        self.queue=[];self.pool=None;self.last_tick=self.start;self.max_gap=0;self.sample_count=0;self.state='initializing';self.snapshot_at=None;self.address_offsets={};self.address_cache={};self.exhausted=set();self.validation_errors=[];self.metrics=collections.defaultdict(list);self.last_fingerprint_check=self.start
        self.heartbeat_seq=0;self.lease_ttl_sec=CAMPAIGN_LEASE_TTL_SEC
        self.rpc_archive_refs=[];self.rpc_archive_count=0;self.rpc_archive_failures=[];self.http_archive_refs=[];self.http_archive_count=0;self.http_archive_failures=[];self.raw_archive_bytes=0
        self.source_hash=subprocess.check_output(['node','--input-type=module','-e',"import {runtimeFingerprint} from './src/runtime-fingerprint.js'; console.log(await runtimeFingerprint())"],cwd=ROOT,text=True).strip()
        self.decompiler=decompiler;self.decompiler_timeout=decompiler_timeout;self.decompiler_hardfork=decompiler_hardfork
        self.review_budget_usd=review_budget_usd
        cloud_configured=all(os.environ.get(key,'').strip() for key in ('DEFI_CLOUD_AI_BASE_URL','DEFI_CLOUD_AI_API_KEY','DEFI_CLOUD_AI_MODEL'))
        self.config={'minimumProtocolChainTvlUsd':10000,'durationSec':duration,'workers':workers,'remoteHostIntervalSec':0.5,'rawArchiveByteBudget':MAX_RAW_ARCHIVE_BYTES,'runtimeBytecodeDecompiler':decompiler,'runtimeBytecodeDecompileTimeoutSec':decompiler_timeout,'runtimeBytecodeDecompileHardfork':decompiler_hardfork,'reviewBudgetUsd':review_budget_usd,'sourceReviewProvider':'external_cloud_ai','cloudReviewAdapter':'openai-compatible','cloudReviewConfiguration':'configured' if cloud_configured else 'unavailable','cloudReviewEvidence':'recorded_calls_only','scope':'public read-only collection, deterministic static analysis and optional external cloud review; no asset operations'}
    def inc(self,key,amount=1):
        with self.lock:self.counts[key]+=amount
    def runtime_bytecode_analysis(self,code,item,address,height,block,folder,record):
        try:
            # Keep deterministic opcode activation and optional Heimdall on
            # the same explicitly configured fork.  Without a decompiler we
            # leave activation unverified instead of treating the CLI default
            # `latest` as proof for an unknown historical deployment.
            analysis_hardfork = self.decompiler_hardfork if self.decompiler else None
            disassembly=analyze_runtime_bytecode(
                code, chain_id=item['chainId'], address=address, block=height,
                block_hash=block['hash'], hardfork=analysis_hardfork,
            )
        except Exception as error:
            record['runtimeBytecodeAnalysis']={'state':'unavailable','failureStage':'runtime_disassembly','error':f'{type(error).__name__}: {str(error)[:180]}','confirmedVulnerability':False}
            self.inc('runtimeBytecodeAnalysisUnavailable')
            return

        decompilation_dir=folder/'runtime-bytecode-decompilation'
        try:
            decompilation=_run_heimdall(code,engine=self.decompiler,output_dir=decompilation_dir,
                timeout_seconds=self.decompiler_timeout,hardfork=self.decompiler_hardfork)
        except Exception as error:
            decompilation={'state':'failed','engine':self.decompiler,'sourceVerified':False,
                'highLevelSemanticsRecovered':False,'error':f'{type(error).__name__}: {str(error)[:180]}'}
        if self.decompiler and isinstance(decompilation, dict):
            # Cross-check only the byte-level tokenization.  This binds the
            # heuristic decompiler record to the primary report without
            # presenting the independent decoder as a second high-level
            # decompiler or semantic validator.
            attach_opcode_cross_validation(decompilation, disassembly)
        if self.decompiler:
            decompilation['outputDirectory']=str(decompilation_dir.relative_to(ROOT))
        disassembly['decompilation']=decompilation
        disassembly_path=folder/'runtime-bytecode-analysis.json'
        result={'state':'partial','analysisType':disassembly['analysisType'],'bytecodeSha256':disassembly['bytecodeSha256'],
            'instructionCount':disassembly['instructionCount'],'selectorCandidateCount':len(disassembly['selectorCandidates']),
            'externalCallSiteCount':len(disassembly['externalCallSites']),'storageOperationSiteCount':len(disassembly['storageOperationSites']),
            'eventTopicCandidateCount':len(disassembly.get('eventTopicCandidates',[])),
            'errorSelectorCandidateCount':len(disassembly.get('errorSelectorCandidates',[])),
            'controlFlowEdgeCount':len(disassembly.get('controlFlowEdges',[])),
            'opcodePcCrossCheckState':(disassembly.get('opcodePcCrossCheck') or {}).get('state','not_recorded'),
            'hardfork':disassembly.get('hardfork'),
            'report':str(disassembly_path.relative_to(ROOT)),'decompilationState':decompilation.get('state'),
            'decompilation':decompilation,'confirmedVulnerability':False}
        record['runtimeBytecodeAnalysis']=result
        self.inc('runtimeBytecodeAnalyses')
        if decompilation.get('state')=='completed':self.inc('runtimeBytecodeDecompilations')
        elif decompilation.get('state')=='not_performed':self.inc('runtimeBytecodeDecompilationsNotRequested')
        else:self.inc('runtimeBytecodeDecompilationsIncomplete')

        # Persist raw bytecode and decompiler evidence before optional IR work.
        try:
            atomic(disassembly_path,disassembly)
        except Exception as error:
            result.update(state='partial',failureStage='disassembly_report_persistence',
                error=f'{type(error).__name__}: {str(error)[:180]}',disassembly=disassembly)
            self.inc('runtimeBytecodeAnalysisPartials')
            return

        try:
            bytecode_ir=from_bytecode_report(disassembly)
        except Exception as error:
            result.update(state='partial',failureStage='unified_ir_conversion',
                error=f'{type(error).__name__}: {str(error)[:180]}',
                unifiedIR={'state':'unavailable','error':f'{type(error).__name__}: {str(error)[:180]}'})
            self.inc('runtimeBytecodeAnalysisPartials')
            return
        ir_path=folder/'unified-ir-bytecode.json'
        try:
            atomic(ir_path,bytecode_ir)
        except Exception as error:
            result.update(state='partial',failureStage='unified_ir_persistence',
                error=f'{type(error).__name__}: {str(error)[:180]}',
                unifiedIR={'state':'unavailable','error':f'{type(error).__name__}: {str(error)[:180]}'})
            self.inc('runtimeBytecodeAnalysisPartials')
            return

        unified_ir={'state':bytecode_ir['state'],'documentId':bytecode_ir['documentId'],
            'report':str(ir_path.relative_to(ROOT)),'functionCount':len(bytecode_ir['functions']),
            'operationCount':len(bytecode_ir['operations']),'linkCount':len(bytecode_ir['links']),
            'controlFlowEdgeCount':len(bytecode_ir.get('controlFlowEdges',[])),
            'eventCount':len(bytecode_ir.get('events',[])),
            'errorCount':len(bytecode_ir.get('errors',[])),
            'fieldStates':{key:bytecode_ir.get('fieldStates',{}).get(key,'not_recorded') for key in ('events','errors')},
            'semanticsProven':False}
        disassembly['unifiedIR']=unified_ir
        result.update(state='completed',unifiedIR=unified_ir)
        try:
            atomic(disassembly_path,disassembly)
        except Exception as error:
            result.update(state='partial',failureStage='disassembly_report_update_persistence',
                error=f'{type(error).__name__}: {str(error)[:180]}',disassembly=disassembly)
            self.inc('runtimeBytecodeAnalysisPartials')

    def timing(self,key,started):
        with self.lock:self.metrics[key].append(round((time.monotonic()-started)*1000))
    def timing_ms(self,key,milliseconds):
        if type(milliseconds)==int and milliseconds>=0:
            with self.lock:self.metrics[key].append(milliseconds)
    def _archive_reference(self, reference):
        """Keep only bounded, relative archive references in the live report."""
        result=dict(reference)
        for key in ('payload_path','metadata_path'):
            value=result.get(key)
            if isinstance(value,str):
                try: result[key]=str(Path(value).relative_to(ROOT))
                except ValueError: pass
        return result
    def archive_rpc_response(self, url, method, params, raw, parsed, chain_id, parse_error=None):
        reserved=False
        try:
            self._reserve_archive_bytes(len(raw));reserved=True
            identity=_rpc_archive_provenance(method, params, parsed)
            reference=archive_bytes(
                self.run/'raw-archive', raw, kind='rpc-response', project_id=self.id,
                source_ref={'url':url,'method':method,'params':params,'chainId':chain_id},
                tool_version='rpc_pool/1', chain_id=chain_id,
                block_number=identity['blockNumber'], block_hash=identity['blockHash'],
                contract_address=identity['contractAddress'], code_hash=identity['codeHash'],
                provenance={'responseParsed':parsed is not None,'parseError':parse_error},
                parse_error=parse_error,
            )
        except Exception as error:
            with self.lock:
                if reserved:self.raw_archive_bytes=max(0,self.raw_archive_bytes-len(raw))
                self.rpc_archive_failures.append(f'{type(error).__name__}: {str(error)[:180]}');self.rpc_archive_failures=self.rpc_archive_failures[-64:]
            self.event('archive_failure',kind='rpc-response',url=url,method=method,error=str(error)[:240])
            raise
        with self.lock:
            self.rpc_archive_count+=1
            self.rpc_archive_refs.append(self._archive_reference(reference));self.rpc_archive_refs=self.rpc_archive_refs[-64:]
            self.counts['rpcResponsesArchived']+=1
        return reference
    def archive_http_response(self, url, raw, parsed, parse_error=None):
        reserved=False
        try:
            self._reserve_archive_bytes(len(raw));reserved=True
            reference=archive_bytes(
                self.run/'raw-archive', raw, kind='http-response', project_id=self.id,
                source_ref={'url':url}, tool_version='defi-campaign/1',
                provenance={'responseParsed':parsed is not None,'parseError':parse_error},
                parse_error=parse_error,
            )
        except Exception as error:
            with self.lock:
                if reserved:self.raw_archive_bytes=max(0,self.raw_archive_bytes-len(raw))
                self.http_archive_failures.append(f'{type(error).__name__}: {str(error)[:180]}');self.http_archive_failures=self.http_archive_failures[-64:]
            self.event('archive_failure',kind='http-response',url=url,error=str(error)[:240])
            raise
        with self.lock:
            self.http_archive_count+=1
            self.http_archive_refs.append(self._archive_reference(reference));self.http_archive_refs=self.http_archive_refs[-64:]
            self.counts['httpResponsesArchived']+=1
        return reference
    def _reserve_archive_bytes(self, amount):
        with self.lock:
            if amount<0 or self.raw_archive_bytes+amount>MAX_RAW_ARCHIVE_BYTES:
                raise OSError(f'raw archive budget exceeded ({MAX_RAW_ARCHIVE_BYTES} bytes)')
            self.raw_archive_bytes+=amount
    def rpc_response(self, url, method, params, timeout, chain_id):
        return rpc(url, method, params, timeout, raw_sink=self.archive_rpc_response, chain_id=chain_id)
    def fingerprint_check(self):
        current=run_bounded(['node','--input-type=module','-e',"import {runtimeFingerprint} from './src/runtime-fingerprint.js'; console.log(await runtimeFingerprint())"],15,cwd=ROOT).stdout.strip()
        if current!=self.source_hash:
            self.validation_errors.append('source fingerprint changed during campaign');self.stop.set()
            self.event('integrity_failure',expected=self.source_hash,actual=current)
        self.last_fingerprint_check=time.monotonic()
    def event(self,kind,**data):
        with self.lock:
            self.journal.write(json.dumps({'at':now(),'type':kind,**data},ensure_ascii=False)+'\n');self.journal.flush()
    def fetch(self,url,timeout=15,json_result=True,cache=False):
        if cache:
            with self.lock:
                if url in self.cache: return self.cache[url]
        host=urllib.parse.urlsplit(url).hostname
        for attempt in range(2):
            if self.stop.is_set(): raise RuntimeError('campaign stopping')
            with self.net_lock:
                current=time.monotonic()
                if self.host_block.get(host,0)>current: raise RuntimeError('provider cooling down')
                delay=max(0,self.host_next.get(host,0)-current);self.host_next[host]=current+delay+0.5
            if self.stop.wait(delay): raise RuntimeError('campaign stopping')
            try:
                req=urllib.request.Request(url,headers={'User-Agent':'BlockchainSecurityResearch/1.0'})
                try:
                    with urllib.request.urlopen(req,timeout=timeout) as r: raw=r.read(MAX_HTTP_RESPONSE_BYTES+1)
                except urllib.error.HTTPError as error:
                    body=error.read(MAX_HTTP_RESPONSE_BYTES+1)
                    suffix='; retained body prefix only' if len(body)>MAX_HTTP_RESPONSE_BYTES else ''
                    self.archive_http_response(url,body[:MAX_HTTP_RESPONSE_BYTES],None,f'HTTP status {error.code}{suffix}')
                    raise
                if len(raw)>MAX_HTTP_RESPONSE_BYTES:
                    self.archive_http_response(url,raw[:MAX_HTTP_RESPONSE_BYTES],None,f'response exceeds {MAX_HTTP_RESPONSE_BYTES} bytes; retained prefix only')
                    raise ValueError('response exceeds 24 MB')
                try:
                    result=json.loads(raw) if json_result else raw.decode('utf-8')
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    self.archive_http_response(url,raw,None,f'{type(error).__name__}: invalid HTTP response body')
                    raise
                self.archive_http_response(url,raw,result)
                if cache:
                    with self.lock:self.cache[url]=result
                return result
            except urllib.error.HTTPError as e:
                if e.code in (403,429):
                    with self.net_lock:self.host_block[host]=time.monotonic()+300
                if e.code<500 or attempt: raise
            except (TimeoutError,OSError):
                if attempt: raise
            self.stop.wait(1+attempt)
    def checkpoint(self):
        with self.lock:
            mono=time.monotonic();self.max_gap=max(self.max_gap,mono-self.last_tick);self.last_tick=mono;self.sample_count+=1
            heartbeat=now();self.heartbeat_seq=getattr(self,'heartbeat_seq',0)+1
            lease_ttl=max(1,int(getattr(self,'lease_ttl_sec',CAMPAIGN_LEASE_TTL_SEC)))
            expires=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+lease_ttl))
            lease={'schemaVersion':1,'kind':'defi-source-campaign-lease','runId':self.id,'pid':os.getpid(),'state':self.state,'heartbeatAt':heartbeat,'expiresAt':expires,'ttlSec':lease_ttl,'sequence':self.heartbeat_seq}
            counts=dict(self.counts)
            row={'schemaVersion':1,'kind':'defi-source-campaign','runId':self.id,'pid':os.getpid(),'state':self.state,'startedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(self.wall)),'updatedAt':heartbeat,'heartbeatAt':heartbeat,'heartbeatSeq':self.heartbeat_seq,'lease':lease,'plannedEndAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(self.wall+self.duration)),'durationMs':round((mono-self.start)*1000),'targetDurationMs':self.duration*1000,'sampleCount':self.sample_count,'maxSamplingGapMs':round(self.max_gap*1000),'sourceFingerprint':self.source_hash,'config':self.config,'tvlSnapshotAt':self.snapshot_at,'qualifiedProtocolChains':len(self.queue),'counts':counts,'active':list(self.active.values()),'recent':self.recent[-12:],'errors':self.failures[-12:],'evidenceDirectory':str(self.run.relative_to(ROOT)),'journal':str((self.run/'events.jsonl').relative_to(ROOT)),'rpc':{'failovers':self.pool.failovers if self.pool else 0,'healthyChains':sum(c['healthyCount']>0 for c in self.pool.rows.values()) if self.pool else 0,'redundantChains':sum(c['redundant'] for c in self.pool.rows.values()) if self.pool else 0},'rawArchive':{'directory':str((self.run/'raw-archive').relative_to(ROOT)),'byteBudget':MAX_RAW_ARCHIVE_BYTES,'reservedBytes':getattr(self,'raw_archive_bytes',0),'rpcResponses':getattr(self,'rpc_archive_count',0),'httpResponses':getattr(self,'http_archive_count',0),'recentReferences':getattr(self,'rpc_archive_refs',[])[-8:]+getattr(self,'http_archive_refs',[])[-8:],'failures':getattr(self,'rpc_archive_failures',[])[-12:]+getattr(self,'http_archive_failures',[])[-12:]},'interpretation':'TVL is a protocol-chain screening proxy, not per-contract funds. Source reviews and static signals are unconfirmed. New-contract local reproduction is tracked separately.'}
            row['metrics']={k:{'count':len(v),'p50Ms':sorted(v)[len(v)//2],'p95Ms':sorted(v)[min(len(v)-1,int(len(v)*.95))],'maxMs':max(v)} for k,v in self.metrics.items() if v}
            row['rpc']['runtime']=self.pool.snapshot() if self.pool else {}
            successful_reviews=counts.get('cloudReviewCompletions',0)
            review_attempts=counts.get('cloudReviewAttempts',0)
            configured=self.config.get('cloudReviewConfiguration')=='configured'
            row['analysisMode']={'cloudAI':{'adapter':'openai-compatible','state':'available_with_recorded_calls' if successful_reviews else 'failed' if review_attempts else 'configured_not_called' if configured else 'unavailable','completedCalls':successful_reviews,'attemptedCalls':review_attempts,'unavailableCount':counts.get('cloudReviewUnavailable',0),'evidence':'per-contract cloud-review-evidence.json'}}
            row['validation']={'sourceUnchanged':not self.validation_errors,'continuousSampling':self.max_gap<=45,'targetWindowReached':mono-self.start>=self.duration,'cloudReviewAttempts':review_attempts,'cloudReviewCompletions':successful_reviews,'cloudReviewEvidence':'recorded_calls_only'}
            row['validationErrors']=self.validation_errors[:]
            row['counts']['qualifiedProtocolChains']=len(self.queue)
            atomic(self.output,row);atomic(self.run/'summary.json',row);atomic(self.run/'lease.json',lease);self.event('checkpoint',counts=counts,durationMs=row['durationMs'],state=self.state,heartbeatAt=heartbeat,heartbeatSeq=self.heartbeat_seq)
    def initialize(self):
        self.checkpoint()
        protocols=self.fetch('https://api.llama.fi/protocols',timeout=25);self.snapshot_at=now()
        atomic(self.run/'protocols.json',{'retrievedAt':self.snapshot_at,'source':'https://api.llama.fi/protocols','data':protocols})
        chains=json.loads((ROOT/'flare-scan/chains.json').read_text())['chains'];self.queue=build_queue(protocols,chains)
        for q in self.queue:q['tvlObservedAt']=self.snapshot_at
        atomic(self.run/'queue.json',self.queue)
        pool=json.loads((ROOT/'work/rpc-pool.json').read_text())
        from datetime import datetime
        if time.time()-datetime.fromisoformat(pool['generatedAt'].replace('Z','+00:00')).timestamp()>1800: raise RuntimeError('RPC validation older than 30 minutes; refresh pool first')
        self.pool=RpcPool(pool, raw_sink=self.archive_rpc_response);atomic(self.run/'rpc-pool.initial.json',pool)
        self.tree=self.fetch('https://api.github.com/repos/DefiLlama/DefiLlama-Adapters/git/trees/main?recursive=1',cache=True)
        if self.tree.get('truncated'): raise RuntimeError('adapter tree truncated')
        self.paths={x['path'] for x in self.tree['tree']};self.ref=self.tree['sha'];atomic(self.run/'adapter-tree.json',self.tree)
        self.state='running';self.checkpoint();self.event('started',runId=self.id,queue=len(self.queue),config=self.config)
    def addresses(self,item):
        module=item.get('module')
        if not isinstance(module,str) or '..' in module or not re.fullmatch(r'[a-zA-Z0-9_./-]+',module): raise ValueError('invalid or missing adapter module')
        path='projects/'+module;revision=self.ref;historical=False
        if path not in self.paths:
            api='https://api.github.com/repos/DefiLlama/DefiLlama-Adapters/commits?path='+urllib.parse.quote(path,safe='/')+'&per_page=5'
            commits=self.fetch(api,timeout=15,cache=True)
            if not isinstance(commits,list) or not commits:raise ValueError('catalog adapter absent from current tree and official path history')
            revisions=historical_revisions(commits)
            for sha in revisions:
                candidate=f'https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/{sha}/{path}'
                try:
                    source=self.fetch(candidate,json_result=False,cache=True);revision=sha;historical=True;url=candidate;break
                except urllib.error.HTTPError as error:
                    if error.code!=404:raise
            if not historical:raise ValueError('no retained historical source for official adapter path')
        if not historical:
            url=f'https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/{revision}/{path}'
            source=self.fetch(url,json_result=False,cache=True)
        adapter=self.run/'adapters'/f'{digest(url)}.js';adapter.parent.mkdir(exist_ok=True);adapter.write_text(source)
        keys=[item['adapterKey']]
        if item['chainId']==100:keys.append('gnosis')
        if item['chainId']==30:keys.append('rootstock')
        parsed=subprocess.run(['node',str(ROOT/'scripts/adapter-addresses.cjs')],input=json.dumps({'source':source,'chainKeys':keys}),capture_output=True,text=True,timeout=8)
        if parsed.returncode: raise ValueError('adapter syntax/static resolution failed: '+parsed.stderr[-200:])
        rows=[{**r,'adapterSource':url,'adapterRevision':revision,'historicalAdapter':historical,'adapterSha256':digest(source),'adapterEvidence':str(adapter.relative_to(ROOT))} for r in json.loads(parsed.stdout)['addresses']]
        # Resolve same-project static config modules without evaluating any JS.
        deps=list(dict.fromkeys(re.findall(r'require\([\"\'](\./[^\"\']+)[\"\']\)',source)))[:4]
        for dep in deps:
            candidate=str(Path(path).parent/dep[2:])
            if not candidate.endswith('.js'):candidate+='.js'
            if '..' in dep or candidate not in self.paths:continue
            dep_url=f'https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/{self.ref}/{candidate}'
            text=self.fetch(dep_url,json_result=False,cache=True);dep_file=self.run/'adapters'/f'{digest(dep_url)}.js';dep_file.write_text(text)
            r=subprocess.run(['node',str(ROOT/'scripts/adapter-addresses.cjs')],input=json.dumps({'source':text,'chainKeys':keys}),capture_output=True,text=True,timeout=8)
            if r.returncode:continue
            rows.extend({**v,'adapterSource':dep_url,'adapterSha256':digest(text),'adapterEvidence':str(dep_file.relative_to(ROOT))} for v in json.loads(r.stdout)['addresses'])
        # Official Beefy deployment API links actual vault addresses by chain.
        if item['slug']=='beefy':
            vaults=self.fetch('https://api.beefy.finance/vaults/all',cache=True)
            rows=[{'address':v['earnContractAddress'],'line':None,'context':v.get('id'),'association':'official Beefy vault chain mapping','deploymentSource':'https://api.beefy.finance/vaults/all'} for v in vaults if v.get('chain') in keys and ADDRESS.fullmatch(v.get('earnContractAddress','')) and v.get('status')=='active']
        return [{'adapterSource':url,'adapterSha256':digest(source),'adapterEvidence':str(adapter.relative_to(ROOT)),**r} for r in rows]
    def review(self,data,record,folder,unified_ir=None,invariants=None):
        sources,targets,missing_imports=reachable_sources(data)
        if not sources:
            raise ValueError('verified source bundle contains no source text')
        endpoint=os.environ.get('DEFI_CLOUD_AI_BASE_URL','').strip()
        api_key=os.environ.get('DEFI_CLOUD_AI_API_KEY','').strip()
        model=os.environ.get('DEFI_CLOUD_AI_MODEL','').strip()
        started=time.monotonic()
        self.inc('cloudReviewAttempts')
        result=run_staged_review(data=data,record=record,sources=sources,targets=targets,
            validate_review=validate_review,build_excerpts=build_excerpts,unified_ir=unified_ir,
            invariants=invariants,dependency_signatures=record.get('dependencyTrace'),
            endpoint=endpoint,api_key=api_key,model=model,
            summary_model=os.environ.get('DEFI_CLOUD_AI_SUMMARY_MODEL','').strip() or None,
            adversarial_model=os.environ.get('DEFI_CLOUD_AI_ADVERSARIAL_MODEL','').strip() or None,
            budget_usd=self.review_budget_usd,
            stop_event=self.stop)
        self.inc('cloudReviewAttempts', max(0, len(result.get('callEvidence', {}).get('calls', [])) - 1))
        result['unresolvedImports']=missing_imports
        atomic(folder/'cloud-review-evidence.json',result)
        self.timing('cloudReview',started)
        return result
    def trace_amt_reward_dependency(self,data,item,record,folder,height,block_hash):
        sources,targets,_=reachable_sources(data)
        if not any(target=='AMTDepositPool' for target in (data.get('metadata',{}).get('settings',{}).get('compilationTarget') or {}).values()):return None
        joined='\n'.join(sources.values())
        if 'config.getContract(AMTConstants.AMT_REWARD_POOL)' not in joined:return None
        address=record.get('originProxy') or record['address'];calls=[]
        def at(to,method,params):
            value,url=self.pool.call(item['chainId'],method,params)
            observed=self.rpc_response(url,'eth_getBlockByNumber',[height,False],7,item['chainId'])
            if observed.get('hash')!=block_hash:raise ValueError('dependency call is not on the pinned block')
            calls.append({'to':to,'method':method,'rpc':url,'result':value})
            return value
        config_result=at(address,'eth_call',[{'to':address,'data':'0x79502c55'},height])
        if not isinstance(config_result,str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}',config_result):raise ValueError('AMTDepositPool config getter returned malformed data')
        config='0x'+config_result[-40:]
        if not int(config,16):raise ValueError('AMTDepositPool config address is zero')
        config_code=at(config,'eth_getCode',[config,height])
        if not isinstance(config_code,str) or config_code in ('0x','0x0','0x00'):raise ValueError('configured dependency registry has no code')
        reward_raw=at(config,'eth_call',[{'to':config,'data':'0xe16c7d9800879fd6837669fabc6aef76234b8a59f97200ed344c21acc3a48a4245ae2038'},height])
        deposit_raw=at(config,'eth_call',[{'to':config,'data':'0xe16c7d98776339db9b1bf7b4cc11df2d9e3faeafdec0e393c7d77e1c9d3e0168b00a14a9'},height])
        if not all(isinstance(x,str) and re.fullmatch(r'0x[0-9a-fA-F]{64}',x) for x in (reward_raw,deposit_raw)):raise ValueError('AMT config getter returned malformed dependency address')
        reward='0x'+reward_raw[-40:];deposit='0x'+deposit_raw[-40:]
        if deposit.lower()!=address.lower():raise ValueError('configured AMT deposit pool does not match traced proxy')
        if not int(reward,16):raise ValueError('configured reward pool is zero')
        impl_raw=at(reward,'eth_getStorageAt',[reward,IMPL_SLOT,height]);implementation='0x'+impl_raw[-40:]
        if not int(implementation,16):raise ValueError('configured reward pool has no EIP-1967 implementation')
        code=at(implementation,'eth_getCode',[implementation,height])
        source_url=f'https://sourcify.dev/server/v2/contract/{item["chainId"]}/{implementation.lower()}?fields=all'
        bundle=self.fetch(source_url,timeout=25)
        if int(bundle.get('chainId',-1))!=item['chainId'] or str(bundle.get('address','')).lower()!=implementation.lower():raise ValueError('reward dependency source identity mismatch')
        if (bundle.get('runtimeBytecode') or {}).get('onchainBytecode','').lower()!=code.lower() or bundle.get('runtimeMatch') not in ('exact_match','match'):raise ValueError('reward implementation source does not match pinned on-chain bytecode')
        fee_receiver='0x'+at(reward,'eth_call',[{'to':reward,'data':'0xb3f00674'},height])[-40:]
        fee_rate=at(reward,'eth_call',[{'to':reward,'data':'0x978bbdb9'},height])
        fee_code=at(fee_receiver,'eth_getCode',[fee_receiver,height]) if int(fee_receiver,16) else '0x'
        atomic(folder/'verified-dependency-source.json',bundle)
        result={'state':'verified','scope':'AMT reward pool dependency; not a separate TVL position','block':height,'blockHash':block_hash,'depositPool':address,'config':config,'rewardPool':reward,'rewardImplementation':implementation,'rewardSourceUrl':source_url,'rewardRuntimeMatch':bundle['runtimeMatch'],'rewardSourceFile':str((folder/'verified-dependency-source.json').relative_to(ROOT)),'feeReceiver':fee_receiver,'feeReceiverHasCode':isinstance(fee_code,str) and fee_code not in ('0x','0x0','0x00'),'feeRate':fee_rate,'calls':calls,'interpretation':'Fee receiver callback depends on privileged configuration; observed code/state do not alone prove reachability or exploitability.'}
        atomic(folder/'dependency-trace.json',result);self.inc('verifiedDependencies');return {'bundle':bundle,'report':result,'path':str((folder/'verified-dependency-source.json').relative_to(ROOT))}
    def contract(self,item,address_info):
        address=address_info['address'];key=f'{item["chainId"]}:{address.lower()}'
        with self.lock:
            if key in self.seen:self.counts['duplicateAddresses']+=1;return
            self.seen.add(key);self.counts['contractCandidates']+=1
        folder=self.run/'contracts'/f'{item["chainId"]}-{address.lower()}';folder.mkdir(parents=True)
        record={**item,**address_info,'address':address,'directory':str(folder),'startedAt':now(),'state':'collecting','confirmed':False,'localTestStatus':'not_performed','dynamicAnalysis':{'state':'not_performed','reason':'No target-specific local EVM harness is defined for this contract.'},'reviewCompleteness':'pending','scope':'adapter-associated contract; not proof of per-contract value or exploitable vulnerability'}
        try:
            height=address_info.get('proxyBlock')
            if not height:height,_=self.pool.call(item['chainId'],'eth_blockNumber',[])
            block,url=self.pool.call(item['chainId'],'eth_getBlockByNumber',[height,False])
            if int(block['number'],16)!=int(height,16):raise ValueError('pinned block mismatch')
            if address_info.get('proxyBlockHash') and block['hash']!=address_info['proxyBlockHash']:raise ValueError('proxy implementation block changed')
            code,code_rpc=self.pool.call(item['chainId'],'eth_getCode',[address,height])
            code_block=self.rpc_response(code_rpc,'eth_getBlockByNumber',[height,False],7,item['chainId'])
            if code_block.get('hash')!=block['hash']:raise ValueError('RPC disagreement or reorg at pinned block')
            if not isinstance(code,str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+',code) or code=='0x00':raise ValueError('address has no valid deployed code at pinned block')
            record['deployment']={'block':height,'hash':block['hash'],'observedAt':now(),'rpc':code_rpc,'codeSha256':digest(code.lower()),'codeBytes':(len(code)-2)//2}
            self.inc('deployedContracts')
            self.runtime_bytecode_analysis(code,item,address,height,block,folder,record)
            try:
                slot,slot_rpc=self.pool.call(item['chainId'],'eth_getStorageAt',[address,IMPL_SLOT,height])
                slot_block=self.rpc_response(slot_rpc,'eth_getBlockByNumber',[height,False],7,item['chainId'])
                if slot_block.get('hash')!=block['hash']:raise ValueError('implementation storage RPC disagrees on pinned block')
                if not isinstance(slot,str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}',slot):raise ValueError('invalid implementation slot response')
                impl='0x'+slot[-40:]
                implementation=impl if ADDRESS.fullmatch(impl) and int(impl,16) else None
                beacon,beacon_rpc=self.pool.call(item['chainId'],'eth_getStorageAt',[address,BEACON_SLOT,height])
                beacon_block=self.rpc_response(beacon_rpc,'eth_getBlockByNumber',[height,False],7,item['chainId'])
                if beacon_block.get('hash')!=block['hash']:raise ValueError('beacon storage RPC disagrees on pinned block')
                if not isinstance(beacon,str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}',beacon):raise ValueError('invalid beacon slot response')
                beacon_address='0x'+beacon[-40:];beacon_address=beacon_address if int(beacon_address,16) else None
                beacon_implementation=None
                if not implementation and beacon_address:
                    result,call_rpc=self.pool.call(item['chainId'],'eth_call',[{'to':beacon_address,'data':'0x5c60da1b'},height])
                    call_block=self.rpc_response(call_rpc,'eth_getBlockByNumber',[height,False],7,item['chainId'])
                    if call_block.get('hash')!=block['hash']:raise ValueError('beacon implementation RPC disagrees on pinned block')
                    if isinstance(result,str) and re.fullmatch(r'0x[0-9a-fA-F]{64}',result):
                        candidate='0x'+result[-40:]
                        if int(candidate,16):beacon_implementation=candidate
                record['proxy']={'eip1967Implementation':implementation,'eip1967Beacon':beacon_address,'beaconImplementation':beacon_implementation,'implementationReviewState':'pending' if implementation or beacon_implementation else 'unavailable' if beacon_address else 'not_applicable','proxyKind':'eip1967_implementation' if implementation else 'eip1967_beacon' if beacon_address else 'unresolved_or_non_proxy','scope':'EIP-1967 implementation and beacon slots; custom proxy patterns and beacons without a readable implementation remain unsupported'}
                # Keep the generic resolver as an independently auditable,
                # fixed-block observation.  It re-reads the block anchor,
                # slots, and runtime code and fails closed on provider drift.
                def fixed_rpc(method, params):
                    value, _url = self.pool.call(item['chainId'], method, params)
                    return value
                fixed = resolve_proxy_at_block(fixed_rpc, address, height, expected_block_hash=block['hash'])
                record['proxy']['fixedBlockResolution'] = fixed
                history_from = address_info.get('proxyHistoryFromBlock')
                history_to = address_info.get('proxyHistoryToBlock')
                if history_from is not None and history_to is not None:
                    record['proxy']['history'] = proxy_history(fixed_rpc, address, history_from, history_to)
            except Exception as e:record['proxy']={'error':str(e)}
            source_url=f'https://sourcify.dev/server/v2/contract/{item["chainId"]}/{address}?fields=all'
            data=self.fetch(source_url,timeout=25)
            if int(data.get('chainId',-1))!=item['chainId'] or str(data.get('address','')).lower()!=address.lower():raise ValueError('source provider identity mismatch')
            stored=(data.get('runtimeBytecode') or {}).get('onchainBytecode','')
            if stored.lower()!=code.lower():raise ValueError('current deployed code does not match source provider onchain bytecode')
            if data.get('runtimeMatch') not in ('exact_match','match'):raise ValueError('source runtime match unavailable')
            atomic(folder/'verified-source.json',data)
            record['reviewCompleteness']=initial_proxy_review_completeness(record.get('proxy'))
            source_hash=source_identity(data);record['source']={'url':source_url,'retrievedAt':now(),'verifiedAt':data.get('verifiedAt'),'runtimeMatch':data['runtimeMatch'],'currentBytecodeMatchesProvider':True,'sha256':source_hash,'fileCount':len(data.get('sources',{})),'compiler':data.get('compilation',{}).get('compilerVersion')}
            dependency=None
            try:dependency=self.trace_amt_reward_dependency(data,item,record,folder,height,block['hash'])
            except Exception as dep_error:record['dependencyTrace']={'state':'unavailable','error':f'{type(dep_error).__name__}: {str(dep_error)[:220]}'};self.inc('dependencyTraceUnavailable')
            if dependency:record['dependencyTrace']=dependency['report']
            self.inc('verifiedSourceBundles')
            with self.lock: source_lock=self.source_locks.setdefault(source_hash,threading.Lock())
            with source_lock:
                previous=self.source_seen.get(source_hash)
                if previous:
                    record.update(state='duplicate_source',reusedSourceFrom=previous)
                    record['reviewCompleteness']='duplicate_source_reused'
                    record['dynamicAnalysis']={'state':'not_performed','reason':'Source work reused; no local execution was repeated for this deployment.'}
                    self.inc('duplicateSourceBundles')
                else:
                    self.inc('uniqueSourceBundles')
                    if not self.stop.is_set():
                        started=time.monotonic()
                        try:
                            command=[os.sys.executable,str(ROOT/'scripts/review-static.py'),str(folder/'verified-source.json')]
                            if dependency:command.append(str(folder/'verified-dependency-source.json'))
                            static=run_bounded(command,90,env=static_analysis_environment())
                            static_result=json.loads(static.stdout) if static.returncode==0 else {'state':'failed','error':static.stderr[-1000:]}
                        except subprocess.TimeoutExpired:
                            static_result={'state':'unavailable','reason':'analysis_timeout','timeoutSec':90,'confirmed':False,'localReproduction':False}
                        except Exception as e:static_result={'state':'failed','error':str(e)[:300]}
                        atomic(folder/'static-analysis.json',static_result)
                        record['staticAnalysis']={k:v for k,v in static_result.items() if k!='findings'}
                        detectors_complete=static_result.get('staticStages',{}).get('detectors')=='completed' or static_result['state']=='completed'
                        if detectors_complete:self.inc('staticAnalyses')
                        else:self.inc('staticAnalysisUnavailable')
                        if static_result.get('callGraph',{}).get('state') in ('completed','partial'):
                            self.inc('staticCallGraphs')
                            if static_result['callGraph']['state']=='partial':self.inc('staticCallGraphPartials')
                            self.inc('staticCallGraphPaths',int(static_result['callGraph'].get('reportedPathCount',0) or 0))
                            self.inc('staticAssetFlowPaths',int(static_result['callGraph'].get('assetRelatedCallPathCount',0) or 0))
                        if detectors_complete and static_result['state']=='partial':
                            self.inc('staticAnalysisPartials')
                        self.timing('analysisPipeline',started)
                        timings=static_result.get('timings') or {}
                        self.timing_ms('staticAnalysis',timings.get('staticAnalysisMs',round((time.monotonic()-started)*1000)))
                        if (static_result.get('localTests') or {}).get('state') in ('passed','partial','failed','unavailable'):
                            self.timing_ms('dynamicAnalysis',timings.get('dynamicAnalysisMs',0))
                    try:
                        source_ir_path=folder/'unified-ir.json'
                        bytecode_ir_path=folder/'unified-ir-bytecode.json'
                        source_ir=json.loads(source_ir_path.read_text(encoding='utf-8')) if source_ir_path.is_file() else None
                        bytecode_ir=json.loads(bytecode_ir_path.read_text(encoding='utf-8')) if bytecode_ir_path.is_file() else None
                        reconciliation=reconcile_ir(source_ir,bytecode_ir,source_sha256=source_hash,contract=address)
                        reconciliation_path=folder/'ir-reconciliation.json'
                        atomic(reconciliation_path,reconciliation)
                        record['irReconciliation']={'state':'completed' if source_ir is not None and bytecode_ir is not None else 'unresolved',
                            'sourceFaithfulnessScore':reconciliation['sourceFaithfulnessScore'],
                            'report':str(reconciliation_path.relative_to(ROOT)),
                            'sourceIrSha256':reconciliation['sourceIrSha256'],'bytecodeIrSha256':reconciliation['bytecodeIrSha256']}
                    except Exception as reconcile_error:
                        record['irReconciliation']={'state':'unavailable','reason':f'{type(reconcile_error).__name__}: {str(reconcile_error)[:250]}'}
                    try:
                        source_ir_path=folder/'unified-ir.json'
                        if source_ir_path.is_file():
                            invariant_result=generate_invariants(json.loads(source_ir_path.read_text(encoding='utf-8')))
                            invariant_path=folder/'invariants.json'
                            atomic(invariant_path,invariant_result)
                            record['invariants']={'state':invariant_result['state'],'detectedRoles':invariant_result['detectedRoles'],
                                'invariantCount':len(invariant_result['invariants']),'report':str(invariant_path.relative_to(ROOT)),
                                'sourceIrSha256':invariant_result['sourceIrSha256']}
                    except Exception as invariant_error:
                        record['invariants']={'state':'unavailable','reason':f'{type(invariant_error).__name__}: {str(invariant_error)[:250]}'}
                    try:
                        source_ir_document = json.loads(source_ir_path.read_text(encoding='utf-8')) if source_ir_path.is_file() else None
                        invariant_document = json.loads(invariant_path.read_text(encoding='utf-8')) if 'invariant_path' in locals() and invariant_path.is_file() else None
                        review=self.review(data,record,folder,source_ir_document,invariant_document)
                        atomic(folder/'review.json',review);record['review']=review
                        record.update(state='source_reviewed',reviewProvider='external_cloud_ai',reviewStatus='completed')
                        self.inc('cloudReviewCompletions')
                        self.inc('reviewObservations',len(review['observations']))
                        self.inc('reviewHypotheses',sum(x['kind']=='risk_hypothesis' for x in review['observations']))
                    except Exception as e:
                        record.update(state='source_review_pending',reviewCompleteness='cloud_review_required',reviewProvider='external_cloud_ai',reviewStatus='unavailable',reviewError=str(e)[:300])
                        self.inc('cloudReviewUnavailable')
                    # Only share successful review AND static work; failed work can retry.
                    stages=record.get('staticAnalysis',{}).get('staticStages',{})
                    if stages.get('compile')=='completed' and stages.get('detectors')=='completed':
                        with self.lock:self.source_seen[source_hash]=key
                    local=record.get('staticAnalysis',{}).get('localTests')
                    if local and local.get('state') in ('passed','partial','failed'):
                        self.inc('dynamicAnalysisAttempts')
                        record['localTestStatus']=local['state']
                        record['dynamicAnalysis']={'state':local['state'],'kind':'isolated in-process Hardhat EVM tests','suite':local.get('suite'),'analysisType':local.get('analysisType'),'sourceHash':local.get('sourceHash'),'harnessHash':local.get('harnessHash'),'report':local.get('report'),'sourceCoverage':local.get('sourceCoverage'),'traceEvidence':local.get('traceEvidence'),'transactionEvidence':local.get('transactionEvidence'),'failureEvidence':local.get('failureEvidence'),'executionBoundary':local.get('executionBoundary'),'resourceLimits':local.get('runnerLimits'),'stateDiff':local.get('stateDiff'),'staticCorrelation':local.get('staticCorrelation'),'unifiedIR':local.get('unifiedIR'),'tests':local.get('tests',0),'passed':local.get('passed',0),'failed':local.get('failed',0),'network':local.get('network'),'deterministicFuzz':local.get('deterministicFuzz'),'confirmedVulnerabilities':local.get('confirmedVulnerabilities',0),'limitations':local.get('limitations',[])}
                        self.inc('localTestSuites');self.inc('localTestsPerformed',local.get('tests',0));self.inc('localTestsFailed',local.get('failed',0));self.inc('dynamicTestSuites');self.inc('dynamicTestsPerformed',local.get('tests',0));self.inc('dynamicTestsFailed',local.get('failed',0))
                    elif local:
                        record['dynamicAnalysis']={'state':local.get('state','not_performed'),'reason':local.get('reason') or local.get('error') or 'No local execution result.'}
                        if local.get('state')=='unavailable':self.inc('dynamicAnalysisAttempts');self.inc('dynamicAnalysisUnavailable')
                        elif local.get('state')=='not_performed':self.inc('dynamicAnalysisNotPerformed')
        except Exception as e:
            record['state']='blocked';record['error']=f'{type(e).__name__}: {str(e)[:250]}';self.inc('contractBlocked')
        record['finishedAt']=now();atomic(folder/'evidence.json',record)
        brief={k:record.get(k) for k in ['protocol','chain','chainId','category','address','state','error','reviewCompleteness','reviewProvider','reviewStatus']};brief['evidence']=str((folder/'evidence.json').relative_to(ROOT));brief['hypotheses']=sum(x['kind']=='risk_hypothesis' for x in record.get('review',{}).get('observations',[]));brief['reviewSummary']=record.get('review',{}).get('summary');brief['reviewEvidence']={k:record.get('review',{}).get(k) for k in ('provider','model','manifestSha256','responseSha256','providerRequestId') if record.get('review',{}).get(k) is not None}
        brief['observations']=record.get('review',{}).get('observations',[])[:3]
        brief['localTests']=record.get('staticAnalysis',{}).get('localTests')
        brief['dynamicAnalysis']=record.get('dynamicAnalysis')
        brief['staticAnalysis']={k:v for k,v in record.get('staticAnalysis',{}).items() if k in ('state','staticError','callGraph','unifiedIR','contracts','detectors','findingCount','findingSummary','discoveryPlan')}
        brief['runtimeBytecodeAnalysis']=record.get('runtimeBytecodeAnalysis')
        brief['originProxy']=record.get('originProxy')
        with self.lock:self.recent.append(brief);self.recent=self.recent[-20:]
        self.event('contract',**brief)
        impl=record.get('proxy',{}).get('eip1967Implementation') or record.get('proxy',{}).get('beaconImplementation')
        if impl and not address_info.get('originProxy') and not self.stop.is_set() and time.monotonic()-self.start<self.duration:
            child=self.contract(item,{**address_info,'address':impl,'originProxy':address,'proxyBlock':record.get('deployment',{}).get('block'),'proxyBlockHash':record.get('deployment',{}).get('hash'),'association':'EIP-1967 implementation read from the associated proxy; implementation address is not a separate TVL position'})
            child_state=child.get('state') if child else 'unavailable'
            record['proxy']['implementationReviewState']='reviewed' if child_state in ('source_reviewed','duplicate_source') else child_state
            record['proxy']['implementationEvidence']=child.get('evidencePath') if child else None
            record['reviewCompleteness']='proxy_and_implementation_reviewed' if child_state in ('source_reviewed','duplicate_source') else 'proxy_only_implementation_unavailable'
            parent_path=folder/'evidence.json';atomic(parent_path,record)
            brief['reviewCompleteness']=record['reviewCompleteness'];brief['proxyImplementationState']=record['proxy']['implementationReviewState']
            with self.lock:
                for index,entry in enumerate(self.recent):
                    if entry.get('evidence')==str(parent_path.relative_to(ROOT)):self.recent[index]=brief
            self.event('proxy_implementation_review',proxy=address,implementation=impl,state=record['proxy']['implementationReviewState'],evidence=record['proxy'].get('implementationEvidence'))
        record['evidencePath']=str((folder/'evidence.json').relative_to(ROOT))
        return record
    def process(self,item,index):
        label=f'{item["slug"]}:{item["chainId"]}';started=time.monotonic()
        with self.lock:
            self.active[label]={'protocol':item['protocol'],'chain':item['chain'],'category':item['category'],'stage':'address discovery'}
        try:
            if label not in self.address_cache:
                self.inc('protocolChainsAttempted')
                if not self.pool.rows.get(item['chainId'],{}).get('healthyCount'):raise RuntimeError('no verified RPC for this chain')
                addresses=self.addresses(item)
                addresses=list({a['address'].lower():a for a in addresses}.values())
                self.event('addresses',protocol=item['protocol'],chainId=item['chainId'],count=len(addresses),addresses=addresses)
                if not addresses:raise ValueError('adapter needs manual deployment resolution; no chain-scoped literal business address')
                self.address_cache[label]=addresses;self.inc('protocolChainsWithAddresses')
            addresses=self.address_cache[label];offset=self.address_offsets.get(label,0)
            with self.lock:self.active[label]['stage']='RPC / verified source / external cloud review'
            for a in addresses[offset:offset+3]:
                if self.stop.is_set() or time.monotonic()-self.start>=self.duration:break
                self.contract(item,a);self.address_offsets[label]=self.address_offsets.get(label,0)+1
            if self.address_offsets.get(label,0)>=len(addresses):self.exhausted.add(label)
        except Exception as e:
            failure={'protocol':item['protocol'],'chain':item['chain'],'stage':'discovery','error':str(e)[:220]}
            with self.lock:
                self.counts['discoveryBlocked']+=1;self.failures.append(failure);self.failures=self.failures[-20:]
                self.exhausted.add(label)
            self.event('blocked',**failure)
        finally:
            with self.lock:self.active.pop(label,None)
            self.timing('protocolBatch',started)
    def refresh_queue(self):
        protocols=self.fetch('https://api.llama.fi/protocols',timeout=25)
        stamp=now();chains=json.loads((ROOT/'flare-scan/chains.json').read_text())['chains']
        fresh=build_queue(protocols,chains);known={f'{q["slug"]}:{q["chainId"]}' for q in self.queue}
        added=[dict(q,tvlObservedAt=stamp) for q in fresh if f'{q["slug"]}:{q["chainId"]}' not in known]
        self.queue.extend(added);self.inc('catalogRefreshes')
        atomic(self.run/f'protocols-refresh-{self.counts["catalogRefreshes"]}.json',{'retrievedAt':stamp,'source':'https://api.llama.fi/protocols','data':protocols})
        self.event('catalog_refresh',newProtocolChains=len(added),at=stamp)
        return added
    def run_campaign(self):
        pending={};cursor=0;round_items=[];last_refresh=self.start
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            init=executor.submit(self.initialize)
            while not init.done():
                concurrent.futures.wait([init],timeout=1)
                if time.monotonic()-self.last_tick>=10:self.checkpoint()
            init.result();round_items=list(self.queue)
            while not self.stop.is_set() and time.monotonic()-self.start<self.duration:
                while len(pending)<self.workers and cursor<len(round_items):
                    item=round_items[cursor];future=executor.submit(self.process,item,cursor);pending[future]=cursor;cursor+=1
                done,_=concurrent.futures.wait(pending,timeout=1,return_when=concurrent.futures.FIRST_COMPLETED) if pending else (set(),set())
                for f in done:pending.pop(f);f.result()
                if time.monotonic()-self.last_tick>=10:self.checkpoint()
                if time.monotonic()-self.last_fingerprint_check>=60:self.fingerprint_check()
                if not pending and cursor>=len(round_items):
                    round_items=[q for q in self.queue if f'{q["slug"]}:{q["chainId"]}' not in self.exhausted];cursor=0
                    if round_items:
                        self.inc('addressBatchRounds');self.event('next_address_batch',protocolChains=len(round_items))
                    else:
                        if time.monotonic()-last_refresh>=300:
                            try:round_items=self.refresh_queue()
                            except Exception as e:self.event('catalog_refresh_failed',error=str(e)[:300])
                            last_refresh=time.monotonic()
                        # Explicit idle state, never inflate counts with repeated old reviews.
                        self.state='running' if round_items else 'waiting_for_new_candidates'
                        if not round_items:self.stop.wait(1)
            final_state='interrupted' if self.stop.is_set() else 'completed'
            self.state='draining';self.checkpoint();self.stop.set()
            while pending:
                done,_=concurrent.futures.wait(pending,timeout=1,return_when=concurrent.futures.FIRST_COMPLETED)
                for f in done:pending.pop(f);f.result()
                if time.monotonic()-self.last_tick>=10:self.checkpoint()
            self.fingerprint_check()
            self.state='invalidated' if self.validation_errors else final_state
        self.checkpoint();atomic(self.run/'rpc-usage.json',self.pool.snapshot());self.journal.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--duration',type=int,default=3600);parser.add_argument('--output',default=str(ROOT/'work/defi-campaign.json'));parser.add_argument('--workers',type=int,default=3)
    parser.add_argument('--review-budget-usd',type=float,default=None,help='每份合约云审查预算上限（美元）')
    parser.add_argument('--decompiler',choices=('heimdall',),help='run local heuristic pseudocode recovery on each deployed runtime')
    parser.add_argument('--decompiler-timeout',type=float,default=30,help='per-contract Heimdall wall-clock limit in seconds')
    parser.add_argument('--decompiler-hardfork',default='latest',help='EVM hardfork passed to Heimdall; select the target chain semantics')
    args=parser.parse_args()
    if not 30<=args.duration<=86400 or not 1<=args.workers<=3:parser.error('duration 30..86400 seconds, workers 1..3')
    if not 1<=args.decompiler_timeout<=300:parser.error('--decompiler-timeout must be between 1 and 300 seconds')
    if args.review_budget_usd is not None and args.review_budget_usd<0:parser.error('--review-budget-usd must be nonnegative')
    if not args.decompiler_hardfork.strip():parser.error('--decompiler-hardfork must not be empty')
    lock_path=ROOT/'work/defi-campaign.lock';lock_path.parent.mkdir(exist_ok=True);handle=lock_path.open('a+')
    try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise SystemExit('A campaign already holds the lock; not starting another')
    old=Path(args.output)
    if old.exists():
        prior=json.loads(old.read_text());archive=old.with_name(old.stem+'.'+prior.get('runId',str(uuid.uuid4()))+'.json');atomic(archive,prior)
    campaign=Campaign(args.duration,args.output,args.workers,args.decompiler,args.decompiler_timeout,args.decompiler_hardfork,args.review_budget_usd);handle.seek(0);handle.truncate();handle.write(json.dumps({'pid':os.getpid(),'runId':campaign.id,'startedAt':now()}));handle.flush()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:campaign.stop.set())
    try:campaign.run_campaign()
    except Exception as e:
        campaign.state='failed';campaign.event('fatal',error=str(e));campaign.failures.append({'stage':'fatal','error':str(e)});campaign.checkpoint();raise
    finally:fcntl.flock(handle,fcntl.LOCK_UN);handle.close()
    print(json.dumps({'runId':campaign.id,'state':campaign.state,'counts':dict(campaign.counts)},ensure_ascii=False))

if __name__=='__main__':main()
