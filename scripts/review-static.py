#!/usr/bin/env python3
"""Compile collected source locally and run Slither; never deploy or transact."""
import copy,inspect,json,os,re,sys,hashlib,urllib.request,fcntl,subprocess,time,collections,posixpath,ntpath,heapq,concurrent.futures,threading,signal,shutil
import warnings
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=NotOpenSSLWarning)
except ImportError:
    pass
from bisect import bisect_left, bisect_right
from contextlib import contextmanager
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
TOOLS=ROOT/'flare-scan/tools'
sys.path[:0]=[str(ROOT/'scripts'),str(TOOLS/'pylibs'),str(TOOLS)]
from repr_cache import cache_key as repr_cache_key, get_or_build as repr_get_or_build, source_bundle_sha256
from unified_ir import effect_site_id, from_call_graph
_VERIFIED_COMPILER_HASHES={}
_COMPILER_HASH_LOCK=threading.Lock()
_ANALYSIS_ENV_LOCK=threading.Lock()
MAX_DYNAMIC_HARNESS_RSS_BYTES=3*1024*1024*1024
PROCESS_RSS_POLL_INTERVAL_SECONDS=0.25

class ProcessMemoryMonitorUnavailable(RuntimeError):
    pass

class ProcessGroupCleanupIncomplete(RuntimeError):
    pass

class ProcessTreeMemoryLimitExceeded(RuntimeError):
    def __init__(self,limit_bytes,observed_bytes,stdout='',stderr=''):
        super().__init__('dynamic_harness_memory_limit_exceeded')
        self.limit_bytes=limit_bytes
        self.observed_bytes=observed_bytes
        self.stdout=stdout
        self.stderr=stderr

def _process_tree_rss_bytes(process_id):
    if os.name=='nt':raise ProcessMemoryMonitorUnavailable('process_memory_monitor_unavailable')
    ps_binary=shutil.which('ps')
    if not ps_binary:raise ProcessMemoryMonitorUnavailable('process_memory_monitor_unavailable')
    try:result=subprocess.run([ps_binary,'-axo','pid=,ppid=,rss='],capture_output=True,text=True,timeout=2,check=False)
    except (OSError,subprocess.TimeoutExpired) as error:raise ProcessMemoryMonitorUnavailable('process_memory_monitor_unavailable') from error
    if result.returncode:raise ProcessMemoryMonitorUnavailable('process_memory_monitor_unavailable')
    rss_by_pid={};children_by_parent={}
    try:
        for line in result.stdout.splitlines():
            fields=line.split()
            if not fields:continue
            if len(fields)!=3:raise ValueError('unexpected ps output')
            pid,parent,rss_kib=(int(field) for field in fields)
            if pid<=0 or parent<0 or rss_kib<0:raise ValueError('invalid ps process row')
            if pid in rss_by_pid:raise ValueError('duplicate ps process id')
            rss_by_pid[pid]=rss_kib*1024;children_by_parent.setdefault(parent,[]).append(pid)
    except ValueError as error:raise ProcessMemoryMonitorUnavailable('process_memory_monitor_invalid_output') from error
    if not rss_by_pid:raise ProcessMemoryMonitorUnavailable('process_memory_monitor_invalid_output')
    if process_id not in rss_by_pid:raise ProcessMemoryMonitorUnavailable('process_memory_monitor_target_missing')
    total=0;pending=[process_id];visited=set()
    while pending:
        pid=pending.pop()
        if pid in visited:continue
        visited.add(pid);total+=rss_by_pid.get(pid,0);pending.extend(children_by_parent.get(pid,()))
    return total

def _process_group_exists(process_id):
    try:os.killpg(process_id,0)
    except ProcessLookupError:return False
    except PermissionError:return True
    return True

def _compiler_file_signature(path):
    info=path.stat()
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def run_bounded(command,timeout,*,max_process_tree_rss_bytes=None,**kwargs):
    """Run an analysis child in its own group and reap descendants on timeout."""
    if max_process_tree_rss_bytes is not None:
        if (isinstance(max_process_tree_rss_bytes,bool) or not isinstance(max_process_tree_rss_bytes,int)
                or max_process_tree_rss_bytes<=0):raise ValueError('max_process_tree_rss_bytes must be positive')
        _process_tree_rss_bytes(os.getpid())
    kwargs.setdefault('start_new_session',True)
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,**kwargs)
    def kill_group():
        if hasattr(os,'killpg'):
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        else:proc.kill()
    def ensure_process_group_exited():
        if os.name=='nt' or not _process_group_exists(proc.pid):return
        kill_group();deadline=time.monotonic()+1
        while _process_group_exists(proc.pid) and time.monotonic()<deadline:time.sleep(0.01)
        if _process_group_exists(proc.pid):
            raise ProcessGroupCleanupIncomplete('analysis_child_process_tree_cleanup_incomplete')
        raise ProcessGroupCleanupIncomplete('analysis_child_process_outlived_parent')
    try:
        if max_process_tree_rss_bytes is None:
            out,err=proc.communicate(timeout=timeout)
        else:
            deadline=time.monotonic()+timeout
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise subprocess.TimeoutExpired(command,timeout)
                try:out,err=proc.communicate(timeout=min(PROCESS_RSS_POLL_INTERVAL_SECONDS,remaining));break
                except subprocess.TimeoutExpired:
                    try:observed=_process_tree_rss_bytes(proc.pid)
                    except ProcessMemoryMonitorUnavailable as error:
                        if str(error)=='process_memory_monitor_target_missing' and proc.poll() is not None:
                            continue
                        raise
                    if observed>max_process_tree_rss_bytes:
                        kill_group();out,err=proc.communicate()
                        raise ProcessTreeMemoryLimitExceeded(max_process_tree_rss_bytes,observed,out,err)
        ensure_process_group_exited()
    except ProcessGroupCleanupIncomplete:
        raise
    except subprocess.TimeoutExpired:
        kill_group()
        out,err=proc.communicate()
        raise subprocess.TimeoutExpired(command,timeout,output=out,stderr=err)
    except BaseException:
        if proc.poll() is None:kill_group()
        proc.communicate()
        raise
    return subprocess.CompletedProcess(command,proc.returncode,out,err)

def _sha256_file(path):
    return '0x'+hashlib.sha256(path.read_bytes()).hexdigest()

def _verified_compiler_hash(path):
    path=Path(path)
    key=str(path.resolve())
    signature=_compiler_file_signature(path)
    with _COMPILER_HASH_LOCK:
        cached=_VERIFIED_COMPILER_HASHES.get(key)
        if cached and cached[0]==signature:return cached[1]
        digest=_sha256_file(path)
        if _compiler_file_signature(path)!=signature:raise ValueError('cached compiler changed while verifying')
        _VERIFIED_COMPILER_HASHES[key]=(signature,digest)
        return digest

def compiler(version):
    if not re.fullmatch(r'0\.\d+\.\d+',version):raise ValueError('invalid release version')
    cache=ROOT/'work/compiler-cache';cache.mkdir(exist_ok=True)
    with (cache/'download.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        catalog=cache/'list.json'
        if not catalog.exists():
            with urllib.request.urlopen('https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/bin/list.json',timeout=20) as r:raw=r.read(2_000_000)
            json.loads(raw);catalog.write_bytes(raw)
        index=json.loads(catalog.read_text());filename=index['releases'].get(version)
        if not filename or '/' in filename:raise ValueError('official compiler release not found')
        entry=next(x for x in index['builds'] if x['path']==filename)
        # The project is type=module; soljson is a CommonJS Emscripten module.
        # Keep upstream bytes unchanged while selecting the correct Node loader.
        target=cache/(filename.removesuffix('.js')+'.cjs')
        if not target.exists():
            with urllib.request.urlopen('https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/bin/'+filename,timeout=35) as r:raw=r.read(35_000_001)
            if len(raw)>35_000_000 or '0x'+hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise ValueError('official compiler checksum mismatch')
            temp=target.with_suffix('.tmp');temp.write_bytes(raw);temp.replace(target)
        if _verified_compiler_hash(target)!=entry['sha256']:raise ValueError('cached compiler checksum mismatch')
        return target,{'version':version,'source':'https://github.com/ethereum/solc-bin','filename':filename,'sha256':entry['sha256']}

def finding_summary(findings,limit=30):
    impacts=collections.Counter();confidences=collections.Counter();checks=collections.Counter();fingerprints=set();priority=[]
    for finding in findings:
        if not isinstance(finding,dict):continue
        impact=str(finding.get('impact') or 'Unknown');confidence=str(finding.get('confidence') or 'Unknown');check=str(finding.get('check') or 'unknown')
        impacts[impact]+=1;confidences[confidence]+=1;checks[check]+=1
        semantic_row=_semantic_finding_row(finding)
        element=next((x for x in semantic_row.get('elements',[]) if isinstance(x,dict) and isinstance(x.get('source_mapping'),dict)),{})
        mapping=element.get('source_mapping') or {};lines=mapping.get('lines') or []
        file=mapping.get('filename_short') or mapping.get('filename_relative') or 'unknown'
        location={'file':str(file),'lines':lines[:2]} if isinstance(lines,list) else {'file':str(file),'lines':[]}
        fingerprints.add(hashlib.sha256(json.dumps(semantic_row,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        if impact in ('High','Medium'):
            priority.append({'check':check,'impact':impact,'confidence':confidence,'location':location,'description':str(finding.get('description') or '')[:500],'_stableKey':json.dumps(semantic_row,sort_keys=True,separators=(',',':'))})
    priority.sort(key=lambda x:(x['impact']!='High',x['confidence']!='High',x['check'],x['location']['file'],x['location']['lines'],x['_stableKey']))
    for row in priority:row.pop('_stableKey',None)
    return {'impactCounts':dict(sorted(impacts.items())),'confidenceCounts':dict(sorted(confidences.items())),'checkCounts':dict(checks.most_common()),'uniqueFingerprintCount':len(fingerprints),'highMediumReviewQueue':priority[:limit],'reviewQueueLimit':limit,'interpretation':'Slither detections are unconfirmed static-analysis signals; queue order is triage aid, not exploitability.'}

def _semantic_finding_row(finding):
    """Canonical detector identity; retain every finding field and full element."""
    def canonical(value,key=None):
        if isinstance(value,dict):
            row={}
            for child_key,child in value.items():
                if child_key=='filename_absolute':continue
                if child_key=='filename_relative' and isinstance(child,str) and '/static-work/' in child:
                    child='static-work/'+child.split('/static-work/',1)[1]
                row[child_key]=canonical(child,child_key)
            return row
        if isinstance(value,list):return [canonical(x) for x in value]
        if key=='first_markdown_element' and isinstance(value,str) and '/static-work/' in value:
            # Slither also embeds the temporary source path in fields such as
            # first_markdown_element. Remove the per-run prefix there too.
            return 'static-work/'+value.split('/static-work/',1)[1]
        return value
    row={key:canonical(value,key) for key,value in finding.items() if key not in ('id','description','markdown')}
    if isinstance(row.get('elements'),list):
        row['elements'].sort(key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')))
    return row

def semantic_finding_fingerprint(findings):
    """Stable semantic comparison; raw Slither evidence remains untouched."""
    rows=[_semantic_finding_row(row) for row in findings if isinstance(row,dict)]
    rows.sort(key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')))
    return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()

ASSET_CALL_NAMES={'approve','burn','burnfrom','claim','deposit','flashloan','mint','redeem','repay','safeapprove','safetransfer','safetransferfrom','sendvalue','swap','transfer','transferfrom','withdraw'}
INLINE_ASSEMBLY_STORAGE_BUILTINS={'sstore','tstore'}
INLINE_ASSEMBLY_CALL_BUILTINS={'call','delegatecall','callcode','staticcall'}
INLINE_ASSEMBLY_DESTRUCTION_BUILTINS={'selfdestruct','suicide'}
INLINE_ASSEMBLY_CONTROL_OR_DATA_BUILTINS={'byte','keccak256','mload','mstore','mstore8','mulmod','revert'}

def _source_location(item,aliases=None):
    mapping=getattr(item,'source_mapping',None)
    if not mapping:return {'file':'unknown','lines':[]}
    source=getattr(mapping,'filename',None)
    filename=(getattr(mapping,'filename_relative',None) or getattr(source,'relative',None) or getattr(mapping,'filename_short',None) or getattr(source,'short',None) or 'unknown')
    normalized=str(filename).replace('\\','/')
    alias_map=aliases or {}
    if normalized in alias_map:
        filename=alias_map[normalized]
    else:
        suffix_matches=[(str(alias).replace('\\','/'),original) for alias,original in alias_map.items()
                        if normalized.endswith('/'+str(alias).replace('\\','/'))]
        if suffix_matches:
            longest=max(len(alias) for alias,_ in suffix_matches)
            originals={original for alias,original in suffix_matches if len(alias)==longest}
            if len(originals)==1:filename=originals.pop()
    lines=getattr(mapping,'lines',None) or []
    result={'file':str(filename),'lines':list(lines[:4]) if isinstance(lines,(list,tuple)) else []}
    start=getattr(mapping,'start',None);length=getattr(mapping,'length',None)
    if type(start) is int and start>=0 and type(length) is int and length>0:
        result.update({'start':start,'length':length})
    return result

def _function_name(function):
    return str(getattr(function,'canonical_name',None) or getattr(function,'full_name',None) or getattr(function,'name',None) or '<unknown>')

def _function_id(function):
    context=getattr(function,'contract',None) or getattr(function,'contract_declarer',None)
    context_name=getattr(context,'name',None) or 'unknown-contract'
    return f'{context_name}::{_function_name(function)}'

def _ir_name(ir):
    value=getattr(ir,'function_name',None)
    if value is None:value=getattr(getattr(ir,'function',None),'name',None)
    if value is not None:return str(value).strip('"\'')
    rendered=str(ir or '')
    match=re.search(r'function:\s*([^,\s\)]+)',rendered)
    return str(match.group(1) if match else '<unknown>').strip('"\'')

def _solidity_call_builtin_name(ir):
    """Return a SolidityCall builtin's exact base name, if present."""
    if type(ir).__name__!='SolidityCall':return None
    name=getattr(getattr(ir,'function',None),'name',None)
    if not isinstance(name,str):return None
    return name.split('(',1)[0].strip('"\'')

def _inline_assembly_arguments(ir):
    arguments=getattr(ir,'arguments',None)
    if not isinstance(arguments,(list,tuple)):return []
    return [str(argument)[:180] for argument in arguments]

def _asset_flow_name(value):
    text=str(value or '').lower()
    if text.startswith('safe'):text=text[4:]
    return text.startswith(tuple(sorted(ASSET_CALL_NAMES,key=len,reverse=True))) or text.startswith(('liquidat','flashloan','payout','bridge','sweep'))

def _value_transfer_evidence(call):
    """Describe value-bearing call syntax without treating an unknown as nonzero."""
    value=getattr(call,'call_value',None)
    if value is None:return {'state':'not_attached'}
    raw=getattr(value,'value',None)
    source='constant' if raw is not None else 'symbolic'
    rendered=str(raw if raw is not None else value).strip()
    if isinstance(raw,bool):amount=int(raw)
    else:
        try:
            amount=int(rendered,0)
        except (TypeError,ValueError):
            try:amount=int(rendered,10)
            except (TypeError,ValueError):amount=None
    if amount is not None:
        return {'state':'zero' if amount==0 else 'nonzero' if amount>0 else 'unknown','source':source,'expression':rendered[:180]}
    return {'state':'unknown','source':source,'expression':rendered[:180]}

def _path_triage_rank(row):
    effect=row['effect'];kind=effect.get('kind');value_state=(effect.get('valueTransferEvidence') or {}).get('state')
    if kind in ('external_call','contract_creation','selfdestruct') and (effect.get('assetRelated') or value_state=='nonzero' or kind=='selfdestruct'):return 1
    if kind=='external_call' and row.get('assetContextHint'):return 2
    if kind in ('external_call','contract_creation','selfdestruct'):return 3
    if row.get('assetContextHint'):return 4
    return 5

def _same_dynamic_pointer(left,right):
    if left is None or right is None:return False
    if left is right:return True
    left_name=getattr(left,'canonical_name',None);right_name=getattr(right,'canonical_name',None)
    return bool(left_name and right_name and str(left_name)==str(right_name))

def _resolve_internal_dynamic_targets(start_node,call_index,pointer,object_ids,source_aliases=None,*,max_targets=32,max_walk_steps=4096):
    """Find same-function reaching function-pointer assignments by a bounded CFG walk."""
    targets={};reasons=set();visited=set();stack=[(start_node,call_index-1)];walk_steps=0
    while stack:
        if walk_steps>=max_walk_steps:
            reasons.add('cfg_walk_budget_exceeded');break
        node,last_ir_index=stack.pop();walk_steps+=1
        marker=(id(node),last_ir_index)
        if marker in visited:continue
        visited.add(marker)
        irs=list(getattr(node,'irs',[]) or []);last_ir_index=min(last_ir_index,len(irs)-1)
        reaching_definition=False
        for ir in reversed(irs[:last_ir_index+1]):
            left=getattr(ir,'lvalue',None)
            if left is None or not _same_dynamic_pointer(left,pointer):continue
            reaching_definition=True
            if type(ir).__name__!='Assignment':
                reasons.add('unsupported_reaching_definition');break
            value=getattr(ir,'rvalue',None);target_key=object_ids.get(id(value)) if value is not None else None
            if not target_key:
                reasons.add('non_function_or_unindexed_target');break
            if target_key not in targets and len(targets)>=max_targets:
                reasons.add('target_limit_exceeded');break
            record=targets.setdefault(target_key,{'assignmentLocations':[],'assignmentExpressions':[]})
            location=_source_location(node,source_aliases)
            if location not in record['assignmentLocations'] and len(record['assignmentLocations'])<8:record['assignmentLocations'].append(location)
            expression=str(getattr(node,'expression',None) or ir)[:240]
            if expression not in record['assignmentExpressions'] and len(record['assignmentExpressions'])<8:record['assignmentExpressions'].append(expression)
            break
        if reaching_definition:continue
        predecessors=list(getattr(node,'fathers',[]) or [])
        if not predecessors:
            reasons.add('no_reaching_definition')
            continue
        for predecessor in predecessors:
            predecessor_irs=list(getattr(predecessor,'irs',[]) or [])
            stack.append((predecessor,len(predecessor_irs)-1))
    return targets,sorted(reasons),walk_steps

def build_call_graph(contracts,target_contracts=None,target_source_units=None,source_aliases=None,source_digests=None,*,max_entrypoints=512,max_paths=160,max_depth=20,max_walk_steps=120000,max_reported_edges=5000,max_unresolved_calls=250,max_dynamic_targets=32,max_dynamic_walk_steps=4096):
    """Build a bounded Slither-IR call/effect map; paths are structural over-approximations."""
    for name,value in {'max_entrypoints':max_entrypoints,'max_paths':max_paths,'max_depth':max_depth,'max_walk_steps':max_walk_steps,'max_reported_edges':max_reported_edges,'max_unresolved_calls':max_unresolved_calls,'max_dynamic_targets':max_dynamic_targets,'max_dynamic_walk_steps':max_dynamic_walk_steps}.items():
        if not isinstance(value,int) or isinstance(value,bool) or value<1:raise ValueError(name+' must be a positive integer')
    functions={};object_ids={};contract_count=0;modifier_ids=set()
    for contract in contracts:
        contract_count+=1
        members=list(getattr(contract,'functions',[]) or [])+list(getattr(contract,'modifiers',[]) or [])
        for function in members:
            key=_function_id(function)
            if key in functions and functions[key] is not function:
                key=f'{key}#{len(functions)+1}'
            functions[key]=function;object_ids[id(function)]=key
            if type(function).__name__=='Modifier':modifier_ids.add(key)
    adjacency={key:[] for key in functions};effects={key:[] for key in functions};unresolved=[];unresolved_count=0;unresolved_assembly=[];unresolved_assembly_count=0;unresolved_assembly_calls=[];unresolved_assembly_call_count=0;recognized_yul_builtin_counts={};dynamic_call_count=0;resolved_dynamic_call_count=0;unresolved_dynamic_call_count=0;dynamic_walk_steps=0;edge_rows=[];edge_count=0
    for key,function in functions.items():
        for node in getattr(function,'nodes',[]) or []:
            location=_source_location(node,source_aliases)
            raw_assembly=getattr(node,'inline_asm',None)
            if getattr(getattr(node,'type',None),'name',None)=='ASSEMBLY' and (raw_assembly is not None or not bool(getattr(getattr(node,'scope',None),'is_yul',False))):
                unresolved_assembly_count+=1
                if len(unresolved_assembly)<max_unresolved_calls:
                    unresolved_assembly.append({'function':key,'kind':'unresolved_inline_assembly','reason':'slither_exposes_raw_assembly_without_decoded_ir' if raw_assembly is not None else 'assembly_block_has_no_parsed_yul_scope','location':location})
            for variable in getattr(node,'state_variables_written',[]) or []:
                effects[key].append({'kind':'state_write','variable':str(getattr(variable,'canonical_name',None) or getattr(variable,'name',variable)),'location':location,'expression':str(getattr(node,'expression',None) or '')[:240]})
            for call in getattr(node,'internal_calls',[]) or []:
                if type(call).__name__=='SolidityCall':continue
                target=getattr(call,'function',None);target_key=object_ids.get(id(target)) if target is not None else None
                if target_key:
                    edge={'from':key,'to':target_key,'kind':'internal_call','location':location};adjacency[key].append((target_key,edge));edge_count+=1
                    if len(edge_rows)<max_reported_edges:edge_rows.append(edge)
                else:
                    unresolved_count+=1
                    if len(unresolved)<max_unresolved_calls:unresolved.append({'from':key,'kind':'unresolved_internal_call','target':_ir_name(call),'location':location})
            for high_level in getattr(node,'high_level_calls',[]) or []:
                call=high_level[1] if isinstance(high_level,tuple) and len(high_level)==2 else high_level
                name=_ir_name(call);lower=name.lower()
                destination=high_level[0].name if isinstance(high_level,tuple) and len(high_level)==2 else getattr(call,'destination','unknown')
                target=getattr(call,'function',None);target_key=object_ids.get(id(target)) if target is not None else None
                if type(call).__name__=='LibraryCall' and target_key and (getattr(target,'nodes',[]) or []):
                    call_kind='library_call'
                    edge={'from':key,'to':target_key,'kind':call_kind,'location':location};adjacency[key].append((target_key,edge));edge_count+=1
                    if len(edge_rows)<max_reported_edges:edge_rows.append(edge)
                    continue
                value_evidence=_value_transfer_evidence(call)
                effects[key].append({'kind':'external_call','callKind':'high_level','function':name,'destination':str(destination)[:180],'assetRelated':lower in ASSET_CALL_NAMES or _asset_flow_name(name),'sendsValue':True if value_evidence['state']=='nonzero' else False if value_evidence['state'] in ('not_attached','zero') else None,'valueTransferEvidence':value_evidence,'location':location,'expression':str(call)[:240]})
            for call in getattr(node,'low_level_calls',[]) or []:
                name=_ir_name(call);lower=name.lower();call_type=str(getattr(call,'type_call','') or '')
                value_evidence=_value_transfer_evidence(call)
                effects[key].append({'kind':'external_call','callKind':'low_level','function':name,'callType':call_type,'destination':str(getattr(call,'destination','unknown'))[:180],'assetRelated':lower in ASSET_CALL_NAMES or _asset_flow_name(name),'sendsValue':True if value_evidence['state']=='nonzero' else False if value_evidence['state'] in ('not_attached','zero') else None,'valueTransferEvidence':value_evidence,'location':location,'expression':str(call)[:240]})
            # Slither's high/low-level lists omit address.send/transfer IR and contract creation.
            for ir_index,call in enumerate(getattr(node,'irs',[]) or []):
                call_type=type(call).__name__
                if call_type=='SolidityCall':
                    builtin_name=_solidity_call_builtin_name(call)
                    arguments=_inline_assembly_arguments(call)
                    if builtin_name in INLINE_ASSEMBLY_STORAGE_BUILTINS:
                        slot=arguments[0] if arguments else 'unknown'
                        effects[key].append({'kind':'state_write','variable':f'Yul storage slot {slot}','storageSlot':slot,'storageKind':'transient' if builtin_name=='tstore' else 'persistent','opcode':builtin_name.upper(),'resolution':'inline_assembly_slot_candidate','location':location,'expression':str(call)[:240]})
                        continue
                    if builtin_name in INLINE_ASSEMBLY_CALL_BUILTINS:
                        effects[key].append({'kind':'external_call','callKind':'inline_assembly_'+builtin_name,'function':builtin_name,'destination':'unknown','targetResolution':'not_decoded_from_inline_assembly_arguments','arguments':arguments,'assetRelated':None,'sendsValue':None,'valueTransferEvidence':{'state':'unknown','source':'inline_assembly','reason':'call_target_and_value_arguments_are_not_semantically_resolved'},'location':location,'expression':str(call)[:240]})
                        continue
                    if builtin_name in INLINE_ASSEMBLY_DESTRUCTION_BUILTINS:
                        effects[key].append({'kind':'selfdestruct','opcode':'SELFDESTRUCT','recipient':arguments[0] if arguments else 'unknown','semantics':'opcode_observed; account deletion depends on active EVM rules','location':location,'expression':str(call)[:240]})
                        continue
                    if bool(getattr(getattr(node,'scope',None),'is_yul',False)) and builtin_name in INLINE_ASSEMBLY_CONTROL_OR_DATA_BUILTINS:
                        recognized_yul_builtin_counts[builtin_name]=recognized_yul_builtin_counts.get(builtin_name,0)+1
                        continue
                    if bool(getattr(getattr(node,'scope',None),'is_yul',False)):
                        unresolved_assembly_call_count+=1
                        if len(unresolved_assembly_calls)<max_unresolved_calls:
                            unresolved_assembly_calls.append({'function':key,'kind':'unresolved_yul_solidity_call','name':str(getattr(getattr(call,'function',None),'name',None) or '<unknown>')[:180],'reason':'inline_yul_solidity_call_not_in_effect_whitelist','location':location,'expression':str(call)[:240]})
                if call_type=='InternalDynamicCall':
                    dynamic_call_count+=1;pointer=getattr(call,'function',None)
                    remaining_dynamic_steps=max_dynamic_walk_steps-dynamic_walk_steps
                    if remaining_dynamic_steps>0:
                        targets,reasons,walked=_resolve_internal_dynamic_targets(node,ir_index,pointer,object_ids,source_aliases,max_targets=max_dynamic_targets,max_walk_steps=remaining_dynamic_steps)
                        dynamic_walk_steps+=walked
                    else:targets,reasons={},['cfg_walk_budget_exceeded']
                    if targets:resolved_dynamic_call_count+=1
                    for target_key,evidence in sorted(targets.items()):
                        edge={'from':key,'to':target_key,'kind':'internal_dynamic_candidate','functionPointer':str(getattr(pointer,'canonical_name',None) or getattr(pointer,'name',pointer))[:180],'resolution':'conservative_function_pointer_candidate','pathFeasibility':'not_proven','assignmentLocations':evidence['assignmentLocations'],'assignmentExpressions':evidence['assignmentExpressions'],'location':location}
                        adjacency[key].append((target_key,edge));edge_count+=1
                        if len(edge_rows)<max_reported_edges:edge_rows.append(edge)
                    if reasons:
                        unresolved_count+=1;unresolved_dynamic_call_count+=1
                        if len(unresolved)<max_unresolved_calls:
                            unresolved.append({'from':key,'kind':'unresolved_dynamic_internal_call','target':str(getattr(pointer,'canonical_name',None) or getattr(pointer,'name',pointer))[:180],'resolvedCandidates':sorted(targets),'reasons':reasons,'location':location})
                    continue
                if call_type=='NewContract':
                    value_evidence=_value_transfer_evidence(call)
                    created=getattr(call,'contract_created',None)
                    created_name=str(getattr(created,'name',None) or created or '<unknown>')
                    is_create2=getattr(call,'call_salt',None) is not None
                    effects[key].append({'kind':'contract_creation','callKind':'create2' if is_create2 else 'create','createdContract':created_name,'assetRelated':False,'sendsValue':True if value_evidence['state']=='nonzero' else False if value_evidence['state'] in ('not_attached','zero') else None,'valueTransferEvidence':value_evidence,'location':location,'expression':str(call)[:240]})
                    continue
                if call_type not in ('Send','Transfer'):continue
                value_evidence=_value_transfer_evidence(call)
                effects[key].append({'kind':'external_call','callKind':'native_'+call_type.lower(),'function':call_type.lower(),'destination':str(getattr(call,'destination','unknown'))[:180],'assetRelated':value_evidence['state']!='zero','sendsValue':True if value_evidence['state']=='nonzero' else False if value_evidence['state'] in ('not_attached','zero') else None,'valueTransferEvidence':value_evidence,'location':location,'expression':str(call)[:240]})
        for modifier in getattr(function,'modifiers',[]) or []:
            modifier_key=object_ids.get(id(modifier))
            if modifier_key and not any(target==modifier_key for target,_ in adjacency[key]):
                edge={'from':key,'to':modifier_key,'kind':'modifier','location':_source_location(function,source_aliases)}
                adjacency[key].append((modifier_key,edge));edge_count+=1
                if len(edge_rows)<max_reported_edges:edge_rows.append(edge)
        adjacency[key].sort(key=lambda row:(row[0],row[1]['location']['file'],row[1]['location']['lines']))
        effects[key].sort(key=lambda row:(row['kind'],row.get('function',row.get('variable','')),row['location']['file'],row['location']['lines']))
    entrypoints=[]
    target_contracts=set(target_contracts or []);target_source_units=set(target_source_units or [])
    for key,function in functions.items():
        context=getattr(function,'contract',None) or getattr(function,'contract_declarer',None)
        if target_contracts and getattr(context,'name',None) not in target_contracts:continue
        if target_source_units:
            # Inherited public methods are entrypoints of the target contract.
            # Filter by its owning contract source, not by the declaring function.
            source=_source_location(context,source_aliases).get('file','')
            if source=='unknown':source=_source_location(function,source_aliases).get('file','')
            normalized=source.replace('\\','/')
            units={(source_aliases or {}).get(unit,unit) for unit in target_source_units}
            if not any(normalized==unit or normalized.endswith('/'+unit) for unit in units):continue
        visibility=str(getattr(function,'visibility',''))
        is_constructor=bool(getattr(function,'is_constructor',False))
        is_fallback=bool(getattr(function,'is_fallback',False) or getattr(function,'is_receive',False))
        if is_constructor or is_fallback or visibility in ('public','external'):
            if not (getattr(function,'nodes',[]) or []):continue
            modifiers=[]
            for modifier in getattr(function,'modifiers',[]) or []:
                modifiers.append({'name':_function_name(modifier),'location':_source_location(modifier,source_aliases)})
            try:protected=bool(function.is_protected())
            except Exception:protected=None
            entrypoints.append({'function':key,'kind':'constructor' if is_constructor else 'fallback_or_receive' if is_fallback else 'external_entrypoint','visibility':visibility,'location':_source_location(function,source_aliases),'modifiers':modifiers,'permissionCandidates':[{'kind':'modifier_gate_candidate','modifier':item['name'],'function':key,'location':item['location'],'confidence':'heuristic','semanticsProven':False} for item in modifiers],'protectionHeuristic':None if modifiers else protected})
    def entry_priority(row):
        function=functions[row['function']]
        name=str(getattr(function,'name',row['function']))
        return (row['kind']!='external_entrypoint',bool(getattr(function,'view',False) or getattr(function,'pure',False)),not _asset_flow_name(name),row['function'])
    entrypoints.sort(key=entry_priority)
    # Modifier names are only authorization candidates. Preserve their exact
    # source location and make the conservative role vocabulary visible to the
    # shared IR; neither list proves that the modifier enforces the named role.
    role_candidates=[]
    for entry in entrypoints:
        for candidate in entry.get('permissionCandidates',[]):
            modifier=str(candidate.get('modifier',''))
            if re.search(r'(role|admin|owner|guardian|manager|operator|governor|pauser)',modifier,re.I):
                role_candidates.append({'name':modifier,'kind':'role_name_candidate','discovery':'modifier_name','function':entry['function'],'location':candidate.get('location'),'confidence':'heuristic','semanticsProven':False})
    total_entrypoints=len(entrypoints);truncated_entrypoints=entrypoints[max_entrypoints:];entrypoints=entrypoints[:max_entrypoints]
    path_heap=[];total_paths=0;asset_paths=0;asset_context_paths=0;state_paths=0;call_paths=0;creation_paths=0;selfdestruct_paths=0;walk_steps=0;depth_cutoff_edge_count=0;cycle_cutoff_edge_count=0;walk_budget_exceeded=False;visited_entrypoints=0
    for entry in entrypoints:
        if walk_steps>=max_walk_steps:walk_budget_exceeded=True;break
        visited_entrypoints+=1
        stack=[(entry['function'],[entry['function']],[],frozenset({entry['function']}))]
        while stack:
            node,path,edge_path,seen=stack.pop();walk_steps+=1
            if walk_steps>max_walk_steps:
                walk_budget_exceeded=True;break
            for effect in effects.get(node,[]):
                location=effect.get('location') or {}
                source_hash=(source_digests or {}).get(location.get('file'))
                if source_hash and type(location.get('start')) is int and type(location.get('length')) is int:
                    effect['sourceSha256']=source_hash
                    effect['effectSiteId']=effect_site_id(source_hash,location['file'],location['start'],location['length'],effect['kind'])
                asset_hint=effect.get('assetRelated',False) or (effect.get('valueTransferEvidence') or {}).get('state')=='nonzero' or any(_asset_flow_name(getattr(functions[name],'name',_function_name(functions[name]))) for name in path if name in functions)
                row={'entrypoint':entry['function'],'path':path,'edges':edge_path,'effect':effect,'modifiers':entry['modifiers'],'pathFeasibility':'not_proven','assetContextHint':bool(asset_hint),'triageRank':None}
                rank=_path_triage_rank(row);row['triageRank']=rank
                total_paths+=1
                if len(path_heap)<max_paths:
                    heapq.heappush(path_heap,(-rank*100-len(path),-total_paths,total_paths,row))
                else:
                    worst=path_heap[0]
                    candidate=(-rank*100-len(path),-total_paths)
                    if candidate>worst[:2]:heapq.heapreplace(path_heap,(*candidate,total_paths,row))
                state_paths+=effect['kind']=='state_write';call_paths+=effect['kind']=='external_call';creation_paths+=effect['kind']=='contract_creation';selfdestruct_paths+=effect['kind']=='selfdestruct'
                value_state=(effect.get('valueTransferEvidence') or {}).get('state')
                asset_paths+=effect['kind']=='external_call' and (effect.get('assetRelated',False) or value_state=='nonzero')
                asset_context_paths+=effect['kind']=='external_call' and asset_hint
            if len(path)>=max_depth:
                depth_cutoff_edge_count+=sum(target not in seen for target,_ in adjacency.get(node,[]))
                continue
            for target,edge in reversed(adjacency.get(node,[])):
                if target in seen:
                    cycle_cutoff_edge_count+=1;continue
                stack.append((target,path+[target],edge_path+[edge],seen|{target}))
        if walk_budget_exceeded:break
    paths=[item[3] for item in sorted(path_heap,key=lambda item:(-item[0],item[2]))]
    truncated_paths=max(0,total_paths-len(paths))
    state='partial' if truncated_paths or truncated_entrypoints or depth_cutoff_edge_count or walk_budget_exceeded or edge_count>len(edge_rows) or unresolved_dynamic_call_count or unresolved_count>len(unresolved) or unresolved_assembly_count or unresolved_assembly_call_count else 'completed'
    return {
        'schemaVersion': 2,
        'state': state,
        'method': 'Slither IR direct internal-call edges plus bounded same-function CFG function-pointer candidates, node-local state writes, recognized inline-assembly effects, and risk-oriented path triage',
        'contractCount': contract_count,
        'functionCount': len(functions) - len(modifier_ids),
        'modifierCount': len(modifier_ids),
        'analysisNodeCount': len(functions),
        'entrypointCount': total_entrypoints,
        'analyzedEntrypointCount': visited_entrypoints,
        'selectedEntrypointCount': len(entrypoints),
        'entrypoints': entrypoints,
        'roles': role_candidates,
        'permissions': [candidate for entry in entrypoints for candidate in entry.get('permissionCandidates',[])],
        'truncatedEntrypoints': [row['function'] for row in truncated_entrypoints[:256]],
        'edgeCount': edge_count,
        'reportedEdgeCount': len(edge_rows),
        'truncatedEdgeCount': max(0, edge_count - len(edge_rows)),
        'stateWritePathCount': state_paths,
        'externalCallPathCount': call_paths,
        'contractCreationPathCount': creation_paths,
        'selfdestructPathCount': selfdestruct_paths,
        'assetRelatedCallPathCount': asset_paths,
        'assetContextCallPathCount': asset_context_paths,
        'internalDynamicCallCount': dynamic_call_count,
        'resolvedInternalDynamicCallCount': resolved_dynamic_call_count,
        'unresolvedInternalDynamicCallCount': unresolved_dynamic_call_count,
        'internalDynamicWalkSteps': dynamic_walk_steps,
        'internalDynamicWalkBudget': max_dynamic_walk_steps,
        'unresolvedAssemblyBlockCount': unresolved_assembly_count,
        'reportedUnresolvedAssemblyBlockCount': len(unresolved_assembly),
        'unresolvedAssemblyBlocks': unresolved_assembly,
        'unresolvedAssemblyCallCount': unresolved_assembly_call_count,
        'reportedUnresolvedAssemblyCallCount': len(unresolved_assembly_calls),
        'unresolvedAssemblyCalls': unresolved_assembly_calls,
        'recognizedYulControlOrDataCallCount': sum(recognized_yul_builtin_counts.values()),
        'recognizedYulControlOrDataCallsByName': dict(sorted(recognized_yul_builtin_counts.items())),
        'totalPathCount': total_paths,
        'reportedPathCount': len(paths),
        'truncatedPathCount': truncated_paths,
        'maxDepth': max_depth,
        'depthCutoffEdgeCount': depth_cutoff_edge_count,
        'cycleCutoffEdgeCount': cycle_cutoff_edge_count,
        'truncatedEntrypointCount': len(truncated_entrypoints),
        'walkSteps': min(walk_steps, max_walk_steps),
        'walkBudgetExceeded': walk_budget_exceeded,
        'walkBudget': max_walk_steps,
        'pathSelectionPolicy': 'bounded top-K favors explicit asset calls, known nonzero value transfers and SELFDESTRUCT opcode observations, then asset-context external calls, then contract creations and other effects; this is triage ordering only',
        'edges': edge_rows,
        'paths': paths,
        'unresolvedInternalCalls': unresolved,
        'unresolvedInternalCallCount': unresolved_count,
        'limitations': [
            'Paths are structural over-approximations; branch predicates, authorization truth, dynamic dispatch and runtime state are not proven.',
            'Internal function-pointer targets are bounded same-function CFG reaching-definition candidates; aliases, storage pointers, cross-function assignments and unsupported definitions remain unresolved.',
            'Unparsed legacy inline assembly and inline Yul SolidityCall builtins outside the exact effect whitelist are reported as unresolved and make the call graph partial. Recognized Yul data and control builtins are counted but omitted from state/external-effect paths; revert can terminate a path and is not modeled as a path predicate. Recognized Yul storage and call builtins remain candidates, but their slots, targets and values are not semantically resolved.',
            'External calls and contract creations are terminal effects; calls into separately deployed targets and created constructors are not recursively expanded.',
            'A symbolic call value is unknown; it is not evidence that native currency is transferred.',
            'Modifier names are context only and do not prove effective access control.',
            'Asset-context labels and triage ranks are review aids, not proof of value transfer or vulnerability.',
            'Depth, walk, path and output-edge caps can omit candidate paths; check completeness fields before relying on coverage.',
            'A call or state-write path is evidence for review, not a confirmed vulnerability.',
        ],
    }

def safe_source_names(source_names):
    mapped={}
    for original in source_names:
        canonical=original.replace('\\','/')
        if canonical.startswith('/') or ntpath.isabs(original):
            safe='__verified_absolute__/'+hashlib.sha256(original.encode()).hexdigest()[:16]+'/'+posixpath.basename(canonical)
        else:
            safe=posixpath.normpath(canonical)
            if safe in ('.','..') or safe.startswith('../') or posixpath.isabs(safe):
                raise ValueError('unsafe relative source unit path')
        if safe in mapped.values():raise ValueError('source unit path collision after normalization: '+safe)
        mapped[original]=safe
    return mapped

def correlate_dynamic_effects(graph,local,limit=200):
    """Join exact source-mapped effect sites; a match does not prove its whole path."""
    if type(limit) is not int or limit < 0:
        raise ValueError('limit must be a non-negative integer')
    graph_fingerprint=hashlib.sha256(json.dumps(graph,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    matches_by_execution={};candidate_path_pairs=0;source_overlap_candidate_pairs=0
    raw_traces=local.get('traces') if isinstance(local,dict) else None
    malformed_trace_collection=raw_traces is not None and not isinstance(raw_traces,list)
    traces=raw_traces if isinstance(raw_traces,list) else []
    # Validate each trace once before joining it to every static path. A harness
    # can retain an unavailable trace for diagnostics, but it must never count
    # as executable evidence or make an all-failed collection look available.
    valid_trace_indices=set();invalid_trace_count=int(malformed_trace_collection);truncated_trace_count=0;truncated_effect_count=0
    step_truncated_trace_count=0;unknown_opcode_trace_count=0;unknown_opcode_count=0;partial_state_trace_count=0
    for trace_index,trace in enumerate(traces):
        invalid=(not isinstance(trace,dict) or trace.get('state') in ('unavailable','not_performed','failed') or
                 ('state' in trace and trace.get('state') not in ('available','partial')) or
                 trace.get('traceValid') is False or
                 not isinstance(trace.get('transactionHash'),str) or not trace['transactionHash'] or
                 type(trace.get('failed')) is not bool or type(trace.get('targetDepth',1)) is not int or
                 trace.get('targetDepth',1)<1 or not isinstance(trace.get('effects'),list))
        if not invalid and any(not isinstance(effect,dict) or type(effect.get('depth')) is not int or
                               not isinstance(effect.get('op'),str) for effect in trace['effects']):
            invalid=True
        if not invalid and 'traceValid' in trace and type(trace['traceValid']) is not bool:
            invalid=True
        # Harness-produced available traces must explicitly attest that the
        # debug trace passed structural validation. Legacy fixtures without a
        # state/traceValid pair remain accepted for backward compatibility.
        if not invalid and 'state' in trace and trace.get('state')=='available' and trace.get('traceValid') is not True:
            invalid=True
        if not invalid and 'effectsTruncated' in trace and type(trace['effectsTruncated']) is not bool:
            invalid=True
        if not invalid and 'stepsTruncated' in trace and type(trace['stepsTruncated']) is not bool:
            invalid=True
        if not invalid and 'effectCountComplete' in trace and type(trace['effectCountComplete']) is not bool:
            invalid=True
        if not invalid and trace.get('stepsTruncated') is True and trace.get('effectCountComplete') is True:
            invalid=True
        if not invalid and 'unknownOpcodeCount' in trace and (
                type(trace['unknownOpcodeCount']) is not int or trace['unknownOpcodeCount'] < 0):
            invalid=True
        if not invalid and ('effectCount' in trace or 'reportedEffectCount' in trace):
            effect_count=trace.get('effectCount');reported_count=trace.get('reportedEffectCount')
            invalid=(type(effect_count) is not int or effect_count<0 or
                     type(reported_count) is not int or reported_count<0 or
                     reported_count!=len(trace['effects']) or reported_count>effect_count)
            if not invalid:
                expected_truncated=effect_count>reported_count
                invalid=(trace.get('effectsTruncated') is not expected_truncated
                         if 'effectsTruncated' in trace else expected_truncated)
        if not invalid and trace.get('effectsTruncated'):
            effect_count=trace.get('effectCount');reported_count=trace.get('reportedEffectCount')
            invalid=(type(effect_count) is not int or effect_count<0 or
                     type(reported_count) is not int or reported_count<0 or
                     reported_count!=len(trace['effects']) or effect_count<=reported_count)
        if invalid:
            invalid_trace_count+=1
            continue
        valid_trace_indices.add(trace_index)
        if trace.get('state')=='partial':
            partial_state_trace_count+=1
        if trace.get('effectsTruncated'):
            truncated_trace_count+=1
            effect_count=trace.get('effectCount');reported_count=trace.get('reportedEffectCount')
            if type(effect_count) is int and type(reported_count) is int:
                truncated_effect_count+=max(0,effect_count-reported_count)
        if trace.get('stepsTruncated') is True or trace.get('effectCountComplete') is False:
            step_truncated_trace_count+=1
        if trace.get('unknownOpcodeCount',0)>0:
            unknown_opcode_trace_count+=1
            unknown_opcode_count+=trace['unknownOpcodeCount']
    # Coarse line overlap is diagnostic, including effects with unbound source
    # hashes/sites. Count interval overlaps without rescanning these effects
    # for each path; exact identity uses a separate, narrower index below.
    line_bounds_by_source=collections.defaultdict(lambda: ([], []))
    effects_by_site=collections.defaultdict(lambda: {'effects':[], 'starts':[], 'ends':[], 'paths':[]})
    opcode_kinds={'SSTORE':'state_write','TSTORE':'state_write',
                  'SELFDESTRUCT':'selfdestruct','CREATE':'contract_creation','CREATE2':'contract_creation',
                  'CALL':'external_call','STATICCALL':'external_call','DELEGATECALL':'external_call','CALLCODE':'external_call'}
    # Each execution belongs to one exact opcode/site bucket. Separate line
    # endpoints count all pairs without walking that bucket for every path.
    for trace_index in sorted(valid_trace_indices):
        trace = traces[trace_index]
        target_depth = trace.get('targetDepth', 1)
        for effect_index, executed in enumerate(trace['effects']):
            if not isinstance(executed, dict):
                continue
            source = executed.get('sourceLocation') or {}
            if (not isinstance(source, dict) or not isinstance(source.get('file'), str) or
                    not source.get('file') or type(executed.get('depth')) is not int or
                    executed.get('depth') != target_depth or not isinstance(executed.get('op'), str)):
                continue
            line_start=source.get('lineStart');line_end=source.get('lineEnd')
            if (type(line_start) is not int or type(line_end) is not int or
                    line_start<1 or line_end<line_start):
                continue
            opcode=executed['op'];kind=opcode_kinds.get(opcode)
            if kind is None:
                continue
            starts,ends=line_bounds_by_source[(opcode,source['file'])]
            starts.append(line_start);ends.append(line_end)
            source_hash=source.get('sourceSha256');site=executed.get('effectSiteId')
            start=source.get('start');length=source.get('length')
            if (not isinstance(source_hash,str) or re.fullmatch(r'[0-9a-f]{64}',source_hash) is None or
                    not isinstance(site,str) or type(start) is not int or type(length) is not int or
                    start<0 or length<1):
                continue
            bucket=effects_by_site[(opcode,source['file'],source_hash,start,length,site)]
            bucket['effects'].append((trace_index,effect_index,trace,executed,source,line_start,line_end))
            bucket['starts'].append(line_start);bucket['ends'].append(line_end)

    for starts,ends in line_bounds_by_source.values():
        starts.sort();ends.sort()
    for bucket in effects_by_site.values():
        bucket['starts'].sort();bucket['ends'].sort()
    paths=(graph.get('paths',[]) if isinstance(graph,dict) else [])
    if not isinstance(paths,list):
        paths=[]

    for path_index,path in enumerate(paths):
        if not isinstance(path, dict):
            continue
        effect=path.get('effect')
        if not isinstance(effect, dict):
            continue
        location=effect.get('location')
        if not isinstance(location, dict):
            continue
        lines=location.get('lines') or []
        if (not isinstance(location.get('file'), str) or not location.get('file') or
                not isinstance(lines,list) or not lines or
                any(type(line) is not int or line < 1 for line in lines)):
            continue
        if effect.get('kind')=='state_write':allowed={'SSTORE','TSTORE'}
        elif effect.get('kind')=='selfdestruct':allowed={'SELFDESTRUCT'}
        elif effect.get('kind')=='contract_creation':allowed={'CREATE2'} if effect.get('callKind')=='create2' else {'CREATE'} if effect.get('callKind')=='create' else set()
        elif effect.get('kind')=='external_call':allowed={'CALL','STATICCALL','DELEGATECALL','CALLCODE'}
        else:allowed=set()
        line_min,line_max=min(lines),max(lines)
        for opcode in allowed:
            bounds=line_bounds_by_source.get((opcode,location['file']))
            if bounds is not None:
                starts,ends=bounds
                source_overlap_candidate_pairs+=bisect_right(starts,line_max)-bisect_left(ends,line_min)
        source_hash=effect.get('sourceSha256');site=effect.get('effectSiteId');kind=effect.get('kind')
        start=location.get('start');length=location.get('length')
        if (not allowed or not isinstance(source_hash,str) or re.fullmatch(r'[0-9a-f]{64}',source_hash) is None or
                type(start) is not int or type(length) is not int or start<0 or length<1 or
                not isinstance(site,str) or site!=effect_site_id(source_hash,location['file'],start,length,kind)):
            continue
        for opcode in allowed:
            bucket=effects_by_site.get((opcode,location['file'],source_hash,start,length,site))
            if bucket is None:continue
            pair_count=bisect_right(bucket['starts'],line_max)-bisect_left(bucket['ends'],line_min)
            candidate_path_pairs+=pair_count
            if pair_count:
                bucket['paths'].append((path_index,line_min,line_max))

    matched_count=0
    def candidate_executions():
        nonlocal matched_count
        for bucket in effects_by_site.values():
            site_paths=bucket['paths']
            if not site_paths:continue
            ordered_paths=sorted(site_paths,key=lambda row: row[1])
            union_starts=[];union_ends=[]
            for _,line_min,line_max in ordered_paths:
                if union_ends and line_min<=union_ends[-1]:
                    union_ends[-1]=max(union_ends[-1],line_max)
                else:
                    union_starts.append(line_min);union_ends.append(line_max)
            # Sweep path starts in order of execution line end. A suffix-min
            # Fenwick tree of path ends finds the first matching path without
            # enumerating all path/execution pairs, including duplicate paths.
            if limit:
                ends=sorted({row[2] for row in site_paths})
                minimum_paths=[len(paths)]*(len(ends)+1)
                next_path=0
                executions=sorted(bucket['effects'],key=lambda row: row[6])
            else:
                executions=bucket['effects']
            for row in executions:
                line_start,line_end=row[5:7]
                union_index=bisect_left(union_ends,line_start)
                if union_index==len(union_ends) or union_starts[union_index]>line_end:continue
                # A spanning execution may intersect several disjoint ranges;
                # union membership counts it once, rather than summing pairs.
                matched_count+=1
                if not limit:continue
                while next_path<len(ordered_paths) and ordered_paths[next_path][1]<=line_end:
                    path_index,_,path_end=ordered_paths[next_path]
                    index=len(ends)-bisect_left(ends,path_end)
                    while index<len(minimum_paths):
                        minimum_paths[index]=min(minimum_paths[index],path_index)
                        index+=index & -index
                    next_path+=1
                index=len(ends)-bisect_left(ends,line_start)
                first_path=len(paths)
                while index:
                    first_path=min(first_path,minimum_paths[index])
                    index-=index & -index
                yield first_path,row[0],row[1],row,bucket

    # Keep only limit lightweight records while counting every execution.
    # First path, then trace/effect order is exactly the legacy insertion order.
    candidates=candidate_executions()
    if limit:
        retained=heapq.nsmallest(limit,candidates,key=lambda row: row[:3])
    else:
        for _ in candidates:pass
        retained=[]
    for _,trace_index,effect_index,row,bucket in retained:
        _,_,trace,executed,source,line_start,line_end=row
        match={'traceIndex':trace_index,'effectIndex':effect_index,'transactionHash':trace['transactionHash'],'opcode':executed['op'],'effectSiteId':executed['effectSiteId'],'sourceLocation':source,'transactionReverted':trace['failed'],'candidatePathIndices':[],'completePathProven':False}
        matches_by_execution[(trace_index,effect_index)]=match
        for path_index,line_min,line_max in bucket['paths']:
            if line_min<=line_end and line_max>=line_start:
                match['candidatePathIndices'].append(path_index)
                if len(match['candidatePathIndices'])==limit:break
    matches=list(matches_by_execution.values())
    state='available' if valid_trace_indices else 'unavailable' if invalid_trace_count else 'not_performed'
    if valid_trace_indices and (invalid_trace_count or truncated_trace_count or step_truncated_trace_count or unknown_opcode_trace_count or partial_state_trace_count):state='partial'
    return {'state':state,'graphFingerprint':graph_fingerprint,'identityMethod':'sha256(sourceSha256, file, UTF-8 byte start, byte length, effect kind)','scope':'exact source-mapped effect-site identity between static candidates and sampled local EVM opcodes; line overlap alone is not bound; complete path, authorization and deployed reachability are not proven','traceCount':len(traces),'validTraceCount':len(valid_trace_indices),'invalidTraceCount':invalid_trace_count,'truncatedTraceCount':truncated_trace_count,'truncatedEffectCount':truncated_effect_count,'stepTruncatedTraceCount':step_truncated_trace_count,'unknownOpcodeTraceCount':unknown_opcode_trace_count,'unknownOpcodeCount':unknown_opcode_count,'partialStateTraceCount':partial_state_trace_count,'matchedEffectCount':matched_count,'candidatePathPairCount':candidate_path_pairs,'sourceOverlapCandidatePathPairCount':source_overlap_candidate_pairs,'unboundSourceOverlapCandidatePathPairCount':max(0,source_overlap_candidate_pairs-candidate_path_pairs),'reportedMatches':len(matches),'truncatedMatches':max(0,matched_count-limit),'matches':matches}

def summarize_source_coverage(coverage):
    if not isinstance(coverage,dict):
        return {'state':'unavailable','reason':'source coverage is not an object'}
    spans=coverage.get('spans')
    scope=coverage.get('scope')
    methods=coverage.get('sampledMethods')
    selectors=coverage.get('sampledSelectors')
    summary={'state':'available' if isinstance(scope,str) and isinstance(spans,list) else 'partial',
             'scope':scope if isinstance(scope,str) else 'unknown',
             'sampledMethods':methods if isinstance(methods,list) else [],
             'sampledSelectors':selectors if isinstance(selectors,list) else [],
             'spanCount':len(spans) if isinstance(spans,list) else None}
    if not isinstance(scope,str) or not isinstance(spans,list):
        summary['reason']='source coverage is missing a valid scope or spans list'
    if methods is not None and not isinstance(methods,list):
        summary['state']='partial';summary['reason']='sampledMethods is not a list'
    if selectors is not None and not isinstance(selectors,list):
        summary['state']='partial';summary['reason']='sampledSelectors is not a list'
    return summary

def rewrite_import_paths(importer,content,source_map,all_sources,remappings,module):
    masked=module.code_only(content)
    pattern=re.compile(r'\bimport\s+(?:[^;]*?\bfrom\s+)?([\"\'])([^\"\']+)\1\s*;')
    replacements=[]
    for match in pattern.finditer(masked):
        original_spec=match.group(2)
        target=module.resolve_source_import(importer,original_spec,remappings,all_sources)
        if target not in source_map:continue
        relative=posixpath.relpath(source_map[target],posixpath.dirname(source_map[importer]) or '.')
        if not relative.startswith('.'):relative='./'+relative
        start,end=match.span(2)
        replacements.append((start,end,relative))
    for start,end,value in reversed(replacements):content=content[:start]+value+content[end:]
    return content

def _expected_dynamic_execution_boundary(env=None):
    """Derive the child harness boundary contract without exposing RPC secrets."""
    values=os.environ if env is None else env
    mode=str(values.get('DYNAMIC_EXECUTION_MODE','')).strip()
    rpc_url=str(values.get('DYNAMIC_FORK_RPC_URL','')).strip()
    block_text=str(values.get('DYNAMIC_FORK_BLOCK_NUMBER','')).strip()
    requested=bool(mode=='fixed_block_fork' or rpc_url or block_text)
    expected_mode='fixed_block_fork' if requested else 'isolated_in_process'
    result={'mode':expected_mode,'chainId':31337,'requestedFork':requested,
            'externalTransactions':False,'externalSigning':False}
    if not requested:
        result.update({'forkState':'not_performed','forkProbeState':'not_performed'})
        return result
    result['rpcUrlHash']=hashlib.sha256(rpc_url.encode()).hexdigest() if rpc_url else None
    try:block=int(block_text,0) if block_text.lower().startswith('0x') else int(block_text,10)
    except (TypeError,ValueError):block=None
    if block is not None and (block<0 or block>9007199254740991):block=None
    result['fixedBlockNumber']=block
    result.update({'forkState':'verified','forkProbeState':'verified'})
    return result

def _validate_dynamic_execution_boundary(value,env=None):
    """Require an attested local network or stable fixed-block fork boundary."""
    errors=[]
    if not isinstance(value,dict):return ['execution_boundary_missing']
    expected=_expected_dynamic_execution_boundary(env)
    for key in ('mode','chainId','externalTransactions','externalSigning'):
        if value.get(key)!=expected[key]:errors.append(f'execution_boundary_{key}_mismatch')
    if value.get('networkWrites')!='local_only':errors.append('execution_boundary_network_writes_not_local')
    if expected['mode']=='isolated_in_process':
        if value.get('forkState')!='not_performed':errors.append('execution_boundary_unexpected_fork')
        probe=value.get('forkProbe') or {}
        if probe.get('state')!='not_performed':errors.append('execution_boundary_fork_probe_unexpected')
    else:
        if expected['fixedBlockNumber'] is None:errors.append('execution_boundary_fork_block_invalid')
        if value.get('forkState')!='verified':errors.append('execution_boundary_fork_not_verified')
        probe=value.get('forkProbe') or {}
        if probe.get('state')!='verified' or probe.get('readOnly') is not True or probe.get('repeatHashMatch') is not True:
            errors.append('execution_boundary_fork_probe_not_verified')
        if value.get('fixedBlockNumber')!=expected['fixedBlockNumber']:
            errors.append('execution_boundary_fork_block_mismatch')
        endpoint=value.get('rpcEndpoint') or {}
        if endpoint.get('sha256')!=expected['rpcUrlHash']:
            errors.append('execution_boundary_rpc_endpoint_mismatch')
    return errors

def _unavailable_dynamic_execution_boundary(env=None,reason='harness_did_not_attest_boundary'):
    expected=_expected_dynamic_execution_boundary(env)
    expected.update({'forkState':'unavailable','forkProbe':{'state':'unavailable','reason':reason},
                     'networkWrites':'local_only'})
    return expected

def _run_dynamic_harness(bundle_path,folder,source_input,target,soljson,dependency=None,timeout=60,harness='test-collected.cjs',contract_name=None,source_aliases=None,env=None):
    test_input=folder/'local-test-input.json';test_input.write_text(json.dumps(source_input))
    command=['node',str(ROOT/'scripts'/harness),str(test_input),target]
    aliases_file=None
    if source_aliases:
        aliases_file=folder/'source-path-aliases.json';aliases_file.write_text(json.dumps(source_aliases,ensure_ascii=False))
    if contract_name:command.extend(['--contract',contract_name])
    if dependency:command.extend(['--dependency',str(dependency)])
    if aliases_file:command.extend(['--source-aliases',str(aliases_file)])
    child_env=dict(os.environ if env is None else env);child_env['CAMPAIGN_SOLJSON']=str(soljson)
    try:
        proc=run_bounded(command,timeout,env=child_env,
                         max_process_tree_rss_bytes=MAX_DYNAMIC_HARNESS_RSS_BYTES)
        try:local=json.loads(proc.stdout)
        except Exception:local={'state':'unavailable','reason':'dynamic_harness_returned_invalid_json','exitCode':proc.returncode,'stderr':proc.stderr[-1200:]}
        if not isinstance(local,dict):local={'state':'unavailable','reason':'dynamic_harness_returned_non_object','exitCode':proc.returncode}
        if proc.returncode and local.get('state')=='passed':local={'state':'failed','reason':'dynamic_harness_exit_code_mismatch','exitCode':proc.returncode,'reported':local}
        binding_errors=[]
        # Harnesses use the same recursive key-sorted JSON representation so
        # source binding is independent of object insertion order.
        expected_source_hash=hashlib.sha256(json.dumps(source_input.get('sources',{}),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if not isinstance(local.get('sourceHash'),str) or local.get('sourceHash')!=expected_source_hash:
            binding_errors.append('source_hash_mismatch')
        harness_path=ROOT/'scripts'/harness
        expected_harness_hash=hashlib.sha256(harness_path.read_bytes()).hexdigest()
        if not isinstance(local.get('harnessHash'),str) or local.get('harnessHash')!=expected_harness_hash:
            binding_errors.append('harness_hash_mismatch')
        support_digest=hashlib.sha256()
        for support_name in ('evm-source-map.cjs','dynamic-trace-support.cjs','dynamic-execution-boundary.cjs'):
            support_digest.update(support_name.encode('utf-8'))
            support_digest.update(b'\0')
            support_digest.update((ROOT/'scripts'/support_name).read_bytes())
            support_digest.update(b'\0')
        expected_support_hash=support_digest.hexdigest()
        if not isinstance(local.get('harnessSupportHash'),str) or local.get('harnessSupportHash')!=expected_support_hash:
            binding_errors.append('harness_support_hash_mismatch')
        binding_errors.extend(_validate_dynamic_execution_boundary(local.get('executionBoundary'),child_env))
        if binding_errors:
            local={'state':'unavailable','reason':'dynamic_evidence_binding_failed','evidenceBindingErrors':binding_errors,'reported':local}
        local['failureEvidence']=build_dynamic_failure_evidence(local,{
            'argv':command,
            'cwd':str(ROOT),
            'env':{'CAMPAIGN_SOLJSON':str(soljson)},
            'isolation':'in_process_hardhat_31337',
            'executionBoundary':_expected_dynamic_execution_boundary(child_env),
        })
    except subprocess.TimeoutExpired as e:
        local={'state':'unavailable','reason':'dynamic_harness_timeout','timeoutSec':timeout,'stdoutTail':(e.stdout or '')[-1200:] if isinstance(e.stdout,str) else '', 'stderrTail':(e.stderr or '')[-1200:] if isinstance(e.stderr,str) else ''}
    except ProcessTreeMemoryLimitExceeded as e:
        local={'state':'unavailable','reason':'dynamic_harness_memory_limit_exceeded',
               'memoryLimitBytes':e.limit_bytes,'observedSampleBytes':e.observed_bytes,
               'stderrTail':(e.stderr or '')[-1200:] if isinstance(e.stderr,str) else ''}
    except ProcessMemoryMonitorUnavailable as e:
        local={'state':'unavailable','reason':str(e)}
    except ProcessGroupCleanupIncomplete as e:
        local={'state':'unavailable','reason':str(e)}
    except Exception as e:local={'state':'unavailable','reason':'dynamic_harness_execution_error','error':f'{type(e).__name__}: {str(e)[:400]}'}
    if 'failureEvidence' not in local:
        local['failureEvidence']=build_dynamic_failure_evidence(local,{
            'argv':command,
            'cwd':str(ROOT),
            'env':{'CAMPAIGN_SOLJSON':str(soljson)},
            'isolation':'in_process_hardhat_31337',
            'executionBoundary':_expected_dynamic_execution_boundary(child_env),
        })
    local.setdefault('executionBoundary',_unavailable_dynamic_execution_boundary(child_env))
    local.setdefault('runnerLimits',{
        'processTreeRssLimitBytes':MAX_DYNAMIC_HARNESS_RSS_BYTES,
        'sampleIntervalMs':round(PROCESS_RSS_POLL_INTERVAL_SECONDS*1000),
        'enforcement':'periodic_process_tree_rss_monitor; not an OS hard quota',
        'processTreeCleanup':'initial process group; detached descendants may escape tracking and cleanup',
        'traceAcquisition':'Pinned Hardhat 2.22.19 / EDR 0.8.0 exposes no streaming or max-step debug-trace API: RawTrace.trace() and debug_traceTransaction materialize complete traces before MAX_TRACE_STEPS bounds summarization; the RSS monitor can terminate an oversized run but cannot prevent trace-acquisition allocations',
    })
    report=bundle_path.parent/'local-tests.json'
    try:local['report']=str(report.relative_to(ROOT))
    except ValueError:local['report']=str(report)
    report.write_text(json.dumps(local,ensure_ascii=False,indent=2))
    return local

def _run_target_dynamic(bundle_path,folder,source_input,targets,version,dependency_path,module,source_aliases=None,env=None):
    target_name=next(iter(targets.values())) if len(targets)==1 else None
    target_path=next(iter(targets)) if len(targets)==1 else None
    source_aliases=source_aliases or {safe:original for original,safe in safe_source_names(module.reachable_sources(json.loads(bundle_path.read_text()))[0]).items()}
    if version=='0.8.28' and target_name=='VaultV2':
        soljson=TOOLS/'solc-0828/node_modules/solc/soljson.js'
        return _run_dynamic_harness(bundle_path,folder,source_input,target_path,soljson,timeout=75,harness='test-vault.cjs',contract_name=target_name,source_aliases=source_aliases,env=env)
    if version in ('0.8.24','0.8.17') and target_name=='EngineChip':
        soljson,_=compiler(version)
        return _run_dynamic_harness(bundle_path,folder,source_input,target_path,soljson,timeout=60,source_aliases=source_aliases,env=env)
    if version=='0.8.17' and target_name=='AMTDepositPool' and dependency_path:
        dependency=json.loads(Path(dependency_path).read_text());dependency_sources,_,dependency_missing=module.reachable_sources(dependency)
        if dependency_missing:return {'state':'not_performed','reason':'verified reward dependency has unresolved imports','missingImports':dependency_missing}
        dependency_input={'sources':{k:{'content':v} for k,v in dependency_sources.items()},'metadata':dependency.get('metadata',{})}
        dependency_file=folder/'verified-dependency-input.json';dependency_file.write_text(json.dumps(dependency_input))
        soljson,_=compiler(version)
        local=_run_dynamic_harness(bundle_path,folder,source_input,target_path,soljson,dependency=dependency_file,timeout=75,source_aliases=source_aliases,env=env)
        local['verifiedDependencySource']=str(Path(dependency_path))
        (bundle_path.parent/'local-tests.json').write_text(json.dumps(local,ensure_ascii=False,indent=2))
        return local
    if version=='0.8.17' and target_name=='AMTDepositPool':
        return {'state':'not_performed','reason':'verified configured reward implementation was not obtained; adversarial mock is not substituted'}
    return {'state':'not_performed','reason':'No reviewed target-specific local harness for this contract'}

def _target_has_dynamic_harness(targets,version,dependency_path):
    target_name=next(iter(targets.values())) if len(targets)==1 else None
    return bool((version=='0.8.28' and target_name=='VaultV2') or
                (version in ('0.8.24','0.8.17') and target_name=='EngineChip') or
                (version=='0.8.17' and target_name=='AMTDepositPool' and dependency_path))

def _available_memory_bytes():
    """Best-effort estimate of reclaimable memory; unknown means serial fallback."""
    try:
        if sys.platform.startswith('linux'):
            for line in Path('/proc/meminfo').read_text().splitlines():
                if line.startswith('MemAvailable:'):
                    return int(line.split()[1])*1024
        if sys.platform=='darwin':
            output=subprocess.run(['vm_stat'],capture_output=True,text=True,timeout=2,check=True).stdout
            page_match=re.search(r'page size of (\d+) bytes',output)
            if not page_match:return None
            page_size=int(page_match.group(1));pages=0
            for name in ('Pages free','Pages inactive','Pages speculative','Pages purgeable'):
                match=re.search(r'^'+re.escape(name)+r':\s*(\d+)\.',output,re.M)
                if match:pages+=int(match.group(1))
            return pages*page_size
        import psutil
        return int(psutil.virtual_memory().available)
    except Exception:
        return None

def _acquire_parallel_analysis_slot():
    """Allow one bounded static/dynamic overlap per machine, with serial fallback."""
    mode=os.environ.get('FLARE_ANALYSIS_PARALLEL','auto').strip().lower()
    if mode in ('0','false','off','serial'):return None,'disabled_by_environment'
    if mode not in ('auto','1','true','on'):return None,'invalid_parallel_setting'
    if mode=='auto':
        cpu_count=os.cpu_count() or 0
        if cpu_count<4:return None,'insufficient_logical_cpus'
        available=_available_memory_bytes()
        if available is None:return None,'available_memory_unknown'
        if available<4*1024**3:return None,'less_than_4_gib_available'
    lock_path=ROOT/'work'/'static-dynamic-overlap.lock';lock_path.parent.mkdir(parents=True,exist_ok=True)
    handle=lock_path.open('a+')
    try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close();return None,'parallel_slot_busy'
    except BaseException:
        handle.close();raise
    return handle,None

def _release_parallel_analysis_slot(handle):
    if handle is None or handle.closed:return
    try:
        try:fcntl.flock(handle,fcntl.LOCK_UN)
        except OSError:pass
    finally:
        try:handle.close()
        except OSError:pass

def _timed_target_dynamic(*args):
    started=time.monotonic()
    try:value=_run_target_dynamic(*args)
    except Exception as e:value={'state':'unavailable','reason':'dynamic_analysis_error','error':f'{type(e).__name__}: {str(e)[:700]}'}
    ended=time.monotonic()
    return value,round((ended-started)*1000),started,ended

@contextmanager
def _dynamic_analysis_overlap(dynamic_args,enabled):
    """Own the overlap lease until both stages finish, including interruption."""
    slot=None;executor=None;future=None;reason='dynamic_harness_not_available'
    try:
        if enabled:
            try:slot,reason=_acquire_parallel_analysis_slot()
            except Exception as error:reason='parallel_slot_unavailable:'+type(error).__name__
            if slot is not None:
                try:
                    executor=concurrent.futures.ThreadPoolExecutor(max_workers=1,thread_name_prefix='contract-dynamic')
                    future=executor.submit(_timed_target_dynamic,*dynamic_args)
                except Exception as error:
                    try:
                        if executor is not None:executor.shutdown(wait=True)
                    except Exception:pass
                    finally:
                        executor=None
                        _release_parallel_analysis_slot(slot);slot=None
                    reason='parallel_start_failed:'+type(error).__name__
        yield future,reason
    finally:
        try:
            if executor is not None:executor.shutdown(wait=True)
        finally:
            _release_parallel_analysis_slot(slot)

def _report_reference(path):
    """Keep project reports relative and support evidence outside the checkout."""
    resolved=Path(path).resolve()
    try:return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:return str(resolved)

# Every failed scenario exposes the same dimensions. A missing measurement is
# represented explicitly instead of being inferred from an assertion message.
DYNAMIC_FAILURE_FIELDS=('seed','caller','role','parameters','value','transactionSequence','blockTime','initialState','dependencyCodeHashes','trace','stateDiff','events','assetChanges','permissionChanges','profit','cost','minimumSequence','replayCommand')

def _available_evidence(value):return {'state':'available','value':value}
def _unavailable_evidence(reason):return {'state':'unavailable','reason':reason}

def validate_dynamic_failure_evidence(value):
    errors=[]
    if not isinstance(value,dict) or value.get('schemaVersion')!=1:return ['schemaVersion_must_be_1']
    if value.get('state') not in ('not_performed','unavailable','partial','available'):errors.append('invalid_state')
    samples=value.get('samples')
    if not isinstance(samples,list):return errors+['samples_must_be_a_list']
    if value.get('state')=='not_performed' and samples:errors.append('not_performed_must_not_have_samples')
    seen=set()
    for index,sample in enumerate(samples):
        prefix=f'samples[{index}]'
        if not isinstance(sample,dict) or not isinstance(sample.get('scenario'),str) or not sample['scenario']:
            errors.append(f'{prefix}_scenario_required');continue
        if sample['scenario'] in seen:errors.append(f'{prefix}_scenario_duplicate')
        seen.add(sample['scenario'])
        if sample.get('confirmedVulnerability') is not False:errors.append(f'{prefix}_must_not_confirm_vulnerability')
        fields=sample.get('fields')
        if not isinstance(fields,dict):errors.append(f'{prefix}_fields_required');continue
        for name in DYNAMIC_FAILURE_FIELDS:
            evidence=fields.get(name)
            if not isinstance(evidence,dict) or evidence.get('state') not in ('available','unavailable'):
                errors.append(f'{prefix}_{name}_must_be_available_or_unavailable')
            elif evidence['state']=='available' and 'value' not in evidence:
                errors.append(f'{prefix}_{name}_available_value_required')
            elif evidence['state']=='unavailable' and not isinstance(evidence.get('reason'),str):
                errors.append(f'{prefix}_{name}_unavailable_reason_required')
    return errors

def build_dynamic_failure_evidence(local,replay_command=None):
    """Bind failed assertions to captured transactions/traces without inventing facts."""
    if not isinstance(local,dict):return {'schemaVersion':1,'state':'unavailable','samples':[],'reason':'dynamic_harness_report_is_not_an_object'}
    results=local.get('results')
    if not isinstance(results,list):return {'schemaVersion':1,'state':'unavailable','samples':[],'reason':'scenario_results_not_recorded'}
    failed=[row for row in results if isinstance(row,dict) and row.get('state')=='failed']
    if not failed:return {'schemaVersion':1,'state':'not_performed','samples':[],'reason':'no_failed_scenario_assertions'}
    evidence=local.get('transactionEvidence') if isinstance(local.get('transactionEvidence'),dict) else {}
    transactions=evidence.get('transactions') if isinstance(evidence.get('transactions'),list) else []
    traces=local.get('traces') if isinstance(local.get('traces'),list) else []
    fuzz=local.get('deterministicFuzz') if isinstance(local.get('deterministicFuzz'),dict) else {}
    seed=fuzz.get('seed') if isinstance(fuzz.get('seed'),(str,int)) else None
    samples=[]
    for row in failed:
        scenario=row.get('name') if isinstance(row.get('name'),str) and row.get('name') else 'unknown_scenario'
        matched=[tx for tx in transactions if isinstance(tx,dict) and (tx.get('scenario')==scenario or tx.get('sequenceId')==scenario)]
        hashes={tx.get('transactionHash') for tx in matched if isinstance(tx.get('transactionHash'),str)}
        trace_refs=[{'transactionHash':trace.get('transactionHash'),'state':trace.get('state'),'traceValid':trace.get('traceValid')} for trace in traces if isinstance(trace,dict) and trace.get('transactionHash') in hashes]
        fields={name:_unavailable_evidence('not_captured_by_dynamic_harness') for name in DYNAMIC_FAILURE_FIELDS}
        if seed is not None and any(token in scenario.lower() for token in ('sequence','fuzz','序列')):fields['seed']=_available_evidence(seed)
        if matched:
            callers=sorted({tx.get('from') for tx in matched if isinstance(tx.get('from'),str)})
            fields['caller']=_available_evidence(callers) if callers else _unavailable_evidence('caller_not_recorded')
            values=[tx.get('value') for tx in matched]
            fields['value']=_available_evidence(values) if all(isinstance(value,str) for value in values) else _unavailable_evidence('transaction_value_not_fully_recorded')
            fields['parameters']=_available_evidence([{'selector':tx.get('selector'),'rawCalldata':tx.get('rawCalldata'),'rawCalldataState':tx.get('rawCalldataState')} for tx in matched])
            fields['transactionSequence']=_available_evidence(matched)
            block_times=[tx.get('blockTime') for tx in matched]
            fields['blockTime']=_available_evidence(block_times) if block_times and all(isinstance(value,str) for value in block_times) else _unavailable_evidence('block_time_not_recorded_for_every_transaction')
            event_rows=[tx.get('events') for tx in matched]
            fields['events']=_available_evidence(event_rows) if matched and all(tx.get('eventsState')=='available' for tx in matched) else _unavailable_evidence('receipt_events_not_recorded_for_every_transaction')
        else:fields['transactionSequence']=_unavailable_evidence('no_transactions_bound_to_failed_scenario')
        fields['trace']=_available_evidence(trace_refs) if trace_refs else _unavailable_evidence('no_trace_bound_to_failed_scenario')
        if isinstance(replay_command,dict):fields['replayCommand']=_available_evidence(replay_command)
        samples.append({'scenario':scenario,'failure':{'state':'observed','message':str(row.get('error','scenario assertion failed'))[:500]},'confirmedVulnerability':False,'fields':fields})
    result={'schemaVersion':1,'state':'partial','samples':samples,'scope':'failed local harness assertions; captured transaction and trace references only; no exploitability inference'}
    errors=validate_dynamic_failure_evidence(result)
    if errors:return {'schemaVersion':1,'state':'unavailable','samples':[],'reason':'generated_failure_evidence_failed_validation','validationErrors':errors}
    return result

def _analyze_uncached(bundle_path,dependency_path=None):
    analysis_started=time.monotonic()
    bundle_path=Path(bundle_path).resolve()
    dependency_path=Path(dependency_path).resolve() if dependency_path else None
    data=json.loads(bundle_path.read_text());original=(data.get('compilation') or {}).get('compilerVersion','unknown');version=original.split('+')[0]
    folder=bundle_path.parent/'static-work';folder.mkdir(exist_ok=True)
    dynamic_folder=bundle_path.parent/'dynamic-work';dynamic_folder.mkdir(exist_ok=True)
    from importlib.util import spec_from_file_location,module_from_spec
    spec=spec_from_file_location('campaign_source',ROOT/'scripts/defi-campaign.py');module=module_from_spec(spec);spec.loader.exec_module(module)
    reachable,_,missing=module.reachable_sources(data)
    if missing: return {'state':'unavailable','reason':'unresolved imports','imports':missing,'localReproduction':False,'localTests':{'state':'not_performed','reason':'source bundle has unresolved imports'},'timings':{'staticAnalysisMs':round((time.monotonic()-analysis_started)*1000),'dynamicAnalysisMs':0}}
    source_map=safe_source_names(reachable)
    all_sources={k:v['content'] for k,v in data.get('sources',{}).items() if isinstance(v,dict) and isinstance(v.get('content'),str)}
    settings=(data.get('stdJsonInput') or {}).get('settings') or (data.get('compilation') or {}).get('compilerSettings') or {}
    compiler_sources={}
    remappings=settings.get('remappings',[])
    for original_name,content in reachable.items():
        name=source_map[original_name]
        compiler_sources[name]={'content':rewrite_import_paths(original_name,content,source_map,all_sources,remappings,module)}
        path=(folder/name).resolve()
        if folder.resolve() not in path.parents:return {'state':'unavailable','reason':'unsafe normalized source unit path','sourceName':original_name,'localReproduction':False,'localTests':{'state':'not_performed','reason':'unsafe normalized source path'},'timings':{'staticAnalysisMs':round((time.monotonic()-analysis_started)*1000),'dynamicAnalysisMs':0}}
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(compiler_sources[name]['content'])
    source_input={'language':'Solidity','sources':compiler_sources,'settings':{}}
    for key in ('optimizer','viaIR','evmVersion','libraries','metadata','remappings'): 
        if key in settings and key!='remappings':source_input['settings'][key]=settings[key]
    # Imports are rewritten to the exact verified source units above; dropping
    # remappings prevents them being applied twice to already-resolved paths.
    source_input['settings']['remappings']=[]
    if isinstance(source_input['settings'].get('libraries'),dict):
        source_input['settings']['libraries']={source_map.get(name,name):values for name,values in source_input['settings']['libraries'].items()}
    original_targets=(data.get('metadata',{}).get('settings',{}).get('compilationTarget') or {})
    targets={source_map.get(name,name):contract for name,contract in original_targets.items()}
    # Slither/CryticCompile mutates its standard-json input in place. Keep the
    # dynamic harness on an immutable snapshot with the verified input settings.
    analysis_input_fingerprint=hashlib.sha256(json.dumps(source_input,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    static_source_input=copy.deepcopy(source_input)
    dynamic_source_input=copy.deepcopy(source_input)
    with _ANALYSIS_ENV_LOCK:dynamic_environment=os.environ.copy()
    # Preserve the documented mutation-test input location while the harness
    # itself uses an isolated directory that cannot race with Slither/CryticCompile.
    (folder/'local-test-input.json').write_text(json.dumps(source_input))
    dynamic_args=(bundle_path,dynamic_folder,dynamic_source_input,dict(targets),version,dependency_path,module,
                  {safe:original for original,safe in source_map.items()},dynamic_environment)
    can_run_dynamic=_target_has_dynamic_harness(targets,version,dependency_path)
    with _dynamic_analysis_overlap(dynamic_args,can_run_dynamic) as (dynamic_future,parallel_reason):
        # Complete source bundle: no remote imports, plugins or downloaded build scripts.
        compiler_info={'version':version,'source':'existing locally installed compiler'};slither=None;detectors=[];findings=[];call_graph=None;unified_ir=None;unified_ir_error=None
        static_error=None;call_graph_error=None;detector_error=None;compile_state='failed';static_started=time.monotonic()
        # Static compiler selection below may modify the parent environment. The
        # dynamic worker already owns the immutable pre-analysis snapshot above.
        _ANALYSIS_ENV_LOCK.acquire();static_parent_environment=os.environ.copy()
        try:
            from crytic_compile import CryticCompile
            from crytic_compile.platform.solc_standard_json import SolcStandardJson
            from slither.slither import Slither
            from slither.detectors import all_detectors
            from slither.detectors.abstract_detector import AbstractDetector
            from slither_compat import install_struct_resolution
            if version in ('0.8.19','0.8.23','0.8.28'):
                os.environ['SOLC_VERSION']=version;executable=TOOLS/'solc-wrapper.sh'
            else:
                soljson,compiler_info=compiler(version);os.environ['CAMPAIGN_SOLJSON']=str(soljson);os.environ.pop('SOLC_VERSION',None)
                executable=ROOT/'scripts/campaign-solc.cjs'
            bin_dir=folder/'bin';bin_dir.mkdir(exist_ok=True);link=bin_dir/'solc'
            if link.is_symlink():link.unlink()
            link.symlink_to(executable)
            os.environ['PATH']=str(bin_dir)+os.pathsep+os.environ['PATH']
            compilation=CryticCompile(SolcStandardJson(static_source_input),solc=str(link),solc_working_dir=str(folder))
            install_struct_resolution(compilation)
            slither=Slither(compilation)
            if not slither.contracts:raise ValueError('empty Slither compilation')
            compile_state='completed'
        except Exception as e:
            static_error=f'{type(e).__name__}: {str(e)[:1200]}'
        finally:
            try:os.environ.clear();os.environ.update(static_parent_environment)
            finally:_ANALYSIS_ENV_LOCK.release()
        if slither is not None:
            try:
                source_aliases={safe:original for original,safe in source_map.items()}
                source_aliases.update({str(folder/safe):original for original,safe in source_map.items()})
                try:
                    source_prefix=folder.relative_to(ROOT).as_posix()
                    source_aliases.update({f'{source_prefix}/{safe}':original for original,safe in source_map.items()})
                except ValueError:pass
                source_digests={original_name:hashlib.sha256(compiler_sources[safe_name]['content'].encode('utf-8')).hexdigest()
                                for original_name,safe_name in source_map.items()}
                call_graph=build_call_graph(slither.contracts,targets.values(),targets.keys(),source_aliases,source_digests)
                call_graph_path=bundle_path.parent/'call-graph.json'
                call_graph['analysisInputFingerprint']=analysis_input_fingerprint
                call_graph_path.write_text(json.dumps(call_graph,ensure_ascii=False,indent=2))
                try:
                    unified_ir=from_call_graph(call_graph)
                    unified_ir_path=bundle_path.parent/'unified-ir.json'
                    unified_ir_path.write_text(json.dumps(unified_ir,ensure_ascii=False,indent=2))
                except Exception as ir_error:
                    unified_ir_error=f'{type(ir_error).__name__}: {str(ir_error)[:700]}'
            except Exception as e:
                call_graph_error=f'{type(e).__name__}: {str(e)[:700]}'
            try:
                from slither.detectors import all_detectors
                from slither.detectors.abstract_detector import AbstractDetector
                detectors=[x for x in (getattr(all_detectors,k) for k in dir(all_detectors)) if inspect.isclass(x) and issubclass(x,AbstractDetector) and x is not AbstractDetector]
                for detector in detectors:slither.register_detector(detector)
                if not detectors:raise ValueError('no Slither detectors registered')
                findings=[x for group in slither.run_detectors() for x in group]
            except Exception as e:
                detector_error=f'{type(e).__name__}: {str(e)[:1200]}'
        static_error=static_error or detector_error or call_graph_error
        static_ended=time.monotonic();static_elapsed=round((static_ended-static_started)*1000)
        dynamic_join_started=time.monotonic()
        dynamic_started_at=dynamic_ended_at=None
        if dynamic_future is not None:
            try:local,dynamic_runner_ms,dynamic_started_at,dynamic_ended_at=dynamic_future.result()
            except Exception as e:
                local={'state':'unavailable','reason':'dynamic_analysis_error','error':f'{type(e).__name__}: {str(e)[:700]}'};dynamic_runner_ms=0;dynamic_started_at=dynamic_ended_at=None
        else:
            local,dynamic_runner_ms,dynamic_started_at,dynamic_ended_at=_timed_target_dynamic(*dynamic_args)
    dynamic_wait_ms=round((time.monotonic()-dynamic_join_started)*1000) if dynamic_future is not None else 0
    dynamic_finalize_started=time.monotonic()
    call_graph_partial=bool(call_graph and call_graph.get('state')=='partial')
    static_state='completed' if static_error is None and not call_graph_partial else 'partial' if slither is not None else 'failed'
    result={'state':static_state,'compiler':original,'compilerProvenance':compiler_info,'contracts':len(slither.contracts) if slither else 0,'detectors':len(detectors),'findingCount':len(findings),'findingSemanticFingerprint':semantic_finding_fingerprint(findings),'findingSummary':finding_summary(findings),'findings':findings,'confirmed':False,'localReproduction':False,'scope':'locally compiled verified source; static signals only','timings':{'staticAnalysisMs':static_elapsed,'dynamicAnalysisMs':0}}
    if static_error:result['staticError']=static_error
    result['staticStages']={'compile':compile_state,'callGraph':call_graph.get('state') if call_graph is not None else 'failed' if call_graph_error else 'not_run','detectors':'completed' if detector_error is None and slither is not None else 'failed' if detector_error else 'not_run'}
    if detector_error:result['detectorError']=detector_error
    if call_graph is not None:
        result['callGraph']={'state':call_graph['state'],'report':_report_reference(call_graph_path),'entrypointCount':call_graph['entrypointCount'],'edgeCount':call_graph['edgeCount'],'stateWritePathCount':call_graph['stateWritePathCount'],'externalCallPathCount':call_graph['externalCallPathCount'],'contractCreationPathCount':call_graph['contractCreationPathCount'],'assetRelatedCallPathCount':call_graph['assetRelatedCallPathCount'],'assetContextCallPathCount':call_graph['assetContextCallPathCount'],'totalPathCount':call_graph['totalPathCount'],'reportedPathCount':call_graph['reportedPathCount'],'truncatedPathCount':call_graph['truncatedPathCount'],'truncatedEntrypointCount':call_graph['truncatedEntrypointCount'],'truncatedEdgeCount':call_graph['truncatedEdgeCount'],'unresolvedAssemblyCallCount':call_graph['unresolvedAssemblyCallCount'],'recognizedYulControlOrDataCallCount':call_graph['recognizedYulControlOrDataCallCount'],'recognizedYulControlOrDataCallsByName':call_graph['recognizedYulControlOrDataCallsByName'],'maxDepth':call_graph['maxDepth'],'depthCutoffEdgeCount':call_graph['depthCutoffEdgeCount'],'cycleCutoffEdgeCount':call_graph['cycleCutoffEdgeCount'],'walkBudgetExceeded':call_graph['walkBudgetExceeded'],'pathSelectionPolicy':call_graph['pathSelectionPolicy'],'pathFeasibility':'not_proven'}
    else:result['callGraph']={'state':'unavailable','reason':'Slither IR call-graph build failed' if slither else 'Slither compilation failed'}
    if call_graph_error:result['callGraph']['error']=call_graph_error
    if unified_ir is not None:
        result['unifiedIR']={'state':unified_ir['state'],'documentId':unified_ir['documentId'],'report':_report_reference(unified_ir_path),'functionCount':len(unified_ir['functions']),'operationCount':len(unified_ir['operations']),'linkCount':len(unified_ir['links']),'roleCount':len(unified_ir.get('roles',[])),'permissionCount':len(unified_ir.get('permissions',[])),'fieldStates':{key:unified_ir['fieldStates'][key] for key in ('roles','permissions')},'source':'slither_ir','semanticsProven':False}
    else:
        result['unifiedIR']={'state':'unavailable','reason':unified_ir_error or 'call graph unavailable'}
    try:verified_source_fingerprint=module.source_identity(data)
    except Exception:verified_source_fingerprint=None
    if verified_source_fingerprint:
        result['verifiedSourceFingerprint']=verified_source_fingerprint
        result['analysisInputFingerprint']=analysis_input_fingerprint
        if local.get('state') not in ('not_performed',):local['verifiedSourceFingerprint']=verified_source_fingerprint
    if dependency_path and Path(dependency_path).is_file():
        try:
            dependency_data=json.loads(Path(dependency_path).read_text());dependency_fingerprint=module.source_identity(dependency_data)
            result['verifiedDependencyFingerprint']=dependency_fingerprint
            if local.get('state') not in ('not_performed',):local['verifiedDependencyFingerprint']=dependency_fingerprint
        except Exception as e:
            result['verifiedDependencyFingerprintError']=f'{type(e).__name__}: {str(e)[:300]}'
    source_aliases={safe:original for original,safe in source_map.items()}
    local_report=Path(local.get('report','')) if local.get('report') else None
    if local_report is not None and not local_report.is_absolute():local_report=ROOT/local_report
    if local_report and local_report.is_file():
        try:
            dynamic_report=json.loads(local_report.read_text())
            for trace in dynamic_report.get('traces',[]):
                for effect in trace.get('effects',[]):
                    loc=effect.get('sourceLocation') or {}
                    if loc.get('file') in source_aliases:loc['file']=source_aliases[loc['file']]
            coverage=dynamic_report.get('sourceCoverage') or {}
            for span in coverage.get('spans',[]):
                if span.get('file') in source_aliases:span['file']=source_aliases[span['file']]
            dynamic_report['staticCorrelation']=correlate_dynamic_effects(call_graph,dynamic_report)
            local['staticCorrelation']=dynamic_report['staticCorrelation']
            local['sourceCoverage']=coverage
            local['traces']=dynamic_report.get('traces',[])
            local['harnessHash']=dynamic_report.get('harnessHash') or dynamic_report.get('harnessSupportHash')
            atomic_report=json.dumps(dynamic_report,ensure_ascii=False,indent=2)
            local_report.write_text(atomic_report)
        except Exception as e:local['staticCorrelation']={'state':'unavailable','reason':f'{type(e).__name__}: {str(e)[:300]}'}
    if 'staticCorrelation' not in local:local['staticCorrelation']=correlate_dynamic_effects(call_graph,local)
    result['localTests']={k:v for k,v in local.items() if k not in ('sequences','traces','sourceCoverage','staticCorrelation')}
    if unified_ir is not None:
        result['localTests']['unifiedIR']={'documentId':unified_ir['documentId'],'state':unified_ir['state'],'semanticsProven':False}
    if local.get('sourceCoverage'):
        result['localTests']['sourceCoverage']=summarize_source_coverage(local['sourceCoverage'])
    result['localTests']['staticCorrelation']={k:v for k,v in local['staticCorrelation'].items() if k!='matches'}
    if local.get('state')!='not_performed':
        (bundle_path.parent/'local-tests.json').write_text(json.dumps(local,ensure_ascii=False,indent=2))
        try:result['localTests']['report']=str((bundle_path.parent/'local-tests.json').relative_to(ROOT))
        except ValueError:result['localTests']['report']=str(bundle_path.parent/'local-tests.json')
    dynamic_assembly_ms=round((time.monotonic()-dynamic_finalize_started)*1000)
    result['analysisExecution']={'staticDynamicStages':'parallel' if can_run_dynamic and dynamic_future is not None else 'serial','parallelReason':parallel_reason,'pythonHashSeed':os.environ.get('PYTHONHASHSEED','random')}
    if local.get('state')!='not_performed':
        result['timings']['dynamicAnalysisMs']=dynamic_runner_ms
        result['timings']['dynamicResultAssemblyMs']=dynamic_assembly_ms
        result['timings']['dynamicJoinMs']=dynamic_wait_ms
        result['timings']['stageOverlapMs']=round(max(0.0,min(static_ended,dynamic_ended_at)-max(static_started,dynamic_started_at))*1000) if dynamic_future is not None and dynamic_started_at is not None and dynamic_ended_at is not None else 0
    discovery_started=time.monotonic()
    if call_graph is not None:
        try:
            from discovery_plan import write_artifacts
            result['discoveryPlan']=write_artifacts(result,call_graph,local,bundle_path.parent)
            result['discoveryPlan'].update(report=_report_reference(bundle_path.parent/'discovery-plan.json'),html=_report_reference(bundle_path.parent/'discovery-plan.html'))
        except Exception as error:
            result['discoveryPlan']={'state':'unavailable','reason':f'{type(error).__name__}: {str(error)[:700]}'}
    else:result['discoveryPlan']={'state':'unavailable','reason':'static call graph unavailable'}
    result['timings']['discoveryPlanMs']=round((time.monotonic()-discovery_started)*1000)
    result['timings']['analysisWallMs']=round((time.monotonic()-analysis_started)*1000)
    return result


def _repr_cache_versions(version):
    try:
        from importlib.metadata import version as package_version
        slither_version=package_version('slither-analyzer')
    except Exception:
        slither_version='unavailable'
    return {'reviewStaticSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'slither':slither_version,'solc':version}


def analyze(bundle_path,dependency_path=None):
    bundle_path=Path(bundle_path).resolve()
    dependency_path=Path(dependency_path).resolve() if dependency_path else None
    try:
        data=json.loads(bundle_path.read_text(encoding='utf-8'))
        version=(data.get('compilation') or {}).get('compilerVersion','unknown').split('+')[0]
        source_digest=source_bundle_sha256(data)
        settings=((data.get('stdJsonInput') or {}).get('settings') or
                  (data.get('compilation') or {}).get('compilerSettings') or {})
        dependency_digest=None
        if dependency_path and dependency_path.is_file():
            dependency_digest=source_bundle_sha256(json.loads(dependency_path.read_text(encoding='utf-8')))
        if dependency_digest:
            source_digest=hashlib.sha256((source_digest+'\0'+dependency_digest).encode()).hexdigest()
        key=repr_cache_key(source_digest,version,settings)
    except (OSError,ValueError,TypeError,json.JSONDecodeError):
        return _analyze_uncached(bundle_path,dependency_path)

    fresh_result={}

    def build_cache_artifacts():
        result=_analyze_uncached(bundle_path,dependency_path)
        fresh_result['result']=result
        if (result.get('state') not in ('completed','partial') or
                (result.get('localTests') or {}).get('state')!='not_performed'):
            return {'source-ir.json':{'state':'not_available','reason':'static_result_not_cacheable'}}
        artifacts={'state':result['state'],'result':result}
        for filename in ('call-graph.json','unified-ir.json','discovery-plan.json','discovery-plan.html'):
            path=bundle_path.parent/filename
            if path.is_file():
                try:
                    artifacts[filename]=path.read_text(encoding='utf-8')
                except (OSError,UnicodeDecodeError):
                    pass
        return {'source-ir.json':artifacts}

    cached=repr_get_or_build(key,build_cache_artifacts,
        inputs={'sourceBundleSha256':source_digest,'solcVersion':version,
                'compileSettingsCanonicalJson':json.loads(json.dumps(settings,sort_keys=True,allow_nan=False))},
        tool_versions=_repr_cache_versions(version),required_artifacts=('source-ir.json',))
    if not cached['cacheHit']:
        result=fresh_result.get('result')
        if result is None:
            return _analyze_uncached(bundle_path,dependency_path)
    else:
        try:
            payload=json.loads(cached['artifacts']['source-ir.json'].decode('utf-8'))
        except (UnicodeDecodeError,json.JSONDecodeError):
            return _analyze_uncached(bundle_path,dependency_path)
        result=payload.get('result') if isinstance(payload,dict) else None
        if not isinstance(result,dict):
            return _analyze_uncached(bundle_path,dependency_path)
        bundle_path.parent.mkdir(parents=True,exist_ok=True)
        for filename in ('call-graph.json','unified-ir.json','discovery-plan.json','discovery-plan.html'):
            content=payload.get(filename)
            if isinstance(content,str):
                (bundle_path.parent/filename).write_text(content,encoding='utf-8')
        for row,key_name,filename in ((result.get('callGraph'),'report','call-graph.json'),
                                     (result.get('unifiedIR'),'report','unified-ir.json'),
                                     (result.get('discoveryPlan'),'report','discovery-plan.json'),
                                     (result.get('discoveryPlan'),'html','discovery-plan.html')):
            if isinstance(row,dict) and row.get(key_name):
                try:row[key_name]=str((bundle_path.parent/filename).relative_to(ROOT))
                except ValueError:row[key_name]=str(bundle_path.parent/filename)
        result.setdefault('timings',{})['staticAnalysisMs']=0
        result['timings']['discoveryPlanMs']=0
        result['timings']['analysisWallMs']=0
    result['reprCache']={'key':key,'cacheHit':cached['cacheHit'],
                         'meta':str((Path(__file__).resolve().parent.parent/'work'/'repr-cache'/key/'meta.json').relative_to(ROOT))}
    return result

if __name__=='__main__':
    try: result=analyze(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
    except Exception as e:result={'state':'failed','error':str(e)[:1800],'confirmed':False,'localReproduction':False}
    print(json.dumps(result,ensure_ascii=False))
