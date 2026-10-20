import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import collections
import gzip
import io
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'scripts'))
import rpc_pool
spec=importlib.util.spec_from_file_location('campaign',ROOT/'scripts/defi-campaign.py')
campaign=importlib.util.module_from_spec(spec);spec.loader.exec_module(campaign)

class CampaignTests(unittest.TestCase):
    def test_beacon_proxy_is_never_reported_complete_without_implementation_review(self):
        implementation='0x'+'1'*40
        beacon='0x'+'2'*40
        self.assertEqual(campaign.initial_proxy_review_completeness({
            'eip1967Implementation':None,'eip1967Beacon':beacon,'beaconImplementation':implementation,
        }),'proxy_only_pending_implementation')
        self.assertEqual(campaign.initial_proxy_review_completeness({
            'eip1967Implementation':None,'eip1967Beacon':beacon,'beaconImplementation':None,
        }),'proxy_only_implementation_unavailable')
        self.assertEqual(campaign.initial_proxy_review_completeness({'error':'RPC unavailable'}),
            'proxy_metadata_unavailable')
        self.assertEqual(campaign.initial_proxy_review_completeness({
            'eip1967Implementation':None,'eip1967Beacon':None,'beaconImplementation':None,
        }),'verified_source_reviewed')

    def test_reachable_sources_excludes_unrelated_tests_and_preserves_strings(self):
        data={'metadata':{'settings':{'compilationTarget':{'contracts/A.sol':'A'}}},'sources':{'contracts/A.sol':{'content':'// import "Wrong.sol";\nimport "./B.sol";\ncontract A { string constant URL="https://example.com"; }'},'contracts/B.sol':{'content':'contract B {}'},'test/Exploit.sol':{'content':'contract Fake {}'}}}
        sources,targets,missing=campaign.reachable_sources(data)
        self.assertEqual(list(sources),['contracts/A.sol','contracts/B.sol']);self.assertFalse(missing)
        self.assertIn('https://example.com',campaign.code_only(sources['contracts/A.sol']))
        first=campaign.source_identity(data);data['sources']['test/Exploit.sol']['content']='different unrelated fixture'
        self.assertEqual(campaign.source_identity(data),first)
        data['metadata']['settings']['compilationTarget']['contracts/A.sol']='OtherContract'
        self.assertNotEqual(campaign.source_identity(data),first)
        data['sources']['contracts/B.sol']['content']='contract B { uint x; }'
        self.assertNotEqual(campaign.source_identity(data),first)
    def test_reachable_sources_uses_longest_prefix_solidity_remapping(self):
        data={
            'metadata':{'settings':{'compilationTarget':{'src/Entry.sol':'Entry'}}},
            'stdJsonInput':{'settings':{'remappings':['pkg/=lib/default/','pkg/v2/=lib/v2/']}},
            'sources':{
                'src/Entry.sol':{'content':'import "pkg/v2/Token.sol"; contract Entry {}'},
                'pkg/v2/Token.sol':{'content':'contract WrongAlias {}'},
                'lib/v2/Token.sol':{'content':'import "./Base.sol"; contract Token {}'},
                'lib/v2/Base.sol':{'content':'contract Base {}'},
                'lib/default/Token.sol':{'content':'contract WrongDefault {}'},
                'other/Noise.sol':{'content':'contract Noise {}'},
            },
        }
        sources,_,missing=campaign.reachable_sources(data)
        self.assertEqual(list(sources),['src/Entry.sol','lib/v2/Token.sol','lib/v2/Base.sol'])
        self.assertFalse(missing)

    def test_reachable_sources_applies_importer_context_before_prefix(self):
        data={
            'metadata':{'settings':{'compilationTarget':{'src/Entry.sol':'Entry'}}},
            'stdJsonInput':{'settings':{'remappings':['src/:pkg/=lib/scoped/','pkg/=lib/general/']}},
            'sources':{
                'src/Entry.sol':{'content':'import "pkg/Token.sol"; contract Entry {}'},
                'lib/scoped/Token.sol':{'content':'contract ScopedToken {}'},
                'lib/general/Token.sol':{'content':'contract GeneralToken {}'},
            },
        }
        sources,_,missing=campaign.reachable_sources(data)
        self.assertEqual(list(sources),['src/Entry.sol','lib/scoped/Token.sol'])
        self.assertFalse(missing)
    def test_solidity_remapping_prefers_longest_context_and_last_equal_rule(self):
        sources={'src/scoped/Entry.sol':'','lib/context/Token.sol':'','lib/prefix/Token.sol':'','lib/last/Token.sol':''}
        resolved=campaign.resolve_source_import('src/scoped/Entry.sol','pkg/Token.sol',['src/:pkg/=lib/prefix/','src/scoped/:pkg/=lib/context/'],sources)
        self.assertEqual(resolved,'lib/context/Token.sol')
        resolved=campaign.resolve_source_import('src/scoped/Entry.sol','pkg/Token.sol',['pkg/=lib/prefix/','pkg/=lib/last/'],sources)
        self.assertEqual(resolved,'lib/last/Token.sol')
    def test_comments_and_unsubmitted_lines_are_not_evidence(self):
        sources={'A.sol':'/*\n transfer(amount);\n*/\nrequire(amount > 0); // transfer(amount);'}
        items=[{'evidence':[{'file':'A.sol','lineStart':2,'lineEnd':2,'quote':'transfer(amount);'}]}, {'evidence':[{'file':'A.sol','lineStart':4,'lineEnd':4,'quote':'transfer(amount);'}]}, {'evidence':[{'file':'A.sol','lineStart':5,'lineEnd':5,'quote':'balance -= amount;'}]}, {'kind':'security_control','evidence':[{'file':'A.sol','lineStart':4,'lineEnd':4,'quote':'require(amount > 0);'}]}]
        result=campaign.validate_review({'observations':items},sources)
        self.assertEqual(len(result['observations']),1);self.assertEqual(len(result['rejectedUnsupportedObservations']),3)
        self.assertEqual(result['observations'][0]['kind'],'security_control')
    def test_parallel_counters_are_exact(self):
        c=campaign.Campaign.__new__(campaign.Campaign);c.lock=threading.RLock();c.counts=collections.Counter()
        def add():
            for _ in range(1000):c.inc('calls')
        threads=[threading.Thread(target=add) for _ in range(8)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(c.counts['calls'],8000)

    def test_heimdall_can_be_skipped_without_creating_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'decompilation'
            with patch.object(campaign,'run_heimdall') as run:
                result=campaign._run_heimdall('0x6000',engine=None,output_dir=output,timeout_seconds=30)
            run.assert_not_called()
            self.assertEqual(result['state'],'not_performed')
            self.assertEqual(result['hardfork'],'latest')
            self.assertEqual(result['crossValidation']['state'],'not_performed')
            self.assertFalse(result['sourceVerified'])
            self.assertFalse(result['highLevelSemanticsRecovered'])
            self.assertFalse(output.exists())

    def test_heimdall_adapter_result_is_preserved_with_exact_arguments(self):
        expected={'state':'timeout','sourceVerified':False,'highLevelSemanticsRecovered':False}
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'decompilation'
            with patch.object(campaign,'run_heimdall',return_value=expected) as run:
                result=campaign._run_heimdall('0x6000',engine='heimdall',output_dir=output,
                    timeout_seconds=17,hardfork='cancun')
            self.assertIs(result,expected)
            run.assert_called_once_with('0x6000',binary=campaign.ROOT/'work/tools/heimdall/heimdall',
                output_dir=output,timeout_seconds=17,hardfork='cancun')

    def test_heimdall_adapter_exception_is_recorded_without_claiming_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'decompilation'
            with patch.object(campaign,'run_heimdall',side_effect=OSError('tool failed')):
                result=campaign._run_heimdall('0x6000',engine='heimdall',output_dir=output,timeout_seconds=30)
            self.assertEqual(result['state'],'failed')
            self.assertEqual(result['inputSha256'],hashlib.sha256(bytes.fromhex('6000')).hexdigest())
            self.assertFalse(result['sourceVerified'])
            self.assertFalse(result['highLevelSemanticsRecovered'])
            self.assertIn('tool failed',result['error'])

    def _runtime_analysis_fixture(self,folder):
        c=campaign.Campaign.__new__(campaign.Campaign)
        c.decompiler='heimdall';c.decompiler_timeout=17;c.decompiler_hardfork='cancun'
        c.lock=threading.RLock();c.counts=collections.Counter()
        folder.mkdir()
        record={}
        return c,record

    def test_heimdall_wrapper_failure_keeps_bytecode_analysis(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
            folder=Path(tmp)/'contract';c,record=self._runtime_analysis_fixture(folder)
            bytecode_ir={'state':'available','documentId':'doc','functions':[],'operations':[],'links':[]}
            with patch.object(campaign,'_run_heimdall',side_effect=RuntimeError('wrapper failed')), \
                 patch.object(campaign,'from_bytecode_report',return_value=bytecode_ir):
                c.runtime_bytecode_analysis('0x6000',{'chainId':100},'0x'+'1'*40,'0x123',
                    {'hash':'0x'+'a'*64},folder,record)
            summary=record['runtimeBytecodeAnalysis']
            report=json.loads((folder/'runtime-bytecode-analysis.json').read_text())
            self.assertEqual(summary['state'],'completed')
            self.assertEqual(summary['decompilationState'],'failed')
            self.assertIn('wrapper failed',summary['decompilation']['error'])
            self.assertEqual(report['decompilation']['state'],'failed')
            self.assertEqual(c.counts['runtimeBytecodeDecompilationsIncomplete'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisUnavailable'],0)

    def test_runtime_disassembly_uses_configured_decompiler_hardfork(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
            folder=Path(tmp)/'contract';c,record=self._runtime_analysis_fixture(folder)
            bytecode_ir={'state':'available','documentId':'doc','functions':[],'operations':[],'links':[]}
            with patch.object(campaign,'_run_heimdall',return_value={'state':'not_performed'}), \
                 patch.object(campaign,'from_bytecode_report',return_value=bytecode_ir):
                c.runtime_bytecode_analysis('0x5f',{'chainId':100},'0x'+'1'*40,'0x123',
                    {'hash':'0x'+'a'*64},folder,record)
            report=json.loads((folder/'runtime-bytecode-analysis.json').read_text())
            self.assertEqual(report['hardfork'],'cancun')
            self.assertEqual(report['instructions'][0]['opcodeActivation']['status'],'active')
            self.assertEqual(report['opcodePcCrossCheck']['state'],'consistent')
            self.assertEqual(record['runtimeBytecodeAnalysis']['opcodePcCrossCheckState'],'consistent')

    def test_ir_conversion_failure_keeps_disassembly_and_decompiler_evidence(self):
        decompilation={'state':'completed','confidence':'heuristic','sourceVerified':False,
            'highLevelSemanticsRecovered':False,'artifacts':[{'path':'pseudocode.txt','sha256':'abc'}]}
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
            folder=Path(tmp)/'contract';c,record=self._runtime_analysis_fixture(folder)
            with patch.object(campaign,'_run_heimdall',return_value=decompilation), \
                 patch.object(campaign,'from_bytecode_report',side_effect=ValueError('malformed IR input')):
                c.runtime_bytecode_analysis('0x6000',{'chainId':100},'0x'+'1'*40,'0x123',
                    {'hash':'0x'+'a'*64},folder,record)
            persisted=json.loads((folder/'runtime-bytecode-analysis.json').read_text())
            summary=record['runtimeBytecodeAnalysis']
            self.assertEqual(summary['state'],'partial')
            self.assertEqual(summary['failureStage'],'unified_ir_conversion')
            self.assertIn('malformed IR input',summary['error'])
            self.assertEqual(persisted['decompilation'],decompilation)
            self.assertEqual(c.counts['runtimeBytecodeAnalyses'],1)
            self.assertEqual(c.counts['runtimeBytecodeDecompilations'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisPartials'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisUnavailable'],0)

    def test_ir_persistence_failure_keeps_raw_report_and_marks_partial(self):
        decompilation={'state':'completed','confidence':'heuristic','sourceVerified':False,
            'highLevelSemanticsRecovered':False,'artifacts':[{'path':'pseudocode.txt','sha256':'def'}]}
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
            folder=Path(tmp)/'contract';c,record=self._runtime_analysis_fixture(folder)
            persist=campaign.atomic
            def fail_ir_persistence(path,data):
                if Path(path).name=='unified-ir-bytecode.json':raise OSError('IR disk full')
                return persist(path,data)
            with patch.object(campaign,'_run_heimdall',return_value=decompilation), \
                 patch.object(campaign,'atomic',side_effect=fail_ir_persistence):
                c.runtime_bytecode_analysis('0x6000',{'chainId':100},'0x'+'1'*40,'0x123',
                    {'hash':'0x'+'a'*64},folder,record)
            persisted=json.loads((folder/'runtime-bytecode-analysis.json').read_text())
            summary=record['runtimeBytecodeAnalysis']
            self.assertEqual(summary['state'],'partial')
            self.assertEqual(summary['failureStage'],'unified_ir_persistence')
            self.assertIn('IR disk full',summary['error'])
            self.assertEqual(persisted['decompilation'],decompilation)
            self.assertEqual(c.counts['runtimeBytecodeDecompilations'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisPartials'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisUnavailable'],0)

    def test_raw_report_persistence_failure_keeps_inline_disassembly_evidence(self):
        decompilation={'state':'completed','confidence':'heuristic','sourceVerified':False,
            'highLevelSemanticsRecovered':False,'artifacts':[{'path':'pseudocode.txt','sha256':'ghi'}]}
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
            folder=Path(tmp)/'contract';c,record=self._runtime_analysis_fixture(folder)
            persist=campaign.atomic
            def fail_raw_report(path,data):
                if Path(path).name=='runtime-bytecode-analysis.json':raise OSError('report directory read-only')
                return persist(path,data)
            with patch.object(campaign,'_run_heimdall',return_value=decompilation), \
                 patch.object(campaign,'atomic',side_effect=fail_raw_report):
                c.runtime_bytecode_analysis('0x6000',{'chainId':100},'0x'+'1'*40,'0x123',
                    {'hash':'0x'+'a'*64},folder,record)
            summary=record['runtimeBytecodeAnalysis']
            self.assertEqual(summary['state'],'partial')
            self.assertEqual(summary['failureStage'],'disassembly_report_persistence')
            self.assertIn('report directory read-only',summary['error'])
            self.assertEqual(summary['disassembly']['decompilation'],decompilation)
            self.assertEqual(summary['disassembly']['runtimeBytecode'],'0x6000')
            self.assertEqual(c.counts['runtimeBytecodeDecompilations'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisPartials'],1)
            self.assertEqual(c.counts['runtimeBytecodeAnalysisUnavailable'],0)

    def test_checkpoint_writes_explicit_lease_and_monotonic_heartbeat(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
            c=campaign.Campaign.__new__(campaign.Campaign)
            c.id='lease-test';c.start=100.0;c.wall=1700000000;c.duration=60;c.output=Path(tmp)/'campaign.json';c.run=Path(tmp)/'run';c.run.mkdir()
            c.lock=threading.RLock();c.counts=collections.Counter();c.metrics=collections.defaultdict(list);c.last_tick=100.0;c.max_gap=0;c.sample_count=0;c.state='running';c.source_hash='source';c.config={};c.snapshot_at=None;c.queue=[];c.active={};c.recent=[];c.failures=[];c.pool=None;c.validation_errors=[];c.heartbeat_seq=0;c.lease_ttl_sec=45;c.journal=(c.run/'events.jsonl').open('a')
            try:
                c.checkpoint();first=json.loads(c.output.read_text());lease=json.loads((c.run/'lease.json').read_text())
                c.checkpoint();second=json.loads(c.output.read_text())
            finally:
                c.journal.close()
            self.assertEqual(first['heartbeatAt'],first['updatedAt']);self.assertEqual(first['lease'],lease)
            self.assertEqual(first['heartbeatSeq'],1);self.assertEqual(second['heartbeatSeq'],2)
            self.assertEqual(first['lease']['runId'],'lease-test');self.assertEqual(first['lease']['pid'],campaign.os.getpid())
            heartbeat=datetime.fromisoformat(first['heartbeatAt'].replace('Z','+00:00'))
            expires=datetime.fromisoformat(first['lease']['expiresAt'].replace('Z','+00:00'))
            self.assertGreaterEqual((expires-heartbeat).total_seconds(),44)
    def test_compiler_timeout_returns_promptly(self):
        with self.assertRaises(subprocess.TimeoutExpired):campaign.run_bounded([sys.executable,'-c','import time;time.sleep(10)'],.05)
    def test_excerpt_budget_prefers_sensitive_functions_beyond_prefix_and_validates_lines(self):
        target='Main.sol'
        content='pragma solidity ^0.8.24;\n'+''.join(f'function f{i}() external {{ uint x={i}; }}\n' for i in range(1200))+'function withdraw() external { token.transfer(msg.sender, amount); }'
        sources={target:content,'Dep.sol':'interface I { function f(uint x) external; }'}
        excerpts,included,submitted=campaign.build_excerpts(sources,[target],max_chars=12000)
        row=next(x for x in excerpts if x['file']==target)
        self.assertIn('withdraw()',row['numberedSource'])
        line=len(content.splitlines())-1
        review={'observations':[{'kind':'risk_hypothesis','evidence':[{'file':target,'lineStart':line+1,'lineEnd':line+1,'quote':'token.transfer(msg.sender, amount);'}]}]}
        self.assertEqual(len(campaign.validate_review(review,sources,submitted)['observations']),1)
        omitted=next(i for i in range(len(content.splitlines())) if i not in submitted[target])
        review['observations'][0]['evidence'][0].update(lineStart=omitted+1,lineEnd=omitted+1,quote=content.splitlines()[omitted])
        self.assertFalse(campaign.validate_review(review,sources,submitted)['observations'])
    def test_retired_adapter_history_checks_commit_then_parent(self):
        sha='a'*40;parent='b'*40
        self.assertEqual(campaign.historical_revisions([{'sha':sha,'parents':[{'sha':parent}]}]),[sha,parent])
        self.assertEqual(campaign.historical_revisions([]),[])
    def test_per_chain_threshold_aliases_and_category_rotation(self):
        chains=[{'name':'Gnosis','llamaName':'Gnosis','chainId':100},{'name':'Rootstock','llamaName':'Rootstock','chainId':30}]
        protocols=[{'name':'A','slug':'a','category':'Lending','tvl':1e9,'chainTvls':{'xDai':9999,'RSK':10000}}, {'name':'B','slug':'b','category':'Dexs','chainTvls':{'xDai':10001}},{'name':'CEX','slug':'c','category':'CEX','chainTvls':{'xDai':1e9}}]
        q=campaign.build_queue(protocols,chains)
        self.assertEqual([(x['slug'],x['chainId']) for x in q],[('a',30),('b',100)])
    def test_model_claims_require_real_line_and_quote(self):
        review={'observations':[{'title':'valid','evidence':[{'file':'A.sol','lineStart':2,'lineEnd':2,'quote':'balance -= amount;'}]}, {'title':'invented','evidence':[{'file':'A.sol','lineStart':1,'lineEnd':1,'quote':'transfer(amount)'}]}]}
        r=campaign.validate_review(review,{'A.sol':'function withdraw() {\nbalance -= amount;\n}'})
        self.assertEqual(len(r['observations']),1);self.assertEqual(len(r['rejectedUnsupportedObservations']),1);self.assertFalse(r['observations'][0]['confirmed'])
    def test_adapter_extraction_binds_chain_and_never_executes_source(self):
        a='0x'+'1'*40;b='0x'+'2'*40;c='0x'+'3'*40
        source=f"throw Error('must not execute'); const local='{a}'; function tvl() {{ return local }}; const config={{xdai:{{tvl,token:'{c}'}},fantom:{{pool:'{b}'}}}}; // '{b}'"
        p=subprocess.run(['node',str(ROOT/'scripts/adapter-addresses.cjs')],input=json.dumps({'source':source,'chainKeys':['xdai']}),capture_output=True,text=True,timeout=4)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual([x['address'] for x in json.loads(p.stdout)['addresses']],[a])
    def test_private_and_credentialed_rpc_urls_rejected(self):
        for u in ['http://public.example','https://127.0.0.1','https://user:secret@rpc.example','https://rpc.example/?apikey=x','https://rpc.example/${KEY}']:
            self.assertFalse(rpc_pool.public_url(u),u)
    def test_wrong_chain_is_rejected_before_block_query(self):
        with patch.object(rpc_pool,'rpc',return_value='0x1') as call:
            result=rpc_pool.probe(100,'https://rpc.example')
        self.assertFalse(result['healthy']);self.assertIn('wrong chain',result['error']);self.assertEqual(call.call_count,1)
    def test_failover_respects_read_only_and_cooldown(self):
        pool=rpc_pool.RpcPool({'chains':[{'chainId':100,'endpoints':[{'url':'https://a.example','host':'a.example','healthy':True,'latencyMs':1},{'url':'https://b.example','host':'b.example','healthy':True,'latencyMs':2}]}]})
        with patch.object(rpc_pool,'rpc',side_effect=[TimeoutError('failed'), '0x123']) as call:
            value,url=pool.call(100,'eth_getCode',['0x'+'1'*40,'0x123'])
        self.assertEqual(url,'https://b.example');self.assertEqual(pool.failovers,1);self.assertEqual(call.call_args.args[2][-1],'0x123')
        with self.assertRaises(ValueError):pool.call(100,'eth_sendRawTransaction',['bad'])

    def test_rpc_raw_sink_receives_exact_body_and_parse_failures(self):
        class Response:
            def __init__(self, body): self.body=body
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return self.body
        seen=[]
        with patch.object(rpc_pool.urllib.request,'urlopen',return_value=Response(b'{"jsonrpc":"2.0","id":1,"result":"0x2a"}')):
            self.assertEqual(rpc_pool.rpc('https://rpc.example','eth_blockNumber',[],raw_sink=lambda *args: seen.append(args),chain_id=100),'0x2a')
        self.assertEqual(seen[0][3],b'{"jsonrpc":"2.0","id":1,"result":"0x2a"}')
        self.assertEqual(seen[0][4]['result'],'0x2a');self.assertEqual(seen[0][5],100);self.assertIsNone(seen[0][6])
        seen.clear()
        with patch.object(rpc_pool.urllib.request,'urlopen',return_value=Response(b'not-json')):
            with self.assertRaises(ValueError):rpc_pool.rpc('https://rpc.example','eth_blockNumber',[],raw_sink=lambda *args: seen.append(args),chain_id=100)
        self.assertEqual(seen[0][3],b'not-json');self.assertIsNone(seen[0][4]);self.assertIn('invalid JSON',seen[0][6])
        seen.clear()
        with patch.object(rpc_pool,'MAX_RPC_RESPONSE_BYTES',5), patch.object(rpc_pool.urllib.request,'urlopen',return_value=Response(b'123456')):
            with self.assertRaisesRegex(ValueError,'exceeds limit'):rpc_pool.rpc('https://rpc.example','eth_blockNumber',[],raw_sink=lambda *args: seen.append(args),chain_id=100)
        self.assertEqual(seen[0][3],b'12345');self.assertIsNone(seen[0][4]);self.assertIn('retained first',seen[0][6])
        seen.clear()
        http_error=rpc_pool.urllib.error.HTTPError('https://rpc.example',429,'limited',{},io.BytesIO(b'provider throttled'))
        with patch.object(rpc_pool.urllib.request,'urlopen',side_effect=http_error):
            with self.assertRaises(rpc_pool.urllib.error.HTTPError):rpc_pool.rpc('https://rpc.example','eth_blockNumber',[],raw_sink=lambda *args: seen.append(args),chain_id=100)
        self.assertEqual(seen[0][3],b'provider throttled');self.assertIn('429',seen[0][6])

    def test_campaign_archives_raw_rpc_bytes_with_bounded_references_and_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            c=campaign.Campaign.__new__(campaign.Campaign)
            c.id='archive-test';c.run=Path(temporary);c.lock=threading.RLock();c.counts=collections.Counter()
            c.rpc_archive_refs=[];c.rpc_archive_count=0;c.rpc_archive_failures=[];c.raw_archive_bytes=0
            c.event=lambda *args,**kwargs: None
            payload=b'{ "jsonrpc":"2.0", "id":1, "result":"0x2a" }'
            c.archive_rpc_response('https://rpc.example','eth_blockNumber',[],payload,{'result':'0x2a'},100)
            reference=c.rpc_archive_refs[0]
            self.assertEqual(gzip.decompress(Path(temporary,reference['payload_path']).read_bytes()),payload)
            self.assertEqual(c.rpc_archive_count,1);self.assertEqual(c.counts['rpcResponsesArchived'],1)
            self.assertEqual(c.raw_archive_bytes,len(payload))
            with patch.object(campaign,'MAX_RAW_ARCHIVE_BYTES',len(payload)):
                with self.assertRaisesRegex(OSError,'budget exceeded'):
                    c.archive_rpc_response('https://rpc.example','eth_blockNumber',[],b'overflow',None,100,'invalid JSON')
            self.assertEqual(c.raw_archive_bytes,len(payload));self.assertEqual(len(c.rpc_archive_failures),1)

    def test_campaign_rpc_archive_records_explicit_chain_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            c=campaign.Campaign.__new__(campaign.Campaign)
            c.id='provenance-test';c.run=Path(temporary);c.lock=threading.RLock();c.counts=collections.Counter()
            c.rpc_archive_refs=[];c.rpc_archive_count=0;c.rpc_archive_failures=[];c.raw_archive_bytes=0
            c.event=lambda *args,**kwargs: None
            address='0x'+'ab'*20
            code='0x6001600055'
            payload=json.dumps({'jsonrpc':'2.0','id':1,'result':code},separators=(',',':')).encode()
            c.archive_rpc_response('https://rpc.example','eth_getCode',[address,'0x2a'],payload,{'jsonrpc':'2.0','id':1,'result':code},100)
            reference=c.rpc_archive_refs[0]
            metadata=json.loads(Path(temporary,reference['metadata_path']).read_text())
            provenance=metadata['provenance']
            self.assertEqual(provenance['chain_id'],100)
            self.assertEqual(provenance['block_number'],42)
            self.assertEqual(provenance['contract_address'],address)
            self.assertEqual(provenance['code_hash'],hashlib.sha256(bytes.fromhex(code[2:])).hexdigest())
            self.assertIsNone(provenance['block_hash'])

            block={'number':'0x2a','hash':'0x'+'cd'*32}
            block_payload=json.dumps({'jsonrpc':'2.0','id':1,'result':block},separators=(',',':')).encode()
            c.archive_rpc_response('https://rpc.example','eth_getBlockByNumber',['0x2a',False],block_payload,{'result':block},100)
            block_ref=c.rpc_archive_refs[-1]
            block_meta=json.loads(Path(temporary,block_ref['metadata_path']).read_text())
            self.assertEqual(block_meta['provenance']['block_number'],42)
            self.assertEqual(block_meta['provenance']['block_hash'],block['hash'])

    def test_rpc_archive_provenance_does_not_infer_symbolic_or_malformed_identity(self):
        identity=campaign._rpc_archive_provenance(
            'eth_getCode',['not-an-address','latest'],{'result':'0x0'}
        )
        self.assertEqual(identity,{'blockNumber':None,'blockHash':None,'contractAddress':None,'codeHash':None})
        self.assertEqual(
            campaign._rpc_archive_provenance('eth_getBlockByNumber',['0x2a',False],{'result':None})['blockNumber'],
            42,
        )

if __name__=='__main__':unittest.main()
