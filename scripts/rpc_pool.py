#!/usr/bin/env python3
"""Public read-only RPC discovery, verification, bounded rotation and failover."""
import argparse
import collections
import concurrent.futures
import ipaddress
import json
import os
import socket
import statistics
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ['https://chainlist.org/rpcs.json', 'https://chainid.network/chains.json']
READ_METHODS = {
    'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getCode',
    'eth_getStorageAt', 'eth_call', 'eth_getBalance', 'eth_getBlockReceipts',
    'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getLogs',
    'eth_getProof', 'debug_traceTransaction', 'trace_transaction',
}
MAX_RPC_RESPONSE_BYTES = 24_000_000
CAPABILITY_PROBE_SCHEMA_VERSION = 1


def _probe_failure(error):
    """Classify a capability failure without exposing provider response text."""
    if isinstance(error, urllib.error.HTTPError):
        if error.code in (403, 429):
            return 'rate_limited'
        return 'unavailable'
    message = str(error)
    if 'RPC error -32601' in message or 'RPC error -32602' in message:
        return 'unsupported'
    return 'unavailable'


def is_transient(error):
    """Report whether a failure is a passing condition rather than a verdict.

    A snapshot is a point-in-time observation.  A provider that throttled one
    request, timed out, or answered with a gateway error at that moment is
    not disqualified; a provider that served the wrong chain, an old block,
    or a block the peers disagree with is.  Conflating the two let a transient
    429 remove a node from the pool for as long as the snapshot lived, and
    the pool then reported the chain as unavailable even though the node
    answered every request minutes later.
    """
    if isinstance(error, urllib.error.HTTPError):
        # 4xx other than throttling means the endpoint does not serve this
        # request; 5xx and 408/429 are conditions that may clear on their own.
        return error.code in (408, 425, 429) or error.code >= 500
    if isinstance(error, (TimeoutError, socket.timeout, ConnectionError, OSError)):
        return True
    if isinstance(error, urllib.error.URLError):
        return True
    message = str(error)
    if 'timed out' in message or 'timeout' in message.lower() or 'EOF occurred' in message:
        return True
    return False


def endpoint_failure_kind(item):
    """Classify a recorded endpoint failure as a passing condition or a verdict.

    Snapshots written before this distinction existed carry only an error
    string, so the older format is read back with the same rules applied to
    the text.  A legacy snapshot must not be trusted to mean something
    different from a current one.
    """
    kind = item.get('failureKind')
    if kind in ('transient', 'verdict', 'capability', 'none'):
        return kind
    if item.get('healthy'):
        return 'none'
    error = str(item.get('error') or '')
    if not error:
        return 'verdict'
    # A node that answered the live view but refused a block-height read is
    # limited, not broken: it still serves the chain's current state.
    if 'common block probe failed' in error and any(
            code in error for code in ('HTTP Error 400', 'HTTP Error 404', 'HTTP Error 501')):
        return 'capability'
    transient_markers = (
        'HTTP Error 429', 'HTTP Error 408', 'HTTP Error 425', 'HTTP Error 500',
        'HTTP Error 502', 'HTTP Error 503', 'HTTP Error 504',
        'provider cooldown after HTTP 403/429', 'URLError', 'timed out',
        'timeout', 'EOF occurred', 'SSLV3_ALERT', 'CERTIFICATE_VERIFY_FAILED',
    )
    if any(marker in error for marker in transient_markers):
        return 'transient'
    return 'verdict'


HISTORICAL_METHODS = {
    'eth_getBlockByNumber', 'eth_getStorageAt', 'eth_getCode', 'eth_call',
    'eth_getBalance', 'eth_getBlockReceipts', 'eth_getLogs',
}
BLOCK_TAGS = ('latest', 'pending', 'earliest')


def needs_historical(method, params):
    """Report whether a read asks for a block height rather than a live view."""
    if method not in HISTORICAL_METHODS:
        return False
    for value in params or []:
        if isinstance(value, str) and value.startswith('0x') and value not in BLOCK_TAGS:
            return True
        if isinstance(value, dict):
            for key in ('blockNumber', 'fromBlock', 'toBlock', 'blockHash'):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate not in BLOCK_TAGS:
                    return True
    return False


def _capability_probe(url, chain_id, name, method, params, timeout, raw_sink=None,
                      validator=None):
    item = {'state': 'not_tested', 'method': method}
    try:
        result = _rpc_observed(url, method, params, timeout, raw_sink, chain_id)
        if validator is not None:
            validator(result)
        item['state'] = 'available'
    except Exception as error:
        item['state'] = _probe_failure(error)
        item['error'] = f'{type(error).__name__}: {str(error)[:150]}'
    return item


def _batch_probe(url, chain_id, height, timeout, raw_sink=None):
    """Probe JSON-RPC batching with read-only requests and strict response IDs."""
    requests = [
        {'jsonrpc': '2.0', 'id': 101, 'method': 'eth_chainId', 'params': []},
        {'jsonrpc': '2.0', 'id': 102, 'method': 'eth_blockNumber', 'params': []},
    ]
    request = urllib.request.Request(
        url, data=json.dumps(requests).encode(),
        headers={'User-Agent': 'BlockchainSecurityResearch/1.0', 'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RPC_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RPC_RESPONSE_BYTES:
            raise ValueError('response exceeds limit')
        data = json.loads(raw)
        if raw_sink is not None:
            raw_sink(url, 'rpc.batch', requests, raw, data, chain_id, None)
        if not isinstance(data, list):
            raise ValueError('batch response is not an array')
        by_id = {item.get('id'): item for item in data if isinstance(item, dict)}
        if set(by_id) != {101, 102}:
            raise ValueError('batch response IDs do not match requests')
        if any('error' in by_id[item_id] for item_id in (101, 102)):
            raise ValueError('batch response contains RPC error')
        return {'state': 'available', 'method': 'json-rpc-batch', 'requestCount': len(requests)}
    except Exception as error:
        if raw_sink is not None and isinstance(error, urllib.error.HTTPError):
            raw = error.read(MAX_RPC_RESPONSE_BYTES + 1)
            raw_sink(url, 'rpc.batch', requests, raw[:MAX_RPC_RESPONSE_BYTES], None, chain_id,
                     f'HTTP status {error.code}')
        return {'state': _probe_failure(error), 'method': 'json-rpc-batch',
                'error': f'{type(error).__name__}: {str(error)[:150]}'}


def probe_capabilities(chain_id, url, height, timeout=6, raw_sink=None, tx_hash=None):
    """Probe optional read-only RPC capabilities at a bounded historical point.

    A successful latest-block probe never implies archive, trace, proof or log
    support.  Each result is independent and carries an explicit state.  A
    missing transaction is reported as ``not_tested`` for trace methods rather
    than being misclassified as unsupported.
    """
    historical_height = max(0, int(height) - 1024)
    historical_tag = hex(historical_height)
    latest_tag = hex(int(height))
    capabilities = {
        'schemaVersion': CAPABILITY_PROBE_SCHEMA_VERSION,
        'observedAt': now(),
        'historicalBlock': historical_height,
        'latestBlock': int(height),
        'archive': _capability_probe(
            url, chain_id, 'archive', 'eth_getBlockByNumber', [historical_tag, False], timeout,
            raw_sink, validator=lambda value: (_ for _ in ()).throw(ValueError('invalid historical block'))
            if not isinstance(value, dict) or value.get('number') is None else None,
        ),
        'historicalCode': _capability_probe(
            url, chain_id, 'historicalCode', 'eth_getCode', ['0x' + '00' * 20, historical_tag], timeout,
            raw_sink, validator=lambda value: None if isinstance(value, str) and value.startswith('0x')
            else (_ for _ in ()).throw(ValueError('invalid historical code')),
        ),
        'logs': _capability_probe(
            url, chain_id, 'logs', 'eth_getLogs', [{'fromBlock': latest_tag, 'toBlock': latest_tag}], timeout,
            raw_sink, validator=lambda value: None if isinstance(value, list)
            else (_ for _ in ()).throw(ValueError('logs result is not an array')),
        ),
        'proof': _capability_probe(
            url, chain_id, 'proof', 'eth_getProof', ['0x' + '00' * 20, [], historical_tag], timeout,
            raw_sink, validator=lambda value: None if isinstance(value, dict)
            else (_ for _ in ()).throw(ValueError('proof result is not an object')),
        ),
        'batch': _batch_probe(url, chain_id, int(height), timeout, raw_sink),
        'rateLimit': {
            'state': 'observed_only',
            'description': '仅记录探测请求返回的 403/429；未主动压测 provider',
            'maxRequestsMeasured': None,
        },
    }
    if not tx_hash:
        for method in ('debug_traceTransaction', 'trace_transaction'):
            capabilities[method] = {'state': 'not_tested', 'reason': 'latest block did not expose a transaction hash', 'method': method}
    else:
        capabilities['debug_traceTransaction'] = _capability_probe(
            url, chain_id, 'debugTrace', 'debug_traceTransaction', [tx_hash, {}], timeout, raw_sink,
            validator=lambda value: None if isinstance(value, dict) else (_ for _ in ()).throw(ValueError('trace result is not an object')),
        )
        capabilities['trace_transaction'] = _capability_probe(
            url, chain_id, 'trace', 'trace_transaction', [tx_hash], timeout, raw_sink,
            validator=lambda value: None if isinstance(value, list) else (_ for _ in ()).throw(ValueError('trace result is not an array')),
        )
    return capabilities

def now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def atomic(path, data):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f'.{os.getpid()}.{threading.get_ident()}.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)

def public_url(url):
    try:
        p = urllib.parse.urlsplit(url)
        if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment: return False
        if any(x in url.lower() for x in ['${', '{', 'api_key', 'apikey', '<', 'localhost', '.local', '.internal']): return False
        try:
            if not ipaddress.ip_address(p.hostname).is_global: return False
        except ValueError: pass
        return True
    except ValueError: return False

def json_http(url, payload=None, timeout=8, limit=24_000_000):
    req = urllib.request.Request(url, data=None if payload is None else json.dumps(payload).encode(), headers={'User-Agent':'BlockchainSecurityResearch/1.0', 'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
        if len(data) > limit: raise ValueError('response exceeds limit')
        return json.loads(data)

def rpc(url, method, params, timeout=6, raw_sink=None, chain_id=None):
    if method not in READ_METHODS: raise ValueError('read-only RPC method required')
    request = {'jsonrpc':'2.0', 'id':1, 'method':method, 'params':params}
    req = urllib.request.Request(url, data=json.dumps(request).encode(), headers={'User-Agent':'BlockchainSecurityResearch/1.0', 'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(MAX_RPC_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_RPC_RESPONSE_BYTES + 1)
        if raw_sink is not None:
            status_error = f'HTTP status {error.code}'
            if len(raw) > MAX_RPC_RESPONSE_BYTES:
                status_error += '; body prefix only, response exceeds limit'
            raw_sink(url, method, params, raw[:MAX_RPC_RESPONSE_BYTES], None, chain_id, status_error)
        raise
    if len(raw) > MAX_RPC_RESPONSE_BYTES:
        if raw_sink is not None:
            raw_sink(url, method, params, raw[:MAX_RPC_RESPONSE_BYTES], None, chain_id,
                     f'response exceeds limit; retained first {MAX_RPC_RESPONSE_BYTES} bytes only')
        raise ValueError('response exceeds limit')
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if raw_sink is not None:
            raw_sink(url, method, params, raw, None, chain_id, f'{type(error).__name__}: invalid JSON-RPC body')
        raise ValueError('invalid JSON-RPC response body') from error
    if raw_sink is not None:
        raw_sink(url, method, params, raw, data, chain_id, None)
    if not isinstance(data, dict) or data.get('id') != 1 or data.get('jsonrpc') != '2.0': raise ValueError('invalid JSON-RPC envelope')
    if 'error' in data: raise ValueError('RPC error ' + str(data['error'].get('code')))
    if 'result' not in data: raise ValueError('missing RPC result')
    return data['result']

def _rpc_observed(url, method, params, timeout, raw_sink, chain_id):
    if raw_sink is None:
        return rpc(url, method, params, timeout)
    return rpc(url, method, params, timeout, raw_sink=raw_sink, chain_id=chain_id)

def probe(chain_id, url, timeout=6, raw_sink=None):
    item = {'url':url, 'host':urllib.parse.urlsplit(url).hostname, 'chainId':chain_id, 'observedAt':now(), 'healthy':False}
    started = time.monotonic()
    try:
        if not public_url(url): raise ValueError('not an uncredentialed public HTTPS endpoint')
        # The user's local network uses synthetic 198.18/15 DNS addresses.
        # Validate curated HTTPS hostnames, TLS and chain data instead of
        # rejecting the local resolver's transport mapping as a private RPC.
        actual = int(_rpc_observed(url, 'eth_chainId', [], timeout, raw_sink, chain_id), 16)
        if actual != chain_id: raise ValueError(f'wrong chain ID: {actual}')
        block = _rpc_observed(url, 'eth_getBlockByNumber', ['latest', False], timeout, raw_sink, chain_id)
        height, stamp = int(block['number'], 16), int(block['timestamp'], 16)
        if height <= 0 or not isinstance(block.get('hash'), str) or len(block['hash']) != 66: raise ValueError('invalid block')
        age = time.time() - stamp
        if age < -60 or age > 600: raise ValueError(f'stale/future block: age={round(age)}s')
        tx_hash = None
        try:
            full = _rpc_observed(url, 'eth_getBlockByNumber', ['latest', True], timeout, raw_sink, chain_id)
            transactions = full.get('transactions') if isinstance(full, dict) else None
            if isinstance(transactions, list):
                for transaction in transactions:
                    candidate = transaction.get('hash') if isinstance(transaction, dict) else None
                    if isinstance(candidate, str) and len(candidate) == 66:
                        tx_hash = candidate
                        break
        except Exception as error:
            item['capabilityWarning'] = f'full transaction block unavailable: {type(error).__name__}'
        item.update(healthy=True, height=height, blockHash=block['hash'], blockTime=stamp,
                    blockAgeSec=round(age), latencyMs=round((time.monotonic()-started)*1000), error=None)
        item['capabilities'] = probe_capabilities(chain_id, url, height, timeout, raw_sink, tx_hash)
    except Exception as e:
        item['error'] = f'{type(e).__name__}: {str(e)[:150]}'
        # A transient failure is not a verdict about the endpoint.  Recording
        # that separately keeps a throttled or timed-out node out of the
        # healthy set without treating it as permanently disqualified.
        item['failureKind'] = 'transient' if is_transient(e) else 'verdict'
    item['failureKind'] = item.get('failureKind', 'none')
    return item

def discover(chains, max_per_chain=8, timeout=6):
    catalogs, errors = [], []
    for url in SOURCES:
        try:
            data = json_http(url, timeout=15)
            if not isinstance(data,list): raise ValueError('catalog is not an array')
            catalogs.append((url, {x['chainId']:x for x in data if isinstance(x,dict) and isinstance(x.get('chainId'),int)}))
        except Exception as e: errors.append({'source':url,'error':str(e)[:180]})
    if not catalogs: raise RuntimeError('RPC catalogs unavailable; no stale pool substituted')
    seeds=json.loads((ROOT/'config/rpc-seeds.json').read_text())['entries'] if (ROOT/'config/rpc-seeds.json').exists() else []
    jobs = []
    for chain in chains:
        urls = [(chain.get('rpc'), 'project configuration')] if chain.get('rpc') else []
        for item in seeds:
            if item['chainId']==chain['chainId']:urls.extend((u,item['source']) for u in item['urls'])
        for source, catalog in catalogs:
            for x in catalog.get(chain['chainId'],{}).get('rpc',[]):
                urls.append((x.get('url') if isinstance(x,dict) else x, source))
        seen, hosts = set(), set(); unique, repeats = [], []
        for url, source in urls:
            if not isinstance(url,str) or not public_url(url) or url in seen: continue
            seen.add(url); host=urllib.parse.urlsplit(url).hostname
            target = repeats if host in hosts else unique; hosts.add(host)
            target.append((chain, url, source))
        jobs.extend((unique+repeats)[:max_per_chain])
    rows = {c['chainId']:{'chainId':c['chainId'],'name':c['name'],'endpoints':[]} for c in chains}
    blocked_hosts=set();gate=threading.Lock()
    def bounded_probe(chain_id,url):
        host=urllib.parse.urlsplit(url).hostname
        with gate:
            if host in blocked_hosts:
                # The host answered the previous probe with a throttle.  Do not
                # spend more requests on it during this sweep, but record the
                # reason as a passing condition so the pool may retry it later
                # instead of treating the host as disqualified for good.
                return {'url':url,'host':host,'chainId':chain_id,'observedAt':now(),
                        'healthy':False,'failureKind':'transient',
                        'error':'provider cooldown after HTTP 403/429'}
        result=probe(chain_id,url,timeout)
        if any(x in str(result.get('error')) for x in ['HTTP Error 403','HTTP Error 429']):
            with gate:blocked_hosts.add(host)
        return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(bounded_probe,c['chainId'],url):(c,source) for c,url,source in jobs}
        for f in concurrent.futures.as_completed(futures):
            c, source = futures[f]; item=f.result(); item['source']=source
            rows[c['chainId']]['endpoints'].append(item)
    # Agree at a common block: checking chainId alone cannot detect stale forks.
    for row in rows.values():
        live=[e for e in row['endpoints'] if e['healthy']]
        if live:
            median=statistics.median(e['height'] for e in live)
            for e in live:
                if abs(e['height']-median)>120: e.update(healthy=False,error='height deviates from peer median by >120 blocks',failureKind='verdict')
            live=[e for e in live if e['healthy']]
        if len(live)>1:
            height=min(e['height'] for e in live)-2
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                jobs={pool.submit(rpc,e['url'],'eth_getBlockByNumber',[hex(height),False],timeout):e for e in live}
                for f in concurrent.futures.as_completed(jobs):
                    e=jobs[f]
                    try:
                        b=f.result()
                        if int(b['number'],16)!=height: raise ValueError('common block number mismatch')
                        e['commonBlockHash']=b['hash'];e['commonBlockNumber']=height
                    except Exception as ex:
                        # A node that cannot serve one historical block is not
                        # disqualified for the live view: most public providers
                        # serve only the head and reject archive reads.  The
                        # limit is recorded so height-specific reads skip it,
                        # and the node keeps answering live requests.
                        if is_transient(ex):
                            e.update(error='common block probe failed: '+str(ex)[:100],failureKind='transient')
                        else:
                            e.update(error='common block probe failed: '+str(ex)[:100],failureKind='capability')
                        e['historicalUnavailable']=True
            witnesses=[e for e in live if e.get('commonBlockHash')]
            if witnesses:
                hashes=[e['commonBlockHash'] for e in witnesses]
                consensus=max(set(hashes),key=hashes.count)
                votes=hashes.count(consensus)
                for e in witnesses:
                    # A node that disagrees with the majority is on a
                    # different fork.  That is a verdict, not a passing
                    # condition.
                    if e['commonBlockHash']!=consensus:
                        e.update(healthy=False,error='no majority agreement at common block',failureKind='verdict')
                row['witnessCount']=len(witnesses); row['consensusVotes']=votes
            else:
                row['witnessCount']=0; row['consensusVotes']=0
        else:
            row['witnessCount']=len([e for e in live if e.get('commonBlockHash')]); row['consensusVotes']=row['witnessCount']
        row['healthyCount']=sum(e['healthy'] for e in row['endpoints'])
        row['redundant']=row['healthyCount']>=2
        # "Multiple endpoint block agreement" is a claim about independent
        # witnesses, so it needs at least two votes.  A chain with one
        # archive-capable node is served, but it is served by a single
        # endpoint and must not be described as agreed by several.
        row['assurance']=('multiple endpoint block agreement'
                          if (row['redundant'] and row.get('consensusVotes',0)>=2)
                          else 'single endpoint only' if row['healthyCount'] else 'unavailable')
        row['endpoints'].sort(key=lambda e:(not e['healthy'],e.get('latencyMs',1e9)))
    return {'schemaVersion':1,'generatedAt':now(),'sources':[u for u,_ in catalogs],'sourceErrors':errors,'chains':list(rows.values()),'policy':{'publicHttpsOnly':True,'maxPerChain':max_per_chain,'probeConcurrency':8,'maxBlockAgeSec':600,'maxHeightDeviation':120,'readOnly':True,'caveat':'不同主机名不保证不同运营商；节点验证不证明合约安全。'}}

class RpcPool:
    def __init__(self, report, raw_sink=None):
        self.rows={c['chainId']:c for c in report['chains']}; self.lock=threading.Lock(); self.stats={}; self.failovers=0;self.host_cooldown={};self.host_next={};self.raw_sink=raw_sink
        self.recovered=collections.Counter(); self.revalidation_failures=collections.Counter()
        self._revalidating={}
        # Endpoints the snapshot rejected for a passing condition (throttle,
        # timeout, gateway error) are not disqualified: they are candidates
        # for revalidation.  Endpoints rejected on a verdict (wrong chain,
        # stale block, peer disagreement) stay out.
        self.candidates={}
        for chain_id,row in self.rows.items():
            for endpoint in row.get('endpoints',[]):
                if endpoint.get('healthy'): continue
                if endpoint_failure_kind(endpoint)=='transient':
                    self.candidates.setdefault(chain_id,[]).append(endpoint)
            # Recompute the chain's counts from the endpoints rather than
            # trusting the snapshot's summary.  The summary is a number the
            # pool then reports as the chain's availability, so a stale or
            # hand-edited count would be a value that looks authoritative
            # and describes nothing.
            row['healthyCount']=sum(1 for e in row.get('endpoints',[]) if e.get('healthy'))
            row['redundant']=row['healthyCount']>=2
            row['assurance']=self._assurance(row)
    def snapshot(self):
        with self.lock:
            return {'failovers':self.failovers,'nodes':{url:{**s,'coolingDown':s.get('cooldownUntil',0)>time.monotonic()} for url,s in self.stats.items()},
                    'recovered':{str(k):v for k,v in self.recovered.items()},
                    'revalidationFailures':{str(k):v for k,v in self.revalidation_failures.items()}}
    def _assurance(self,row):
        """Describe what the chain's endpoints actually prove.

        "Multiple endpoint block agreement" is a claim about independent
        witnesses agreeing on a block, so it needs at least two votes.  A
        chain served by a single endpoint is served, but it is not agreed by
        several, and saying otherwise would overstate the evidence.

        A snapshot written before the vote count existed does not carry it.
        For that case the witness hashes themselves are counted, because
        they are the votes; a chain with two endpoints that both recorded a
        common block hash did agree, and dropping that to "single endpoint
        only" would understate evidence that was actually collected.
        """
        healthy=sum(1 for e in row.get('endpoints',[]) if e.get('healthy'))
        votes=row.get('consensusVotes')
        if votes is None:
            witnesses=[e.get('commonBlockHash') for e in row.get('endpoints',[]) if e.get('commonBlockHash')]
            votes=len([h for h in witnesses if h==max(set(witnesses),key=witnesses.count)]) if witnesses else 0
        if not healthy: return 'unavailable'
        if healthy>=2 and votes>=2: return 'multiple endpoint block agreement'
        return 'single endpoint only'
    def _revive(self,chain_id,endpoint):
        """Put a revalidated endpoint back into the chain's healthy set."""
        row=self.rows.get(chain_id)
        if row is None: return
        for candidate in row.get('endpoints',[]):
            if candidate.get('url')==endpoint.get('url'):
                candidate.update(endpoint); candidate['healthy']=True; candidate['error']=None
                candidate['failureKind']='none'; candidate['recoveredAt']=now()
                break
        else:
            row.setdefault('endpoints',[]).append(dict(endpoint,healthy=True,error=None,failureKind='none',recoveredAt=now()))
        row['healthyCount']=sum(1 for e in row.get('endpoints',[]) if e.get('healthy'))
        row['redundant']=row['healthyCount']>=2
        row['assurance']=self._assurance(row)
    def _drop(self,chain_id,endpoint):
        """Retire an endpoint that failed revalidation on a verdict."""
        row=self.rows.get(chain_id)
        if row is None: return
        kept=[]
        for candidate in row.get('endpoints',[]):
            if candidate.get('url')==endpoint.get('url'):
                candidate.update(healthy=False,error=endpoint.get('error'),failureKind=endpoint.get('failureKind','verdict'))
                candidate['revokedAt']=now()
            kept.append(candidate)
        row['endpoints']=kept
        row['healthyCount']=sum(1 for e in row.get('endpoints',[]) if e.get('healthy'))
        row['redundant']=row['healthyCount']>=2
        row['assurance']=self._assurance(row)
    def revalidate(self,chain_id,timeout=6):
        """Re-probe endpoints the snapshot rejected for a passing condition.

        A snapshot records one moment.  A provider throttled at that moment
        is usable again minutes later, and a pool that never looks again
        reports the chain as unavailable while healthy nodes sit idle in the
        file.  This brings those candidates back after checking them.
        """
        # Several campaign workers can reach the same chain at once.  One
        # worker probes it; the others wait for that result instead of
        # sending the same requests to the same providers again.
        with self.lock:
            entry=self._revalidating.get(chain_id)
            if entry is None:
                entry=threading.Event()
                self._revalidating[chain_id]=entry
                owner=True
            else:
                owner=False
        if not owner:
            entry.wait(timeout=timeout+30)
            return []
        try:
            return self._revalidate(chain_id,timeout)
        finally:
            with self.lock:
                self._revalidating.pop(chain_id,None)
            entry.set()
    def _revalidate(self,chain_id,timeout):
        pending=list(self.candidates.get(chain_id,[]))
        if not pending: return []
        revived=[]
        for endpoint in pending:
            url=endpoint.get('url')
            if not url: continue
            health=probe(chain_id,url,timeout,raw_sink=self.raw_sink)
            if health.get('healthy'):
                with self.lock:
                    self._revive(chain_id,health); self.recovered[chain_id]+=1
                    # The node answered; it is no longer a candidate, so it is
                    # not probed again on the next refresh.
                    self.candidates[chain_id]=[e for e in self.candidates.get(chain_id,[]) if e.get('url')!=url]
                    self.stats.setdefault(url,{'calls':0,'errors':0,'nextAt':0,'cooldownUntil':0})['lastValidatedAt']=time.time()
                revived.append(url)
            else:
                # A verdict here means the endpoint really does not serve this
                # chain; keep it out of the candidate set so it is not probed
                # on every refresh.  A repeated passing condition keeps it in
                # the set, because the condition may still clear.
                kind=endpoint_failure_kind(health)
                if kind!='transient':
                    with self.lock:
                        self.revalidation_failures[chain_id]+=1
                        self.candidates[chain_id]=[e for e in self.candidates.get(chain_id,[]) if e.get('url')!=url]
                        self._drop(chain_id,health)
        return revived
    def call(self, chain_id, method, params, timeout=7):
        if method not in READ_METHODS: raise ValueError('read-only RPC method required')
        nodes=[e for e in self.rows.get(chain_id,{}).get('endpoints',[]) if e['healthy']]
        errors=[]; tried=set()
        if not nodes and self.candidates.get(chain_id):
            # The chain looks dead because the snapshot rejected its nodes for
            # a passing condition.  Re-check them before reporting the chain
            # as unusable: the throttling that excluded them has usually
            # cleared by now, and reporting "no verified RPC" here is what
            # silently drops whole chains from the corpus.
            try:
                self.revalidate(chain_id,timeout=min(timeout,8))
            except Exception as error:
                errors.append(f'revalidation: {type(error).__name__}')
            nodes=[e for e in self.rows.get(chain_id,{}).get('endpoints',[]) if e['healthy']]
        historical=needs_historical(method,params)
        if historical:
            # A node that has already shown it cannot serve a block-height
            # read is skipped for height-specific reads instead of consuming
            # the attempt budget on a request it cannot answer.
            nodes=[e for e in nodes if not e.get('historicalUnavailable')]
        # The budget counts endpoints, not attempts: a provider that answers a
        # query it does not serve with a null result should not consume the
        # whole allowance for a read the next endpoint can answer.  The bound
        # stays small so a broken chain fails fast rather than trying every
        # endpoint in the pool.
        budget=min(len(nodes),max(3,min(6,len(nodes))))
        for _ in range(budget):
            with self.lock:
                available=[e for e in nodes if e['url'] not in tried and self.stats.get(e['url'],{}).get('cooldownUntil',0)<=time.monotonic() and self.host_cooldown.get(e['host'],0)<=time.monotonic()]
                if not available: break
                # Weighted rotation: use fast nodes more, while keeping alternatives warm.
                e=min(available,key=lambda x:(self.stats.get(x['url'],{}).get('calls',0)+1)*max(25,self.stats.get(x['url'],{}).get('ewmaMs',x['latencyMs'])))
                url=e['url'];tried.add(url);s=self.stats.setdefault(url,{'calls':0,'errors':0,'nextAt':0,'cooldownUntil':0})
                delay=max(0,s['nextAt']-time.monotonic(),self.host_next.get(e['host'],0)-time.monotonic());s['nextAt']=time.monotonic()+delay+0.4;self.host_next[e['host']]=s['nextAt'];s['calls']+=1
            if delay: time.sleep(delay)
            try:
                from datetime import datetime
                initial=datetime.fromisoformat(e['observedAt'].replace('Z','+00:00')).timestamp() if e.get('observedAt') else time.time()
                if time.time()-s.get('lastValidatedAt',initial)>300:
                    health=probe(chain_id,url,timeout,raw_sink=self.raw_sink)
                    if not health['healthy']:raise ValueError('periodic verification failed: '+health['error'])
                    with self.lock:s['lastValidatedAt']=time.time()
                started=time.monotonic()
                value=_rpc_observed(url,method,params,timeout,self.raw_sink,chain_id)
                if value is None:
                    # Some providers answer a query they do not serve with a
                    # JSON-RPC `null` result instead of an error.  Returning
                    # that null made the caller read the absence of the answer
                    # as the absence of the thing it asked about: a creation
                    # transaction that exists came back as "carries no input",
                    # and the contract was dropped from the corpus on some
                    # attempts and kept on others.  A null result is a failed
                    # read here, so the pool moves on to the next endpoint.
                    raise ValueError('endpoint returned a null result')
                elapsed=round((time.monotonic()-started)*1000)
                with self.lock:
                    s['lastSuccessAt']=now();s['ewmaMs']=round(.8*s.get('ewmaMs',elapsed)+.2*elapsed);s['lastError']=None
                    if errors:self.failovers+=1
                return value,url
            except Exception as ex:
                with self.lock:
                    s['errors']+=1;s['cooldownUntil']=time.monotonic()+(300 if isinstance(ex,urllib.error.HTTPError) and ex.code in (403,429) else 60)
                    s['lastError']=f'{type(ex).__name__}: {str(ex)[:120]}';s['lastErrorAt']=now()
                    if isinstance(ex,urllib.error.HTTPError) and ex.code in (403,429):self.host_cooldown[e['host']]=s['cooldownUntil']
                    # A node that answers the live view but refuses a
                    # block-height read is still useful for live reads.  Record
                    # the limit instead of treating it as a broken node.
                    if historical and isinstance(ex,urllib.error.HTTPError) and ex.code in (400,404,500,501):
                        e['historicalUnavailable']=True
                        s['historicalUnavailable']=True
                errors.append(f'{e["host"]}: {type(ex).__name__}')
        raise RuntimeError('No usable verified RPC: '+('; '.join(errors) or str(chain_id)))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',default=str(ROOT/'work/rpc-pool.json'));p.add_argument('--timeout',type=float,default=6);p.add_argument('--per-chain',type=int,default=8);a=p.parse_args()
    data=discover(json.loads((ROOT/'flare-scan/chains.json').read_text())['chains'],a.per_chain,a.timeout)
    atomic(a.output,data)
    print(json.dumps({'output':a.output,'chains':len(data['chains']),'healthyChains':sum(c['healthyCount']>0 for c in data['chains']),'redundantChains':sum(c['redundant'] for c in data['chains']),'endpoints':sum(c['healthyCount'] for c in data['chains'])},ensure_ascii=False))
