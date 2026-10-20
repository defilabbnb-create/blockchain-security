#!/usr/bin/env python3
"""Rank historically active, currently quieter EVM chains by value and transferability.

This is a discovery aid. A LI.FI connection is only a compatible token/chain
connection; a quote is the only result treated as a currently executable route.
It never signs, sends, or approves a transaction.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import socket
import sys
import time
import hashlib
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / 'flare-scan' / 'chains.json'
LLAMA = 'https://api.llama.fi'
LIFI = 'https://li.quest/v1'
CHAINLIST = 'https://chainid.network/chains.json'
HEX_CHAIN_ID = re.compile(r'^0x[0-9a-fA-F]+$')
EVM_ADDRESS = re.compile(r'^0x[0-9a-fA-F]{40}$')


class FetchError(RuntimeError):
    pass


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    # Do not include a query value or path that could contain a token in errors.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))


def fetch_json(url: str, *, timeout: float = 20, retries: int = 2,
               opener=urlopen) -> Any:
    if not url.startswith(('https://', 'http://')):
        raise FetchError('只允许 HTTP(S) 数据源')
    last = '网络请求失败'
    for attempt in range(retries + 1):
        try:
            request = Request(url, headers={'accept': 'application/json', 'user-agent': 'dsh-chain-screener/1'})
            with opener(request, timeout=timeout) as response:
                if getattr(response, 'status', 200) >= 400:
                    raise HTTPError(url, response.status, 'HTTP error', response.headers, None)
                body = response.read()
            try:
                return json.loads(body.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise FetchError(f'数据源响应不是 JSON：{_safe_url(url)}') from None
        except HTTPError as error:
            last = f'HTTP {error.code}'
            retryable = error.code == 429 or error.code >= 500
        except (URLError, TimeoutError, socket.timeout, OSError):
            last = '网络连接失败或超时'
            retryable = True
        except FetchError:
            raise
        if not retryable or attempt == retries:
            raise FetchError(f'{_safe_url(url)}：{last}')
        time.sleep(min(0.4 * (2 ** attempt), 2.0))
    raise FetchError(f'{_safe_url(url)}：{last}')


def rpc_json(url: str, method: str, params: list[Any], *, timeout: float = 12,
             opener=urlopen) -> Any:
    if not url.startswith(('https://', 'http://')):
        raise FetchError('RPC URL 不是 HTTP(S)')
    payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    try:
        request = Request(url, data=payload, headers={'content-type': 'application/json', 'accept': 'application/json'})
        with opener(request, timeout=timeout) as response:
            body = json.loads(response.read().decode('utf-8'))
    except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise FetchError(f'RPC 连接失败：{_safe_url(url)}') from None
    if not isinstance(body, dict) or body.get('jsonrpc') != '2.0' or body.get('id') != 1:
        raise FetchError('RPC 响应不匹配')
    if body.get('error'):
        try:
            code = int(body['error'].get('code'))
        except (TypeError, ValueError):
            code = 0
        raise FetchError(f'RPC 错误 {code}')
    return body.get('result')


def load_config(path: Path = CONFIG) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding='utf-8'))
    chains = data.get('chains')
    if not isinstance(chains, list) or not chains:
        raise ValueError('chains.json 没有链配置')
    result = []
    seen = set()
    seen_chain_ids = set()
    for item in chains:
        if not isinstance(item, dict) or not isinstance(item.get('chainId'), int) or item['chainId'] <= 0:
            raise ValueError('chains.json 含无效 chainId')
        if item['chainId'] in seen_chain_ids:
            raise ValueError(f"chains.json chainId 重复：{item['chainId']}")
        seen_chain_ids.add(item['chainId'])
        key = item.get('name')
        if not key or key in seen:
            raise ValueError('chains.json 链名称必须唯一')
        seen.add(key)
        item = dict(item)
        item.setdefault('llamaName', key)
        result.append(item)
    return result


def parse_chainlist(raw: Any) -> dict[int, dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError('chainlist 响应不是数组')
    result = {}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get('chainId'), int):
            continue
        urls = []
        for value in item.get('rpc') or []:
            if isinstance(value, str) and value.startswith(('https://', 'http://')) and '${' not in value:
                if value not in urls:
                    urls.append(value)
        result[item['chainId']] = {'name': item.get('name'), 'shortName': item.get('shortName'), 'rpcs': urls}
    return result


def historical_stats(raw: Any) -> dict[str, Any]:
    points = raw if isinstance(raw, list) else raw.get('data', []) if isinstance(raw, dict) else []
    valid = []
    for point in points:
        if not isinstance(point, dict):
            continue
        try:
            date = int(point['date'])
            tvl = float(point['tvl'])
        except (KeyError, TypeError, ValueError):
            continue
        if date >= 0 and math.isfinite(tvl) and tvl >= 0:
            valid.append((date, tvl))
    if not valid:
        return {'points': 0, 'peakTvlUsd': 0, 'peakAt': None, 'firstTvlUsd': None, 'lastHistoricalTvlUsd': None}
    peak = max(valid, key=lambda pair: pair[1])
    return {'points': len(valid), 'peakTvlUsd': round(peak[1], 2), 'peakAt': datetime.fromtimestamp(peak[0], timezone.utc).isoformat(),
            'firstTvlUsd': round(valid[0][1], 2), 'lastHistoricalTvlUsd': round(valid[-1][1], 2)}


def cached_json(url: str, *, cache_dir: Path | None, cache_ttl: int, timeout: float) -> Any:
    """Use a short-lived content-addressed cache for read-only discovery APIs."""
    cache_path = None
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / (hashlib.sha256(url.encode()).hexdigest() + '.json')
        if cache_path.exists() and time.time() - cache_path.stat().st_mtime <= cache_ttl:
            try:
                return json.loads(cache_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                cache_path.unlink(missing_ok=True)
    value = fetch_json(url, timeout=timeout)
    if cache_path is not None:
        temp = cache_path.with_suffix('.tmp')
        try:
            temp.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
            temp.replace(cache_path)
        finally:
            temp.unlink(missing_ok=True)
    return value


def _connection_result(raw: Any, to_chain: int) -> dict[str, Any]:
    connections = raw.get('connections', []) if isinstance(raw, dict) else []
    if not isinstance(connections, list):
        connections = []
    valid = [c for c in connections if isinstance(c, dict)]
    from_tokens = sum(len(c.get('fromTokens', [])) for c in valid if isinstance(c.get('fromTokens', []), list))
    to_tokens = sum(len(c.get('toTokens', [])) for c in valid if isinstance(c.get('toTokens', []), list))
    return {'toChainId': to_chain, 'connectionCount': len(valid), 'fromTokenCount': from_tokens,
            'toTokenCount': to_tokens, 'connectionAvailable': bool(valid),
            'routeVerification': 'connection_only'}


def _quote_result(raw: Any, to_chain: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {'toChainId': to_chain, 'quoteAvailable': False, 'routeVerification': 'quote_failed'}
    routes = raw.get('routes')
    # /quote returns one transaction quote; /advanced/routes returns routes.
    available = bool(routes) if isinstance(routes, list) else bool(raw.get('transactionRequest') or raw.get('estimate'))
    estimate = raw.get('estimate') if isinstance(raw.get('estimate'), dict) else {}
    return {'toChainId': to_chain, 'quoteAvailable': available, 'routeVerification': 'quote_verified' if available else 'quote_failed',
            'tool': raw.get('tool') if isinstance(raw.get('tool'), str) else estimate.get('tool') if isinstance(estimate.get('tool'), str) else None,
            'quotedFromAmount': estimate.get('fromAmount'), 'quotedToAmount': estimate.get('toAmount'),
            'quotedToAmountMin': estimate.get('toAmountMin'), 'fromAmountUsd': estimate.get('fromAmountUSD'),
            'toAmountUsd': estimate.get('toAmountUSD')}


def score_chain(current: float, peak: float, connections: int, *, min_peak: float) -> dict[str, Any]:
    ratio = current / peak if peak > 0 else None
    history_score = min(100.0, max(0.0, 25 * math.log10(1 + peak / max(min_peak, 1)))) if peak else 0.0
    current_score = min(100.0, max(0.0, 20 * math.log10(1 + current / 1000))) if current else 0.0
    bridge_score = min(100.0, 25.0 * connections)
    priority = round(history_score * 0.5 + current_score * 0.25 + bridge_score * 0.25, 2)
    return {'historicalHeatScore': round(history_score, 2), 'currentValueScore': round(current_score, 2),
            'crossChainScore': round(bridge_score, 2), 'priorityScore': priority,
            'currentToPeakRatio': round(ratio, 6) if ratio is not None else None}


def analyze_one(chain: dict[str, Any], llama_chains: dict[str, Any], chainlist: dict[int, dict[str, Any]],
                destination_ids: list[int], *, timeout: float, min_peak: float,
                min_current: float, from_token: str | None, to_token: str | None,
                amount: str | None, from_address: str, to_address: str,
                historical: dict[str, Any] | None = None, prefilter_skipped: bool = False,
                cache_dir: Path | None = None, cache_ttl: int = 0) -> dict[str, Any]:
    name, chain_id, llama_name = chain['name'], chain['chainId'], chain.get('llamaName', chain['name'])
    result: dict[str, Any] = {'name': name, 'chainId': chain_id, 'llamaName': llama_name,
                              'historicalHeat': {}, 'crossChain': [], 'rpc': {}, 'errors': []}
    try:
        result['currentTvlUsd'] = round(float(llama_chains.get(llama_name, {}).get('tvl', 0) or 0), 2)
    except (TypeError, ValueError):
        result['currentTvlUsd'] = 0
    result['historicalHeat'] = historical or {}
    peak = result['historicalHeat'].get('peakTvlUsd', 0)
    if prefilter_skipped:
        result['selection'] = {'historicallyHot': False, 'currentValueAboveFloor': False,
                               'crossChainConnection': None, 'rpcHealthy': None,
                               'candidateForDeepDive': False, 'readyForDeepDive': False,
                               'prefilterSkipped': True}
        result['transferability'] = 'not_checked'
        result['skipReason'] = 'historical peak and current TVL are below thresholds; cross-chain/RPC probes skipped'
        result['score'] = score_chain(result.get('currentTvlUsd', 0), peak, 0, min_peak=min_peak)
        result['caveats'] = ['This chain was prefiltered for speed; rerun with --chain to force probes.']
        return result
    # Fetch compatibility for each destination. Connections do not prove a route.
    for destination in destination_ids:
        try:
            raw = cached_json(f'{LIFI}/connections?{urlencode({"fromChain": chain_id, "toChain": destination})}',
                              cache_dir=cache_dir, cache_ttl=cache_ttl, timeout=timeout)
            connection = _connection_result(raw, destination)
            if from_token and to_token and amount and connection['connectionAvailable']:
                if not EVM_ADDRESS.fullmatch(from_token) or not EVM_ADDRESS.fullmatch(to_token) or not re.fullmatch(r'[0-9]+', amount):
                    raise ValueError('quote token 必须是地址，amount 必须是非负整数')
                params = {'fromChain': chain_id, 'toChain': destination, 'fromToken': from_token, 'toToken': to_token,
                          'fromAmount': amount, 'fromAddress': from_address, 'toAddress': to_address}
                try:
                    connection.update(_quote_result(fetch_json(f'{LIFI}/quote?{urlencode(params)}', timeout=timeout), destination))
                except FetchError as error:
                    connection.update({'quoteAvailable': False, 'routeVerification': 'quote_failed', 'quoteError': str(error)})
            result['crossChain'].append(connection)
        except (FetchError, ValueError) as error:
            result['crossChain'].append({'toChainId': destination, 'connectionAvailable': False, 'routeVerification': 'unavailable', 'error': str(error)})
    # Pick a public RPC from the config first, then chainlist. This is a health check only.
    configured_rpc = chain.get('rpc')
    candidate_rpcs = ([configured_rpc] if isinstance(configured_rpc, str) else []) + chainlist.get(chain_id, {}).get('rpcs', [])
    seen = set(); candidate_rpcs = [u for u in candidate_rpcs if not (u in seen or seen.add(u))]
    for rpc in candidate_rpcs[:3]:
        try:
            actual = rpc_json(rpc, 'eth_chainId', [], timeout=min(timeout, 12))
            height = rpc_json(rpc, 'eth_blockNumber', [], timeout=min(timeout, 12))
            actual_id = int(actual, 16) if isinstance(actual, str) and HEX_CHAIN_ID.fullmatch(actual) else None
            result['rpc'] = {'url': _safe_url(rpc), 'ok': actual_id == chain_id and isinstance(height, str) and HEX_CHAIN_ID.fullmatch(height) is not None,
                             'observedChainId': actual_id, 'blockNumber': int(height, 16) if isinstance(height, str) and HEX_CHAIN_ID.fullmatch(height) else None}
            if result['rpc']['ok']:
                break
        except FetchError as error:
            result['rpc'] = {'url': _safe_url(rpc), 'ok': False, 'error': str(error)}
    connection_count = sum(int(c.get('connectionCount', 0)) for c in result['crossChain'] if c.get('connectionAvailable'))
    quote_verified = any(c.get('routeVerification') == 'quote_verified' for c in result['crossChain'])
    connection_only = any(c.get('routeVerification') == 'connection_only' for c in result['crossChain'])
    result['transferability'] = ('quote_verified' if quote_verified else
                                 'connection_only' if connection_only else 'unavailable')
    result['score'] = score_chain(result.get('currentTvlUsd', 0), peak, connection_count, min_peak=min_peak)
    result['selection'] = {'historicallyHot': peak >= min_peak, 'currentValueAboveFloor': result.get('currentTvlUsd', 0) >= min_current,
                           'crossChainConnection': connection_count > 0, 'rpcHealthy': result.get('rpc', {}).get('ok', False),
                           'candidateForDeepDive': peak >= min_peak and connection_count > 0,
                           'readyForDeepDive': peak >= min_peak and connection_count > 0 and result.get('rpc', {}).get('ok', False)}
    result['caveats'] = ['TVL is a heat/value proxy, not proof of recoverable or safe funds.',
                         'LI.FI connections indicate supported assets/chain pairs; only a quote verifies a currently executable route.',
                         'RPC health verifies the endpoint and chain ID, not contract safety or bridge solvency.']
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chain', action='append', help='Configured chain name; repeatable')
    parser.add_argument('--all', action='store_true', help='Analyze all configured chains (default: first selected chain)')
    parser.add_argument('--destination', action='append', type=int, default=None, help='LI.FI destination chain ID; repeatable')
    parser.add_argument('--min-peak-tvl-usd', type=float, default=1_000_000)
    parser.add_argument('--min-current-tvl-usd', type=float, default=100_000)
    parser.add_argument('--from-token', help='Optional EVM token address for a real LI.FI quote check')
    parser.add_argument('--to-token', help='Optional EVM token address for a real LI.FI quote check')
    parser.add_argument('--amount', help='Optional base-unit amount for a real LI.FI quote check')
    parser.add_argument('--from-address', default='0x0000000000000000000000000000000000000001', help='Quote-only sender address')
    parser.add_argument('--to-address', default='0x0000000000000000000000000000000000000001', help='Quote-only receiver address')
    parser.add_argument('--timeout', type=float, default=20)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--output', type=Path, default=ROOT / 'flare-scan/reports/chain-screen.json')
    parser.add_argument('--source-cache', type=Path, help='Optional JSON file with API responses for offline tests')
    parser.add_argument('--cache-dir', type=Path, default=ROOT / 'work' / 'chain-cache', help='Short-lived API cache directory')
    parser.add_argument('--cache-ttl', type=int, default=21600, help='API cache lifetime in seconds')
    args = parser.parse_args(argv)
    destination_ids = args.destination or [1]
    if args.min_peak_tvl_usd < 0 or args.min_current_tvl_usd < 0 or not 1 <= args.workers <= 12 or not 1 <= args.timeout <= 120 or not 0 <= args.cache_ttl <= 604800:
        parser.error('阈值、workers 或 timeout 无效')
    if any(bool(x) for x in (args.from_token, args.to_token, args.amount)) and not all((args.from_token, args.to_token, args.amount)):
        parser.error('quote 检查需要同时提供 --from-token、--to-token、--amount')
    if not EVM_ADDRESS.fullmatch(args.from_address) or not EVM_ADDRESS.fullmatch(args.to_address):
        parser.error('--from-address 和 --to-address 必须是 EVM 地址')
    chains = load_config()
    selected = chains if args.all else [c for c in chains if c.get('selectedForDeepDive')]
    if args.chain:
        names = set(args.chain)
        unknown = names - {c['name'] for c in chains}
        if unknown:
            parser.error('未知链：' + ', '.join(sorted(unknown)))
        selected = [c for c in chains if c['name'] in names]
    if not selected:
        parser.error('没有待分析链；使用 --chain 或 --all')
    try:
        if args.source_cache:
            cache = json.loads(args.source_cache.read_text(encoding='utf-8'))
            llama_data, chainlist_data = cache['llamaChains'], cache['chainlist']
        else:
            with ThreadPoolExecutor(max_workers=2) as pool:
                llama_future = pool.submit(cached_json, f'{LLAMA}/v2/chains', cache_dir=args.cache_dir, cache_ttl=args.cache_ttl, timeout=args.timeout)
                chainlist_future = pool.submit(cached_json, CHAINLIST, cache_dir=args.cache_dir, cache_ttl=args.cache_ttl, timeout=args.timeout)
                llama_data, chainlist_data = llama_future.result(), chainlist_future.result()
        if not isinstance(llama_data, list):
            raise ValueError('DefiLlama chains 响应不是数组')
        llama_chains = {x['name']: x for x in llama_data if isinstance(x, dict) and isinstance(x.get('name'), str)}
        chainlist = parse_chainlist(chainlist_data)
    except (FetchError, ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print('链筛选失败：' + str(error), file=sys.stderr)
        return 1
    llama_chains = llama_chains
    # Historical TVL is the cheap broad filter. Fetch all selected histories concurrently,
    # then reserve LI.FI and RPC calls for chains that crossed at least one threshold.
    histories: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(args.workers, len(selected))) as pool:
        pending_history = {
            pool.submit(cached_json, f"{LLAMA}/v2/historicalChainTvl/{c.get('llamaName', c['name'])}",
                        cache_dir=args.cache_dir, cache_ttl=args.cache_ttl, timeout=args.timeout): c
            for c in selected
        }
        for future in as_completed(pending_history):
            chain = pending_history[future]
            try:
                histories[chain['name']] = historical_stats(future.result())
            except (FetchError, ValueError) as error:
                histories[chain['name']] = {'points': 0, 'peakTvlUsd': 0, 'peakAt': None,
                                             'firstTvlUsd': None, 'lastHistoricalTvlUsd': None,
                                             'error': str(error)}
    results = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(selected))) as pool:
        pending = {pool.submit(analyze_one, c, llama_chains, chainlist, destination_ids, timeout=args.timeout,
                               min_peak=args.min_peak_tvl_usd, min_current=args.min_current_tvl_usd,
                               from_token=args.from_token, to_token=args.to_token, amount=args.amount,
                               from_address=args.from_address, to_address=args.to_address,
                               historical=histories.get(c['name']),
                               cache_dir=args.cache_dir, cache_ttl=args.cache_ttl,
                               prefilter_skipped=(not args.chain and histories.get(c['name'], {}).get('peakTvlUsd', 0) < args.min_peak_tvl_usd
                                                  and float(llama_chains.get(c.get('llamaName', c['name']), {}).get('tvl', 0) or 0) < args.min_current_tvl_usd)): c for c in selected}
        for future in as_completed(pending):
            try:
                results.append(future.result())
            except Exception as error:
                chain = pending[future]
                results.append({'name': chain['name'], 'chainId': chain['chainId'], 'selection': {'candidateForDeepDive': False}, 'errors': [str(error)]})
    results.sort(key=lambda item: item.get('score', {}).get('priorityScore', 0), reverse=True)
    report = {'schemaVersion': 1, 'generatedAt': datetime.now(timezone.utc).isoformat(),
              'criteria': {'minHistoricalPeakTvlUsd': args.min_peak_tvl_usd, 'minCurrentTvlUsd': args.min_current_tvl_usd,
                           'destinations': destination_ids, 'quoteRequested': bool(args.from_token)},
              'scope': 'EVM chain discovery: historical heat, current TVL proxy, RPC identity/health, and cross-chain compatibility.',
              'sources': {'currentTvl': f'{LLAMA}/v2/chains', 'historicalTvl': f'{LLAMA}/v2/historicalChainTvl/{{chain}}',
                          'chainMetadata': CHAINLIST, 'crossChainConnections': f'{LIFI}/connections', 'quote': f'{LIFI}/quote'},
              'quoteSafety': 'Quote requests are read-only. A returned transactionRequest is not signed, approved, or broadcast.',
              'chains': results,
              'selected': [r['name'] for r in results if r.get('selection', {}).get('candidateForDeepDive')],
              'ready': [r['name'] for r in results if r.get('selection', {}).get('readyForDeepDive')]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_name(args.output.name + '.tmp')
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    tmp.replace(args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
