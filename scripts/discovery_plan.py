"""Turn structural source paths into explicit, evidence-bound test obligations.

This is a test planner, not a vulnerability detector or a proof engine. A passed
property only describes the recorded local fixture; line overlap is not coverage.
"""
import argparse
import collections
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys


PROPERTIES = {
    'accounting.asset_conservation': ('资产守恒', '独立追踪全部参与者资产与协议托管余额，逐步核对总和。'),
    'accounting.share_conservation': ('份额守恒', '独立追踪各持有人份额；每步核对总供给与余额之和。'),
    'accounting.rounding_direction': ('舍入方向', '独立整数参考模型检查 deposit/redeem 向下、mint/withdraw 向上及小额边界。'),
    'accounting.donation_consistency': ('捐赠后记账', '存款→直接捐赠→另一用户存款→赎回，检查份额、资产与独立记账模型。'),
    'authorization.redemption': ('赎回授权', '分离 caller/owner/receiver，检查未授权回滚、有限授权消耗及撤销。'),
    'authorization.share_allowance': ('份额授权额度', '检查有限额度扣减、额度不足原子回滚、撤销后拒绝、MaxUint256 额度不变，以及 owner 自调用无需 allowance。'),
    'authorization.revocation': ('授权撤销恢复', '授权→撤销→拒绝第三方操作→重新授权；检查余额、授权额度与恢复路径。'),
    'settlement.payer_owner_separation': ('付款人与持有人分离', '由一方付款为另一方铸造份额，再由第三方接收资产，核对三方独立余额。'),
    'settlement.receiver_exact': ('精确到账', '以接收者实际余额差核对付款，区分 owner、caller 与 receiver。'),
    'rollback.atomicity': ('失败原子性', '外部依赖失败前后核对所有受影响余额、负债与授权。'),
    'liveness.failure_recovery': ('故障恢复', '依赖失败→恢复依赖→合法操作，排除静默锁死或重复记账。'),
    'external.reentrancy_safety': ('回调安全', '在独立本地恶意依赖夹具中枚举回调入口与共享状态，验证结算性质。'),
    'liveness.matured_claim': ('成熟请求活性', '有效请求→时间推进→领取；检查精确到账、负债清零与不可重复领取。'),
    'oracle.freshness': ('价格与时效', '边界价格、过期值、精度差、零值与异常返回下核对估值性质。'),
    'admin.role_boundaries': ('角色边界', '普通用户、角色持有人、撤销角色三种上下文检查敏感变更与现有防护。'),
    'contract.lifecycle': ('合约生命周期', '检查 SELFDESTRUCT opcode 在目标 EVM 规则下的余额转移和代码/存储生命周期；opcode 本身不证明账户已删除。'),
    'batch.atomicity': ('批量一致性', '有效/无效操作混合、重复项与顺序变化；以协议约定的回滚语义验证。'),
}


def _effect_site_id(source_sha256, file_name, start, length, kind):
    if (not isinstance(source_sha256, str) or len(source_sha256) != 64 or
            any(char not in '0123456789abcdef' for char in source_sha256) or
            not isinstance(file_name, str) or not file_name or
            type(start) is not int or start < 0 or
            type(length) is not int or length < 1 or
            kind not in ('state_write', 'external_call', 'contract_creation', 'selfdestruct')):
        return None
    key = '\0'.join((source_sha256, file_name, str(start), str(length), kind))
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _method(entry):
    # Function names only select a hypothesis family. They never establish ABI
    # compatibility, business semantics, lack of protection or a vulnerability.
    return entry.split('(')[0].rsplit('.', 1)[-1].rsplit('::', 1)[-1].lower()


def _valid_run(local):
    results = local.get('results')
    if not isinstance(results, list) or not results:
        return False
    if not all(isinstance(row, dict) and row.get('state') in ('passed', 'failed') for row in results):
        return False
    counts = {key: local.get(key) for key in ('tests', 'passed', 'failed')}
    if any(type(value) is not int or value < 0 for value in counts.values()):
        return False
    passed = sum(row['state'] == 'passed' for row in results)
    failed = len(results) - passed
    return counts == {'tests': len(results), 'passed': passed, 'failed': failed} and (
        local.get('state') == ('failed' if failed else 'passed'))


def _property_evidence(report, local):
    expected, actual = report.get('verifiedSourceFingerprint'), local.get('verifiedSourceFingerprint')
    expected_dep, actual_dep = report.get('verifiedDependencyFingerprint'), local.get('verifiedDependencyFingerprint')
    bound = isinstance(expected, str) and bool(re.fullmatch(r'[0-9a-f]{64}', expected)) and expected == actual
    bound = bound and expected_dep == actual_dep and _valid_run(local)
    index = collections.defaultdict(list)
    if bound:
        for row in local['results']:
            ids = row.get('targetPropertyIds', row.get('propertyIds', [])) if row['state'] == 'failed' else row.get('propertyIds', [])
            if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
                continue
            for property_id in sorted(set(ids) & PROPERTIES.keys()):
                index[property_id].append({'testId': row.get('id'), 'state': row['state']})
    return bound, index


def _observation(local, bound):
    # A transition count is evidence of action ordering, never branch/state coverage.
    transitions = collections.Counter()
    operations = 0
    for sequence in local.get('sequences', []) if bound else []:
        if not isinstance(sequence, dict) or not isinstance(sequence.get('operations'), list):
            continue
        previous = None
        for operation in sequence['operations']:
            if not isinstance(operation, dict) or not isinstance(operation.get('method'), str):
                continue
            outcome = 'reverted' if operation.get('reverted') else 'succeeded' if operation.get('transactionHash') else 'unresolved'
            action = operation['method'] + ':' + outcome
            operations += 1
            if previous is not None:
                transitions[(previous, action)] += 1
            previous = action
    return {'state': 'recorded' if bound else 'unbound_or_unavailable',
            'operationCount': operations, 'distinctTransitionCount': len(transitions),
            'transitions': [{'from': a, 'to': b, 'count': count} for (a, b), count in sorted(transitions.items())],
            'interpretation': 'Recorded adjacent actions only; not branch, state-space or full-path coverage.'}


def _dynamic_path_observations(local, source_bound, graph_bound, graph_paths, graph_fingerprint):
    """Bind validated opcode/source overlaps to original call-graph path indices."""
    if not (source_bound and graph_bound) or not isinstance(graph_paths, list):
        return {}
    correlation = local.get('staticCorrelation')
    matches = correlation.get('matches') if isinstance(correlation, dict) else None
    if (not isinstance(matches, list) or
            correlation.get('graphFingerprint') != graph_fingerprint):
        return {}
    traces = local.get('traces')
    if not isinstance(traces, list):
        return {}
    by_path = collections.defaultdict(list)
    for match in matches:
        if not isinstance(match, dict):
            continue
        indices = match.get('candidatePathIndices')
        location = match.get('sourceLocation')
        opcode = match.get('opcode')
        start = location.get('lineStart') if isinstance(location, dict) else None
        end = location.get('lineEnd') if isinstance(location, dict) else None
        if (not isinstance(indices, list) or not indices or
                any(type(index) is not int or not 0 <= index < len(graph_paths) for index in indices) or
                len(indices) > len(graph_paths) or len(set(indices)) != len(indices) or
                type(match.get('traceIndex')) is not int or match['traceIndex'] < 0 or
                type(match.get('effectIndex')) is not int or match['effectIndex'] < 0 or
                not isinstance(match.get('transactionHash'), str) or not match['transactionHash'] or
                not isinstance(opcode, str) or
                opcode not in {'SSTORE', 'TSTORE', 'CREATE', 'CREATE2', 'SELFDESTRUCT', 'CALL',
                               'STATICCALL', 'DELEGATECALL', 'CALLCODE'} or
                type(match.get('transactionReverted')) is not bool or
                match.get('completePathProven') is not False or
                not isinstance(location, dict) or not isinstance(location.get('file'), str) or not location['file'] or
                type(start) is not int or type(end) is not int or start < 1 or end < start):
            continue
        trace_index = match['traceIndex']
        effect_index = match['effectIndex']
        if trace_index >= len(traces):
            continue
        trace = traces[trace_index]
        effects = trace.get('effects') if isinstance(trace, dict) else None
        if (not isinstance(effects, list) or effect_index >= len(effects) or
                trace.get('state') in ('unavailable', 'not_performed', 'failed') or
                not isinstance(trace.get('transactionHash'), str) or not trace['transactionHash'] or
                type(trace.get('failed')) is not bool):
            continue
        executed = effects[effect_index]
        target_depth = trace.get('targetDepth', 1)
        dynamic_kind = ('state_write' if opcode in {'SSTORE', 'TSTORE'} else
                        'selfdestruct' if opcode == 'SELFDESTRUCT' else
                        'contract_creation' if opcode in {'CREATE', 'CREATE2'} else
                        'external_call' if opcode in {'CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE'} else None)
        runtime_site = executed.get('sourceLocation') if isinstance(executed, dict) else None
        runtime_site_id = (_effect_site_id(runtime_site.get('sourceSha256'), runtime_site.get('file'),
                                           runtime_site.get('start'), runtime_site.get('length'), dynamic_kind)
                           if isinstance(runtime_site, dict) else None)
        if (not isinstance(executed, dict) or
                executed.get('op') != opcode or
                type(executed.get('depth')) is not int or
                type(target_depth) is not int or target_depth < 1 or executed['depth'] != target_depth or
                executed.get('sourceLocation') != location or
                not isinstance(match.get('effectSiteId'), str) or
                executed.get('effectSiteId') != match.get('effectSiteId') or
                runtime_site_id != match.get('effectSiteId') or
                trace['transactionHash'] != match.get('transactionHash') or
                trace['failed'] != match['transactionReverted'] or
                ('depth' in match and
                 (type(match['depth']) is not int or match['depth'] != executed['depth']))):
            continue
        allowed_by_kind = {
            'state_write': {'SSTORE', 'TSTORE'},
            'selfdestruct': {'SELFDESTRUCT'},
            'external_call': {'CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE'},
        }
        valid_paths = True
        for index in indices:
            path = graph_paths[index]
            effect = path.get('effect') if isinstance(path, dict) else None
            path_location = effect.get('location') if isinstance(effect, dict) else None
            lines = path_location.get('lines') if isinstance(path_location, dict) else None
            static_site_id = (_effect_site_id(effect.get('sourceSha256'), path_location.get('file'),
                                               path_location.get('start'), path_location.get('length'), effect.get('kind'))
                              if isinstance(effect, dict) and isinstance(path_location, dict) else None)
            if isinstance(effect, dict) and effect.get('kind') == 'contract_creation':
                call_kind = effect.get('callKind')
                allowed_opcodes = {'CREATE2'} if call_kind == 'create2' else {'CREATE'} if call_kind == 'create' else set()
            else:
                allowed_opcodes = allowed_by_kind.get(effect.get('kind'), set()) if isinstance(effect, dict) else set()
            if (not isinstance(path_location, dict) or path_location.get('file') != location['file'] or
                    not isinstance(lines, list) or not lines or
                    any(type(line) is not int or line < 1 for line in lines) or
                    min(lines) > end or max(lines) < start or
                    opcode not in allowed_opcodes or
                    effect.get('effectSiteId') != match.get('effectSiteId') or
                    static_site_id != match.get('effectSiteId')):
                valid_paths = False
                break
        if not valid_paths:
            continue
        observation = {
            'traceIndex': match['traceIndex'], 'effectIndex': match['effectIndex'],
            'transactionHash': match.get('transactionHash'), 'opcode': opcode,
            'effectSiteId': match['effectSiteId'],
            'sourceLocation': {'file': location['file'], 'lineStart': start, 'lineEnd': end},
            'transactionReverted': match['transactionReverted'],
            'completePathProven': False,
            'evidenceType': 'observed_opcode_source_location_overlap',
            'interpretation': '仅表示观察到的 opcode 与此候选路径 effect 源位置重叠；不证明完整路径、任何性质、授权、部署可达性或漏洞。',
        }
        for index in sorted(set(indices)):
            by_path[index].append(observation)
    return by_path


def build_plan(report, graph, local=None, max_obligations=160):
    if not isinstance(report, dict) or not isinstance(graph, dict):
        raise ValueError('report and call graph must be objects')
    if not isinstance(graph.get('paths'), list) or not isinstance(graph.get('entrypoints'), list):
        raise ValueError('call graph requires paths and entrypoints lists')
    if type(max_obligations) is not int or not 1 <= max_obligations <= 2000:
        raise ValueError('max_obligations must be in 1..2000')
    local = local if isinstance(local, dict) else {}
    bound, tested = _property_evidence(report, local)
    expected_graph = report.get('analysisInputFingerprint')
    actual_graph = graph.get('analysisInputFingerprint')
    graph_bound = isinstance(expected_graph, str) and bool(re.fullmatch(r'[0-9a-f]{64}', expected_graph)) and expected_graph == actual_graph
    graph_fingerprint = _digest(graph)
    if expected_graph is not None and not graph_bound:
        raise ValueError('call graph input fingerprint mismatch')
    if not graph_bound:
        # A matching suite fingerprint binds the suite to its source, not an
        # unrelated graph supplied through the standalone/legacy CLI.
        tested = collections.defaultdict(list)
    source_fingerprint = report.get('verifiedSourceFingerprint')
    source_bound = (isinstance(source_fingerprint, str) and
                    bool(re.fullmatch(r'[0-9a-f]{64}', source_fingerprint)) and
                    source_fingerprint == local.get('verifiedSourceFingerprint'))
    dynamic_path_observations = _dynamic_path_observations(
        local, source_bound, graph_bound, graph['paths'], graph_fingerprint)
    entries = {row['function']: row for row in graph['entrypoints']
               if isinstance(row, dict) and isinstance(row.get('function'), str)}
    grouped = collections.defaultdict(list)
    for entry in entries:
        grouped[entry] = []
    for path_index, row in enumerate(graph['paths']):
        if isinstance(row, dict) and isinstance(row.get('entrypoint'), str) and isinstance(row.get('effect'), dict):
            grouped[row['entrypoint']].append((path_index, row))
    obligations = []
    for entry, indexed_paths in sorted(grouped.items()):
        paths = [row for _, row in indexed_paths]
        method = _method(entry)
        effect_kinds = {row['effect'].get('kind') for row in paths}
        external = 'external_call' in effect_kinds
        asset = any(row['effect'].get('assetRelated') or row['effect'].get('sendsValue') for row in paths)
        properties = set()
        reasons = []
        if external:
            properties.update(('rollback.atomicity', 'external.reentrancy_safety', 'liveness.failure_recovery'))
            reasons.append('structural_external_call')
        if asset:
            properties.add('settlement.receiver_exact')
            reasons.append('asset_effect_hint')
        if method in ('deposit', 'mint', 'withdraw', 'redeem'):
            properties.update(('accounting.share_conservation', 'accounting.asset_conservation', 'accounting.rounding_direction', 'accounting.donation_consistency', 'settlement.payer_owner_separation'))
            reasons.append('vault_method_name_hint_requires_semantic_review')
        if method in ('withdraw', 'redeem'):
            properties.update(('authorization.redemption', 'authorization.revocation', 'settlement.receiver_exact'))
        if method in ('approve', 'transferfrom'):
            properties.add('authorization.share_allowance')
            reasons.append('allowance_method_name_hint_requires_semantic_review')
        if method == 'transferfrom':
            properties.add('accounting.share_conservation')
        if 'claim' in method:
            properties.update(('liveness.matured_claim', 'settlement.receiver_exact'))
            reasons.append('claim_method_name_hint_requires_semantic_review')
        if any(token in method for token in ('price', 'oracle', 'liquidat', 'borrow', 'collateral')):
            properties.add('oracle.freshness')
            reasons.append('valuation_method_name_hint_requires_semantic_review')
        if method.startswith(('set', 'grant', 'revoke', 'upgrade')):
            properties.add('admin.role_boundaries')
            reasons.append('configuration_method_name_hint_requires_semantic_review')
        if 'selfdestruct' in effect_kinds:
            properties.add('contract.lifecycle')
            reasons.append('selfdestruct_opcode_observation_requires_fork_semantics_review')
        if 'multicall' in method or 'batch' in method:
            properties.add('batch.atomicity')
            reasons.append('batch_method_name_hint_requires_semantic_review')
        if not properties:
            continue
        path_rows = []
        for path_index, row in indexed_paths:
            path = {key: row.get(key) for key in ('entrypoint', 'path', 'edges', 'effect', 'modifiers', 'pathFeasibility')}
            path_row = {'id': _digest(path)[:24], **path}
            if path_index in dynamic_path_observations:
                path_row['observedDynamicEffects'] = dynamic_path_observations[path_index]
            path_rows.append(path_row)
        unique_paths = {}
        for path_row in path_rows:
            current = unique_paths.get(path_row['id'])
            if current is None:
                unique_paths[path_row['id']] = path_row
            elif 'observedDynamicEffects' in path_row:
                observations = current.setdefault('observedDynamicEffects', [])
                known = {_digest(item) for item in observations}
                for item in path_row['observedDynamicEffects']:
                    item_digest = _digest(item)
                    if item_digest not in known:
                        observations.append(item)
                        known.add(item_digest)
        evidence = [{'propertyId': property_id, 'label': PROPERTIES[property_id][0],
                     'oracle': PROPERTIES[property_id][1],
                     'state': 'failed_scenario_requires_triage' if any(t['state'] == 'failed' for t in tested[property_id])
                     else 'passed_in_fixture' if tested[property_id] else 'needs_test',
                     'tests': tested[property_id],
                     'entrypointBinding': 'not_established'} for property_id in sorted(properties)]
        # Local suite properties are intentionally not claimed as coverage of this
        # particular function/path. A future harness must emit stable path IDs.
        entry_info = entries.get(entry, {})
        priority = 2 * int(asset) + int(external) + int(any(p['state'] == 'needs_test' for p in evidence))
        row = {'id': _digest({'entrypoint': entry, 'properties': sorted(properties)})[:24],
               'entrypoint': entry, 'location': entry_info.get('location'),
               'priority': priority, 'selectionReasons': sorted(reasons),
               'modifiers': entry_info.get('modifiers', []),
               'protectionHeuristic': entry_info.get('protectionHeuristic'),
               'pathEvidenceState': 'reported' if paths else 'no_effect_path_reported',
               'properties': evidence, 'paths': [unique_paths[k] for k in sorted(unique_paths)],
               'status': 'hypothesis_requires_validation', 'confirmed': False,
               'pathFeasibility': 'not_proven'}
        obligations.append(row)
    obligations.sort(key=lambda row: (-row['priority'], row['entrypoint']))
    omitted = max(0, len(obligations) - max_obligations)
    obligations = obligations[:max_obligations]
    path_ids = {p['id'] for row in obligations for p in row['paths']}
    property_ids = {p['propertyId'] for row in obligations for p in row['properties']}
    plan = {
        'schemaVersion': 1, 'state': 'partial' if graph.get('state') != 'completed' or omitted or not graph_bound else 'planned',
        'verifiedSourceFingerprint': report.get('verifiedSourceFingerprint'),
        'verifiedDependencyFingerprint': report.get('verifiedDependencyFingerprint'),
        'graphFingerprint': graph_fingerprint, 'graphInputBound': graph_bound, 'dynamicEvidenceBound': bound,
        'obligationCount': len(obligations), 'omittedObligationCount': omitted,
        'candidatePathCount': len(path_ids), 'propertyCount': len(property_ids),
        'entrypointsWithoutReportedPaths': sum(not grouped[entry] for entry in entries),
        'obligationsWithoutReportedPaths': sum(not row['paths'] for row in obligations),
        'fixturePassedPropertyCount': sum(bool(tested[key]) and all(t['state'] == 'passed' for t in tested[key]) for key in property_ids),
        'fixtureFailureAssociatedPropertyCount': sum(any(t['state'] == 'failed' for t in tested[key]) for key in property_ids),
        'untestedPropertyCount': sum(not tested[key] for key in property_ids),
        'pathSpecificPropertiesVerified': 0, 'confirmedVulnerabilities': 0,
        'graphCoverage': {key: graph.get(key) for key in ('state', 'entrypointCount', 'analyzedEntrypointCount',
            'selectedEntrypointCount', 'edgeCount', 'reportedEdgeCount', 'truncatedEdgeCount',
            'totalPathCount', 'reportedPathCount', 'truncatedPathCount', 'truncatedEntrypointCount',
            'maxDepth', 'depthCutoffEdgeCount', 'cycleCutoffEdgeCount', 'unresolvedAssemblyCallCount',
            'unresolvedAssemblyBlockCount', 'unresolvedInternalCallCount', 'unresolvedInternalDynamicCallCount',
            'walkSteps', 'walkBudget', 'walkBudgetExceeded', 'internalDynamicWalkSteps', 'internalDynamicWalkBudget')},
        'sequenceObservation': _observation(local, bound and graph_bound), 'obligations': obligations,
        'fixtureProvenance': {key: local.get(key) for key in ('sourceHash', 'compilerSettingsHash', 'harnessHash', 'harnessSupportHash', 'fixtureHash', 'compiler')},
        'limitations': [
            'Function names and structural effects select test obligations; they do not infer a vulnerability or lack of protection.',
            'Fixture property IDs require matching verified source and dependency fingerprints and consistent test counts.',
            'Passed fixture properties are not bound to individual candidate paths or all deployment configurations.',
            'A failed scenario lists its target properties for investigation; it does not prove that each target property failed.',
            'Graph truncation, unresolved calls and unproven branch predicates remain explicit coverage gaps.',
            'Sensitive entrypoints without reported effect paths still produce obligations; missing paths are not evidence of safety.',
            'This planner does not execute generated tests, establish an exploit, or certify contract safety.',
        ],
    }
    plan['planId'] = _digest(plan)
    return plan


def render_html(plan):
    def esc(value):
        return html.escape(str(value), quote=True)
    rows = []
    for row in plan['obligations']:
        properties = ''.join('<li><b>' + esc(p['label']) + '</b> <span class="tag">' +
            esc({'needs_test': '未验证', 'passed_in_fixture': '夹具通过 · 路径未绑定',
                 'failed_scenario_requires_triage': '关联场景失败 · 性质待定位'}[p['state']]) + '</span><p>' + esc(p['oracle']) +
            '</p><small>' + esc(', '.join(str(t['testId']) for t in p['tests'])) + '</small></li>' for p in row['properties'])
        paths = ''.join('<details><summary>' + esc(p['effect'].get('kind')) + ' · ' +
            esc(p['effect'].get('location')) + '</summary><div class="flow">' +
            ''.join('<span>' + esc(node) + '</span><i aria-hidden="true">→</i>' for node in (p.get('path') or [p['entrypoint']])) +
            '<b>' + esc(p['effect'].get('kind')) + '</b></div><pre>' +
            esc(json.dumps(p, ensure_ascii=False, indent=2)) + '</pre></details>' for p in row['paths'])
        rows.append('<article data-search="' + esc(row['entrypoint'].lower()) + '"><h2>' + esc(row['entrypoint']) +
            '</h2><p>排序分值 ' + esc(row['priority']) + ' · 源码 ' + esc(row['location']) +
            '</p><small>现有 modifiers：' + esc(row['modifiers']) + ' · 可行性未证明</small><ol>' + properties +
            '</ol>' + ('<details><summary>查看 ' + str(len(row['paths'])) + ' 条结构化证据路径</summary>' + paths + '</details>' if paths else '<p>该入口未报告效果路径；验证计划依据入口提示生成，须补充语义与路径证据。</p>') + '</article>')
    coverage = esc(json.dumps(plan['graphCoverage'], ensure_ascii=False, indent=2))
    transitions = esc(json.dumps(plan['sequenceObservation'], ensure_ascii=False, indent=2))
    return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; script-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;"><title>业务漏洞验证计划</title><style>.flow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px 0}.flow span,.flow b{padding:7px;background:#edf0f4;overflow-wrap:anywhere;max-width:100%}.flow i{font-style:normal}' + \
        'body{font:15px/1.6 system-ui;margin:0;background:#f5f6f8;color:#202735}main{max-width:1100px;margin:auto;padding:28px}h1{font-size:26px}h2{font-size:17px;overflow-wrap:anywhere}.metrics{display:flex;gap:24px;flex-wrap:wrap;border-block:1px solid #ccd2db;padding:18px 0}.metrics strong{font-size:24px;display:block}article{background:white;border:1px solid #d4d9e1;padding:20px;margin-top:18px}small{color:#526078;overflow-wrap:anywhere}.tag{font-size:12px;background:#edf0f4;padding:3px 6px;margin-left:8px}li{margin:12px 0}li p{margin:5px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}summary{cursor:pointer}input{box-sizing:border-box;width:100%;padding:12px;font:inherit;margin:18px 0}details{margin-top:10px}footer{padding-top:24px}a{color:#245d8c}</style><main><h1>从静态线索到业务性质验证</h1><p>局部证据与覆盖缺口；不将测试通过等同漏洞确认或线上安全。</p><div class="metrics">' + \
        ''.join('<div><strong>' + esc(plan[key]) + '</strong>' + label + '</div>' for key, label in (
            ('obligationCount', '入口验证计划'), ('fixturePassedPropertyCount', '夹具通过性质'),
            ('untestedPropertyCount', '未验证性质'), ('pathSpecificPropertiesVerified', '已绑定验证路径'))) + \
        '</div><p><small>来源指纹 ' + esc(plan['verifiedSourceFingerprint']) + '<br>计划 ' + esc(plan['planId']) +
        ' · 图状态 ' + esc(plan['state']) + ' · 图输入绑定 ' + esc(plan['graphInputBound']) + ' · 动态证据绑定 ' + esc(plan['dynamicEvidenceBound']) +
        '</small></p><details><summary>图截断、未解析调用与覆盖边界</summary><pre>' + coverage +
        '</pre></details><details><summary>实际记录的动作转换（非分支覆盖率）</summary><pre>' + transitions +
        '</pre></details><label for="filter">按函数名筛选验证计划</label><input id="filter" placeholder="deposit / redeem / claim …"><div id="results">' +
        ''.join(rows) + '</div><footer><b>证据限制</b><ul>' + ''.join('<li>' + esc(x) + '</li>' for x in plan['limitations']) +
        '</ul></footer></main><script>document.getElementById("filter").addEventListener("input",function(){const q=this.value.toLowerCase();document.querySelectorAll("article").forEach(function(x){x.hidden=!x.dataset.search.includes(q)})})</script></html>')


def write_artifacts(report, graph, local, output_dir):
    plan = build_plan(report, graph, local)
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    for name, value in (('discovery-plan.json', json.dumps(plan, ensure_ascii=False, indent=2, allow_nan=False) + '\n'),
                        ('discovery-plan.html', render_html(plan))):
        target = folder / name
        temp = target.with_suffix(target.suffix + '.tmp')
        temp.write_text(value, encoding='utf-8')
        os.replace(temp, target)
    return {key: value for key, value in plan.items() if key not in ('obligations', 'sequenceObservation', 'limitations')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--graph', type=Path, required=True)
    parser.add_argument('--dynamic', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text())
        graph = json.loads(args.graph.read_text())
        local = json.loads(args.dynamic.read_text()) if args.dynamic else report.get('localTests', {})
        if args.output.exists():
            raise ValueError('output directory must be new; preserve prior evidence')
        summary = write_artifacts(report, graph, local, args.output)
        print(json.dumps(summary, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({'state': 'failed', 'error': str(error)}, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    sys.exit(main())
