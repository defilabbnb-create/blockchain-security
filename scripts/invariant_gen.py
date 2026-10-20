"""Generate unverified protocol invariants from unified source IR evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

try:
    from invariant_templates import TEMPLATES
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from invariant_templates import TEMPLATES


def _canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _function_name(function):
    return str(function.get('name') or '')


def _signature(function):
    """Return a normalized ABI-like signature and its base name."""
    raw = _function_name(function).strip()
    match = re.search(r'([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)$', raw)
    if not match:
        return None, None
    base, raw_params = match.groups()
    params = []
    depth = 0
    token = []
    chunks = []
    for char in raw_params:
        if char == ',' and depth == 0:
            chunks.append(''.join(token).strip())
            token = []
            continue
        token.append(char)
        if char in '([':
            depth += 1
        elif char in ')]' and depth:
            depth -= 1
    if token or raw_params.strip():
        chunks.append(''.join(token).strip())
    for param in chunks:
        # IR may contain ABI types with parameter names or storage locations.
        cleaned = re.sub(r'\s+(memory|calldata|storage)\b', '', param).strip()
        cleaned = re.sub(r'\s+[A-Za-z_$][A-Za-z0-9_$]*$', '', cleaned)
        params.append(cleaned.replace(' ', ''))
    return f'{base}({",".join(params)})', base


def _function_base(function):
    return _signature(function)[1]


def _function_matches(function, required):
    base = _function_base(function)
    if not base:
        return False
    if base == required:
        return True
    # Accept protocol prefixes such as vaultDeposit while avoiding arbitrary
    # substring matches such as depositToken or totalAssetsSnapshot.
    return bool(re.search(rf'(?:^|[_$]){re.escape(required)}$', base, re.I) or
                base.lower().endswith(required.lower()))


def _return_types(function):
    values = function.get('returns')
    if values is None:
        values = function.get('returnTypes', function.get('outputs', function.get('returnType')))
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    result = []
    for value in values:
        if isinstance(value, dict):
            value = value.get('type') or value.get('internalType') or value.get('name')
        if isinstance(value, str):
            result.append(re.sub(r'\s+', '', value).lower())
    return result


def _state_details(document):
    names = set()
    types = {}
    refs = {}
    for item in document.get('storageAccesses', []):
        if not isinstance(item, dict):
            continue
        effect = item.get('effect') if isinstance(item.get('effect'), dict) else item
        variable = effect.get('variable') or effect.get('name')
        if not isinstance(variable, str) or not variable:
            continue
        short = variable.rsplit('.', 1)[-1]
        key = short.lower()
        names.add(key)
        variable_type = (effect.get('type') or effect.get('variableType') or
                         effect.get('stateVariableType') or item.get('type'))
        if isinstance(variable_type, str):
            types[key] = re.sub(r'\s+', '', variable_type).lower()
        refs.setdefault(key, []).append(item.get('sourceRef') or effect.get('location'))
    return names, types, refs


def _state_names(document):
    names, _, refs = _state_details(document)
    return names, refs


def _decimals(document):
    contract = document.get('contract') if isinstance(document.get('contract'), dict) else {}
    candidates = [contract.get('decimals'), contract.get('tokenDecimals')]
    metadata = contract.get('metadata') if isinstance(contract.get('metadata'), dict) else {}
    candidates.extend((metadata.get('decimals'), metadata.get('tokenDecimals')))
    for parameter in document.get('parameters', []):
        if isinstance(parameter, dict) and str(parameter.get('name', '')).lower() in ('decimals', 'tokendecimals'):
            candidates.extend((parameter.get('value'), parameter.get('precision')))
    for value in candidates:
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255:
            return value
        if isinstance(value, str) and value.isdecimal() and 0 <= int(value) <= 255:
            return int(value)
    return None


def _source_refs(document, names):
    refs = []
    for function in document.get('functions', []):
        if not isinstance(function, dict):
            continue
        name = _function_name(function).lower()
        if any(candidate in name for candidate in names):
            ref = function.get('sourceRef')
            if isinstance(ref, dict):
                refs.append({'kind': 'function', 'name': function.get('name'), **ref})
    for operation in document.get('operations', []):
        if not isinstance(operation, dict):
            continue
        effect = operation.get('effect') if isinstance(operation.get('effect'), dict) else operation
        variable = str(effect.get('variable') or '').lower()
        if any(candidate in variable for candidate in names):
            ref = operation.get('sourceRef') or effect.get('location')
            if isinstance(ref, dict):
                refs.append({'kind': 'storage_effect', 'variable': effect.get('variable'), **ref})
    unique = {}
    for ref in refs:
        key = json.dumps(ref, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        unique[key] = ref
    return [unique[key] for key in sorted(unique)]


def _call_graph_features(document):
    graph = document.get('callGraph') or document.get('call_graph') or []
    if isinstance(graph, dict):
        graph = graph.get('edges', graph.get('calls', []))
    edges = graph if isinstance(graph, list) else []
    normalized = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        caller = str(edge.get('caller') or edge.get('from') or '').lower()
        callee = str(edge.get('callee') or edge.get('to') or '').lower()
        if caller and callee:
            normalized.append((caller, callee))
    return normalized


def _role_feature(document, name, matched, missing):
    total = len(matched) + len(missing)
    confidence = round(len(matched) / total, 4) if total else 0.0
    return {
        'confidence': confidence,
        'matchedFeatures': sorted(matched),
        'missingFeatures': sorted(missing),
        # Keep the old boolean feature contract for callers that consume it.
        **{name: True},
    }


def detect_roles(document):
    if not isinstance(document, dict):
        raise ValueError('unified IR must be an object')
    functions = document.get('functions')
    if not isinstance(functions, list):
        raise ValueError('unified IR requires a functions array')
    functions = [item for item in functions if isinstance(item, dict)]
    state_names, state_types, _ = _state_details(document)
    call_edges = _call_graph_features(document)
    roles = []
    details = {}

    def score_role(role, required):
        matched, missing = [], []
        for label, predicate in required:
            (matched if predicate else missing).append(label)
        total = len(matched) + len(missing)
        confidence = round(len(matched) / total, 4) if total else 0.0
        detail = {
            'confidence': confidence,
            'matchedFeatures': sorted(matched),
            'missingFeatures': sorted(missing),
            'threshold': 0.7,
        }
        details[role] = detail
        if confidence >= 0.7:
            roles.append(role)

    def has_method(name):
        return any(_function_matches(function, name) for function in functions)

    def has_returning(name, return_type='uint256'):
        return any(_function_matches(function, name) and return_type.lower() in _return_types(function)
                   for function in functions)

    # Atomic features make it impossible for a lending-only myTotalAssets()
    # helper to satisfy the ERC4626 role by substring coincidence.
    score_role('erc4626', [
        ('state.totalAssets', 'totalassets' in state_names),
        ('state.totalSupply', 'totalsupply' in state_names),
        ('function.deposit', has_method('deposit')),
        ('function.withdraw', has_method('withdraw')),
        ('function.redeem', has_method('redeem')),
        ('function.mint', has_method('mint')),
        ('function.convertToShares:uint256', has_returning('convertToShares')),
        ('function.convertToAssets:uint256', has_returning('convertToAssets')),
    ])
    risk_health = 'healthfactor' in state_names or has_method('healthFactor')
    score_role('lending_pool', [
        ('state.totalBorrows', 'totalborrows' in state_names),
        ('state.totalSupply', 'totalsupply' in state_names),
        ('function.borrow', has_method('borrow')),
        ('function.liquidate', has_method('liquidate')),
        ('risk.healthFactorOrLiquidationThreshold', risk_health or
         'liquidationthreshold' in state_names or has_method('liquidationThreshold')),
    ])
    score_role('amm_pool', [
        ('state.reserve0', 'reserve0' in state_names),
        ('state.reserve1', 'reserve1' in state_names),
        ('function.swap', has_method('swap')),
        ('function.syncOrSkim', has_method('sync') or has_method('skim')),
        ('callGraph.swapToReserve', any('swap' in caller and ('reserve' in callee or 'sync' in callee)
                                        for caller, callee in call_edges) or not call_edges),
    ])
    score_role('staking_reward', [
        ('state.rewardPerTokenOrRate', 'rewardpertoken' in state_names or 'rewardrate' in state_names),
        ('function.stake', has_method('stake')),
        ('function.withdraw', has_method('withdraw')),
        ('function.claimOrGetReward', has_method('claim') or has_method('getReward') or has_method('claimRewards')),
        ('function.rewardView', has_method('earned') or has_method('rewardPerToken')),
    ])
    return roles, details


def generate_invariants(document, *, source_sha256=None):
    roles, role_features = detect_roles(document)
    digest = _canonical_hash(document)
    decimals = _decimals(document)
    contract = document.get('contract') if isinstance(document.get('contract'), dict) else {}
    ir_source_sha256 = contract.get('sourceSha256') or contract.get('analysisInputFingerprint')
    if not isinstance(ir_source_sha256, str) or len(ir_source_sha256) != 64:
        ir_source_sha256 = digest
    if source_sha256 is None:
        source_sha256 = ir_source_sha256
    if not isinstance(source_sha256, str) or len(source_sha256) != 64:
        raise ValueError('source_sha256 must be a SHA-256 digest')
    role_templates = {
        'erc4626': tuple(TEMPLATES.get('erc4626', ())) + (
            {'template': 'first_deposit_no_inflation', 'name': '首存不产生通胀',
             'description': '首笔存款和随后捐赠不应让攻击者无成本抽取后续存款价值。',
             'params': {'assetsField': 'totalAssets', 'sharesField': 'totalSupply', 'toleranceBps': 0, 'decimals': '$decimals'}},
            {'template': 'rounding_direction_correct', 'name': '舍入方向偏向协议',
             'description': '份额和资产换算的整数舍入误差应始终偏向协议而非存取款用户。',
             'params': {'assetsField': 'totalAssets', 'sharesField': 'totalSupply', 'toleranceBps': 0, 'decimals': '$decimals'}},
        ),
        'amm_pool': (
            {'template': 'k_never_decreases', 'name': '恒定乘积不下降',
             'description': '交换后储备乘积不应在未记录费用的情况下下降。',
             'params': {'reserve0Field': 'reserve0', 'reserve1Field': 'reserve1', 'toleranceBps': 0}},
            {'template': 'fee_conserved', 'name': '手续费守恒',
             'description': '手续费应进入协议或流动性提供者账本，不应凭空消失。',
             'params': {'feeField': 'fee', 'reserve0Field': 'reserve0', 'reserve1Field': 'reserve1', 'toleranceBps': 0}},
            {'template': 'oracle_assumption_holds', 'name': '预言机假设成立',
             'description': '交易价格和外部预言机读数应满足调用方声明的边界。',
             'params': {'oracleField': 'oracle', 'maxDeviationBps': 0}},
        ),
        'staking_reward': (
            {'template': 'reward_accrual_conserves_value', 'name': '奖励累计守恒',
             'description': '奖励累计指数与用户可领取余额应保持一致。',
             'params': {'rewardPerTokenField': 'rewardPerToken', 'rewardRateField': 'rewardRate', 'toleranceBps': 0}},
            {'template': 'stake_withdraw_preserves_shares', 'name': '质押份额守恒',
             'description': '质押和提取操作不应无故改变其他用户的份额。',
             'params': {'totalStakedField': 'totalStaked', 'totalSharesField': 'totalShares', 'toleranceBps': 0}},
        ),
    }
    invariants = []
    for role in roles:
        if role == 'erc4626':
            feature_names = ('totalassets', 'totalsupply', 'deposit', 'withdraw', 'redeem', 'mint')
            substitutions = {'decimals': decimals}
            templates = role_templates['erc4626']
        elif role == 'lending_pool':
            feature_names = ('totalborrows', 'totalsupply', 'healthfactor', 'liquidationthreshold', 'borrow', 'liquidat')
            risk_field = 'healthFactor' if ('healthfactor' in _state_details(document)[0] or
                                             any(_function_matches(item, 'healthFactor') for item in document['functions'] if isinstance(item, dict))) else 'liquidationThreshold'
            substitutions = {'decimals': decimals, 'riskField': risk_field}
            templates = TEMPLATES.get(role, ())
        else:
            feature_names = tuple(sorted({part for label in role_features.get(role, {}).get('matchedFeatures', [])
                                          for part in re.findall(r'[A-Za-z][A-Za-z0-9]+', label)}))
            substitutions = {}
            templates = role_templates.get(role, ())
        refs = _source_refs(document, feature_names)
        for template in templates:
            params = {key: (substitutions.get(value[1:]) if isinstance(value, str) and value.startswith('$') else value)
                      for key, value in template['params'].items()}
            identity = {'role': role, 'template': template['template'], 'sourceSha256': source_sha256,
                        'params': params, 'sourceRefs': refs}
            invariants.append({
                'invariantId': hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False,
                    separators=(',', ':')).encode('utf-8')).hexdigest(),
                'role': role,
                'template': template['template'],
                'name': template['name'],
                'description': template['description'],
                'params': params,
                'sourceRefs': refs,
                'generatedTestPath': None,
                'status': 'unverified',
            })
    unresolved = []
    if not roles:
        unresolved.append('未识别到受支持的协议角色特征组合。')
    if roles and decimals is None:
        unresolved.append('IR 未记录 token decimals；精度相关参数保持 null。')
    return {
        'schemaVersion': 1,
        'state': 'available' if invariants else 'template_unavailable',
        'sourceSha256': source_sha256,
        'declaredSourceBundleSha256': ir_source_sha256,
        'sourceIrDocumentId': document.get('documentId'),
        'sourceIrSha256': digest,
        'detectedRoles': roles,
        'roleFeatures': role_features,
        'unresolved': unresolved,
        'invariants': invariants,
    }


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump(value, output, ensure_ascii=False, indent=2, allow_nan=False)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('unified_ir', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    document = json.loads(args.unified_ir.read_text(encoding='utf-8'))
    result = generate_invariants(document)
    if args.output:
        _atomic_json(args.output, result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
