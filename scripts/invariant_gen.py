"""Generate unverified protocol invariants from unified source IR evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
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


def _state_names(document):
    names = set()
    refs = {}
    for item in document.get('storageAccesses', []):
        if not isinstance(item, dict):
            continue
        effect = item.get('effect') if isinstance(item.get('effect'), dict) else item
        variable = effect.get('variable') or effect.get('name')
        if isinstance(variable, str) and variable:
            short = variable.rsplit('.', 1)[-1]
            names.add(short.lower())
            refs.setdefault(short.lower(), []).append(item.get('sourceRef') or effect.get('location'))
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


def _has_feature(function_names, state_names, feature):
    return any(feature in name for name in function_names) or feature in state_names


def detect_roles(document):
    if not isinstance(document, dict):
        raise ValueError('unified IR must be an object')
    functions = document.get('functions')
    if not isinstance(functions, list):
        raise ValueError('unified IR requires a functions array')
    function_names = [_function_name(item).lower() for item in functions if isinstance(item, dict)]
    state_names, _ = _state_names(document)
    roles = []
    erc4626_features = {
        'accounting': (_has_feature(function_names, state_names, 'totalassets') and
                       _has_feature(function_names, state_names, 'totalsupply')),
        'entrypoints': all(any(name.split('(')[0].endswith('.' + required) or
                               name.split('(')[0].endswith('::' + required) or
                               name.split('(')[0] == required for name in function_names)
                           for required in ('deposit', 'withdraw', 'redeem', 'mint')),
    }
    if all(erc4626_features.values()):
        roles.append('erc4626')
    lending_features = {
        'totalBorrows': _has_feature(function_names, state_names, 'totalborrows'),
        'totalSupply': _has_feature(function_names, state_names, 'totalsupply'),
        'riskField': (_has_feature(function_names, state_names, 'healthfactor') or
                      _has_feature(function_names, state_names, 'liquidationthreshold')),
    }
    if all(lending_features.values()):
        roles.append('lending_pool')
    return roles, {'erc4626': erc4626_features, 'lending_pool': lending_features}


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
    invariants = []
    for role in roles:
        if role == 'erc4626':
            feature_names = ('totalassets', 'totalsupply', 'deposit', 'withdraw', 'redeem', 'mint')
            substitutions = {'decimals': decimals}
        else:
            feature_names = ('totalborrows', 'totalsupply', 'healthfactor', 'liquidationthreshold', 'borrow', 'liquidat')
            risk_field = 'healthFactor' if _has_feature([_function_name(item).lower() for item in document['functions'] if isinstance(item, dict)], set(), 'healthfactor') else 'liquidationThreshold'
            substitutions = {'decimals': decimals, 'riskField': risk_field}
        refs = _source_refs(document, feature_names)
        for template in TEMPLATES[role]:
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
