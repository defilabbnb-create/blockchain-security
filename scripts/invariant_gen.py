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

# 前缀与词根，用于从 ABI 推断特权入口点。
#
# 固定的候选名表只能覆盖写它时想到的那些协议；合约把所有权 setter 叫
# `changeOwner`、把升级 setter 叫 `setImplementation` 时一个都匹配不上，于
# 是明明 ABI 里列着入口点，却被记成需要适配器而无法执行。真正区分特权入口的
# 是它的命名，而不是某一份枚举名单。
_PRIVILEGED_PREFIXES = (
    "set", "change", "update", "transfer", "replace", "assign",
    "grant", "revoke", "pause", "unpause", "destroy", "kill", "close", "withdraw",
)
_PRIVILEGED_WORDS = (
    "owner", "admin", "implementation", "price", "fee", "rate", "limit",
    "authority", "operator", "guardian", "minter", "burner",
)

# A getter name reaches generated Solidity as an identifier, so anything that is
# not a plain identifier is rejected before it can be substituted into a call.
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

try:
    from invariant_templates import TEMPLATES
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from invariant_templates import TEMPLATES

try:
    from invariant_templates_vuln import TEMPLATES as VULNERABILITY_TEMPLATES
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from invariant_templates_vuln import TEMPLATES as VULNERABILITY_TEMPLATES

try:
    from invariant_assertions._common import encoded_entry_call
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from invariant_assertions._common import encoded_entry_call

# 角色名 -> 漏洞类模板表的键。
#
# 模板表是按"断言性质"命名的（`reentrancy_guard_rechecked`），检测器报出的
# 角色名却按类别命名（`reentrancy`）。两者只差一个后缀，直接用角色查表会对
# 13 个角色中的 9 个返回空，于是整个基准套件生成不出任何断言。显式列出对应
# 关系，而不是靠前缀或去后缀猜测：猜测会把 `access_control` 和
# `access_control_guard_present` 这类同源但语义不同的名字错并到一起。
#
# 未列出的角色没有可用断言，产出 0 条断言是正确的；给它编一条断言才是错的。
_VULNERABILITY_TEMPLATE_ALIASES = {
    'reentrancy': 'reentrancy_guard_rechecked',
    'access_control': 'access_control_guard_present',
    'unchecked_low_level_call': 'unchecked_low_level_call',
    'bad_randomness': 'bad_randomness',
    'arithmetic': 'arithmetic',
    'denial_of_service': 'denial_of_service',
}


def _module(filename, name):
    """Load one of this repository's hyphenated modules by path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'module_unavailable:{filename}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


# Semantic anchors for vulnerability classes.  Unlike the protocol roles, these
# are deliberately independent of interface completeness: the benchmark corpus
# is made of deliberately minimal teaching contracts, so requiring a full
# reference interface would reject genuine instances while accepting none.
# Each anchor is a property that only holds when the class is actually present,
# so an unrelated contract (an overflow sample, a plain ERC20) stays unmatched.
#
# Each entry is (label, predicate).  A role is confirmed when *any* of its
# anchors matches; confidence then still reflects how many supporting features
# were found, so a weak match is visible in the evidence.
VULNERABILITY_ANCHORS = {
    # An external value-bearing call followed by the write of the ledger it
    # debited.  The source decides this: the IR orders some calls correctly but
    # omits others entirely, so it cannot be the only witness.
    'reentrancy': [
        ('source.callBeforeLedgerWrite',
         lambda ctx: bool(ctx['source'].get('reentrancyCandidateCount'))),
        ('ir.callBeforeStateUpdate',
         lambda ctx: ctx['call_order']['external_before_write']),
    ],
    # A privileged write reached without an authentication modifier.
    'access_control': [
        ('source.privilegedEntryUnguarded',
         lambda ctx: bool(ctx['source'].get('unguardedPrivilegedEntries'))),
    ],
    # Arithmetic that can wrap or truncate silently.
    'arithmetic': [
        ('source.uncheckedBlockOrCast',
         lambda ctx: bool(ctx['source'].get('arithmetic'))),
        ('ir.arithmetic.uncheckedCast',
         lambda ctx: ctx['arithmetic']['unchecked_cast']),
    ],
    # Randomness or block-derived value gating an outcome.
    'bad_randomness': [
        # A block-derived value is the seed; a caller-supplied one only matters
        # when it is the seed.  `msg.sender` appears in almost every contract, so
        # on its own it says nothing about predictability and must not be an
        # anchor: doing so labelled all three clean samples.
        ('random.blockDerived',
         lambda ctx: bool(ctx['source'].get('blockDerivedValue'))),
        ('random.blockHashSeed',
         lambda ctx: bool(ctx['source'].get('blockHashUsed'))),
    ],
    # Attacker-controlled collection size driving unbounded work.
    'denial_of_service': [
        ('dos.collectionDrivenLoop',
         lambda ctx: bool(ctx['source'].get('loopCount')) and
         bool(ctx['source'].get('dynamicCollection'))),
    ],
    # A low-level call whose return value is discarded while value moves.  This
    # distinction exists only in the source: the IR records that the call
    # happened and where its result was bound, but never whether the source read
    # it, so an IR-only rule flags every value-bearing call.
    'unchecked_low_level_call': [
        ('call.uncheckedReturn',
         lambda ctx: bool(ctx['source'].get('uncheckedCallCount'))),
    ],
    # Order-dependent payout: a pending transaction can pre-empt the claim.  The
    # source decides this, and it is a different question from whether the
    # payment's return value was read, so it gets its own signal.
    'front_running': [
        ('frontRunning.mempoolObservablePayout',
         lambda ctx: bool(ctx['source'].get('frontRunning'))),
    ],
    # Time gating a payout.  Distinguished from bad_randomness by use, not by the
    # block-derived value itself: both read `now`, but only one of them decides
    # whether value may be claimed, so the anchor looks for the value beside a
    # payout condition rather than for the read alone.
    'time_manipulation': [
        ('time.timestampGatesPayout',
         lambda ctx: bool(ctx['source'].get('timestampGatesPayout'))),
    ],
    # Implementation pointer replaced at runtime without an access check.
    'unprotected_upgrade': [
        ('upgrade.unprotectedPointer',
         lambda ctx: bool(ctx['source'].get('unprotectedPointer'))),
    ],
    # Return value of an external dependency trusted without a bound.
    'unchecked_cross_contract_assumption': [
        ('cross.unboundedReturn',
         lambda ctx: bool(ctx['crossing']['unbounded_return'])),
    ],
    # DASP-10 classes the vocabulary previously had no room for.  Each is
    # reported from a source observation, because none of them is visible in the
    # IR: the EVM's own decoding rules and a caller's freshness discipline both
    # live outside the operation graph.
    'short_addresses': [
        ('source.addressRepackedWithoutPadding',
         lambda ctx: bool(ctx['source'].get('shortAddressPropagation'))),
    ],
    'incorrect_interface': [
        ('source.callResultConsumedBeyondItsWidth',
         lambda ctx: bool(ctx['source'].get('incorrectInterfaceUse'))),
    ],
    'oracle_stale_price': [
        ('source.priceReadWithoutFreshnessBound',
         lambda ctx: bool(ctx['source'].get('oracleStalePrice'))),
    ],
}


def _call_operations(document):
    """Return the operation rows that describe a call or a state write."""
    rows = []
    for operation in document.get('operations', []) or []:
        if isinstance(operation, dict):
            rows.append(operation)
    return rows


def _operation_effect(operation):
    effect = operation.get('effect') if isinstance(operation.get('effect'), dict) else operation
    return effect


def _is_ledger_write(operation):
    """Whether this state write updates a balance or ledger a payout can re-enter.

    Reentrancy needs the write to be the accounting the external call invalidates.
    The IR records the written field and the written expression, and both are
    read here:

    * a field whose name is a balance/ledger/share/supply/debt quantity, or a
      subscripted entry of one (``balances[msg.sender] -= ...``);
    * an expression that is a compound update (``-=``, ``+=``) of such a field.

    A one-shot flag (``payedOut = true``) and a plain bookkeeping write
    (``reward = msg.value``) are deliberately excluded: neither is the accounting
    a callback can double-spend, so a payout followed by one of them is not
    evidence of reentrancy.
    """
    effect = _operation_effect(operation)
    if str(effect.get('kind') or '').lower() != 'state_write':
        return False
    field = _operation_field(operation)
    expression = effect.get('expression')
    expression = expression if isinstance(expression, str) else ''
    if field is None and not expression:
        return False
    text = f"{field or ''} {expression}"
    return bool(_LEDGER_WRITE_RE.search(text))


_LEDGER_WRITE_RE = re.compile(
    r'\b(?:balances?|ledger|shares?|supply|totalSupply|totalAssets|deposits?|'
    r'allowances?|debts?|credits?|stakes?|positions?|amounts?|withdrawable|'
    r'redeemable|claimable|owed|principal)\b', re.I)


def _operation_field(operation):
    """Return the state field an operation reads or writes, if the IR names one.

    Reentrancy is only possible when the write after the call touches the same
    field the call drew its value from, so the ordering rule needs the field
    identity rather than just the offsets.  ``None`` means the IR recorded no
    field, in which case the caller cannot conclude a match and stays silent.
    """
    effect = _operation_effect(operation)
    for key in ('variable', 'field', 'stateVariable', 'target'):
        value = effect.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    variable = effect.get('variable')
    if isinstance(variable, dict):
        name = variable.get('name')
        if isinstance(name, str) and name.strip():
            return name.strip()
    return None


def _operation_offset(operation):
    """Return the source offset the IR recorded for an operation.

    The IR orders evidence by ``location.start``, which is the byte offset in the
    verified source.  Ordering a call against the write it invalidates needs that
    offset; the array position alone is not reliable because operations are
    grouped per function rather than sorted.
    """
    effect = _operation_effect(operation)
    location = effect.get('location') if isinstance(effect.get('location'), dict) else {}
    start = location.get('start')
    return start if isinstance(start, int) else None


def _operation_order(document):
    """Compute the call/write ordering facts the anchors depend on.

    ``external_before_write`` is the reentrancy signature: within one function, a
    value-bearing external call whose source offset precedes the state write that
    records its effect.  Ordering is evaluated per ``functionId`` so that a write
    in a different entrypoint cannot mask or manufacture the signal.  When the IR
    records no ordering at all the facts stay False rather than defaulting to a
    match.
    """
    external_before_write = False
    value_bearing = False
    by_function: dict[Any, list] = {}
    for operation in _call_operations(document):
        key = operation.get('functionId')
        by_function.setdefault(key, []).append(operation)

    for rows in by_function.values():
        calls = []
        writes = []
        for row in rows:
            effect = _operation_effect(row)
            kind = str(effect.get('kind') or '').lower()
            offset = _operation_offset(row)
            if kind == 'external_call':
                # ``sendsValue`` is the IR's own verdict; ``valueTransferEvidence``
                # carries the symbolic expression when the verdict is unknown.
                sends = effect.get('sendsValue')
                evidence = effect.get('valueTransferEvidence')
                if sends is None and isinstance(evidence, dict):
                    sends = evidence.get('state') == 'known' and bool(evidence.get('expression'))
                moves = sends is True or bool(
                    isinstance(evidence, dict) and evidence.get('expression'))
                if moves:
                    value_bearing = True
                calls.append((offset, bool(moves), effect))
            elif kind == 'state_write':
                writes.append((offset, row))
        if not calls or not writes:
            continue
        for offset, moves, effect in calls:
            if offset is None or not moves:
                continue
            # The write this call invalidates is the first one recorded after it
            # *to the same field the call drew on*.  Requiring a later write at
            # all is too weak: `payedOut = true; winner.send(winAmount)` and
            # `msg.sender.transfer(reward); reward = msg.value` both record a
            # write after a value-bearing call, but neither writes a balance or
            # ledger entry, so a callback cannot drain anything through them.
            # That shape reported reentrancy on two samples whose ground truth is
            # front running and unchecked low-level calls respectively.
            later = [row for value, row in writes if value is not None and value > offset]
            if not later:
                continue
            if not any(_is_ledger_write(row) for row in later):
                continue
            external_before_write = True
            break
    # Explicit declaration wins over inference from ordering metadata.
    for flag in ('callBeforeStateUpdate', 'externalCallBeforeStateUpdate'):
        if document.get(flag) is True:
            external_before_write = True
    return {'external_before_write': external_before_write, 'value_bearing': value_bearing}


def _access_facts(document, functions, state_names):
    """Facts about privileged-state access control.

    Risk needs an explicit declaration.  A contract that merely has a
    ``withdraw`` function is not therefore unguarded: the modifier may be in the
    IR as an annotation, and inferring "unguarded" from the absence of a token
    would mislabel every correctly protected withdrawal function.
    """
    explicit = document.get('accessControl')
    if isinstance(explicit, dict):
        return {'privileged_unauthenticated': bool(explicit.get('unauthenticated')),
                'write_without_auth_guard': bool(explicit.get('unguarded'))}
    return {'privileged_unauthenticated': False, 'write_without_auth_guard': False}


def _arithmetic_facts(document, state_names, operations):
    """Facts about arithmetic risk.

    Field *naming* is not evidence: a plain ERC20 has `balances` and `totalSupply`
    yet no arithmetic defect, so a name-based rule would hand every token the
    arithmetic class.  Risk requires an explicit declaration, or an operation the
    IR actually recorded as a wrapping or truncating computation.
    """
    explicit = document.get('arithmetic')
    if isinstance(explicit, dict):
        return {'on_value_field': bool(explicit.get('onValueField')),
                'unchecked_cast': bool(explicit.get('uncheckedCast'))}
    wrapping = any(token in str(_operation_effect(operation).get('expression') or '').lower()
                   for operation in operations
                   for token in ('unchecked', 'uint(', 'int(', 'wrap'))
    # Solidity >=0.8 reverts on overflow, so the IR is only asked to confirm that
    # a value field exists and is written; the defect signal is the cast.
    value_written = bool({name for name in state_names
                          if any(token in name for token in
                                 ('total', 'amount', 'balance', 'supply', 'price',
                                  'asset', 'share', 'debt', 'reserve'))})
    return {'on_value_field': value_written and wrapping, 'unchecked_cast': wrapping}


def _randomness_facts(document):
    """Facts about randomness source.

    Only an explicit declaration counts.  Probing the serialized document for
    tokens such as ``now`` would match a contract that mentions the keyword in a
    comment, and the rendered assertion would then claim a manipulable source the
    IR never recorded.
    """
    explicit = document.get('randomness')
    if isinstance(explicit, dict):
        return {'block_derived': bool(explicit.get('blockDerived')),
                'known_seed': bool(explicit.get('knownSeed'))}
    return {'block_derived': False, 'known_seed': False}


def _dos_facts(document, state_names):
    """Facts about unbounded work.

    Requires an explicit declaration or an operation row the IR marked as a
    collection traversal; state naming alone is not evidence.
    """
    explicit = document.get('denialOfService')
    if isinstance(explicit, dict):
        return {'collection_driven_loop': bool(explicit.get('collectionDrivenLoop'))}
    collection = bool({name for name in state_names
                       if any(token in name for token in
                              ('array', 'list', 'queue', 'items', 'members',
                               'contributors', 'players', 'entries'))})
    loop = any(str(_operation_effect(row).get('kind') or '').lower() in
               ('loop', 'for_loop', 'while_loop', 'collection_iteration')
               for row in _call_operations(document))
    return {'collection_driven_loop': collection and loop}


def _call_facts(document):
    """Facts about low-level call handling.

    The distinction that matters is whether a value-bearing call's success is
    bound to a variable or discarded.  Only an explicit declaration or an IR
    operation row that actually carries the call is treated as evidence; a
    substring scan over the whole document would match any contract that merely
    mentions a call in a comment or an interface declaration.
    """
    explicit = document.get('lowLevelCalls')
    if isinstance(explicit, dict):
        return {'unchecked_return': bool(explicit.get('uncheckedReturn')),
                'low_level_value_transfer': bool(explicit.get('valueTransfer'))}
    rows = _call_operations(document)
    value_transfer = False
    unchecked = False
    for row in rows:
        effect = _operation_effect(row)
        if str(effect.get('kind') or '').lower() != 'external_call':
            continue
        sends = effect.get('sendsValue')
        evidence = effect.get('valueTransferEvidence')
        symbolic = isinstance(evidence, dict) and bool(evidence.get('expression'))
        moves = sends is True or (sends is None and symbolic)
        value_transfer = value_transfer or moves
        # ``callType`` records what the call returns into.  The IR writes the
        # result to a TMP binding when the source binds it; an expression with no
        # assignment to a named variable is the unchecked form.
        expression = str(effect.get('expression') or '')
        bound = '=' in expression.split('LOW_LEVEL_CALL')[0]
        if moves and str(effect.get('callKind') or '').lower() in ('low_level', 'send', 'transfer') \
                and not bound and effect.get('checked') is not True:
            unchecked = True
    return {'unchecked_return': unchecked, 'low_level_value_transfer': value_transfer}


def _ordering_facts(document):
    explicit = document.get('ordering')
    if isinstance(explicit, dict):
        return {'result_observable': bool(explicit.get('resultObservable'))}
    return {'result_observable': False}


def _time_facts(document):
    explicit = document.get('timeDependence')
    if isinstance(explicit, dict):
        return {'timestamp_gate': bool(explicit.get('timestampGate'))}
    return {'timestamp_gate': False}


def _upgrade_facts(document, state_names):
    explicit = document.get('upgradeability')
    if isinstance(explicit, dict):
        return {'unprotected_pointer': bool(explicit.get('unprotectedPointer'))}
    return {'unprotected_pointer': False}


def _crossing_facts(document):
    """Facts about a trusted external return value.

    The IR marks a cross-contract entry explicitly; the signal that it is
    *unchecked* is the absence of a recorded bound on the returned value.  Both
    sides must come from the same operation row: an external call plus an
    unrelated `require` elsewhere in the contract says nothing about whether that
    call's result is bounded, and treating them as a pair mislabels every
    contract that validates something else.
    """
    explicit = document.get('crossContract')
    if isinstance(explicit, dict):
        return {'unbounded_return': bool(explicit.get('unboundedReturn'))}
    for row in _call_operations(document):
        effect = _operation_effect(row)
        kind = str(effect.get('kind') or '').lower()
        if kind not in ('external_call', 'interface_call', 'delegate_call'):
            continue
        # The IR records whether the call's result was bound or checked; an
        # unchecked external call is one that returns into no variable and
        # carries no bound.  Neither flag being set is the weak case and is
        # reported as unknown rather than as a defect.
        if effect.get('resultBound') is False and effect.get('bounded') is not True:
            return {'unbounded_return': True}
    return {'unbounded_return': False}


def _vulnerability_context(document, functions, state_names):
    operations = _call_operations(document)
    return {
        'functions': functions,
        'state_names': state_names,
        'call_order': _operation_order(document),
        'access': _access_facts(document, functions, state_names),
        'arithmetic': _arithmetic_facts(document, state_names, operations),
        'randomness': _randomness_facts(document),
        'dos': _dos_facts(document, state_names),
        'calls': _call_facts(document),
        'ordering': _ordering_facts(document),
        'time': _time_facts(document),
        'upgrade': _upgrade_facts(document, state_names),
        'crossing': _crossing_facts(document),
    }


def _protocol_facts(document, functions, state_names):
    """Semantic facts that define a DeFi protocol role.

    Each fact pairs a protocol-defining function with the ledger it operates on.
    A function name alone is not enough -- ``totalAssets`` on a lending pool is a
    helper, not a vault -- so the pair is what makes the anchor specific.
    """
    def has(*names):
        return any(_function_matches(function, name)
                   for function in functions for name in names)

    return {
        'deposit_with_share_ledger': has('deposit') and ('totalsupply' in state_names),
        'assets_and_shares_ledger': ('totalassets' in state_names
                                     and 'totalsupply' in state_names
                                     and has('deposit', 'withdraw', 'redeem', 'mint')),
        'swap_with_reserves': has('swap') and bool({'reserve0', 'reserve1'} & state_names),
        'dual_reserves': {'reserve0', 'reserve1'} <= state_names,
        'borrow_with_risk': has('borrow') and bool({'healthfactor', 'liquidationthreshold'} & state_names),
        'debt_ledger': 'totalborrows' in state_names and has('borrow'),
        'stake_with_reward_ledger': (has('stake') and
                                     bool({'rewardpertoken', 'rewardrate'} & state_names)),
    }


def _is_zero_argument(function):
    """Whether an IR function entry takes no parameters.

    The rendered assertions call ``name()`` with an encoded empty argument list,
    so only a no-parameter entrypoint is usable.  ``_signature`` returns the
    normalised signature first and the bare base name second, so the parameter
    list is read out of the signature rather than from either return value.
    """
    signature = _signature(function)[0]
    if not isinstance(signature, str):
        return False
    match = re.search(r'\((.*)\)$', signature)
    if not match:
        return False
    return match.group(1).strip() == ''


def _first_getter(functions, *candidates):
    """Return the base name of the first *zero-argument* getter in the IR.

    The renderer emits a ``staticcall`` against ``name()``, so the entrypoint must
    take no parameters: `balanceOf(address)` would not be callable this way and
    resolving it would produce an assertion that reverts for the wrong reason.
    Returning None when nothing matches is deliberate -- the renderer then refuses
    to emit and the harness records the invariant as ``adapter_required`` instead
    of probing a field that may not exist.
    """
    for candidate in candidates:
        for function in functions:
            if not _function_matches(function, candidate):
                continue
            if _is_zero_argument(function):
                return candidate
    return None


def _first_entrypoint(functions, *candidates):
    """Return a ``name()`` selector for the first matching *zero-argument* entry.

    Same constraint as :func:`_first_getter`: the rendered snippet encodes the
    call with no arguments, so a parameterised entrypoint cannot be used and
    resolving one would produce a reverting assertion.
    """
    for candidate in candidates:
        for function in functions:
            if not _function_matches(function, candidate):
                continue
            if _is_zero_argument(function):
                return f'{candidate}()'
    return None


def _source_facts(document, source_text):
    """Source-level facts for one verified source, bound to its digest.

    The IR records that a call happened but not whether its return value was
    checked, and for some samples it records no call at all.  Reading the
    verified source closes both gaps.  The source is passed in by the caller
    rather than read here so that the digest already bound to this evidence can
    be compared with the bytes actually analysed.
    """
    module = _module('source_vuln_evidence.py', 'source_vuln_evidence_deep')
    return module.observe(source_text)


# Facts that are *local* to one compilation unit: they describe a shape inside a
# single file, so observing them per unit and merging is equivalent to observing
# the concatenated bundle.  Listing them explicitly keeps the merge honest --
# an unlisted key is taken from the concatenation, which is where a cross-unit
# artefact could survive.
_SOURCE_FACTS_CONJUNCTIVE = (
    # Each of these requires two different patterns to appear in the same text.
    # `observe()` intersects them, so two files that each carry one half (a
    # `price` field in DataTypes.sol and a `timestamp` word in IPool.sol) satisfy
    # the conjunction only after concatenation.  AaveProtocolDataProvider was
    # reported as a stale-price defect for exactly that reason, and it is a
    # read-only helper with no oracle of its own.  Merged per unit, neither
    # file qualifies on its own and the role stays absent.
    'oracleStalePrice',
)


def _source_units(source_text):
    """Split a source bundle back into the compilation units it was joined from.

    Callers that hold a multi-file bundle concatenate it with a blank line
    between files, because `observe()` reasons over one text and has no notion
    of a file boundary.  Splitting on the same separator recovers those units so
    that a conjunction can be decided inside one file.  A single-file bundle has
    no separator and passes through unchanged.
    """
    if not isinstance(source_text, str) or not source_text:
        return []
    return [unit for unit in source_text.split('\n\n') if unit.strip()]


def _source_facts_for_units(source_text):
    """Observe a bundle without letting one file satisfy another's conjunct.

    Conjunctive facts are evaluated per unit and the result is the union of the
    units' verdicts, so a class is reported when at least one file actually
    exhibits it.  Non-conjunctive facts are additive, so a single observation
    over the whole bundle already has the right meaning and keeps the exact
    counts and offsets the evidence reports.

    With no source the empty shape is returned so a caller never has to tell
    "nothing found" apart from "nothing looked at" by key presence.  Nothing
    here invents evidence: a unit with no observation stays absent.
    """
    module = _module('source_vuln_evidence.py', 'source_vuln_evidence_deep')
    units = _source_units(source_text)
    if not units:
        return module.observe('')
    if len(units) == 1:
        return module.observe(units[0])
    merged = module.observe('\n\n'.join(units))
    for key in _SOURCE_FACTS_CONJUNCTIVE:
        merged[key] = any(module.observe(unit).get(key) for unit in units)
    return merged


def _vulnerability_substitutions(document, role, source_text=None, abi_getters=None):
    """Resolve template parameters from the IR for one vulnerability class.

    Every value here names something the IR actually recorded.  An unresolvable
    parameter stays None, which makes the renderer decline rather than render an
    assertion against a field that may not exist.
    """
    functions = [item for item in document.get('functions', []) if isinstance(item, dict)]
    state_names, _, _ = _state_details(document)
    # The source observer already identified the exact ledger field the reentrant
    # call debited.  Preferring that name over a fixed candidate list is what lets
    # a minimal teaching contract that names its balance `creditOf` or
    # `userBalance` resolve instead of falling back to no parameter at all.
    source = {}
    if source_text:
        try:
            source = _source_facts_for_units(source_text)
        except Exception:
            source = {}
    observed_field = ''
    for candidate in source.get('reentrancyCandidates') or []:
        if isinstance(candidate, dict) and candidate.get('stateField'):
            observed_field = str(candidate['stateField'])
            break

    # `abi_getters` carries full signatures (`fee()`, `balances(address)`), so the
    # bare names are extracted here.  A zero-argument entry is the only shape a
    # scalar read can address; anything else is left to `_mapping_getter`.
    confirmed = set()
    for signature in (abi_getters or ()):
        match = (re.fullmatch(r'([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)', signature.strip())
                 if isinstance(signature, str) else None)
        if match and match.group(2).strip() == '':
            confirmed.add(match.group(1))

    # Keyed by the bare function name: every consumer looks a candidate up by name
    # and cares about its parameter list separately, so splitting the two here
    # keeps each lookup site reading only the part it needs.
    abi_parameters = {}
    for signature in (abi_getters or ()):
        match = (re.fullmatch(r'([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)', signature.strip())
                 if isinstance(signature, str) else None)
        if match:
            abi_parameters.setdefault(match.group(1), match.group(2))

    def confirmed_getter(candidates):
        """First candidate the compiler reports as a zero-argument getter.

        ``functions`` only holds user-written functions, so a `public uint256 fee`
        leaves no trace there even though `fee()` is callable.  Falling back to
        the compiled ABI keeps such contracts measurable; the name still comes
        from a compilation of the verified source rather than from naming alone.
        """
        for candidate in candidates:
            if candidate in confirmed:
                return candidate
        # `_state_details` lower-cases field names, so the lookup has to be
        # case-insensitive.  The ABI name is returned verbatim because that is the
        # spelling the callable actually has.
        for candidate in candidates:
            for name in confirmed:
                if name.lower() == candidate.lower():
                    return name
        return None

    def value_getter():
        for candidate in ('totalAssets', 'totalSupply', 'amount', 'balance',
                          'total', 'value', 'price', 'supply'):
            resolved = _first_getter(functions, candidate) or confirmed_getter([candidate])
            if resolved:
                return resolved
        if observed_field:
            # A public mapping getter is named after the field, capitalised, but
            # only when the field was declared public.  Confirming it against a
            # compilation keeps the name from being invented for a private field,
            # where no getter exists and the assertion would revert.  The same
            # field can also answer to an argument-taking form, so that is tried
            # too before giving up on the name the source observer identified.
            guess = observed_field[0].upper() + observed_field[1:]
            resolved = (_first_getter(functions, guess) or confirmed_getter([guess])
                        or _mapping_getter(guess) or _mapping_getter(observed_field))
            if resolved:
                return resolved
        # A `uint256 public fee` is both the field and the getter solc emits, so the
        # capitalised guess above never applies.  Any declared state field whose
        # name is a confirmed getter is readable state, so it can stand in for the
        # value slot: the field is taken from the IR, and the getter is taken from
        # the ABI, which together rule out a name that does not exist.
        for field in state_names:
            resolved = confirmed_getter([field])
            if resolved:
                return resolved
        # A `mapping(address => uint256) public balances` exposes `balances(address)`.
        # It is the single most common way a contract publishes a balance, and the
        # IR records no user-written function for it, so nothing above can reach
        # it.  The renderer reads the caller's own slot, which is a real, stable
        # balance rather than an unknown one.
        for field in state_names:
            resolved = _mapping_getter(field)
            if resolved:
                return resolved
        return None

    def _mapping_getter(field):
        """The `name(address)` getter solc emits for a public mapping, if any.

        Any non-empty parameter list is accepted because the renderer supplies the
        only argument it can supply safely -- the calling address -- and the ABI
        already proved such an entry exists.
        """
        for candidate in (field, field[0].upper() + field[1:], field.capitalize()):
            parameters = abi_parameters.get(candidate)
            if parameters:
                return f'{candidate}(address)'
        return None

    def ledger_getter():
        return value_getter()

    def observed_or(name, *candidates):
        """A getter for ``name`` if the contract exposes one, else the observed
        field's public getter when a compilation confirms it.

        A public mapping answers to ``balances(address)``, not ``balances()``, so
        the IR's bare field name has to be resolved against the ABI's parameter
        list rather than accepted on the strength of appearing in the document.
        """
        resolved = _first_getter(functions, name) or confirmed_getter([name])
        if resolved:
            return resolved
        resolved = confirmed_getter(list(candidates))
        if resolved:
            return resolved
        for candidate in candidates:
            resolved = _first_getter(functions, candidate)
            if resolved:
                return resolved
        if observed_field:
            guess = observed_field[0].upper() + observed_field[1:]
            # The source observer names a state *field*, which carries no argument
            # list at all.  A public mapping answers only to `balances(address)`,
            # so a bare name here would compile into a call the contract rejects.
            # The zero-argument form is therefore taken from the ABI rather than
            # from the field name, and the mapping form is the fallback.
            resolved = (_first_getter(functions, guess) or confirmed_getter(
                [guess, observed_field]) or _mapping_getter(guess)
                or _mapping_getter(observed_field))
            if resolved:
                return resolved
        return None
    def _privileged_candidates():
        """ABI functions that read as a privileged entry, best guess first.

        The prefixes are the ones that actually mark a state-changing entry a
        protocol reserves for an authorised caller.  Generated getters are
        excluded because they are named after the field they expose and answer
        to the compiler, so probing one would assert nothing about admission.
        """
        ranked = []
        for name, parameters in abi_parameters.items():
            lowered = name.lower()
            if not (lowered.startswith(_PRIVILEGED_PREFIXES)
                    or any(word in lowered for word in _PRIVILEGED_WORDS)):
                continue
            # A public state variable compiles to a getter under the field's
            # own name; `setOwner` and `owner` are distinguished by the prefix.
            if name in confirmed and parameters == '':
                continue
            ranked.append(name)
        return ranked

    def confirmed_entrypoint(candidates):
        """First candidate the ABI reports as a callable function.

        An entry point that takes arguments was excluded here on the grounds
        that the assertion could only encode an empty argument list, so naming
        one would produce a call that dispatches to nothing and read as a
        violated property.  That reasoning was correct while the encoder really
        could only carry a bare selector; the placeholder encoder now fills in
        an index of zero, this contract's own address, or an empty payload for
        the types these entry points actually take.  Admission is all the
        access-control assertion asks about, so a placeholder is the right
        probe -- and refusing the entry point meant `changeOwner(address)` and
        `setPrice(uint256)` were recorded as needing an adapter even though the
        ABI listed them plainly.

        The full signature is returned rather than the bare name so the encoder
        receives the parameter list it has to fill.  A type the placeholder
        encoder cannot carry is refused at that point instead.
        """
        for candidate in candidates:
            parameters = abi_parameters.get(candidate, None)
            if parameters is None:
                continue
            if parameters == '':
                return f'{candidate}()'
            canonical = [part.strip() for part in parameters.split(",") if part.strip()]
            if not canonical:
                return None
            # Ask the encoder itself rather than keeping a second list of the types
            # a probe can carry: two copies drift, and the drift shows up as an entry
            # point the generator claims and the renderer then refuses.
            if encoded_entry_call(f'{candidate}({",".join(canonical)})'):
                return f'{candidate}({",".join(canonical)})'
        return None

    if role == 'reentrancy':
        return {'guardField': observed_or('balanceOf', 'balances', 'balance'),
                'valueField': value_getter()}
    if role == 'access_control':
        guarded = value_getter() or confirmed_getter(['owner', 'totalSupply'])
        entry = _first_entrypoint(functions, 'withdraw', 'transferOwnership',
                                  'setOwner', 'mint', 'burn', 'selfdestruct') \
            or confirmed_entrypoint(['withdraw', 'withdrawFees', 'transferOwnership',
                                     'setOwner', 'mint', 'burn', 'selfdestruct',
                                     'pause', 'unpause', 'setFee', 'setPrice'])
        if entry is None:
            # A fixed candidate list only ever named the privileged setters of
            # the protocols it was written against.  A contract that calls its
            # ownership setter `changeOwner` or its upgrade setter
            # `setImplementation` matched nothing and was recorded as needing an
            # adapter, although the ABI listed the entry plainly.  The setter
            # prefix is what distinguishes a privileged entry from an ordinary
            # one, so it is read from the ABI instead of enumerated here.
            entry = confirmed_entrypoint(_privileged_candidates())
        return {'guardedField': guarded, 'entrypoint': entry}
    if role == 'unchecked_low_level_call':
        return {'ledgerField': ledger_getter()}
    if role in ('bad_randomness',):
        return {'valueField': value_getter()}
    if role == 'arithmetic':
        return {'valueField': value_getter(), 'ledgerField': ledger_getter()}
    if role == 'denial_of_service':
        entry = _first_entrypoint(functions, 'distribute', 'payout', 'refund',
                                  'withdraw', 'claim', 'process')
        # Both denial-of-service templates read the collection's size before
        # asserting on it, so the getter has to be one the target actually
        # implements.  It is resolved from the ABI rather than assumed, because
        # the name follows what the collection holds.
        size = (confirmed_getter(['collectionSize', 'numberCreditors', 'count',
                                  'length', 'size', 'totalSupply',
                                  'numberOfRequests', 'requestCount'])
                or _mapping_getter('collectionSize'))
        return {'entrypoint': entry, 'collectionSize': size}
    if role in ('front_running', 'time_manipulation',
                'unprotected_upgrade', 'unchecked_cross_contract_assumption'):
        return {'valueField': value_getter()}
    return {}


def detect_roles(document, source_text=None):
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

    # Protocol roles use interface-completeness scoring, which suits a real
    # protocol implementation but rejects this corpus: the benchmark samples are
    # deliberately minimal teaching contracts.  A semantic anchor recognises the
    # role from the properties that actually define it, so a vault that only
    # implements deposit/redeem is still recognised while an unrelated contract
    # that merely owns a field named totalAssets is not.
    PROTOCOL_ANCHORS = {
        'erc4626': (('deposit_with_share_ledger',
                     lambda ctx: ctx['protocol']['deposit_with_share_ledger']),
                    ('assets_and_shares_ledger',
                     lambda ctx: ctx['protocol']['assets_and_shares_ledger'])),
        'amm_pool': (('swap_with_reserves',
                      lambda ctx: ctx['protocol']['swap_with_reserves']),
                     ('dual_reserves',
                      lambda ctx: ctx['protocol']['dual_reserves'])),
        'lending_pool': (('borrow_with_risk',
                          lambda ctx: ctx['protocol']['borrow_with_risk']),
                         ('debt_ledger',
                          lambda ctx: ctx['protocol']['debt_ledger'])),
        'staking_reward': (('stake_with_reward_ledger',
                            lambda ctx: ctx['protocol']['stake_with_reward_ledger']),),
    }
    context = _vulnerability_context(document, functions, state_names)
    context['protocol'] = _protocol_facts(document, functions, state_names)
    # Source-level facts replace the IR-only guesses wherever they speak: the IR
    # has no record of whether a call's result was checked, so any class defined
    # by that distinction is decided from the verified source when one is given.
    context['source'] = _source_facts_for_units(source_text) if source_text else {}
    for role, anchors in PROTOCOL_ANCHORS.items():
        # The scored detail is kept for the existing feature contract; the
        # anchor result is recorded separately so the evidence shows both.
        matched, missing = [], []
        for label, predicate in anchors:
            try:
                holds = bool(predicate(context))
            except Exception:
                holds = False
            (matched if holds else missing).append(f'anchor.{label}')
        anchor_role = bool(matched)
        detail = details.get(role)
        if detail is None:
            detail = {'confidence': 0.0, 'matchedFeatures': [], 'missingFeatures': [],
                      'threshold': 0.7}
            details[role] = detail
        if anchor_role:
            detail['anchorMatchedFeatures'] = sorted(matched)
            detail['detectionKind'] = 'semantic_anchor'
            detail['confidence'] = max(float(detail.get('confidence') or 0.0),
                                       round(len(matched) / len(anchors), 4))
            if role not in roles:
                roles.append(role)

    # Vulnerability classes are recognised by semantic anchors rather than by
    # interface completeness.  A benchmark sample is a minimal teaching contract,
    # so an anchor that holds is the strongest available evidence and a role
    # missing it is reported as unresolved instead of being guessed.
    for role, anchors in VULNERABILITY_ANCHORS.items():
        matched, missing = [], []
        for label, predicate in anchors:
            try:
                holds = bool(predicate(context))
            except Exception:
                holds = False
            (matched if holds else missing).append(label)
        confidence = round(len(matched) / len(anchors), 4) if anchors else 0.0
        details[role] = {'confidence': confidence,
                         'matchedFeatures': sorted(matched),
                         'missingFeatures': sorted(missing),
                         'threshold': 1 / len(anchors) if anchors else 1.0,
                         'detectionKind': 'semantic_anchor'}
        if matched:
            roles.append(role)
    return roles, details


def generate_invariants(document, *, source_sha256=None, source_text=None, abi_getters=None):
    """Generate role-aware invariants for one unified IR document.

    ``abi_getters`` is the set of getters the *compiler* reports for the target,
each as its full signature (``fee()`` or ``balances(address)``).  It is needed
    because the IR's function list comes from the Slither call graph, which walks
    user-written functions and never records the getters solc synthesises for a
    `public` state variable.  Without it every contract whose ledger is a public
    field -- the overwhelmingly common case -- looks like it exposes no readable
    state, and the renderer, correctly refusing to invent a field name, declines
    to emit anything.  The names still come from a compilation of the verified
    source, so nothing here is guessed from naming alone.
    """
    roles, role_features = detect_roles(document, source_text=source_text)
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
             # The renderer reads `maxOracleValue`; emitting `maxDeviationBps`
             # left it with nothing to bound the oracle against, so it declined
             # to render and the sample reported an assertion needing an adapter.
             'params': {'oracleField': 'oracle', 'maxOracleValue': 0, 'toleranceBps': 0}},
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
    unresolved = []
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
            # A protocol role and a vulnerability class are independent axes: a
            # vault can be both.  Looking the role up in both template sets keeps
            # a contract that matched a protocol signature from losing its
            # protocol templates because a vulnerability anchor also fired.
            #
            # The vulnerability template table is keyed by class name, but the
            # roles reported here include the 0.8-era names the benchmarks use
            # (`unchecked_low_level_call`), the guard-style names
            # (`access_control_guard_present`), and the classes that have no
            # entry at all.  Matching on the role alone therefore resolved
            # templates for only four of thirteen roles and produced zero
            # assertions for every sample in the suite.  Lookup is now explicit
            # in both directions, and a role with no entry yields no assertion
            # instead of a fabricated one.
            vulnerability_key = _VULNERABILITY_TEMPLATE_ALIASES.get(role)
            if vulnerability_key is not None:
                substitutions = _vulnerability_substitutions(document, role, source_text,
                                                             abi_getters=abi_getters)
                templates = VULNERABILITY_TEMPLATES.get(vulnerability_key, ())
            else:
                substitutions = {}
                templates = role_templates.get(role, ())
        refs = _source_refs(document, feature_names)
        for template in templates:
            params = {key: (substitutions.get(value[1:]) if isinstance(value, str) and value.startswith('$') else value)
                      for key, value in template['params'].items()}
            # A placeholder the generator could not resolve means this assertion
            # cannot run against this contract: the field it has to read is not
            # exposed, so there is nothing for it to observe.  Declaring it anyway
            # produced a row the harness could not render, and the sample was
            # recorded as having executed no assertion at all rather than as
            # having no applicable one.  A minimal teaching contract often exposes
            # no readable state -- `dos_simple` has only `ifillArray()` and no
            # size getter -- and for those, zero assertions is the correct
            # answer.  Inventing a field to read would be a fabricated
            # observation.
            unresolved_placeholders = sorted(
                key for key, value in template['params'].items()
                if isinstance(value, str) and value.startswith('$') and params.get(key) is None)
            if unresolved_placeholders:
                unresolved.append(
                    f"{template['template']}: 未能从编译产物解析 {'、'.join(unresolved_placeholders)}，"
                    f"该断言在本合约上无可观测状态。")
                continue
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
    if not roles:
        unresolved.append('未识别到受支持的协议角色特征组合。')
    if not source_text:
        # 六个漏洞锚点依赖源码事实，而源码事实只在调用方传入 source_text 时才会
        # 被采集。调用方其实已经在磁盘上持有同一份已验证源码（它写出了本文件所
        # 依据的 IR），却因为漏传这一个参数，让整批真实合约的角色识别静默归零：
        # 结果与"这份合约确实没有任何漏洞类"完全无法区分。把缺参记录进证据，
        # 使"没看源码"不再读作"没有缺陷"。
        unresolved.append(
            '未传入 source_text：六个依赖源码事实的漏洞锚点'
            '（reentrancy/source.callBeforeLedgerWrite、'
            'access_control/source.privilegedEntryUnguarded、'
            'arithmetic/source.uncheckedBlockOrCast、'
            'short_addresses/source.addressRepackedWithoutPadding、'
            'incorrect_interface/source.callResultConsumedBeyondItsWidth、'
            'oracle_stale_price/source.priceReadWithoutFreshnessBound）'
            '本次未被求值，零角色不构成无缺陷的证据。')
    if roles and decimals is None:
        unresolved.append('IR 未记录 token decimals；精度相关参数保持 null。')
    return {
        'schemaVersion': 1,
        'state': 'available' if invariants else 'template_unavailable',
        'sourceSha256': source_sha256,
        'declaredSourceBundleSha256': ir_source_sha256,
        'sourceIrDocumentId': document.get('documentId'),
        'sourceIrSha256': digest,
        'sourceFactsObserved': bool(source_text),
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
