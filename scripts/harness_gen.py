"""Create a bounded Foundry workspace for generated invariant checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

try:
    from invariant_assertions import load_renderers
except ModuleNotFoundError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from invariant_assertions import load_renderers

try:
    # The constructor-argument decoder is shared with the standalone deployment
    # adapter so a contract deployed inline and one deployed by an external
    # script receive byte-for-byte identical arguments.  Two spellings of
    # "turn this recovered ABI value into a Solidity literal" would let the
    # harness and the adapter disagree about what the same arguments mean, and
    # the disagreement would only show up as a constructor reverting.
    from deploy_adapter import _solidity_literal, _constructor
except ModuleNotFoundError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from deploy_adapter import _solidity_literal, _constructor


def _safe_source_path(name):
    if not isinstance(name, str) or not name or '\\' in name or name.startswith('/'):
        raise ValueError('source unit path is unsafe')
    parts = name.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('source unit path is unsafe')
    return Path(*parts)


def _source_digest(sources):
    normalized = {name: entry['content'] for name, entry in sorted(sources.items())}
    encoded = json.dumps(normalized, sort_keys=True, ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


# A bare import names a package rather than a path inside the source tree.
# Foundry reads the leading segment of such a specifier as a dependency it
# resolves on its own, so a file that lives in the bundle under
# ``@openzeppelin/contracts/token/ERC20/ERC20.sol`` is invisible to the
# compiler unless the package is mapped back onto the source root.  The
# verified bundles that ship OpenZeppelin or Uniswap sources carry no
# remappings of their own -- the compiler they were built with resolved the
# package through its own include path -- so the mapping has to be derived
# from the imports the bundle actually contains.
_BARE_IMPORT = re.compile(r'\bimport\s+(?:[^;]*?\bfrom\s+)?["\']([^"\']+)["\']\s*;')
_BARE_PREFIX = re.compile(r'^[A-Za-z0-9_@.-]+/')


def _renderer_unavailable_reason(template):
    """The adapter a renderer named as the reason it cannot render.

    A renderer module may export ``UNAVAILABLE_REASONS`` as a mapping from
    template name to a short reason string.  The reason is evidence about the
    harness, so it is only used when the renderer itself supplied it; nothing
    is inferred from the template name.
    """
    if not isinstance(template, str) or not template:
        return None
    try:
        from invariant_assertions import load_renderers
    except ModuleNotFoundError:
        return None
    import importlib
    for name in ('erc4626', 'lending', 'amm', 'cross', 'vuln'):
        try:
            module = importlib.import_module(f"invariant_assertions.{name}")
        except ModuleNotFoundError:
            continue
        reasons = getattr(module, 'UNAVAILABLE_REASONS', None)
        if isinstance(reasons, dict):
            reason = reasons.get(template)
            if isinstance(reason, str) and reason.strip():
                return reason.strip()[:200]
    return None


def _remappings_for_sources(sources):
    """Derive the Foundry remappings a source bundle's bare imports need.

    A relative import (``./Token.sol``) resolves inside the source tree and
    needs nothing.  A bare import (``@openzeppelin/contracts/...``) names a
    package, and its first path segment is what Foundry treats as the
    dependency name.  Each distinct package is mapped onto the directory the
    bundle already wrote it to, so the compiler finds the verified text
    instead of looking for a package that is not installed.
    """
    prefixes = set()
    for entry in sources.values():
        if not isinstance(entry, dict) or not isinstance(entry.get('content'), str):
            continue
        for match in _BARE_IMPORT.finditer(entry['content']):
            spec = match.group(1)
            if spec.startswith('.') or '/' not in spec:
                continue
            prefix = _BARE_PREFIX.match(spec)
            if prefix is None:
                continue
            package = prefix.group(0)
            # A package that the bundle did not write into the source tree
            # cannot be mapped onto it; leaving it out keeps the failure a
            # reported compiler error instead of a mapping to nothing.
            if any(name == package.rstrip('/') or name.startswith(package)
                   for name in sources):
                prefixes.add(package)
    return sorted(f"{package}=src/{package}" for package in prefixes)


def _is_pre_0_4_22(pragma):
    """Whether a generated pragma compiles with a pre-0.4.22 solc.

    `uint` was only accepted as an alias for `uint256` from 0.4.22, so the
    generated locals have to spell out the width for anything older.
    """
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', str(pragma or ''))
    if not match:
        return True
    return tuple(int(part) for part in match.groups()) < (0, 4, 22)


# `view` and `pure` parse from 0.4.16.
MUTABILITY_FLOOR = (0, 4, 16)
# `interface` parses from 0.5.0.
INTERFACE_FLOOR = (0, 5, 0)


def _is_at_least(pragma, floor):
    """Whether a generated pragma names a compiler at or above ``floor``.

    A pragma that carries no version cannot be checked, and the modern spelling is
    only wrong for the oldest compilers, so an unknown pragma takes the modern
    branch and any real version check happens when the compiler rejects it.
    """
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', str(pragma or ''))
    if not match:
        return True
    return tuple(int(part) for part in match.groups()) >= tuple(floor)


def _pragma_for_sources(sources, compiler_version=None):
    """Return a pragma the generated tests and every source unit can compile with.

    Foundry compiles one project at one compiler version, so the test's pragma
    and the target's pragma have to intersect.  Benchmark samples pin exact
    versions (`pragma solidity 0.4.10;`), and a caret range that merely *covers*
    the target is not enough -- forge resolves the tightest constraint in the
    unit.  The narrowest pinned version present is therefore used verbatim, which
    is exactly what the sources themselves demand.

    ``compiler_version`` overrides that derivation with the version the evidence
    is actually graded against.  A sample whose own pragma reads `>=0.4.11` while
    its ground truth names `0.4.10` would otherwise have its test pinned upward,
    forge would resolve no installed compiler, and the whole deployment probe
    would report "no address" -- a failure caused by the harness, not by the
    contract under test.

    A range-only or missing pragma falls back to the project's own floor rather
    than to `>=0.8.19`, so an old target keeps an old-compilable test.
    """
    if isinstance(compiler_version, str) and re.match(r'^\d+\.\d+\.\d+$', compiler_version):
        return compiler_version
    versions = set()
    for entry in sources.values():
        content = entry.get('content') if isinstance(entry, dict) else None
        if not isinstance(content, str):
            continue
        for match in re.finditer(
                r'pragma\s+solidity\s+([0-9]+\.[0-9]+\.[0-9]+)\s*;', content):
            versions.add(tuple(int(part) for part in match.group(1).split('.')))
    if versions:
        return '.'.join(str(part) for part in min(versions))
    # A range-only or missing pragma leaves no version to copy.  The floor here
    # has to sit below the oldest compiler in the corpus, and the generated test
    # uses `uint`/`uint256` explicitly rather than the `uint` alias, so the two
    # stay consistent on every release.
    return '>=0.4.11'


def _inject_adapter(body, action):
    """Replace the renderer's adapter marker line with the caller's action.

    A renderer marks the place where a state transition belongs with a comment
    line beginning ``// The adapter``.  The caller -- which resolved the
    action from the contract's own interface -- supplies the Solidity that
    performs it, and this substitutes that source for the marker line.

    The marker has to appear exactly once.  Zero occurrences means the body
    does not expect a transition there, and more than one means the action
    could belong to either side of a comparison, so the body is refused
    (``None``) rather than resolved by picking one.
    """
    lines = body.split('\n')
    positions = [index for index, line in enumerate(lines) if line.strip().startswith('// The adapter')]
    if len(positions) != 1:
        return None
    index = positions[0]
    indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
    inserted = []
    for line in action.strip().split('\n'):
        inserted.append(indent + line if line.strip() else line)
    return '\n'.join(lines[:index] + inserted + lines[index + 1:])


def _abi_for(bundle, contract):
    """The ABI rows for one contract of a compilation, or an empty list."""
    from deploy_adapter import _abi
    return _abi(bundle, contract)


def _constructor_literals(abi, provided):
    """Turn recovered constructor values into the Solidity a `new` call takes.

    Returns `(literals, missing)`.  `missing` names the parameters the caller
    did not supply; the caller reports them rather than guessing a value, which
    is what keeps an unknown constructor from being deployed with zeros and read
    as a passing property check on a contract that was never the real one.

    Reuses the standalone adapter's decoder so the inline `new` and the external
    deploy script spell an argument identically.
    """
    constructor = _constructor(abi) if abi else None
    if not constructor:
        return [], []
    inputs = constructor.get('inputs') if isinstance(constructor.get('inputs'), list) else []
    provided = provided if isinstance(provided, (list, dict)) else None
    literals = []
    missing = []
    for index, item in enumerate(inputs):
        name = item.get('name') or f'arg{index}'
        if isinstance(provided, dict):
            value = provided.get(name)
        elif isinstance(provided, list) and index < len(provided):
            value = provided[index]
        else:
            value = None
        if value is None:
            missing.append(name)
            continue
        literals.append(_solidity_literal(value, str(item.get('type') or ''),
                                         str(item.get('internalType') or '')))
    return literals, missing


def _deployment_plan(bundle, contract_name, abi, constructor_arguments):
    """Decide how the test obtains its target.

    Returns a dict with the state and, when the target is deployed inline, the
    Solidity expression that performs the deployment.

    The historical path reads the address from the environment, which requires
    something to have deployed the contract first.  That is the right shape when
    a fork supplies the target and the wrong one for a self-contained harness:
    with nothing deployed, `envAddress` returns zero, the code-size guard trips,
    and the run is reported as an unavailable deployment -- the state every
    benchmark sample was in until this path existed.

    Inline deployment is therefore opt-in, keyed on the caller having supplied
    constructor arguments rather than on the harness noticing a parameterless
    constructor.  Making it automatic for the parameterless case would have been
    tidier, but it would have changed what every existing caller produces --
    the gate, the pipeline and the runner all build a harness and then supply the
    address themselves, and a harness that deploys its own target ignores the one
    they supplied.  A caller that wants the contract deployed inline asks for it
    by saying how to construct it, which is the same thing it has to say for a
    contract that takes arguments.
    """
    if constructor_arguments is None:
        return {'state': 'env_address', 'contract': contract_name,
                'reason': 'constructor_arguments_not_supplied_environment_target_used'}
    if not isinstance(contract_name, str) or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', contract_name):
        return {'state': 'unavailable', 'reason': 'compilation_target_missing_or_ambiguous'}
    literals, missing = _constructor_literals(abi, constructor_arguments)
    if missing:
        return {'state': 'adapter_required', 'reason': 'constructor_arguments_missing',
                'contract': contract_name, 'missing': missing}
    args = ', '.join(literals)
    return {'state': 'inline_deployment', 'contract': contract_name,
            'expression': f'address(new {contract_name}({args}))',
            'constructorArgs': literals}


def generate_harness(invariants, source_bundle, output_dir, compiler_version=None, adapters=None,
                     constructor_arguments=None):
    if not isinstance(invariants, dict) or invariants.get('schemaVersion') != 1:
        raise ValueError('invariants document schemaVersion 1 is required')
    if not isinstance(source_bundle, dict) or not isinstance(source_bundle.get('sources'), dict):
        raise ValueError('verified source bundle requires a sources object')
    if adapters is not None and not isinstance(adapters, dict):
        raise ValueError('adapters must be a mapping from template name to action source')
    sources = source_bundle['sources']
    source_sha256 = _source_digest(sources)
    # The campaign records two digests that mean different things.
    # `sourceSha256` is its own wider identity -- reachable sources, compilation
    # target, compiler version, compiler settings -- and it feeds `invariantId`,
    # `discovery_plan`, `ir_reconcile` and the review output, so its definition
    # is left exactly as it was.
    #
    # `sourceContentsSha256` is this module's own digest over the source
    # contents.  It is produced by calling `_source_digest` itself, so the two
    # sides cannot drift: a second implementation of the same definition would
    # have to be believed to agree, and believing that is what produced the
    # mismatch this field exists to remove.
    #
    # When the narrow field is present it is the one checked, because it is the
    # one this module can actually reproduce.  A document without it keeps the
    # previous behaviour, so bundles generated before this field existed still
    # validate exactly as they did.
    contents_sha256 = invariants.get('sourceContentsSha256')
    if contents_sha256 is None:
        contents_sha256 = invariants.get('sourceSha256')
    if contents_sha256 is not None and contents_sha256 != source_sha256:
        raise ValueError('invariants source contents digest does not match verified source bundle')
    targets = (source_bundle.get('metadata') or {}).get('settings', {}).get('compilationTarget', {})
    if not isinstance(targets, dict) or len(targets) != 1:
        deployment = {'state': 'unavailable', 'reason': 'compilation_target_missing_or_ambiguous'}
        target_name = None
    else:
        source_name, contract_name = next(iter(targets.items()))
        target_name = contract_name if isinstance(contract_name, str) and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', contract_name) else None
        deployment = _deployment_plan(source_bundle, target_name,
                                      _abi_for(source_bundle, target_name) if target_name else [],
                                      constructor_arguments)
        deployment.setdefault('sourceUnit', source_name)
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError('harness output directory must be new or empty')
    output_dir.mkdir(parents=True, exist_ok=True)
    source_root = output_dir / 'src'
    test_root = output_dir / 'test'
    source_root.mkdir(exist_ok=True)
    test_root.mkdir(exist_ok=True)
    for name, entry in sources.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('content'), str):
            raise ValueError('verified source entries must contain source text')
        relative = _safe_source_path(name)
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry['content'], encoding='utf-8')

    generated = []
    renderers = load_renderers()
    adapter_required = []
    seen_ids = set()
    # The dialect is a property of the whole harness, not of one assertion, so it
    # is resolved once before the loop.  The generated test lives in the same
    # compilation unit as the target, so its pragma has to satisfy the target's
    # own constraint.  A fixed `>=0.8.19` made every pre-0.8 benchmark sample
    # uncompilable, which the run then reported as "no assertion executed" rather
    # than as a compiler error -- the assertion existed but could never run.
    pragma = _pragma_for_sources(sources, compiler_version)
    # `uint` as an alias for `uint256` only exists from 0.4.22 on, so the
    # generated locals spell the width out and parse on every release in the
    # corpus rather than only on the recent half of it.
    wide = "uint256" if _is_pre_0_4_22(pragma) else "uint"
    for invariant in invariants.get('invariants', []):
        if not isinstance(invariant, dict):
            raise ValueError('invariant rows must be objects')
        invariant_id = invariant.get('invariantId')
        if not isinstance(invariant_id, str) or not re.fullmatch(r'[0-9a-f]{64}', invariant_id):
            raise ValueError('invariantId must be a lowercase SHA-256 digest')
        if invariant_id in seen_ids:
            raise ValueError('invariantId values must be unique')
        seen_ids.add(invariant_id)
        template = invariant.get('template')
        renderer = renderers.get(template)
        context = {'contract_name': target_name or 'Target', 'target_addr_expr': 'target',
                   # The renderer needs the graded compiler, not the sample's own
                   # pragma, to pick a dialect: `require` only takes a reason
                   # string from 0.4.22 on.  Without this every assertion rendered
                   # the two-argument form and 0.4.10 through 0.4.21 rejected the
                   # harness with "Wrong argument count".
                   'compiler_version': pragma,
                   # A transition property needs an action between its two
                   # readings.  The caller resolves that action from the
                   # contract's own interface and passes it here; a renderer
                   # that needs one refuses to produce a body without it,
                   # rather than producing a comparison of two identical
                   # readings.
                   'adapters': adapters if isinstance(adapters, dict) else {}}
        body = renderer(invariant.get('params') or {}, context) if renderer else None
        if not isinstance(body, str) or not body.strip():
            reason = 'invariant_renderer_missing' if renderer is None else 'invariant_renderer_requires_adapter'
            # A renderer may name the specific adapter it needs.  The generic
            # reason says only that an adapter is required; the specific one
            # says which protocol action the assertion cannot perform without,
            # which is the difference between "this sample was not measured" and
            # "this sample was not measured because the harness cannot perform
            # a swap".  A renderer that declines without naming a reason keeps
            # the generic wording, so the evidence never implies more than the
            # renderer stated.
            specific = _renderer_unavailable_reason(template)
            if specific:
                reason = specific
            adapter_required.append({'invariantId': invariant_id, 'template': template, 'status': 'adapter_required', 'reason': reason, 'path': None})
            continue
        # The action the caller supplied replaces the marker line the renderer
        # left behind.  The marker is a whole line, so the substitution is
        # line-wise: a body that carries the marker more than once is
        # ambiguous about which reading the action belongs between, and it is
        # refused rather than resolved by guesswork.
        action = adapters.get(template) if isinstance(adapters, dict) else None
        if isinstance(action, str) and action.strip():
            body = _inject_adapter(body, action)
            if body is None:
                adapter_required.append({'invariantId': invariant_id, 'template': template,
                                         'status': 'adapter_required',
                                         'reason': 'adapter_marker_missing_or_ambiguous', 'path': None})
                continue
        test_name = f'Invariant_{invariant_id[:16]}.t.sol'
        id_literal = '0x' + invariant_id
        description = json.dumps(str(invariant.get('description') or invariant.get('name') or ''))
        # The mutability keywords and `interface` arrived in different releases,
        # and both are measured rather than remembered: `view` and `pure` parse
        # from 0.4.16, while `interface` only parses from 0.5.0.  Treating both as
        # 0.4.11 -- the value this file previously carried -- rejected 0.4.11
        # through 0.4.15 with "Expected token LBrace got 'View'" and 0.4.11
        # through 0.4.25 with "Expected identifier but got 'interface'".  A corpus
        # sample pinned to any of those releases then failed to parse its own
        # generated harness, and the run reported a failed deployment rather than
        # the version mismatch it was.  A plain `contract` with a body declares the
        # same function and parses on every release the corpus pins; the
        # declaration is only ever called through the cheat-code address, so the
        # body never executes.
        vm_declared = ('interface Vm' if _is_at_least(pragma, INTERFACE_FLOOR)
                       else 'contract Vm')
        # `skip` is declared alongside `envAddress` so the emitted action can ask
        # forge to skip the test when the call it issued did not succeed.  It is
        # only ever reached through the cheat-code address, so the body is
        # irrelevant; the declaration is what has to parse.
        skip_body = ('function skip(bool skipTest) external;'
                     if _is_at_least(pragma, INTERFACE_FLOOR) else
                     'function skip(bool skipTest) external { }')
        vm_body = ('function envAddress(bytes32 name) external view returns (address);'
                   if _is_at_least(pragma, INTERFACE_FLOOR) else
                   'function envAddress(bytes32 name) external returns (address) '
                   '{ return address(0); }')
        # `view` on the harness's own helpers is the same pre-0.4.16 keyword, and
        # dropping it changes nothing about what the helpers do: they read state
        # through `assembly` and never write.
        view_kw = 'view ' if _is_at_least(pragma, MUTABILITY_FLOOR) else ''
        # `pure` arrived in the same release as `view`.
        pure_kw = 'pure ' if _is_at_least(pragma, MUTABILITY_FLOOR) else ''
        # The two-argument `require` -- condition plus reason string -- only
        # exists from 0.4.22.  Below that it is rejected with "Wrong argument
        # count", so the reason is dropped rather than the check.
        require_form = ('require(_codeSizeAt(target) > 0, "INVARIANT_TARGET has no code");'
                        if _is_at_least(pragma, (0, 4, 22))
                        else 'require(_codeSizeAt(target) > 0);')
        # How the test obtains the contract it measures.  An inline deployment
        # needs no import of the target's source unit: the test lives in the same
        # compilation unit as the target, so `new Target(...)` resolves to the
        # contract the sources actually define.  The environment path is kept as
        # the default because a fork supplies its target that way, and swapping
        # the default would break every caller that sets `INVARIANT_TARGET`.
        #
        # The code-size guard is kept on both paths.  Under inline deployment it
        # cannot fail, and that is the point: it is the check that catches an
        # environment path whose `envAddress` returned an address with no code
        # behind it, which is how a silently-never-measured assertion used to be
        # reported as a pass.
        inline = deployment.get('state') == 'inline_deployment'
        target_expr = (deployment.get('expression') or 'address(0)') if inline else (
            'Vm(_cheatCodeAddress()).envAddress(bytes32("INVARIANT_TARGET"))')
        # The cheat-code interface and the handles built on it use post-0.4
        # spellings (`calldata` parameters, `uint256` casts, `.code`), which do
        # not parse under the 0.4.x compilers these benchmark samples pin.  The
        # form below -- plain `bytes32`/`string`, assembly address loads, and
        # `extcodesize` -- means the same thing on every version from 0.4.22 up,
        # so one template serves the whole corpus.  The assertion body itself is
        # renderer output and is left exactly as written.
        import_form = ''
        if inline and isinstance(targets, dict) and len(targets) == 1:
            target_unit = next(iter(targets))
            # The path is the one the sources were written under inside `src/`;
            # the test sits one level up in `test/`, so it reaches across with
            # `../`.  A path that cannot be expressed this way is refused by
            # `_safe_source_path` on the way in, so it is always relative.
            import_form = f'import "../src/{target_unit}";\n'
        solidity = f'''// SPDX-License-Identifier: MIT
pragma solidity {pragma};
{import_form}

{vm_declared} {{
    {vm_body}
    {skip_body}
}}

contract Invariant_{invariant_id[:16]} {{
    // `internal`, not `public`.  A public constant compiles to an external
    // getter, and forge collects every public test-shaped function as a fuzz
    // target before it runs `testInvariant` -- so `invariantId()` made it try to
    // stand up an invariant-testing environment, fail with "No contracts to
    // fuzz", and exit non-zero.  That failure is indistinguishable from a real
    // assertion failure by exit code, so every contract was reported as
    // `violated`.  The values are unchanged; only their visibility is.
    bytes32 internal constant invariantId = {id_literal};
    string internal constant description = {description};

    // The handle `_skipUnavailable` uses to reach `skip`.  It is read through a
    // call rather than held as a constant because the cheat-code address is
    // derived by `_cheatCodeAddress`, which reads storage and so cannot
    // initialise a constant.
    function _vm() private {view_kw}returns (Vm) {{
        return Vm(_cheatCodeAddress());
    }}

    // The cheat-code address is derived inside `assembly` rather than by
    // `Vm(address(uint160(uint256(keccak256(...)))))`: the one-argument
    // `keccak256` only exists in Solidity's expression syntax, and the
    // contract-to-address cast is not available on the 0.4 compilers half of the
    // corpus pins.  The literal is still anchored in this contract's own code,
    // so the slot is resolved by the compiler rather than hand-computed.
    //
    // The address is taken with `div` rather than `shr(96, word)`: `shr` is an
    // assembly builtin Solidity added in 0.5, and 0.4.16 through 0.4.21 rejected
    // this helper with "Function not found", which the deep layer then reported as
    // an unavailable deployment.
    function _cheatCodeAddress() private {view_kw}returns (address out) {{
        bytes32 slot;
        bytes32 word;
        assembly {{
            mstore(0x00, "hevm cheat code")
            slot := keccak256(0x00, 0x10)
            word := sload(slot)
            out := div(word, 0x1000000000000000000000000000000000000000)
        }}
    }}

    function _codeSizeAt(address who) private {view_kw}returns ({wide} size) {{
        assembly {{ size := extcodesize(who) }}
    }}

    // Selector + calldata, assembled by hand.  Every library form is
    // version-gated: `abi.encodeWithSignature` only accepts trailing arguments
    // from 0.5 on, and `abi.encodeWithSelector` needs the one-argument
    // `keccak256` that does not exist before 0.5 either.  Hashing the signature
    // inside `assembly` and concatenating the encoded argument is the one
    // spelling a public mapping getter can be read through on every release this
    // corpus pins.
    //
    // The hash starts at `add(signature, 32)`, not at `signature`.  A `string
    // memory` parameter points at its own length word, so hashing `signatureLength`
    // bytes from `signature` folds that prefix into the digest and yields a
    // selector the target does not implement -- every read then reverted and the
    // run reported "getter unavailable" for contracts whose getters are perfectly
    // readable.  The compiler's own `abi.encodeWithSignature` skips the prefix.
    //
    // The selector occupies the low four bytes of the data area and the argument is
    // written immediately after it, right-aligned in the following 32 bytes --
    // byte for byte what `abi.encodeWithSignature` produces.  Storing the selector
    // left-aligned and the argument one word further out looks equivalent and is
    // not: a 36-byte buffer cannot hold two words, so the second store lands past
    // the end of the data and the dispatch fails.  Verified against a live
    // `mapping(address => uint256) public balances` getter rather than inferred.
    function _encodeSelector(string memory signature) private {pure_kw}returns (bytes memory) {{
        bytes memory encoded = new bytes(4);
        assembly {{
            let signatureLength := mload(signature)
            mstore(add(encoded, 32), and(keccak256(add(signature, 32), signatureLength),
                0xffffffff00000000000000000000000000000000000000000000000000000000))
        }}
        return encoded;
    }}

    // The same four bytes as `_encodeSelector`, from a signature that is
    // already `bytes`.  The two spellings differ because `string` and `bytes` are
    // distinct types with no implicit conversion between them before 0.8, and
    // the ledger names are assembled as `bytes` because they come out of a
    // `bytes32` literal.  The hash covers the same range in both.
    function _encodeSelectorBytes(bytes memory signature) private {pure_kw}returns (bytes memory) {{
        bytes memory encoded = new bytes(4);
        assembly {{
            let signatureLength := mload(signature)
            mstore(add(encoded, 32), and(keccak256(add(signature, 32), signatureLength),
                0xffffffff00000000000000000000000000000000000000000000000000000000))
        }}
        return encoded;
    }}

    function _encodeSelectorWithAddress(string memory signature, address argument) private {pure_kw}returns (bytes memory) {{
        bytes memory encoded = new bytes(36);
        assembly {{
            let signatureLength := mload(signature)
            let out := encoded
            mstore(add(out, 32), and(keccak256(add(signature, 32), signatureLength),
                0xffffffff00000000000000000000000000000000000000000000000000000000))
            mstore(add(out, 36), and(argument, 0xffffffffffffffffffffffffffffffffffffffff))
        }}
        return encoded;
    }}

    function _encodeSelectorWithUint256(string memory signature, uint256 argument) private {pure_kw}returns (bytes memory) {{
        bytes memory encoded = new bytes(36);
        assembly {{
            let signatureLength := mload(signature)
            let out := encoded
            mstore(add(out, 32), and(keccak256(add(signature, 32), signatureLength),
                0xffffffff00000000000000000000000000000000000000000000000000000000))
            mstore(add(out, 36), argument)
        }}
        return encoded;
    }}

    // Probes for entry points that take arguments.  These carry a placeholder
    // rather than a value the caller reads back: an access-control assertion
    // asks whether the call was admitted, so an index of zero for an array
    // position and an empty payload for an uninspected argument say everything
    // the assertion needs.  Only the admission flag is read, so the contents of
    // the payload never affect the verdict.
    //
    // The empty dynamic payload is an offset of 0x20 followed by a zero length,
    // which is byte for byte what `abi.encodeWithSignature(sig, new bytes(0))`
    // produces: the tail sits immediately behind the head, so the offset is the
    // head size rather than a full two-word stride.
    function _encodeSelectorWithBytes(string memory signature) private {pure_kw}returns (bytes memory) {{
        bytes memory encoded = new bytes(68);
        assembly {{
            let signatureLength := mload(signature)
            let out := encoded
            mstore(add(out, 32), and(keccak256(add(signature, 32), signatureLength),
                0xffffffff00000000000000000000000000000000000000000000000000000000))
            mstore(add(out, 36), 0x20)
            mstore(add(out, 68), 0)
            mstore(out, 68)
        }}
        return encoded;
    }}

    function _encodeSelectorWithTwoUint256(string memory signature, uint256 first, uint256 second) private {pure_kw}returns (bytes memory) {{
        bytes memory encoded = new bytes(68);
        assembly {{
            let signatureLength := mload(signature)
            let out := encoded
            mstore(add(out, 32), and(keccak256(add(signature, 32), signatureLength),
                0xffffffff00000000000000000000000000000000000000000000000000000000))
            mstore(add(out, 36), first)
            mstore(add(out, 68), second)
            mstore(out, 68)
        }}
        return encoded;
    }}

    // A low-level call whose success flag and first returned word are returned as
    // a two-value tuple.  Neither `.call()` nor `abi.decode` has a spelling every
    // compiler in this corpus accepts: `.call()` cannot be destructured at all
    // before 0.5, and `abi.decode` is undeclared before 0.4.22 and absent from
    // `abi` before 0.5.  Issuing the call inside `assembly` against an explicit
    // memory buffer and reading the result with `mload` parses on every release,
    // and callers never discard a tuple component -- a trailing-comma discard is
    // rejected by every compiler from 0.4.22 on when the callee returns one
    // value, which is why the boolean-only helper below is separate.
    function _readWord(address callee, bytes memory payload) private returns (bool ok, uint256 value) {{
        bytes memory out = new bytes(32);
        assembly {{
            let head := payload
            let length := mload(head)
            let data := add(head, 32)
            let outPtr := add(out, 32)
            ok := call(gas(), callee, 0, data, length, outPtr, 32)
            value := mload(outPtr)
        }}
    }}

    function _callSucceeded(address callee, bytes memory payload) private returns (bool ok) {{
        bytes memory out = new bytes(32);
        assembly {{
            let head := payload
            let length := mload(head)
            let data := add(head, 32)
            ok := call(gas(), callee, 0, data, length, add(out, 32), 32)
        }}
    }}

    // The action an adapter emitted calls this when its low-level call did not
    // succeed.  The placeholder arguments the action carries are not guaranteed
    // to satisfy the contract's own preconditions -- `deposit(0)` against a vault
    // that requires a non-zero amount reverts, and a swap of two zero amounts
    // may leave the reserves untouched -- and a reverted call cannot tell a
    // protocol defect from an action the contract declined.  Requiring the
    // success flag instead would abort the test, which forge reports as FAIL and
    // which is indistinguishable from a real assertion failure by return code
    // alone.  Skipping records the measurement as not taken, which is what
    // actually happened.
    //
    // `vm` is the harness's own handle on the cheat-code address, present in the
    // gate contract that lifts this helper but not in the harness template, which
    // reads the address through `_cheatCodeAddress` instead.  Either spelling
    // reaches the same cheat code, so the fallback keeps one helper usable in
    // both places rather than forking the helper per host.
    function _skipUnavailable() private {{
        _vm().skip(true);
        revert("ADAPTER_ACTION_UNAVAILABLE");
    }}

    // The amount an adapter's emitted call carries.  It is read from the
    // contract's own ledger rather than written down, because no fixed number
    // is right in both directions:
    //
    //   * zero is refused outright by anything that checks its input, so the
    //     action reverts and the property is never measured;
    //   * a constant large enough to clear that check can still mint a single
    //     wei of shares once the share price has risen.  That call succeeds,
    //     so nothing is reported as failed, and the assertion goes on to
    //     compare two readings it never changed -- the same defect as the zero
    //     placeholder, reached from the other side and no easier to notice.
    //
    // Scaling against the ledger avoids both: a tenth of what the contract
    // currently holds is proportional to its state at every stage, and a vault
    // that has accrued yield is asked for a proportionally larger amount.
    //
    // The empty case still needs a value, and it needs one big enough to clear
    // a rounding check on a vault whose price has left 1.  A tenth of 1e24 is
    // the derived shape extrapolated to a zero ledger: for any share price
    // below 1e18 per share -- that is, any price at or under a million tokens
    // per share -- it mints a whole share.
    function _adapterAmount(address self) private {view_kw}returns (uint256) {{
        uint256 held = _readHeld(self);
        if (held == 0) {{
            return 1e24;
        }}
        uint256 tenth = held / 10;
        return tenth == 0 ? 1 : tenth;
    }}

    // The largest ledger the contract exposes under the names a vault, a pool
    // or a market uses for it.  The value is read through a getter rather than
    // a storage slot: the slot of a public state variable is fixed by that
    // contract's own layout, and a harness that guessed the slot number would be
    // reading its own storage instead of the target's.  A name the contract does
    // not expose simply fails to respond, and the caller moves on to the next.
    //
    // The caller rejects the address zero as well as a failed call, because a
    // contract whose first ledger field is genuinely zero is indistinguishable
    // from one that does not have the field, and treating a real zero as
    // "found" would shrink the amount to nothing.
    function _readHeld(address self) private {view_kw}returns (uint256 held) {{
        bytes32[5] memory getters = [
            bytes32("totalAssets()"), bytes32("totalSupply()"),
            bytes32("totalBorrows()"), bytes32("totalDebt()"),
            bytes32("reserve0()")
        ];
        for (uint256 i = 0; i < getters.length; i++) {{
            bytes memory payload = _encodeSelectorBytes(_toString(getters[i]));
            (bool ok, uint256 value) = _readLedgerWord(self, payload);
            if (ok && value > held) {{
                held = value;
            }}
        }}
    }}

    // A zero-argument read that reports whether the contract answered at all,
    // separately from the value.  `_readWord` cannot be used here: it issues a
    // plain `call`, which the compiler counts as a possible state modification,
    // so a `view` helper calling it is rejected.  `staticcall` is the correct
    // instruction for a read anyway -- it propagates no value and cannot change
    // anything -- and it fails rather than reporting a false zero when the target
    // does not implement the getter.
    function _readLedgerWord(address self, bytes memory payload) private {view_kw}returns (bool ok, uint256 value) {{
        bytes memory out = new bytes(32);
        assembly {{
            let head := payload
            let length := mload(head)
            let data := add(head, 32)
            let outPtr := add(out, 32)
            ok := staticcall(gas(), self, data, length, outPtr, 32)
            value := mload(outPtr)
        }}
    }}

    // A `bytes32` spelling a function signature, as the `string` the selector
    // helper takes.  The two are the same 32 bytes in the same order, so the
    // conversion copies rather than re-encodes: a getter name padded to 32
    // bytes on the right is exactly the short string literal Solidity would
    // have produced, which is why the array above is padded already.
    function _toString(bytes32 packed) private {pure_kw}returns (bytes memory) {{
        uint256 length = 0;
        for (uint256 i = 0; i < 32; i++) {{
            if (packed[i] == 0) {{
                break;
            }}
            length++;
        }}
        bytes memory out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {{
            out[i] = packed[i];
        }}
        return out;
    }}

    // The assertion body runs in its own frame rather than inline in the test.
    // A protocol property is checked from several snapshots at once -- an
    // ERC-4626 share price compares four ledger reads and cross-multiplies them --
    // and the 0.4.x codegen has no `via_ir` to relieve the legacy 16-slot stack.
    // Those compilers report the overflow as "Stack too deep, try removing local
    // variables", pointing at the test entry rather than at the assertion, and the
    // deep layer then recorded an unavailable deployment for every sample pinned
    // below 0.5.  A separate frame gives the body the same headroom everywhere.
    function _assertProtocol(address target) private {{
        {body}
    }}

    function testInvariant() public {{
        address target = {target_expr};
        {require_form}
        _assertProtocol(target);
    }}
}}
'''
        (test_root / test_name).write_text(solidity, encoding='utf-8')
        generated.append({'invariantId': invariant_id, 'path': f'test/{test_name}',
                          'template': template, 'status': invariant.get('status', 'unverified')})
    remappings = _remappings_for_sources(sources)
    foundry = '''[profile.default]
src = "src"
test = "test"
out = "out"
cache_path = "cache"
libs = []
auto_detect_solc = true
offline = true
# A rendered assertion that reads several ledger fields at once can hold more
# locals than the legacy 16-slot stack limit allows, and the failure mode is a
# compiler internal error that says nothing about the contract under test.  The
# optimizer plus the IR pipeline removes the artificial pressure; `via_ir`
# exists from 0.8.13 on, so older profiles simply ignore it.
optimizer = true
optimizer_runs = 200
via_ir = true
'''
    if remappings:
        foundry += 'remappings = [\n' + ''.join(f'    "{entry}",\n' for entry in remappings) + ']\n'
    (output_dir / 'foundry.toml').write_text(foundry, encoding='utf-8')
    manifest = {'schemaVersion': 1, 'sourceSha256': source_sha256,
                'invariantsSha256': hashlib.sha256(json.dumps(invariants, sort_keys=True,
                    ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest(),
                'deployment': deployment, 'tests': generated + adapter_required,
                'adapterRequiredCount': len(adapter_required),
                'scope': 'Generated checks execute registered protocol assertions; entries without a renderer remain adapter_required and never enter forge.'}
    (output_dir / 'harness.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('invariants', type=Path)
    parser.add_argument('verified_source_bundle', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--constructor-arguments', type=Path,
                        help='JSON file of constructor values keyed by parameter name. '
                             'Supplying this is what asks for an inline deployment; '
                             'omitting it leaves the harness reading its target from '
                             'the INVARIANT_TARGET environment variable.')
    args = parser.parse_args(argv)
    constructor_arguments = (json.loads(args.constructor_arguments.read_text(encoding='utf-8'))
                             if args.constructor_arguments else None)
    manifest = generate_harness(json.loads(args.invariants.read_text(encoding='utf-8')),
                                json.loads(args.verified_source_bundle.read_text(encoding='utf-8')),
                                args.output, constructor_arguments=constructor_arguments)
    print(json.dumps({'state': 'generated', 'harness': str(args.output),
                      'testCount': len(manifest['tests']), 'deployment': manifest['deployment']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
