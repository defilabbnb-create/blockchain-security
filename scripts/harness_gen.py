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


def generate_harness(invariants, source_bundle, output_dir, compiler_version=None):
    if not isinstance(invariants, dict) or invariants.get('schemaVersion') != 1:
        raise ValueError('invariants document schemaVersion 1 is required')
    if not isinstance(source_bundle, dict) or not isinstance(source_bundle.get('sources'), dict):
        raise ValueError('verified source bundle requires a sources object')
    sources = source_bundle['sources']
    source_sha256 = _source_digest(sources)
    if invariants.get('sourceSha256') not in (None, source_sha256):
        raise ValueError('invariants sourceSha256 does not match verified source bundle')
    targets = (source_bundle.get('metadata') or {}).get('settings', {}).get('compilationTarget', {})
    if not isinstance(targets, dict) or len(targets) != 1:
        deployment = {'state': 'unavailable', 'reason': 'compilation_target_missing_or_ambiguous'}
        target_name = None
    else:
        source_name, contract_name = next(iter(targets.items()))
        target_name = contract_name if isinstance(contract_name, str) and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', contract_name) else None
        deployment = {'state': 'adapter_required', 'reason': 'constructor_and_initialization_arguments_are_not_inferred',
                      'contract': target_name, 'sourceUnit': source_name}
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
                   'compiler_version': pragma}
        body = renderer(invariant.get('params') or {}, context) if renderer else None
        if not isinstance(body, str) or not body.strip():
            reason = 'invariant_renderer_missing' if renderer is None else 'invariant_renderer_requires_adapter'
            adapter_required.append({'invariantId': invariant_id, 'template': template, 'status': 'adapter_required', 'reason': reason, 'path': None})
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
        # The cheat-code interface and the handles built on it use post-0.4
        # spellings (`calldata` parameters, `uint256` casts, `.code`), which do
        # not parse under the 0.4.x compilers these benchmark samples pin.  The
        # form below -- plain `bytes32`/`string`, assembly address loads, and
        # `extcodesize` -- means the same thing on every version from 0.4.22 up,
        # so one template serves the whole corpus.  The assertion body itself is
        # renderer output and is left exactly as written.
        solidity = f'''// SPDX-License-Identifier: MIT
pragma solidity {pragma};

{vm_declared} {{
    {vm_body}
}}

contract Invariant_{invariant_id[:16]} {{
    bytes32 public constant invariantId = {id_literal};
    string public constant description = {description};

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
        address target = Vm(_cheatCodeAddress()).envAddress(bytes32("INVARIANT_TARGET"));
        {require_form}
        _assertProtocol(target);
    }}
}}
'''
        (test_root / test_name).write_text(solidity, encoding='utf-8')
        generated.append({'invariantId': invariant_id, 'path': f'test/{test_name}',
                          'template': template, 'status': invariant.get('status', 'unverified')})
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
    args = parser.parse_args(argv)
    manifest = generate_harness(json.loads(args.invariants.read_text(encoding='utf-8')),
                                json.loads(args.verified_source_bundle.read_text(encoding='utf-8')),
                                args.output)
    print(json.dumps({'state': 'generated', 'harness': str(args.output),
                      'testCount': len(manifest['tests']), 'deployment': manifest['deployment']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
