"""Run generated invariant harnesses within explicit local/fork boundaries."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def _bounded_runner():
    spec = importlib.util.spec_from_file_location('review_static_runner', ROOT / 'scripts' / 'review-static.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_bounded, module.ProcessTreeMemoryLimitExceeded


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _rpc_url_is_safe(value):
    try:
        parsed = urlsplit(value)
        return parsed.scheme == 'https' and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    except Exception:
        return False


def _result(invariant_id, mode, state, *, reason=None, minimal_repro=None, gas_used=None, block_anchor=None, evidence=None,
            reconciliation=None):
    return {'schemaVersion': 1, 'invariantId': invariant_id, 'mode': mode, 'state': state,
            'minimalRepro': minimal_repro or [], 'gasUsed': gas_used,
            'blockAnchor': block_anchor, 'evidenceSha256': evidence,
            **({'reason': reason} if reason else {}),
            **({'suiteReconciliation': reconciliation} if reconciliation else {})}


def _forge_test_outcomes(output):
    """Read the per-test status forge recorded for each suite it ran.

    Returns `{suite_name: status}` where status is one of `success`, `failure`,
    `skipped`, or `unknown`.  Forge emits one JSON document per test suite and a
    trailing provenance line, so the document is parsed line by line rather than
    taken as a whole; anything unparseable is ignored rather than guessed at,
    because a guessed status here decides whether a detection is reported.
    """
    outcomes={}
    for line in output.decode('utf-8', errors='replace').splitlines():
        line=line.strip()
        if not line.startswith('{'):continue
        try:
            document=json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(document,dict):continue
        for suite,payload in document.items():
            if not isinstance(payload,dict):continue
            results=payload.get('test_results')
            if not isinstance(results,dict):continue
            for test,payload_test in results.items():
                if not isinstance(payload_test,dict):continue
                status=str(payload_test.get('status') or '').strip().lower()
                # A suite that contains both a passing and a failing test is a
                # failure.  Recording the first success and ignoring the rest
                # would drop a real detection inside the one suite that carries
                # the evidence.
                if status=='failure':outcomes[suite]='failure'
                elif status=='success':outcomes.setdefault(suite,'success')
                elif status=='skipped':outcomes.setdefault(suite,'skipped')
                else:outcomes.setdefault(suite,'unknown')
    return outcomes


def _compilation_failed(output_text):
    """Whether forge failed while compiling rather than while running a test.

    A bundle that imports a package it does not carry -- `openzeppelin-solidity`
    against a bundle holding only the protocol's own sources -- produces a
    parser error before any test exists.  Nothing was measured, so the result
    is unavailable, and saying which kind of unavailability it was matters:
    a compile failure is a missing dependency in the bundle, while a missing
    adapter is a template this project cannot render.
    """
    return any(marker in output_text for marker in (
        'compiler run failed',
        'parsererror',
        'error: source',
        'not found: file import callback not supported',
    ))


def _forge_command(forge, harness_dir, manifest=None):
    # A bare `forge` cannot resolve a compiler for the pre-0.8 samples in the
    # benchmark corpus: with nothing installed for, say, `^0.4.10` it exits
    # before any test runs, and the failure then surfaces as "no assertion
    # executed" rather than as the compiler error it is.  When the caller hands
    # us the solc bridge, the run goes through it and one already-cached soljson
    # release is pinned with `--use`.  A harness that recorded the exact compiler
    # it was built with is honoured, because `auto` would otherwise take the
    # newest release the pragma range allows.
    forge = Path(forge)
    if forge.name == 'forge-with-solc.py':
        recorded = (manifest or {}).get('deployment', {}).get('compilerVersion')
        return [sys.executable, str(forge), '--compiler-version', recorded or 'auto',
                '--forge', str(_default_forge(harness_dir)),
                'test', '--root', str(harness_dir), '--json']
    # A bare forge binary resolves solc through Foundry's own installed-compiler
    # directory, which this project does not populate: every release lives in
    # work/compiler-cache and is reached through the bridge.  Left unbridged,
    # forge reports "No compiler version installed that matches the version
    # requirement" and exits non-zero, and the classifier could not tell that
    # from a failed assertion -- so every assertion on the contract was reported
    # as violated.  Measured over the real collected corpus this affected every
    # harness whose pragma range had no compiler in Foundry's directory.
    if not _harness_needs_bridge(harness_dir):
        return [str(forge), 'test', '--root', str(harness_dir), '--json']
    bridge = Path(__file__).resolve().parent / 'forge-with-solc.py'
    if not bridge.is_file():
        return [str(forge), 'test', '--root', str(harness_dir), '--json']
    recorded = (manifest or {}).get('deployment', {}).get('compilerVersion')
    return [sys.executable, str(bridge), '--compiler-version', recorded or 'auto',
            '--forge', str(forge), 'test', '--root', str(harness_dir), '--json']


def _harness_needs_bridge(harness_dir):
    """True when the harness has sources to compile and the bridge is usable.

    A harness with no Solidity at all cannot need a compiler, and neither can one
    the bridge cannot lay out, so both are left on the bare binary.
    """
    if not any(Path(harness_dir).rglob('*.sol')):
        return False
    cache = Path(__file__).resolve().parent.parent / 'work' / 'compiler-cache'
    if not cache.is_dir() or not any(cache.glob('soljson-v*.cjs')):
        return False
    return True


def _rpc_block_hash(url, block_number):
    parsed = urlsplit(url)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=10,
                                               context=ssl.create_default_context())
    path = parsed.path or '/'
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber',
                       'params': [hex(block_number), False]}).encode('utf-8')
    try:
        connection.request('POST', path, body=body, headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('fixed_block_rpc_http_error')
        if response.getheader('Location'):
            raise ValueError('fixed_block_rpc_redirect_rejected')
        payload = json.loads(response.read(1_000_001))
        block = payload.get('result') if isinstance(payload, dict) else None
        block_hash = block.get('hash') if isinstance(block, dict) else None
        if not isinstance(block_hash, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', block_hash):
            raise ValueError('fixed_block_hash_unavailable')
        return block_hash.lower()
    finally:
        connection.close()


def _default_forge(harness_dir):
    """Resolve the bundled forge binary.

    A harness lives under a task directory, so walking up from it does not
    reliably reach the repository. Prefer the project's own tool location and
    keep the historical relative path as a fallback.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / 'work' / 'tools' / 'forge',
        Path(harness_dir).resolve().parent.parent / 'tools' / 'forge',
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def run_harness(harness_dir, *, mode='local', forge=None, timeout_seconds=120, max_output_bytes=2_000_000,
                rpc_url=None, block_number=None, block_hash_before=None, block_hash_after=None,
                replay_enabled=False, max_process_tree_rss_bytes=3 * 1024 * 1024 * 1024):
    harness_dir = Path(harness_dir).resolve()
    manifest_path = harness_dir / 'harness.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    all_rows = manifest.get('tests', [])
    adapter_rows = [row for row in all_rows if row.get('status') == 'adapter_required']
    invariant_rows = [row for row in all_rows if row not in adapter_rows]

    def finish(rows):
        adapter_results = [_result(row['invariantId'], mode, 'unavailable', reason=row.get('reason', 'adapter_required'))
                           for row in adapter_rows]
        return adapter_results + rows

    if not invariant_rows:
        return finish([])
    forge = Path(forge or _default_forge(harness_dir)).expanduser().resolve()
    if mode not in ('local', 'fixed_block_fork', 'replay'):
        raise ValueError('mode must be local, fixed_block_fork, or replay')
    if mode == 'replay':
        reason = 'replay_disabled_by_default' if not replay_enabled else 'replay_adapter_not_configured'
        return finish([_result(row['invariantId'], mode, 'unavailable', reason=reason) for row in invariant_rows])
    deployment = manifest.get('deployment') or {}
    if deployment.get('state') == 'adapter_required':
        return [_result(row['invariantId'], mode, 'unavailable', reason='protocol_specific_deployment_adapter_required') for row in all_rows]
    if mode == 'fixed_block_fork':
        if not isinstance(rpc_url, str) or not _rpc_url_is_safe(rpc_url):
            return finish([_result(row['invariantId'], mode, 'unavailable', reason='fixed_block_fork_requires_https_rpc_without_credentials') for row in invariant_rows])
        if not isinstance(block_number, int) or block_number < 0:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason='fixed_block_fork_requires_nonnegative_block') for row in invariant_rows])
        try:
            block_hash_before = _rpc_block_hash(rpc_url, block_number)
        except Exception as error:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason=str(error)[:120]) for row in invariant_rows])
    if not forge.is_file():
        return finish([_result(row['invariantId'], mode, 'unavailable', reason='forge_not_found') for row in invariant_rows])
    command = _forge_command(forge, harness_dir, manifest)
    env = dict(os.environ)
    for key in ('RPC_URL', 'DYNAMIC_FORK_RPC_URL', 'DYNAMIC_FORK_BLOCK_NUMBER', 'ETH_RPC_URL', 'FOUNDRY_ETH_RPC_URL'):
        env.pop(key, None)
    env['FOUNDRY_OFFLINE'] = 'true' if mode == 'local' else 'false'
    if mode == 'local':
        env.pop('DYNAMIC_EXECUTION_MODE', None)
    if mode == 'fixed_block_fork':
        command.extend(['--fork-url', rpc_url, '--fork-block-number', str(block_number)])
        env['DYNAMIC_EXECUTION_MODE'] = 'fixed_block_fork'
        env['DYNAMIC_FORK_RPC_URL_SHA256'] = _sha256_bytes(rpc_url.encode('utf-8'))
        env['DYNAMIC_FORK_BLOCK_NUMBER'] = str(block_number)
    started = time.monotonic()
    try:
        run_bounded, memory_error = _bounded_runner()
        completed = run_bounded(command, timeout_seconds, cwd=harness_dir, env=env,
                                max_process_tree_rss_bytes=max_process_tree_rss_bytes)
        return_code = completed.returncode
        output = (completed.stdout or '').encode('utf-8', errors='replace') + (completed.stderr or '').encode('utf-8', errors='replace')
    except memory_error as error:
        evidence = _sha256_bytes((getattr(error, 'stdout', '') or '').encode('utf-8') + (getattr(error, 'stderr', '') or '').encode('utf-8'))
        return finish([_result(row['invariantId'], mode, 'timeout', reason='process_tree_memory_limit_exceeded', evidence=evidence) for row in invariant_rows])
    except subprocess.TimeoutExpired as error:
        evidence = _sha256_bytes((error.stdout or b'') + (error.stderr or b''))
        return finish([_result(row['invariantId'], mode, 'timeout', reason='forge_timeout', evidence=evidence) for row in invariant_rows])
    except Exception as error:
        return finish([_result(row['invariantId'], mode, 'unavailable', reason=f'runner_error:{type(error).__name__}') for row in invariant_rows])
    if len(output) > max_output_bytes:
        output = output[:max_output_bytes]
    evidence = _sha256_bytes(output)
    if mode == 'fixed_block_fork':
        try:
            block_hash_after = _rpc_block_hash(rpc_url, block_number)
        except Exception as error:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason=str(error)[:120],
                            evidence=evidence, block_anchor={'number': block_number, 'hashBefore': block_hash_before,
                                                             'rpcUrlSha256': _sha256_bytes(rpc_url.encode('utf-8'))}) for row in invariant_rows])
        if block_hash_after != block_hash_before:
            return finish([_result(row['invariantId'], mode, 'unavailable', reason='block_anchor_changed', evidence=evidence,
                            block_anchor={'number': block_number, 'hashBefore': block_hash_before,
                                          'hashAfter': block_hash_after,
                                          'rpcUrlSha256': _sha256_bytes(rpc_url.encode('utf-8'))}) for row in invariant_rows])
    output_text = output.decode('utf-8', errors='replace').lower()
    unavailable = any(marker in output_text for marker in ('compilation failed', 'compiler run failed',
        'invariant_target', 'failed to resolve', 'could not find'))
    # A missing compiler is the same class of outcome as a failed compilation: the
    # harness never ran, so nothing was measured.  Forge words it several ways
    # depending on which stage gave up, and each variant that went unrecognised
    # reached the `violated` branch below and reported every assertion on the
    # contract as a detection -- a 100% false-positive rate on every bundle
    # whose pragma range had no cached solc.  Measured on the real collected
    # corpus, that was all of them.
    no_compiler = any(marker in output_text for marker in (
        'invalid compiler version',
        'no compiler version installed',
        'compiler version not installed',
        'no solc version',
        'failed to download solc',
        'could not find compiler',
        'error: no such file or directory',
    ))
    # Forge exits 0 when every test skipped, so an exit 0 on its own says the
    # test passed.  It did not: the adapter's call was rejected and the run
    # stopped before the assertion read anything.  The per-test outcome is the
    # only place that distinction is recorded, so it is checked before the return
    # code -- otherwise a skipped measurement is filed as a pass, which is a
    # silent false negative where the FAIL path is a silent false positive.
    skipped = 'adapter_action_unavailable' in output_text or '[skip]' in output_text
    # `violated` is only claimed when forge got as far as running a test and that
    # test failed.  Anything else -- an unrecognised error, an unusable harness, a
    # missing toolchain -- is `unavailable`.  A state that looks like a detection
    # but is not one is the failure mode this project keeps meeting, and the exit
    # code alone cannot tell the two apart.
    ran_a_test = ('"test_results"' in output_text or 'ran ' in output_text
                  or '[pass]' in output_text or '[fail' in output_text)
    # Forge's JSON records the outcome of every test it ran.  The process exit
    # code does not: it is one bit for the whole invocation, so a suite that
    # passed and a suite that reverted in the same run are indistinguishable from
    # outside.  Reading only the exit code reported every assertion on the
    # contract as violated whenever any one of them failed -- measured on the
    # real corpus, 59 of 106 assertions, including suites forge had recorded as
    # `Success` in the very same document.
    #
    # The per-test record is the only place the distinction exists, so it is read
    # before the return code is consulted, in either direction: a suite recorded
    # as Success must not be filed as a detection, and one recorded as Failure
    # must not be filed as a pass because another suite succeeded.
    per_test=_forge_test_outcomes(output)
    if skipped:
        state = 'unavailable'
        reason = 'adapter_action_unavailable'
    elif per_test and all(status=='success' for status in per_test.values()):
        state = 'passed'
        reason = None
    elif per_test and any(status=='failure' for status in per_test.values()):
        state = 'violated'
        reason = 'forge_assertion_or_compilation_failed'
    elif per_test:
        state = 'unavailable'
        reason = 'forge_reported_no_completed_test_result'
    elif return_code == 0:
        state = 'passed'
        reason = None
    elif unavailable:
        state = 'unavailable'
        reason = 'harness_not_executable_or_target_adapter_missing'
    elif no_compiler or not ran_a_test:
        state = 'unavailable'
        reason = ('required_compiler_not_installed' if no_compiler
                  else 'forge_failed_before_any_assertion_ran')
    elif _compilation_failed(output_text):
        # A harness whose imports do not resolve never compiles, so no
        # assertion ran and nothing was measured.  That is not the same thing
        # as a target that could not be reached, and the two were reported
        # under one reason -- a compile failure read as a missing adapter.
        state = 'unavailable'
        reason = 'harness_did_not_compile'
    else:
        state = 'violated'
        reason = 'forge_assertion_or_compilation_failed'
    anchor={'number': block_number, 'hash': block_hash_before,
            'rpcUrlSha256': _sha256_bytes(rpc_url.encode('utf-8'))} if mode == 'fixed_block_fork' else None
    # Forge is invoked once for the whole contract and returns one document
    # describing every suite, so the invocation's outcome and an individual
    # assertion's outcome are not the same thing.  One reverting suite used to
    # mark every assertion on the contract as violated, including the suites
    # forge had just recorded as Success in the same document -- so a contract
    # with seven assertions of which three broke was reported as seven findings.
    #
    # Each assertion is attributed to its own suite where forge's record can be
    # matched; only an assertion whose suite cannot be identified falls back to
    # the invocation-wide state, and that is stated in its reason.
    per_assertion_state=_attribute_per_suite(invariant_rows,per_test,state,reason)
    # With a per-test record every assertion has its own entry, so the
    # invocation-wide state is only ever applied when forge produced no
    # per-test record to attribute from.
    #
    # The counts let a reader see at a glance that forge ran fewer suites than
    # the harness generated, instead of finding it in a state column.
    reconciliation=({'generated':len(invariant_rows),'recorded':len(per_test),
                     'missing':sum(1 for entry in per_assertion_state.values()
                                   if entry[1]=='suite_result_missing')}
                    if per_test else None)
    return finish([_result(row['invariantId'], mode,
                    per_assertion_state.get(row['invariantId'],(state,reason))[0],
                    reason=per_assertion_state.get(row['invariantId'],(state,reason))[1],
                    block_anchor=anchor,evidence=evidence,reconciliation=reconciliation)
                   for row in invariant_rows])


def _expected_suite_key(row):
    """The key forge uses for this assertion's suite: `<file>:<contract>`.

    `harness_gen` writes each assertion to `test/Invariant_<id[:16]>.t.sol` and
    names the contract `Invariant_<id[:16]>`, and forge keys its JSON by file and
    contract.  Both halves are derived from the same 16 characters, so the key is
    an exact string and is compared for equality -- a substring match on a shorter
    prefix let two assertions claim one suite, and let a suite that merely
    contained the prefix stand in for the assertion's own.
    """
    identifier=str(row.get('invariantId') or '')
    if not identifier:return None
    stem='Invariant_%s'%identifier[:16]
    path=row.get('path') or 'test/%s.t.sol'%stem
    return '%s:%s'%(path,stem)


def _attribute_per_suite(invariant_rows,per_test,invocation_state=None,invocation_reason=None):
    """Map every invariantId to the outcome forge recorded for its own suite.

    Forge is invoked once and returns one document per suite, so the
    invocation's state says nothing about an assertion whose suite it did not
    record.  Such an assertion was not measured, and it is reported as
    `unavailable` with `suite_result_missing` -- never as the invocation's
    state.  Inheriting it filed an unmeasured assertion as a pass when the
    suites that did run passed, and as a detection when one of them failed.
    The invocation-level arguments are accepted for signature compatibility and
    deliberately not consulted.

    An assertion whose expected suite key is shared with another assertion
    cannot be told apart by forge's record either, so both are
    `suite_result_ambiguous` rather than one of them silently taking the
    other's outcome.

    With no per-test record at all nothing is attributed (an empty mapping) and
    the caller decides from the invocation as a whole.
    """
    attributed={}
    if not per_test:return attributed
    keys={}
    for row in invariant_rows:
        key=_expected_suite_key(row)
        if key:keys.setdefault(key,[]).append(str(row['invariantId']))
    for row in invariant_rows:
        identifier=str(row.get('invariantId') or '')
        if not identifier:continue
        key=_expected_suite_key(row)
        if len(keys.get(key,()))>1:
            attributed[identifier]=('unavailable','suite_result_ambiguous')
            continue
        status=per_test.get(key)
        if status is None:
            attributed[identifier]=('unavailable','suite_result_missing')
        elif status=='success':
            attributed[identifier]=('passed',None)
        elif status=='failure':
            attributed[identifier]=('violated','forge_assertion_failed')
        else:
            attributed[identifier]=('unavailable','forge_reported_no_completed_test_result')
    return attributed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('harness', type=Path)
    parser.add_argument('--mode', choices=('local', 'fixed_block_fork', 'replay'), default='local')
    parser.add_argument('--forge', type=Path)
    parser.add_argument('--timeout-seconds', type=float, default=120)
    parser.add_argument('--rpc-url')
    parser.add_argument('--block-number', type=int)
    parser.add_argument('--block-hash-before')
    parser.add_argument('--block-hash-after')
    parser.add_argument('--enable-replay', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    results = run_harness(args.harness, mode=args.mode, forge=args.forge,
                          timeout_seconds=args.timeout_seconds, rpc_url=args.rpc_url,
                          block_number=args.block_number, block_hash_before=args.block_hash_before,
                          block_hash_after=args.block_hash_after, replay_enabled=args.enable_replay)
    payload = results[0] if len(results) == 1 else {'schemaVersion': 1, 'results': results}
    text = json.dumps(payload, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        descriptor, temporary = tempfile.mkstemp(prefix=f'.{args.output.name}.', dir=args.output.parent)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
                output.write(text)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, args.output)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    else:
        print(text, end='')
    # "Nothing ran" must never look like "everything passed". When every
    # invariant ended up unavailable the harness produced no evidence, so the
    # exit status has to distinguish that from an actual passing run.
    states = [item.get('state') for item in results]
    if states and all(state == 'unavailable' for state in states):
        return 2
    return 0 if all(state in ('passed', 'unavailable') for state in states) else 1


if __name__ == '__main__':
    raise SystemExit(main())
