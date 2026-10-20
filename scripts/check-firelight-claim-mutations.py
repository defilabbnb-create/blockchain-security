#!/usr/bin/env python3
"""Check Firelight matured-claim liveness invariants against isolated source mutations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / 'flare-scan/contracts/firelight-core'
VAULT_REL = Path('contracts/core/FirelightVault.sol')
TEST_REL = Path('test/foundry/invariant/FirelightVault.invariant.t.sol')
HANDLER_REL = Path('test/foundry/harness/FirelightVaultHandler.sol')
MOCK_REL = Path('contracts/test/MockERC20.sol')
MUTATIONS = {
    'claim_always_reverts': (
        'if (period >= currentPeriod()) revert InvalidPeriod();',
        'if (period < currentPeriod()) revert InvalidPeriod();',
    ),
    'claim_pays_vault_instead': (
        'IERC20(asset()).safeTransfer(sender, assets);',
        'IERC20(asset()).safeTransfer(address(this), assets);',
    ),
}
DIRECT_TEST = 'test_maturedWithdrawalCanBeClaimed'
INVARIANT_TEST = 'invariant_maturedClaimsRemainLive'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_forge(explicit=None):
    if explicit:
        return str(Path(explicit).resolve())
    local = ROOT / 'work/tools/forge'
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    found = shutil.which('forge')
    if not found:
        raise RuntimeError('forge executable not found')
    return found


def build_isolated_project(destination, forge_std_source, node_modules):
    project = destination / 'project'
    project.mkdir(parents=True)
    for rel in (MOCK_REL, TEST_REL, HANDLER_REL):
        (project / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(PROJECT / 'contracts/core', project / 'contracts/core')
    shutil.copy2(PROJECT / MOCK_REL, project / MOCK_REL)
    shutil.copy2(PROJECT / TEST_REL, project / TEST_REL)
    shutil.copy2(PROJECT / HANDLER_REL, project / HANDLER_REL)
    shutil.copy2(PROJECT / 'foundry.toml', project / 'foundry.toml')
    (project / 'lib').mkdir()
    shutil.copytree(forge_std_source, project / 'lib/forge-std')
    (project / 'node_modules').symlink_to(node_modules, target_is_directory=True)
    return project


def run_command(forge, project, case_output, test_name, invariant=False):
    args = [forge, 'test', '--match-path', str(TEST_REL), '--match-test', test_name, '--threads', '1']
    if invariant:
        args.extend(['--invariant-depth', '30'])
    started = time.monotonic()
    try:
        proc = subprocess.run(args, cwd=project, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=180, check=False)
        output = proc.stdout
        code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ''
        output = partial.decode(errors='replace') if isinstance(partial, bytes) else partial
        code = None
        timed_out = True
    log = case_output / f'{test_name}.log'
    log.write_text(output)
    pass_marker = f'[PASS] {test_name}'
    fail_marker = f'[FAIL' in output and test_name in output
    return {
        'test': test_name,
        'exitCode': code,
        'timedOut': timed_out,
        'passedMarker': pass_marker in output,
        'failedMarker': fail_marker,
        'durationMs': round((time.monotonic() - started) * 1000),
        'log': str(log.relative_to(ROOT)),
    }


def execute_case(name, mutation, output, forge, forge_std_source, node_modules):
    case_dir = output / name
    case_dir.mkdir()
    with tempfile.TemporaryDirectory(prefix=f'.{name}-', dir=output) as scratch:
        project = build_isolated_project(Path(scratch), forge_std_source, node_modules)
        vault = project / VAULT_REL
        original = vault.read_text()
        if mutation:
            before, after = mutation
            if original.count(before) != 1:
                raise RuntimeError(f'{name}: mutation anchor must occur exactly once')
            vault.write_text(original.replace(before, after))
        suite = []
        for test_name, is_invariant in ((DIRECT_TEST, False), (INVARIANT_TEST, True)):
            suite.append(run_command(forge, project, case_dir, test_name, is_invariant))
        mutated_hash = sha256(vault)
    expected = 'baseline' if mutation is None else 'mutation_detected'
    valid = all(
        r['exitCode'] == 0 and r['passedMarker'] and not r['failedMarker']
        for r in suite
    ) if mutation is None else all(
        r['exitCode'] not in (0, None) and r['failedMarker']
        for r in suite
    )
    return {
        'name': name,
        'expected': expected,
        'state': 'passed' if valid else 'failed',
        'suite': suite,
        'scratchProjectDeletedAfterRun': not Path(scratch).exists(),
        'mutatedVaultSha256': mutated_hash,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--forge', type=Path)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists() and any((output / name).exists() for name in ('baseline', *MUTATIONS, 'report.json')):
        raise SystemExit(f'case output already exists: {output}')
    source = PROJECT / VAULT_REL
    original_hash = sha256(source)
    forge_std = PROJECT / 'lib/forge-std'
    node_modules = PROJECT / 'node_modules'
    forge = find_forge(args.forge)
    output.mkdir(parents=True, exist_ok=True)
    baseline = execute_case('baseline', None, output, forge, forge_std, node_modules)
    results = [baseline]
    for name, mutation in MUTATIONS.items():
        results.append(execute_case(name, mutation, output, forge, forge_std, node_modules))
    source_hash_after = sha256(source)
    report = {
        'state': 'passed' if source_hash_after == original_hash and all(r['state'] == 'passed' for r in results) else 'failed',
        'scope': 'isolated local Foundry copies; no RPC, live contract changes, or external transactions',
        'realFirelightVaultSha256Before': original_hash,
        'realFirelightVaultSha256After': source_hash_after,
        'realSourceUnchanged': source_hash_after == original_hash,
        'forge': forge,
        'mutations': list(MUTATIONS),
        'results': results,
    }
    report_path = output / 'report.json'
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['state'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
