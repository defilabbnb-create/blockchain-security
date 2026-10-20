#!/usr/bin/env python3
"""Run real compilation and Slither detectors, recording failures explicitly."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parent.parent
TOOLS = BASE / 'tools'


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf8', dir=path.parent, delete=False) as handle:
            temp = Path(handle.name)
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
        temp.replace(path)
    finally:
        if temp and temp.exists():
            temp.unlink()


def load_targets():
    targets = json.loads((BASE / 'targets.json').read_text())
    if not isinstance(targets, list) or not targets:
        raise ValueError('targets.json must contain at least one target')
    names = set()
    for target in targets:
        name = target['name']
        if not re.fullmatch(r'[a-z0-9-]+', name) or name in names:
            raise ValueError('Target names must be unique and use a-z, 0-9, hyphen')
        names.add(name)
        project = (BASE / target['project']).resolve()
        source = (project / target['source']).resolve()
        if BASE.resolve() not in project.parents or project not in source.parents:
            raise ValueError('Target must be inside the local project')
        if target['compiler'] not in ('0.8.19', '0.8.23', '0.8.28'):
            raise ValueError('Unsupported compiler')
        if target['evmVersion'] not in ('paris', 'london') or not isinstance(target['viaIR'], bool):
            raise ValueError('Invalid compiler configuration')
        if type(target['optimizerRuns']) is not int or not 0 <= target['optimizerRuns'] <= 10000000:
            raise ValueError('Invalid optimizer runs')
    return targets


def worker(target):
    if (TOOLS / 'pylibs').is_dir():
        sys.path.insert(0, str(TOOLS / 'pylibs'))
    from slither.slither import Slither
    from crytic_compile import CryticCompile
    from crytic_compile.platform.solc import Solc
    from slither.detectors import all_detectors
    from slither.detectors.abstract_detector import AbstractDetector
    from importlib.metadata import version
    project = (BASE / target['project']).resolve()
    source = project / target['source']
    if not source.is_file():
        raise ValueError('Source file missing: ' + target['source'])
    os.environ['SOLC_VERSION'] = target['compiler']
    remappings_file = project / 'remappings.txt'
    remappings = [line.strip() for line in remappings_file.read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith('#')] if remappings_file.exists() else []
    compilation = CryticCompile(Solc(str(source)), solc=str(TOOLS / 'solc-wrapper.sh'), solc_working_dir=str(project),
                      compile_force_framework='solc', solc_remaps=remappings, solc_args='--optimize --optimize-runs {} --evm-version {}{}'.format(target['optimizerRuns'], target['evmVersion'], ' --via-ir' if target['viaIR'] else ''),
                      cwd=str(project))
    from slither_compat import install_struct_resolution
    compatibility = install_struct_resolution(compilation) if version('slither-analyzer') == '0.11.4' else None
    slither = Slither(compilation, filter_paths=['node_modules/'], exclude_dependencies=True)
    detectors = [getattr(all_detectors, name) for name in dir(all_detectors)]
    detectors = [d for d in detectors if inspect.isclass(d) and issubclass(d, AbstractDetector) and d is not AbstractDetector]
    if not slither.contracts or not detectors:
        raise RuntimeError('No contracts or detectors loaded; refusing an empty success report')
    for detector in detectors:
        slither.register_detector(detector)
    findings = [finding for group in slither.run_detectors() for finding in group]
    hashes = {}
    for filename, content in slither.source_code.items():
        hashes[filename] = hashlib.sha256(content.encode()).hexdigest()
    return {'success': True, 'target': target, 'compiler': target['compiler'], 'slitherVersion': version('slither-analyzer'),
            'analyzedContracts': len(slither.contracts), 'detectorCount': len(detectors),
            'sourceHashes': hashes, 'compatibility': compatibility, 'findingCount': len(findings), 'severityCounts': dict(Counter(f['impact'] for f in findings)),
            'results': {'detectors': findings}, 'error': None,
            'scope': 'Static analysis of local source and imported dependencies; findings require manual validation. Not proof of deployed contract safety.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', action='append', help='Target name from targets.json; repeatable')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--output-dir', type=Path, default=BASE / 'reports')
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--worker', help=argparse.SUPPRESS)
    args = parser.parse_args()
    targets = load_targets()
    if args.worker:
        target = next(t for t in targets if t['name'] == args.worker)
        try:
            print(json.dumps(worker(target)))
            return 0
        except Exception as error:
            print(json.dumps({'success': False, 'target': target, 'error': str(error), 'results': {}}))
            return 1
    if args.list:
        for target in targets:
            print(target['name'] + ': ' + target['source'])
        return 0
    if not 1 <= args.timeout <= 1800:
        parser.error('--timeout must be between 1 and 1800 seconds')
    if args.target:
        unknown = set(args.target) - {t['name'] for t in targets}
        if unknown:
            parser.error('Unknown targets: ' + ', '.join(sorted(unknown)))
        targets = [t for t in targets if t['name'] in args.target]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary = {'schemaVersion': 1, 'generatedAt': datetime.now(timezone.utc).isoformat(),
               'complete': True, 'targets': [], 'scope': 'Local static analysis; automatic findings are not confirmed vulnerabilities.'}
    for target in targets:
        name = target['name']
        print('Analyzing ' + name + ' ...', file=sys.stderr, flush=True)
        try:
            with subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker', name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True) as run:
                try:
                    stdout, stderr = run.communicate(timeout=args.timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    os.killpg(run.pid, signal.SIGKILL)
                    stdout, stderr = run.communicate()
                    (output / (name + '.log')).write_text(stderr)
                    raise
            (output / (name + '.log')).write_text(stderr)
            data = json.loads(stdout)
            if run.returncode != 0 or data.get('success') is not True or not data.get('analyzedContracts') or not data.get('detectorCount'):
                raise RuntimeError(data.get('error') or 'Analyzer failed or produced empty analysis')
        except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            data = {'success': False, 'target': target, 'error': str(error), 'results': {}}
            summary['complete'] = False
        atomic_json(output / (name + '.json'), data)
        summary['targets'].append({k: v for k, v in data.items() if k not in ('results', 'sourceHashes')})
        print(name + ': ' + ('complete, {} findings'.format(data['findingCount']) if data['success'] else 'FAILED'), file=sys.stderr, flush=True)
    atomic_json(output / 'summary.json', summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary['complete'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError) as error:
        print('Analysis failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
