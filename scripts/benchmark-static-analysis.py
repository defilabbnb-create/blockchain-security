#!/usr/bin/env python3
"""Compare serial/parallel/auto runs on one immutable verified source bundle."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_process import run_analyzer
from benchmark_support import summarize_performance

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('benchmark_comparator', ROOT / 'scripts/compare-static-analysis.py')
comparator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparator)
FINGERPRINTS = ('callGraphSha256', 'dynamicEvidenceSha256', 'tracesSha256',
                'sourceCoverageSha256', 'correlationSha256', 'semanticFingerprint')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def code_hashes():
    files = [p for directory in (ROOT / 'scripts', ROOT / 'flare-scan/tools')
             for p in directory.iterdir() if p.suffix in ('.py', '.cjs', '.mjs', '.js') and p.is_file()]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def write_json(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    os.replace(temp, path)


def read_bundle(path):
    raw = path.read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get('sources'), dict) or not data['sources']:
        raise ValueError('expected verified source bundle with nonempty sources')
    return raw


def validate_dynamic(local):
    if not isinstance(local, dict) or local.get('state') != 'passed':
        raise ValueError('dynamic tests did not pass')
    for name in ('tests', 'passed', 'failed'):
        if type(local.get(name)) is not int:
            raise ValueError('invalid dynamic count: ' + name)
    if local['tests'] <= 0 or local['passed'] != local['tests'] or local['failed'] != 0:
        raise ValueError('incomplete dynamic test counts')
    results = local.get('results')
    if not isinstance(results, list) or len(results) != local['tests'] or any(
            not isinstance(row, dict) or row.get('state') != 'passed' for row in results):
        raise ValueError('incomplete dynamic scenario results')


def collect_evidence(folder, row):
    report = json.loads((folder / 'stdout.json').read_text())
    comparator.validate_report(report)
    execution = report['analysisExecution']
    actual = execution['staticDynamicStages']
    row.update(actualMode=actual, parallelReason=execution.get('parallelReason'))
    if actual not in ('serial', 'parallel') or (row['mode'] != 'auto' and actual != row['mode']):
        raise ValueError('requested mode differs from executed mode')
    validate_dynamic(report['localTests'])
    local = json.loads((folder / 'local-tests.json').read_text())
    graph = json.loads((folder / 'call-graph.json').read_text())
    validate_dynamic(local)
    if not isinstance(graph, dict) or graph.get('state') != report['callGraph']['state']:
        raise ValueError('companion call graph state mismatch')
    for key, value in report['callGraph'].items():
        if key not in ('report', 'pathFeasibility') and graph.get(key) != value:
            raise ValueError('report and companion call graph differ: ' + key)
    for key in ('state', 'tests', 'passed', 'failed', 'verifiedSourceFingerprint',
                'verifiedDependencyFingerprint', 'results'):
        if report['localTests'].get(key) != local.get(key):
            raise ValueError('report and companion dynamic evidence differ: ' + key)
    if local.get('verifiedSourceFingerprint') != report['verifiedSourceFingerprint']:
        raise ValueError('companion source fingerprint mismatch')
    if local.get('verifiedDependencyFingerprint') != report.get('verifiedDependencyFingerprint'):
        raise ValueError('companion dependency fingerprint mismatch')
    coverage = local.get('sourceCoverage', {})
    row.update(state=report['state'], staticStages=report['staticStages'],
               findingCount=report['findingCount'], semanticFingerprint=report['findingSemanticFingerprint'],
               timings=report.get('timings', {}), dynamicTests=local['tests'], dynamicPassed=local['passed'],
               dynamicFailed=local['failed'], traceCount=len(local.get('traces', [])),
               sourceSpanCount=len(coverage.get('spans', [])),
               deterministicOperations=local.get('deterministicFuzz', {}).get('executedOperations'),
               callGraphSha256=digest(graph), dynamicEvidenceSha256=digest(comparator._stable_local_tests(local)),
               tracesSha256=digest(local.get('traces', [])), sourceCoverageSha256=digest(coverage),
               correlationSha256=digest(local.get('staticCorrelation')))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dependency', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--seed', type=int, default=72531)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--modes', nargs='+', choices=('serial', 'parallel', 'auto'), default=['serial', 'parallel', 'auto'])
    args = parser.parse_args(argv)
    try:
        if args.rounds < 1 or not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError('rounds and timeout must be positive and finite')
        if len(set(args.modes)) != len(args.modes) or not {'serial', 'parallel'} <= set(args.modes):
            raise ValueError('unique modes must include serial and parallel')
        raw = read_bundle(args.source)
        dep_raw = read_bundle(args.dependency) if args.dependency else None
        before = code_hashes()
        args.output = args.output.resolve()
        args.output.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({'status': 'invalid', 'equivalent': False, 'error': str(error)}))
        return 2
    order = [(mode, f'{mode}-{round_index + 1}') for round_index in range(args.rounds) for mode in args.modes]
    random.Random(args.seed).shuffle(order)
    input_hash = hashlib.sha256(raw).hexdigest()
    dep_hash = hashlib.sha256(dep_raw).hexdigest() if dep_raw is not None else None
    summary = {'status': 'running', 'equivalent': False, 'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'evidenceDirectory': str(args.output), 'inputSha256': input_hash, 'dependencyInputSha256': dep_hash,
               'sourceCodeSha256': before, 'seed': args.seed, 'order': order, 'runs': [],
               'scope': 'Local controlled benchmark of one source, not universal performance or security proof. '
                        'Process-group RSS is sampled, not a hardware/unified-memory peak.'}
    reports = {}
    interrupted = False
    try:
        write_json(args.output / 'order.json', summary)
        for mode, label in order:
            folder = args.output / label
            row = {'mode': mode, 'label': label, 'success': False, 'reportFile': str(folder / 'stdout.json')}
            summary['runs'].append(row)
            try:
                folder.mkdir()
                bundle = folder / 'verified-source.json'
                bundle.write_bytes(raw)
                command = [sys.executable, str(ROOT / 'scripts/review-static.py'), str(bundle)]
                if dep_raw is not None:
                    dependency = folder / 'verified-dependency-source.json'
                    dependency.write_bytes(dep_raw)
                    command.append(str(dependency))
                env = dict(os.environ, FLARE_ANALYSIS_PARALLEL={'serial': 'off', 'parallel': 'on', 'auto': 'auto'}[mode],
                           PYTHONHASHSEED='0', PYTHONDONTWRITEBYTECODE='1')
                row.update(run_analyzer(command, ROOT, env, folder, args.timeout))
                if row.get('error') or row['exitCode'] != 0:
                    raise ValueError(row.get('error', 'analyzer_nonzero_exit'))
                reports[label] = collect_evidence(folder, row)
                row['success'] = True
            except Exception as error:
                row['error'] = f'{type(error).__name__}: {str(error)[:700]}'
            except KeyboardInterrupt:
                interrupted = True
                row['error'] = 'interrupted'
                raise
            finally:
                if folder.is_dir():
                    write_json(folder / 'metrics.json', row)
    except KeyboardInterrupt:
        interrupted = True
    except Exception as error:
        summary['error'] = f'{type(error).__name__}: {str(error)[:700]}'
    try:
        summary['sourceUnchanged'] = before == code_hashes()
        summary['inputUnchanged'] = hashlib.sha256(args.source.read_bytes()).hexdigest() == input_hash
        summary['dependencyInputUnchanged'] = dep_raw is None or hashlib.sha256(args.dependency.read_bytes()).hexdigest() == dep_hash
        baseline = reports.get('serial-1')
        summary['comparisons'] = {label: comparator.compare_reports(baseline, report)
                                  for label, report in reports.items() if label != 'serial-1'} if baseline else {}
        summary['evidenceMatches'] = {key: bool(reports) and len({row[key] for row in summary['runs'] if row['success']}) == 1
                                      for key in FINGERPRINTS}
        valid = [row for row in summary['runs'] if row['success']]
        if {'serial', 'parallel'} <= {row['mode'] for row in valid}:
            if all(row['peakGroupRssMiB'] is not None for row in valid):
                summary['performance'] = summarize_performance(valid)
            else:
                summary['memoryMeasurementError'] = 'missing nonempty process-group RSS samples'
        summary['equivalent'] = bool(baseline) and len(valid) == len(order) and not interrupted and 'error' not in summary and all(
            summary[key] for key in ('sourceUnchanged', 'inputUnchanged', 'dependencyInputUnchanged')) and all(
            value['equivalent'] for value in summary['comparisons'].values()) and all(summary['evidenceMatches'].values())
    except Exception as error:
        summary.update(equivalent=False, error=f'{type(error).__name__}: {str(error)[:700]}')
    summary['status'] = 'interrupted' if interrupted else 'completed' if summary['equivalent'] else 'failed'
    summary['completedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write_json(args.output / 'validation.json', summary)
    print(json.dumps({'validationFile': str(args.output / 'validation.json'), 'status': summary['status'],
                      'equivalent': summary['equivalent'], 'performance': summary.get('performance')}))
    return 130 if interrupted else 0 if summary['equivalent'] else 1


if __name__ == '__main__':
    sys.exit(main())
