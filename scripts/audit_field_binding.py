#!/usr/bin/env python3
"""Re-derive invariant field bindings for the audited candidates and judge them.

The 78-row table in ``work/audit/task1-semantic-audit.json`` was produced before
the binding fix and by a throwaway script, so it cannot say whether the fix
worked.  This script regenerates the invariants through the same entry point
the campaign uses (``generate_invariants`` with source text and ABI getters from
the stored verified-source bundle) and checks every candidate row against what
the compiler-reported ABI says, with explicit rules instead of hand judgement.

It does not run forge.  The ``state`` of a row (``violated`` ...) comes from the
earlier run and is only carried along for reference; what is audited here is
whether the field a template reads is the kind of field the template asks about.

Verdicts
  match               the bound field has the type/role the template needs
  no_field_required   template reads no field (entrypoint only); entrypoint exists
  mismatch            a field is bound but cannot answer the template's question
  dropped             the regenerated set has no such invariant (binding refused)
  unverifiable        the rule cannot decide from ABI alone; reported, not counted as match
"""
import argparse, collections, importlib.util, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT))

NUMERIC = ('uint', 'int')


def _load_campaign():
    spec = importlib.util.spec_from_file_location('campaign', ROOT / 'scripts/defi-campaign.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bundles_for(name):
    """Every stored copy of one contract that has both inputs, newest first."""
    found = []
    for folder in (ROOT / 'work/defi-campaign').glob('*/contracts/%s' % name):
        if (folder / 'verified-source.json').is_file() and (folder / 'unified-ir.json').is_file():
            found.append(folder)
    return sorted(found, key=lambda p: (p / 'verified-source.json').stat().st_mtime, reverse=True)


def _abi_index(data):
    """name -> list of (inputs, outputs, mutability) from the deployment's own ABI."""
    index = collections.defaultdict(list)
    for entry in data.get('abi') or []:
        if isinstance(entry, dict) and entry.get('type') == 'function' and entry.get('name'):
            index[entry['name']].append((
                [i.get('type', '') for i in entry.get('inputs') or []],
                [o.get('type', '') for o in entry.get('outputs') or []],
                entry.get('stateMutability', '')))
    return index


def _signature_known(index, signature):
    name = signature.split('(', 1)[0]
    arguments = signature[len(name) + 1:-1]
    wanted = [a for a in arguments.split(',') if a] if arguments else []
    return [m for (inputs, _, m) in index.get(name, []) if inputs == wanted]


def _readable_getter(index, name):
    """Return the output types of a zero-argument view getter, else None."""
    for inputs, outputs, mutability in index.get(name, []):
        if not inputs and outputs and mutability in ('view', 'pure'):
            return outputs
    return None


def judge(template, params, index):
    """Return (verdict, reason) for one regenerated invariant."""
    if template == 'privileged_entry_requires_authentication':
        extra = sorted(set(params) - {'entrypoint', 'toleranceBps'})
        if extra:
            return 'mismatch', 'unexpected parameters %s' % extra
        mutability = _signature_known(index, params.get('entrypoint') or '')
        if not mutability:
            return 'mismatch', 'entrypoint %r is not in the ABI' % params.get('entrypoint')
        if all(m in ('view', 'pure') for m in mutability):
            return 'mismatch', 'entrypoint %r is read-only' % params.get('entrypoint')
        return 'no_field_required', 'entrypoint exists and is state-changing'
    if template == 'unauthorized_caller_cannot_mutate_state':
        field = params.get('guardedField')
        mutability = _signature_known(index, params.get('entrypoint') or '')
        if not mutability or all(m in ('view', 'pure') for m in mutability):
            return 'mismatch', 'entrypoint %r missing or read-only' % params.get('entrypoint')
        outputs = _readable_getter(index, field or '')
        if outputs is None:
            return 'mismatch', 'guardedField %r is not a readable zero-argument getter' % field
        if outputs != ['address']:
            return 'mismatch', 'guardedField %r returns %s; a privilege holder is an address' % (field, outputs)
        return 'match', 'guardedField %r returns address' % field
    if template in ('arithmetic_result_never_wraps', 'balance_delta_matches_intended_amount',
                    'call_success_is_enforced'):
        field = params.get('valueField') or params.get('ledgerField')
        outputs = _readable_getter(index, field or '')
        if outputs is None:
            return 'mismatch', 'field %r is not a readable zero-argument getter' % field
        if len(outputs) != 1 or not outputs[0].startswith(NUMERIC):
            return 'mismatch', 'field %r returns %s; the template needs a number' % (field, outputs)
        return 'unverifiable', ('field %r is numeric, but ABI alone cannot show it is the quantity '
                                'the flagged operation changes' % field)
    if template == 'randomness_source_is_unpredictable':
        field = params.get('valueField')
        return 'unverifiable', 'randomness field %r: needs source-level confirmation' % field
    return 'unverifiable', 'no rule for template %r' % template


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--out', default=str(ROOT / 'work/audit/binding-audit-post-fix.json'))
    args = parser.parse_args(argv)

    campaign = _load_campaign()
    from invariant_gen import generate_invariants

    rows = json.loads((ROOT / 'work/audit/track-g-candidates.json').read_text(encoding='utf-8')) + \
        json.loads((ROOT / 'work/audit/track-g-held.json').read_text(encoding='utf-8'))
    old = {r['invariantId']: r for r in json.loads(
        (ROOT / 'work/audit/task1-semantic-audit.json').read_text(encoding='utf-8'))}

    regenerated = {}
    copies_disagree = []
    for name in sorted({r['contract'] for r in rows}):
        results = []
        for folder in _bundles_for(name):
            data = campaign.normalize_source_unit_names(
                json.loads((folder / 'verified-source.json').read_text(encoding='utf-8')))
            ir = json.loads((folder / 'unified-ir.json').read_text(encoding='utf-8'))
            result = generate_invariants(
                ir, source_sha256=campaign.source_identity(data),
                source_text=campaign.invariant_source_text(data),
                abi_getters=campaign.invariant_abi_getters(data),
                abi_getter_outputs=campaign.invariant_abi_getter_outputs(data))
            results.append((folder, data, result))
        if not results:
            regenerated[name] = None
            continue
        signatures = {json.dumps(sorted((i['template'], json.dumps(i['params'], sort_keys=True))
                                        for i in r['invariants'])) for _, _, r in results}
        if len(signatures) > 1:
            copies_disagree.append(name)
        regenerated[name] = results[0]

    audited = []
    for row in rows:
        entry = regenerated.get(row['contract'])
        base = {'contract': row['contract'], 'template': row['template'],
                'priorState': row.get('state'), 'oldParams': row.get('params'),
                'oldVerdict': (old.get(row['invariantId']) or {}).get('semanticMatch')}
        if entry is None:
            audited.append({**base, 'verdict': 'dropped', 'reason': 'no stored bundle with source and IR'})
            continue
        _, data, result = entry
        candidates = [i for i in result['invariants'] if i['template'] == row['template']
                      and i['params'].get('entrypoint') == (row.get('params') or {}).get('entrypoint')]
        if not candidates:
            audited.append({**base, 'verdict': 'dropped',
                            'reason': 'regeneration no longer emits this template for this entrypoint'})
            continue
        invariant = candidates[0]
        verdict, reason = judge(row['template'], invariant['params'], _abi_index(data))
        audited.append({**base, 'newParams': invariant['params'], 'verdict': verdict, 'reason': reason,
                        'paramsChanged': invariant['params'] != row.get('params')})

    summary = collections.Counter(a['verdict'] for a in audited)
    report = {'generatedFor': 'post-binding-fix re-audit', 'rows': len(audited),
              'summary': dict(summary), 'copiesDisagree': copies_disagree,
              'oldSummary': dict(collections.Counter(a['oldVerdict'] for a in audited)),
              'paramsChanged': sum(1 for a in audited if a.get('paramsChanged')),
              'audited': audited}
    out = Path(args.out)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('rows', 'summary', 'oldSummary', 'paramsChanged',
                                             'copiesDisagree')}, ensure_ascii=False, indent=1))
    print('wrote %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
