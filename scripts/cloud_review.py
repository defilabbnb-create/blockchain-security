"""Three-stage, evidence-bound review over an OpenAI-compatible endpoint."""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_RESPONSE_BYTES = 2_000_000


class CloudReviewError(RuntimeError):
    pass


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha256_json(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _line_ranges(values):
    ranges = []
    for line in sorted(values):
        if not ranges or line > ranges[-1][1] + 1:
            ranges.append([line, line])
        else:
            ranges[-1][1] = line
    return ranges


def validate_endpoint(value):
    parsed = urllib.parse.urlparse(str(value or '').strip())
    if (parsed.scheme != 'https' or not parsed.netloc or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise CloudReviewError('cloud review unavailable: base URL must be https without credentials, query, or fragment')
    endpoint = str(value).strip().rstrip('/')
    return endpoint if endpoint.endswith('/chat/completions') else endpoint + '/chat/completions'


def _clean_content(raw):
    if not isinstance(raw, str):
        raise CloudReviewError('cloud review response did not contain text')
    clean = re.sub(r'<think>[\s\S]*?</think>', '', raw).strip()
    return re.sub(r'^```(?:json)?\s*|\s*```$', '', clean).strip()


def _cost(payload, parsed):
    candidates = [parsed.get('costUsd') if isinstance(parsed, dict) else None,
                  payload.get('costUsd') if isinstance(payload, dict) else None,
                  (payload.get('usage') or {}).get('costUsd') if isinstance(payload, dict) and isinstance(payload.get('usage'), dict) else None]
    for candidate in candidates:
        if isinstance(candidate, (int, float)) and not isinstance(candidate, bool) and candidate >= 0:
            return float(candidate)
    return None


class _Budget:
    def __init__(self, limit):
        if limit is None:
            self.limit = None
        elif isinstance(limit, (int, float)) and not isinstance(limit, bool) and 0 <= limit:
            self.limit = float(limit)
        else:
            raise CloudReviewError('review budget must be a nonnegative number')
        self.spent = 0.0
        self.costs_known = True

    def permits(self):
        return self.limit is None or (self.costs_known and self.spent < self.limit - 1e-12)

    def charge(self, amount):
        if amount is None:
            self.costs_known = False
        else:
            self.spent += max(0.0, float(amount))


def _request(endpoint, api_key, model, stage, prompt, budget):
    if not budget.permits():
        raise CloudReviewError('review_budget_exhausted')
    payload = {'model': model, 'temperature': 0.1 if stage != 'adversarial_reflection' else 0.0,
               'max_tokens': 1600, 'stream': False,
               'messages': [{'role': 'system', 'content': '你是外部云端合约安全审查员。只返回 JSON，不把观察写成确认漏洞。'},
                            {'role': 'user', 'content': json.dumps(prompt, ensure_ascii=False)}]}
    request = urllib.request.Request(endpoint, data=json.dumps(payload).encode('utf-8'),
                                     headers={'Content-Type': 'application/json',
                                              'Authorization': 'Bearer ' + api_key})
    started = time.monotonic()
    try:
        opener = urllib.request.build_opener(_RejectRedirect())
        with opener.open(request, timeout=90) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise CloudReviewError('cloud review response exceeds 2 MB')
            try:
                reply = json.loads(body)
            except Exception as error:
                raise CloudReviewError('cloud review response was not valid JSON') from error
            request_id = response.headers.get('x-request-id') if getattr(response, 'headers', None) else None
    except CloudReviewError:
        raise
    except Exception as error:
        raise CloudReviewError(f'cloud review request failed: {type(error).__name__}') from error
    try:
        raw = reply.get('choices', [{}])[0].get('message', {}).get('content')
        parsed = json.loads(_clean_content(raw))
    except CloudReviewError:
        raise
    except Exception as error:
        raise CloudReviewError('cloud review response was not valid JSON') from error
    if not isinstance(parsed, dict):
        raise CloudReviewError('cloud review response was not a JSON object')
    budget.charge(_cost(reply, parsed))
    return parsed, {'stage': stage, 'model': model, 'responseSha256': hashlib.sha256(body).hexdigest(),
                    'providerRequestId': str(request_id)[:200] if request_id else None,
                    'latencyMs': round((time.monotonic() - started) * 1000),
                    'usage': reply.get('usage'), 'costUsd': _cost(reply, parsed)}


def _require_manifest(response, manifest_sha256):
    if response.get('manifestSha256') != manifest_sha256:
        raise CloudReviewError('cloud review manifest hash mismatch')


def _summary_ir(document):
    document = document if isinstance(document, dict) else {}
    return {
        'functions': [{'name': f.get('name'), 'selector': f.get('selector'), 'entrypoint': f.get('entrypoint')}
                      for f in document.get('functions', []) if isinstance(f, dict)][:300],
        'stateVariables': document.get('storageAccesses', [])[:200] if isinstance(document.get('storageAccesses'), list) else [],
        'callEdgeCount': len(document.get('links', [])) if isinstance(document.get('links'), list) else 0,
        'eventCount': len(document.get('events', [])) if isinstance(document.get('events'), list) else 0,
    }


def _area_excerpts(excerpts, area, sources=None):
    """Keep only the requested source ranges when the model identifies them."""
    if not isinstance(area, dict):
        return excerpts
    requested = area.get('lineRanges') or area.get('sourceRefs')
    if not isinstance(requested, list):
        requested = []
    if area.get('file'):
        requested.append({'file': area.get('file'), 'lineStart': area.get('lineStart'), 'lineEnd': area.get('lineEnd')})
        function_name = area.get('function')
        source = (sources or {}).get(area.get('file'))
        if isinstance(function_name, str) and isinstance(source, str) and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', function_name):
            lines = source.splitlines()
            for index, line in enumerate(lines):
                if not re.search(r'\bfunction\s+' + re.escape(function_name) + r'\s*\(', line):
                    continue
                depth = 0
                opened = False
                end = index
                for cursor in range(index, len(lines)):
                    depth += lines[cursor].count('{') - lines[cursor].count('}')
                    opened = opened or '{' in lines[cursor]
                    if opened and depth <= 0:
                        end = cursor
                        break
                if opened:
                    requested.append({'file': area['file'], 'lineStart': index + 1, 'lineEnd': end + 1})
                break
    ranges = {}
    for item in requested:
        if not isinstance(item, dict) or not isinstance(item.get('file'), str):
            continue
        start = item.get('lineStart', item.get('start'))
        end = item.get('lineEnd', item.get('end', start))
        if isinstance(start, int) and isinstance(end, int) and 1 <= start <= end and end - start <= 240:
            ranges.setdefault(item['file'], []).append((start, end))
    if not ranges:
        return excerpts
    result = []
    for excerpt in excerpts:
        file = excerpt.get('file')
        if file not in ranges:
            continue
        lines = excerpt.get('numberedSource', '').splitlines()
        selected = []
        for index, line in enumerate(lines, 1):
            try:
                source_line = int(line.split(':', 1)[0])
            except (ValueError, IndexError):
                continue
            if any(start <= source_line <= end for start, end in ranges[file]):
                selected.append(line)
        if selected:
            result.append({**excerpt, 'numberedSource': '\n'.join(selected), 'truncated': True,
                           'submittedLineRanges': [[int(line.split(':', 1)[0]) - 1, int(line.split(':', 1)[0]) - 1] for line in selected]})
    return result or excerpts


def run_staged_review(*, data, record, sources, targets, validate_review, build_excerpts,
                      unified_ir=None, invariants=None, dependency_signatures=None,
                      endpoint, api_key, model, summary_model=None, adversarial_model=None,
                      budget_usd=None, stop_event=None):
    endpoint = validate_endpoint(endpoint)
    if not api_key or not model:
        raise CloudReviewError('cloud review unavailable: API key and model are required')
    excerpts, included, submitted_lines = build_excerpts(sources, targets)
    manifest = {'schemaVersion': 1, 'protocol': record['protocol'], 'chain': record['chain'],
                'address': record['address'],
                'files': [{'file': x['file'], 'sourceSha256': x['sourceSha256'],
                           'submittedLineRanges': x['submittedLineRanges'], 'truncated': x['truncated']}
                          for x in excerpts]}
    manifest_sha256 = sha256_json(manifest)
    budget = _Budget(budget_usd)
    calls = []
    if stop_event is not None and stop_event.is_set():
        raise CloudReviewError('campaign stopping before cloud review')

    phase_one, evidence = _request(endpoint, api_key, summary_model or model, 'summary', {
        'phase': 1, 'manifest': manifest, 'manifestSha256': manifest_sha256,
        'unifiedIrSummary': _summary_ir(unified_ir),
        'instruction': '只输出 protocolSummary、keyStates、suspectedAreas。不得输出 finding。'}, budget)
    _require_manifest(phase_one, manifest_sha256)
    calls.append(evidence)
    suspected = phase_one.get('suspectedAreas', [])
    if not isinstance(suspected, list):
        suspected = []
    observations = []
    reviewed_lines = {name: set() for name in sources}
    for area in suspected[:12]:
        if not budget.permits():
            break
        area_name = str(area.get('name') if isinstance(area, dict) else area)[:300]
        question = str(area.get('question') if isinstance(area, dict) else area)[:1000]
        area_excerpts = _area_excerpts(excerpts, area, sources)
        for excerpt in area_excerpts:
            file = excerpt.get('file')
            if file not in reviewed_lines:
                continue
            for line in excerpt.get('numberedSource', '').splitlines():
                try:
                    reviewed_lines[file].add(int(line.split(':', 1)[0]) - 1)
                except (ValueError, IndexError):
                    continue
        prompt = {'phase': 2, 'manifestSha256': manifest_sha256, 'area': area_name,
                  'question': question, 'files': area_excerpts,
                  'invariants': invariants if isinstance(invariants, dict) else {'state': 'unavailable'},
                  'dependencySignatures': dependency_signatures or [],
                  'instruction': '只回答这一个具体问题；输出 observations，每条必须有 assumptions 数组。'}
        response, evidence = _request(endpoint, api_key, model, 'targeted_deep_review', prompt, budget)
        _require_manifest(response, manifest_sha256)
        calls.append(evidence)
        for item in response.get('observations', []) if isinstance(response.get('observations'), list) else []:
            if isinstance(item, dict):
                observations.append({**item, 'assumptions': item.get('assumptions', []) if isinstance(item.get('assumptions', []), list) else []})

    phase_two_complete = (not suspected) or (len(calls) > 1 and len(calls) - 1 == min(len(suspected), 12) and budget.permits())
    phase_three = None
    if observations and phase_two_complete and budget.permits():
        phase_three, evidence = _request(endpoint, api_key, adversarial_model or model, 'adversarial_reflection', {
            'phase': 3, 'manifestSha256': manifest_sha256, 'findings': observations,
            'instruction': '对每条观察只输出 refute 或 cannot_refute 及理由。'}, budget)
        _require_manifest(phase_three, manifest_sha256)
        calls.append(evidence)
        decisions = phase_three.get('reviews', []) if isinstance(phase_three.get('reviews'), list) else []
        for index, item in enumerate(observations):
            decision = decisions[index] if index < len(decisions) and isinstance(decisions[index], dict) else {}
            if decision.get('decision') == 'refute':
                item['confidence'] = 'low'
            item['adversarialReview'] = {'decision': decision.get('decision'), 'reason': str(decision.get('reason', ''))[:1000]}

    validated = validate_review({'summary': phase_one.get('protocolSummary', ''),
                                 'role': phase_one.get('role', ''), 'observations': observations,
                                 'limits': phase_one.get('limits', [])}, included, reviewed_lines)
    result = {**validated, 'provider': 'external_cloud_ai', 'model': model,
              'manifestSha256': manifest_sha256,
              'responseSha256': calls[-1]['responseSha256'] if calls else None,
              'providerRequestId': calls[-1].get('providerRequestId') if calls else None,
              'mode': 'cloud-ai-staged', 'securityConclusion': 'unconfirmed_observations_only',
              'stageModels': {'summary': summary_model or model, 'targeted': model,
                              'adversarial': adversarial_model or model},
              'assumptions': [a for item in validated['observations'] for a in item.get('assumptions', [])],
              'stages': {'summary': 'completed', 'targeted': 'not_run' if not suspected else 'completed' if phase_two_complete else 'budget_exhausted',
                         'adversarial': 'completed' if phase_three is not None else 'budget_exhausted' if observations else 'not_run'},
              'budget': {'limitUsd': budget.limit, 'spentUsd': round(budget.spent, 8), 'costsKnown': budget.costs_known},
              'callEvidence': {'requestCompleted': True, 'responseReceived': True, 'calls': calls},
              'excerptManifest': manifest['files'], 'sourceFilesTotal': len(data.get('sources', {})),
              'reachableSourceFiles': len(sources), 'excerptChars': sum(len(x['numberedSource']) for x in excerpts),
              'submittedSourceLines': {k: _line_ranges(lines) for k, lines in reviewed_lines.items() if lines}}
    result['modelSummary'] = result['summary']
    result['summary'] = f'外部云端分阶段审查已返回；阶段一摘要、阶段二定向审查和阶段三对抗复核均记录在案。风险观察仍未确认可利用。'
    return result
