import importlib.util
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('cloud_review', ROOT / 'scripts' / 'cloud_review.py')
cloud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cloud)


@contextmanager
def _mock_server(handler):
    class RequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            body = handler(request)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('x-request-id', 'test-request')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(('127.0.0.1', 0), RequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        build_opener = cloud.urllib.request.build_opener
        with patch.object(cloud, 'validate_endpoint', side_effect=lambda value: value), \
             patch.object(cloud.urllib.request, 'build_opener',
                          side_effect=lambda *handlers: build_opener(cloud.urllib.request.ProxyHandler({}), *handlers)):
            yield f'http://127.0.0.1:{server.server_port}/v1/chat/completions'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _reply(value, cost=0):
    value = dict(value)
    value.setdefault('costUsd', cost)
    content = json.dumps(value, ensure_ascii=False)
    return json.dumps({'choices': [{'message': {'content': content}}], 'usage': {'costUsd': cost}}).encode()


class CloudReviewTests(unittest.TestCase):
    def test_budget_exact_boundary_blocks_next_request(self):
        budget = cloud._Budget(1)
        self.assertTrue(budget.permits())
        budget.charge(1)
        self.assertFalse(budget.permits())

    def fixture(self):
        sources = {'Vault.sol': 'contract Vault {\n function withdraw() external { token.transfer(msg.sender, amount); }\n}'}
        record = {'protocol': '示例协议', 'chain': '示例链', 'address': '0x' + '1' * 40}
        data = {'sources': {'Vault.sol': {'content': sources['Vault.sol']}}}

        def excerpts(value, targets):
            row = {'file': 'Vault.sol', 'sourceSha256': 'a' * 64, 'submittedLineRanges': [[0, 1]],
                   'truncated': False, 'numberedSource': '1: contract Vault {\n2: function withdraw() external { token.transfer(msg.sender, amount); }\n3: }'}
            return [row], sources, {'Vault.sol': {0, 1}}

        def validate(review, included, submitted):
            return {'summary': review.get('summary', ''), 'role': review.get('role', ''),
                    'observations': review.get('observations', []), 'rejectedUnsupportedObservations': [],
                    'limits': review.get('limits', []), 'confirmedVulnerabilities': 0,
                    'localReproduction': 'not performed'}

        return data, record, sources, excerpts, validate

    def test_three_stages_are_ordered_and_assumptions_survive(self):
        data, record, sources, excerpts, validate = self.fixture()
        calls = []
        current_manifest = {'value': None}

        def handler(payload):
            prompt = json.loads(payload['messages'][1]['content'])
            calls.append(prompt['phase'])
            current_manifest['value'] = prompt['manifestSha256']
            if prompt['phase'] == 1:
                return _reply({'manifestSha256': current_manifest['value'], 'protocolSummary': '摘要',
                                'keyStates': [], 'suspectedAreas': [{'name': '提现', 'question': '提现是否受保护？'}]})
            if prompt['phase'] == 2:
                return _reply({'manifestSha256': current_manifest['value'], 'observations': [{
                    'kind': 'risk_hypothesis', 'title': '观察', 'confidence': 'medium',
                    'assumptions': ['token 是外部可调用合约'], 'evidence': [{'file': 'Vault.sol', 'lineStart': 2, 'lineEnd': 2, 'quote': 'token.transfer(msg.sender, amount);'}]
                }]})
            return _reply({'manifestSha256': current_manifest['value'], 'reviews': [{'decision': 'cannot_refute', 'reason': '证据仍需 PoC'}]})

        with _mock_server(handler) as endpoint:
            result = cloud.run_staged_review(data=data, record=record, sources=sources, targets=['Vault.sol'],
                validate_review=validate, build_excerpts=excerpts, unified_ir={'functions': []}, invariants={'invariants': []},
                endpoint=endpoint, api_key='secret', model='review', budget_usd=10)
        self.assertEqual(calls, [1, 2, 3])
        self.assertEqual(result['observations'][0]['assumptions'], ['token 是外部可调用合约'])
        self.assertEqual(result['stages']['adversarial'], 'completed')

    def test_budget_exhaustion_runs_summary_then_degrades(self):
        data, record, sources, excerpts, validate = self.fixture()
        phases = []

        def handler(payload):
            prompt = json.loads(payload['messages'][1]['content'])
            phases.append(prompt['phase'])
            return _reply({'manifestSha256': prompt['manifestSha256'], 'protocolSummary': '摘要',
                            'keyStates': [], 'suspectedAreas': [{'name': '提现'}]}, cost=2)

        with _mock_server(handler) as endpoint:
            result = cloud.run_staged_review(data=data, record=record, sources=sources, targets=['Vault.sol'],
                validate_review=validate, build_excerpts=excerpts, unified_ir={}, invariants={},
                endpoint=endpoint, api_key='secret', model='review', budget_usd=1)
        self.assertEqual(phases, [1])
        self.assertEqual(result['stages']['targeted'], 'budget_exhausted')

    def test_manifest_mismatch_is_rejected(self):
        data, record, sources, excerpts, validate = self.fixture()

        def handler(payload):
            prompt = json.loads(payload['messages'][1]['content'])
            return _reply({'manifestSha256': '0' * 64, 'protocolSummary': 'bad', 'keyStates': [], 'suspectedAreas': []})

        with _mock_server(handler) as endpoint:
            with self.assertRaisesRegex(cloud.CloudReviewError, 'manifest hash mismatch'):
                cloud.run_staged_review(data=data, record=record, sources=sources, targets=['Vault.sol'],
                    validate_review=validate, build_excerpts=excerpts, unified_ir={}, invariants={},
                    endpoint=endpoint, api_key='secret', model='review')

    def test_non_json_response_is_rejected(self):
        data, record, sources, excerpts, validate = self.fixture()

        with _mock_server(lambda payload: b'not-json') as endpoint:
            with self.assertRaisesRegex(cloud.CloudReviewError, 'not valid JSON'):
                cloud.run_staged_review(data=data, record=record, sources=sources, targets=['Vault.sol'],
                    validate_review=validate, build_excerpts=excerpts, unified_ir={}, invariants={},
                    endpoint=endpoint, api_key='secret', model='review')

    def test_endpoint_requires_https_and_rejects_credentials_and_query(self):
        for endpoint in ('http://api.example.com/v1', 'https://user:secret@api.example.com/v1',
                         'https://api.example.com/v1?key=secret'):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(cloud.CloudReviewError):
                    cloud.validate_endpoint(endpoint)


if __name__ == '__main__':
    unittest.main()
