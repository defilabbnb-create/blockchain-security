import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from scanner import DeepScanner

ADDRESS = '0x' + '11' * 20


class ScannerTests(unittest.TestCase):
    def test_missing_key_and_invalid_address(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'ETHERSCAN_API_KEY'):
                DeepScanner()
        with self.assertRaises(ValueError):
            DeepScanner('test').scan('0x0')

    def test_correct_query_parameters_and_no_records(self):
        data = {'status': '0', 'message': 'No transactions found', 'result': []}
        with patch('scanner.urlopen', return_value=io.StringIO(json.dumps(data))) as request:
            self.assertEqual(DeepScanner('test').scan(ADDRESS, page=2, startblock=5)['result'], [])
            params = parse_qs(urlparse(request.call_args[0][0]).query)
            self.assertEqual(params['startblock'], ['5'])
            self.assertEqual(params['page'], ['2'])
            self.assertNotIn('fromblock', params)
            self.assertEqual(request.call_args[1]['timeout'], 15)

    def test_api_error_is_not_empty_success_or_key_leak(self):
        data = {'status': '0', 'message': 'NOTOK', 'result': 'Invalid API Key SECRET'}
        with patch('scanner.urlopen', return_value=io.StringIO(json.dumps(data))):
            with self.assertRaises(RuntimeError) as raised:
                DeepScanner('SECRET').scan(ADDRESS)
            self.assertNotIn('SECRET', str(raised.exception))

    def test_rate_limit_retries(self):
        responses = [io.StringIO(json.dumps({'status': '0', 'result': 'Max rate limit reached'})),
                     io.StringIO(json.dumps({'status': '1', 'result': []}))]
        with patch('scanner.urlopen', side_effect=responses) as request, patch('scanner.time.sleep'):
            self.assertEqual(DeepScanner('test').scan(ADDRESS)['status'], '1')
            self.assertEqual(request.call_count, 2)

    def test_network_failure_redacted_and_bounded(self):
        with patch('scanner.urlopen', side_effect=URLError('SECRET')) as request, patch('scanner.time.sleep'):
            with self.assertRaises(RuntimeError) as raised:
                DeepScanner('SECRET').scan(ADDRESS)
            self.assertEqual(request.call_count, 3)
            self.assertNotIn('SECRET', str(raised.exception))

    def test_bad_json_and_block_range(self):
        with patch('scanner.urlopen', return_value=io.StringIO('<html>')):
            with self.assertRaisesRegex(RuntimeError, 'JSON'):
                DeepScanner('test').scan(ADDRESS)
        with self.assertRaises(ValueError):
            DeepScanner('test').scan(ADDRESS, startblock=10, endblock=1)
