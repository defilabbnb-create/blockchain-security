#!/usr/bin/env python3
"""Etherscan V2 address transaction history. New deployments: use scan.sh."""
import argparse
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


class DeepScanner:
    def __init__(self, api_key=None, chain_id=1, timeout=15, retries=2):
        self.key = api_key or os.environ.get('ETHERSCAN_API_KEY')
        if not self.key or not self.key.strip():
            raise ValueError('请设置 ETHERSCAN_API_KEY')
        if not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError('chain_id 必须是正整数')
        if not 0 < timeout <= 120 or not isinstance(retries, int) or not 0 <= retries <= 5:
            raise ValueError('timeout/retries 超出允许范围')
        self.chain_id, self.timeout, self.retries = chain_id, timeout, retries
        self.base = 'https://api.etherscan.io/v2/api'

    def scan(self, address, limit=256, page=1, startblock=0, endblock=99999999):
        if not isinstance(address, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', address):
            raise ValueError('address 必须是完整的 20 字节以太坊地址')
        for name, value, low, high in [('limit', limit, 1, 1000), ('page', page, 1, 1000000),
                                      ('startblock', startblock, 0, 99999999), ('endblock', endblock, 0, 99999999)]:
            if not isinstance(value, int) or not low <= value <= high:
                raise ValueError(name + ' 超出允许范围')
        if startblock > endblock:
            raise ValueError('startblock 不能大于 endblock')
        params = dict(chainid=self.chain_id, apikey=self.key, module='account', action='txlist',
                      address=address, startblock=startblock, endblock=endblock,
                      sort='asc', page=page, offset=limit)
        for attempt in range(self.retries + 1):
            retry = False
            try:
                with urlopen(self.base + '?' + urlencode(params), timeout=self.timeout) as response:
                    data = json.load(response)
            except HTTPError as error:
                retry = error.code == 429 or error.code >= 500
                message = 'Etherscan HTTP 错误 {}'.format(error.code)
            except (URLError, TimeoutError, OSError):
                retry, message = True, 'Etherscan 网络连接失败或超时'
            except (ValueError, UnicodeError):
                raise RuntimeError('Etherscan 响应不是有效 JSON') from None
            else:
                if not isinstance(data, dict):
                    raise RuntimeError('Etherscan 响应格式错误')
                if data.get('status') == '1' and isinstance(data.get('result'), list):
                    return data
                if data.get('status') == '0' and data.get('message') == 'No transactions found' and data.get('result') == []:
                    return data
                retry = 'rate limit' in str(data.get('result', '')).lower()
                message = 'Etherscan 限流' if retry else 'Etherscan 拒绝查询，请检查密钥、链和参数'
            if not retry or attempt == self.retries:
                raise RuntimeError(message) from None
            time.sleep(0.5 * 2 ** attempt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    parser.add_argument('--chain-id', type=int, default=1)
    parser.add_argument('--limit', type=int, default=256)
    parser.add_argument('--page', type=int, default=1)
    parser.add_argument('--startblock', type=int, default=0)
    parser.add_argument('--endblock', type=int, default=99999999)
    args = parser.parse_args()
    try:
        result = DeepScanner(chain_id=args.chain_id).scan(args.address, args.limit, args.page, args.startblock, args.endblock)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (ValueError, RuntimeError) as error:
        print('查询失败：' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
