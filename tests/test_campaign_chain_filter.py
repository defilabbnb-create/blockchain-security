import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('campaign', ROOT / 'scripts/defi-campaign.py')
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)

CHAIN_IDS = [14, 19, 250, 1285, 9001, 1666600000, 1284, 7700, 1313161554, 2222, 288, 122, 40, 1088, 592, 30, 25, 100, 42220]


class ChainFilterTests(unittest.TestCase):
    def test_filter_matches_chain_id_name_and_llama_name(self):
        chains = [{'name': 'Flare', 'llamaName': 'Flare', 'chainId': 14},
                  {'name': 'Gnosis', 'llamaName': 'xDai', 'chainId': 100},
                  {'name': 'Celo', 'llamaName': 'Celo', 'chainId': 42220}]
        selected, unmatched = campaign.filter_chains(chains, ['14'])
        self.assertEqual([c['chainId'] for c in selected], [14])
        self.assertEqual(unmatched, [])
        selected, unmatched = campaign.filter_chains(chains, ['flare'])
        self.assertEqual([c['chainId'] for c in selected], [14])
        selected, unmatched = campaign.filter_chains(chains, ['xDai'])
        self.assertEqual([c['chainId'] for c in selected], [100])
        selected, unmatched = campaign.filter_chains(chains, ['Gnosis'])
        self.assertEqual([c['chainId'] for c in selected], [100])

    def test_filter_without_criteria_keeps_every_chain(self):
        chains = [{'name': 'Flare', 'llamaName': 'Flare', 'chainId': 14},
                  {'name': 'Celo', 'llamaName': 'Celo', 'chainId': 42220}]
        selected, unmatched = campaign.filter_chains(chains, [])
        self.assertEqual(len(selected), 2)
        self.assertEqual(unmatched, [])
        selected, unmatched = campaign.filter_chains(chains, None)
        self.assertEqual(len(selected), 2)
        self.assertEqual(unmatched, [])

    def test_unmatched_filter_is_reported_not_silently_ignored(self):
        chains = [{'name': 'Flare', 'llamaName': 'Flare', 'chainId': 14}]
        selected, unmatched = campaign.filter_chains(chains, ['999'])
        self.assertEqual(selected, [])
        self.assertEqual(unmatched, ['999'])
        selected, unmatched = campaign.filter_chains(chains, ['14', '999'])
        self.assertEqual([c['chainId'] for c in selected], [14])
        self.assertEqual(unmatched, ['999'])

    def test_queue_only_contains_selected_chains(self):
        chains = [{'name': 'Flare', 'llamaName': 'Flare', 'chainId': 14},
                  {'name': 'Gnosis', 'llamaName': 'xDai', 'chainId': 100}]
        protocols = [{'name': 'A', 'slug': 'a', 'category': 'Lending', 'chainTvls': {'Flare': 10001, 'xDai': 10001}}]
        selected, _ = campaign.filter_chains(chains, ['14'])
        queue = campaign.build_queue(protocols, selected)
        self.assertEqual(sorted(q['chainId'] for q in queue), [14])

    def test_cli_rejects_chain_filter_that_matches_nothing(self):
        # 必须先在拿到 flock 之前失败，不能留下一个看起来在跑的锁。
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/defi-campaign.py'), '--chain', '999999999', '--duration', '30'],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no configured chain matched', result.stderr)

    def test_cli_accepts_valid_chain_without_starting_a_run(self):
        # --help 走完参数解析即可，用来确认 --chain 是已注册的参数。
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/defi-campaign.py'), '--help'],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn('--chain', result.stdout)

    def test_configured_chains_uses_the_filter_and_refuses_empty_match(self):
        instance = campaign.Campaign.__new__(campaign.Campaign)
        instance.chain_filter = ['999999999']
        with self.assertRaises(RuntimeError) as caught:
            instance.configured_chains()
        self.assertIn('no chain matched', str(caught.exception))

    def test_configured_chains_without_filter_returns_all_configured_chains(self):
        instance = campaign.Campaign.__new__(campaign.Campaign)
        instance.chain_filter = []
        chains = instance.configured_chains()
        self.assertEqual(len(chains), len(CHAIN_IDS))

    def test_refresh_pool_is_not_narrowed_by_the_chain_filter(self):
        # 共享的 work/rpc-pool.json 覆盖全部链。按链采集时若把它截断，
        # 下一次全链采集在其余链上会全部找不到已验证端点。
        source = (ROOT / 'scripts/defi-campaign.py').read_text()
        body = source.split('def refresh_pool(self):', 1)[1].split('def load_pool(self):', 1)[0]
        self.assertIn("flare-scan/chains.json", body)
        self.assertNotIn('self.configured_chains()', body)


if __name__ == '__main__':
    unittest.main()
