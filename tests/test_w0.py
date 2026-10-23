import json
import pathlib
import unittest

from scripts.invariant_assertions import RENDERER_MODULES, load_renderers


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "assertions"


class W0FoundationTests(unittest.TestCase):
    def test_registry_contract_has_expected_modules_and_loads_renderers(self):
        # vuln 模块提供跨协议通用不变量（CEI 顺序、鉴权、返回值强制检查等），
        # 与 erc4626/lending/amm/cross 四个协议族并列。
        self.assertEqual(RENDERER_MODULES, ("erc4626", "lending", "amm", "cross", "vuln"))
        registry = load_renderers()
        # 协议族不变量
        self.assertIn("share_price_monotonic", registry)
        self.assertIn("health_factor_monotonic_on_borrow", registry)
        self.assertIn("k_never_decreases", registry)
        # 通用不变量：这些与协议无关，是本轮新增模块的核心价值
        self.assertIn("state_update_precedes_external_call", registry)
        self.assertIn("privileged_entry_requires_authentication", registry)
        self.assertIn("unauthorized_caller_cannot_mutate_state", registry)
        self.assertIn("call_success_is_enforced", registry)
        self.assertIn("randomness_source_is_unpredictable", registry)
        # 质押族不变量：奖励累计守恒与提取份额守恒。生成端曾为这两个模板发出
        # 参数，但没有任何 renderer 消费它们，于是样本被记为"需要适配器"。
        self.assertIn("reward_accrual_conserves_value", registry)
        self.assertIn("stake_withdraw_preserves_shares", registry)
        self.assertEqual(len(registry), 24)

    def test_every_assertion_fixture_has_correct_and_violating_sources(self):
        fixture_dirs = [path for path in FIXTURES.iterdir() if path.is_dir()]
        self.assertEqual(len(fixture_dirs), 7)
        for fixture_dir in fixture_dirs:
            with self.subTest(fixture=fixture_dir.name):
                self.assertTrue((fixture_dir / "correct").is_dir())
                self.assertTrue((fixture_dir / "violating").is_dir())
                meta = json.loads((fixture_dir / "meta.json").read_text())
                self.assertIn("role", meta)
                self.assertIn("template", meta)
                self.assertEqual(meta["expectedOnCorrect"], "passed")
                self.assertEqual(meta["expectedOnViolating"], "violated")
