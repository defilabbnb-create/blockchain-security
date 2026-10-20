import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deploy_adapter", ROOT / "scripts" / "deploy_adapter.py")
DEPLOY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DEPLOY)


class DeployAdapterTests(unittest.TestCase):
    def bundle(self):
        return {
            "sources": {"Vault.sol": {"content": "pragma solidity >=0.8.19; contract Vault { constructor(address owner, uint256 limit) {} }"}},
            "metadata": {"settings": {"compilationTarget": {"Vault.sol": "Vault"}}},
            "abi": [{"type": "constructor", "inputs": [{"name": "owner", "type": "address"}, {"name": "limit", "type": "uint256"}]}],
        }

    def test_missing_constructor_args_is_adapter_required(self):
        with tempfile.TemporaryDirectory() as directory:
            result = DEPLOY.generate_deployment(self.bundle(), Path(directory) / "deploy")
        self.assertEqual(result["state"], "adapter_required")
        self.assertEqual(result["missing"], ["owner", "limit"])

    def test_generates_foundry_script_with_supplied_args(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "deploy"
            result = DEPLOY.generate_deployment(self.bundle(), output, constructor_args={"owner": "0x" + "1" * 40, "limit": 100})
            self.assertEqual(result["state"], "ready")
            script = (output / "script" / "Deploy.s.sol").read_text()
            self.assertIn("new Vault(0x" + "1" * 40 + ", 100)", script)
            self.assertEqual(json.loads((output / "deployment.json").read_text())["target"], None)

    def test_deployment_error_keeps_original_forge_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "deploy"
            DEPLOY.generate_deployment(self.bundle(), output, constructor_args=["0x" + "1" * 40, 100])
            result = DEPLOY.run_deployment(output, forge="/definitely/missing/forge")
        self.assertEqual(result["state"], "unavailable")
        self.assertIn("forge_not_found", result["reason"])


if __name__ == "__main__":
    unittest.main()
