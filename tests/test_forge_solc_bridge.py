import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "forge-with-solc.py"
SPEC = importlib.util.spec_from_file_location("forge_with_solc", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ForgeSolcBridgeTests(unittest.TestCase):
    def test_foundry_config_receives_selected_profile_and_contract_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            forge = root / "forge"
            forge.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            forge.chmod(0o755)
            calls = []

            def run(command, **kwargs):
                calls.append(command)
                return type("Result", (), {"returncode": 0, "stdout": '{"src":"contracts"}'})()

            with patch.object(MODULE.subprocess, "run", run):
                config = MODULE._foundry_config(
                    root, ["build", "--profile", "legacy", "--contracts", "src"], forge)

            self.assertEqual(config, {"src": "contracts"})
            self.assertEqual(calls[0], [str(forge), "config", "--json", "--root", str(root),
                                        "--profile", "legacy", "--contracts", "src"])

    def test_forwards_exact_verified_soljson_to_offline_foundry(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            forge = root / "forge"
            forge.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            forge.chmod(0o755)
            soljson = root / "soljson.cjs"
            soljson.write_text("module.exports = {};\n", encoding="utf-8")
            calls = []

            def compiler_loader(version):
                self.assertEqual(version, "0.4.18+commit.9cf6e910")
                return soljson, {"version": version, "longVersion": "0.4.18+commit.test",
                                 "sha256": "0xcompiler", "catalogSha256": "0xcatalog"}

            def command_runner(command, **kwargs):
                calls.append((command, kwargs))
                return type("Result", (), {"returncode": 17})()

            with patch.dict(os.environ, {"SOLC_VERSION": "0.8.28", "CAMPAIGN_SOLJSON": "wrong"}), \
                    redirect_stderr(io.StringIO()), \
                    patch.object(MODULE, "WRAPPER", root / "campaign-solc.cjs"):
                result = MODULE.run_with_solc("0.4.18+commit.9cf6e910", ["test", "--root", str(root)], forge=forge,
                                              compiler_loader=compiler_loader, command_runner=command_runner)

            self.assertEqual(result, 17)
            command, options = calls[0]
            self.assertEqual(command[:5], [str(forge.resolve()), "test", "--root", str(root), "--use"])
            self.assertEqual(command[-2:], [str(root / "campaign-solc.cjs"), "--offline"])
            self.assertEqual(options["env"]["CAMPAIGN_SOLJSON"], str(soljson.resolve()))
            self.assertEqual(options["env"]["CAMPAIGN_FOUNDRY_COMPAT"], "1")
            self.assertNotIn("SOLC_VERSION", options["env"])
            self.assertFalse(options["check"])

    def test_refuses_a_second_compiler_override(self):
        with self.assertRaisesRegex(ValueError, "do_not_override_selected_solc"):
            MODULE.run_with_solc("0.4.18", ["build", "--use", "0.8.28"],
                                 compiler_loader=lambda _version: self.fail("compiler should not be loaded"),
                                 command_runner=lambda *_args, **_kwargs: self.fail("forge should not run"))

    def test_preserves_explicit_online_mode_for_fixed_block_fork(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            forge = root / "forge"
            forge.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            forge.chmod(0o755)
            soljson = root / "soljson.cjs"
            soljson.write_text("module.exports = {};\n", encoding="utf-8")
            calls = []

            def command_runner(command, **kwargs):
                calls.append((command, kwargs))
                return type("Result", (), {"returncode": 0})()

            with patch.dict(os.environ, {"FOUNDRY_OFFLINE": "false"}, clear=False), \
                    patch.object(MODULE, "WRAPPER", root / "campaign-solc.cjs"):
                MODULE.run_with_solc(
                    "0.4.18", ["test", "--fork-url", "https://rpc.example", "--fork-block-number", "1"],
                    forge=forge, compiler_loader=lambda _version: (soljson, {"version": "0.4.18"}),
                    command_runner=command_runner)

            self.assertNotIn("--offline", calls[0][0])

    def test_auto_selects_exact_pragma_from_foundry_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "src").mkdir()
            (root / "src" / "Legacy.sol").write_text(
                "pragma solidity 0.4.18; contract Legacy {}\n", encoding="utf-8")
            forge = root / "forge"
            forge.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            forge.chmod(0o755)
            soljson = root / "soljson.cjs"
            soljson.write_text("module.exports = {};\n", encoding="utf-8")
            selected = []
            (root / "unrelated").mkdir()
            (root / "unrelated" / "Modern.sol").write_text(
                "pragma solidity ^0.8.19; contract Modern {}\n", encoding="utf-8")

            def compiler_loader(version):
                selected.append(version)
                return soljson, {"version": version, "selection": "pragma_exact_cached"}

            with redirect_stderr(io.StringIO()), patch.object(MODULE, "WRAPPER", root / "campaign-solc.cjs"):
                result = MODULE.run_with_solc(
                    "auto", ["build", "--root", str(root)], forge=forge,
                    compiler_loader=compiler_loader,
                    config_loader=lambda *_args: {"src": "src", "test": "test", "script": "script", "libs": []},
                    command_runner=lambda *_args, **_kwargs: type("Result", (), {"returncode": 0})())

            self.assertEqual(result, 0)
            self.assertEqual(selected, ["0.4.18"])

    def test_auto_rejects_incompatible_mixed_pragmas(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "src").mkdir()
            (root / "src" / "Legacy.sol").write_text(
                "pragma solidity 0.4.18; contract Legacy {}\n", encoding="utf-8")
            (root / "src" / "Modern.sol").write_text(
                "pragma solidity ^0.8.19; contract Modern {}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "compiler_auto_selection_failed"):
                MODULE.run_with_solc("auto", ["build", "--root", str(root)],
                                     compiler_loader=lambda _version: self.fail("must not load compiler"),
                                     config_loader=lambda *_args: {"src": "src", "test": "test", "script": "script", "libs": []},
                                     command_runner=lambda *_args, **_kwargs: self.fail("must not run forge"))


if __name__ == "__main__":
    unittest.main()
