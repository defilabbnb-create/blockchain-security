import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export-training-jsonl.py"
SPEC = importlib.util.spec_from_file_location("training_evidence_export", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TrainingEvidenceExportTests(unittest.TestCase):
    def test_reentrancy_profit_evidence_is_confirmed_without_draining_target_completely(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            record = {
                "state": "passed", "confirmedVulnerability": True, "sourceSha256": "source-hash",
                "runnerExitCode": 0, "attackStatus": 1, "callTrace": [{"op": "CALL"}],
                "seededBalanceWei": "100", "extractedWei": "200", "profitWei": "100",
                "victimCreditBeforeWei": "200", "victimCreditAfterWei": "200",
                "beforeTargetBalanceWei": "300", "afterTargetBalanceWei": "100",
                "attackerBalanceBeforeAttackWei": "0", "attackerBalanceWei": "200",
                "executionBoundary": {"mode": "isolated_in_process", "externalTransactions": False,
                                       "externalSigning": False},
            }
            evidence_bytes = json.dumps(record).encode()
            evidence_path = root / "poc-result.json"
            evidence_path.write_bytes(evidence_bytes)
            sample = {"confirmedVulnerability": True}
            analysis = {"dynamic": "passed", "dynamicEvidence": "poc-result.json",
                        "dynamicEvidenceSha256": hashlib.sha256(evidence_bytes).hexdigest()}

            evidence, confirmed = MODULE._dynamic_evidence(root, sample, analysis, None, "source-hash")

            self.assertTrue(evidence["valid"])
            self.assertEqual(evidence["state"], "passed")
            self.assertTrue(confirmed)

            record["victimCreditAfterWei"] = "100"
            evidence_bytes = json.dumps(record).encode()
            evidence_path.write_bytes(evidence_bytes)
            analysis["dynamicEvidenceSha256"] = hashlib.sha256(evidence_bytes).hexdigest()
            _evidence, confirmed = MODULE._dynamic_evidence(root, sample, analysis, None, "source-hash")
            self.assertFalse(confirmed)

    def test_dynamic_evidence_digest_is_kept_in_jsonl(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sample.sol"
            source.write_text("pragma solidity 0.4.18; contract Sample {}\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"samples": [{
                "objectPath": "sample.sol", "sha256": __import__("hashlib").sha256(source.read_bytes()).hexdigest(),
                "analysis": {"dynamic": "passed", "dynamicEvidence": "evidence.json",
                             "dynamicEvidenceSha256": "evidence-digest"},
            }]}), encoding="utf-8")
            output = root / "training.jsonl"

            with patch.object(MODULE, "ROOT", root), patch.object(MODULE, "MANIFEST", manifest):
                result = MODULE.main(["--output", str(output)])

            self.assertEqual(result, 0)
            row = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["dynamicEvidenceSha256"], "evidence-digest")
            self.assertFalse(row["confirmedVulnerability"])

    def test_exports_all_manifests_and_validates_multifile_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)

            def add_source(dataset, path, text):
                content = text.encode()
                digest = hashlib.sha256(content).hexdigest()
                object_path = f"training-data/{dataset}/objects/{digest}.sol"
                destination = root / object_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                return {"path": path, "objectPath": object_path, "sha256": digest}

            github_source = add_source("github-vulnerabilities", "Legacy.sol", "contract Legacy {}\n")
            github_manifest = root / "training-data/github-vulnerabilities/manifest.json"
            github_manifest.parent.mkdir(parents=True, exist_ok=True)
            github_manifest.write_text(json.dumps({"samples": [{
                **github_source, "repo": "example/legacy", "analysis": {"dynamic": "not_run"},
            }]}), encoding="utf-8")

            dvd_target = add_source("damn-vulnerable-defi", "src/Pool.sol", "contract Pool {}\n")
            dvd_dependency = add_source("damn-vulnerable-defi", "lib/Token.sol", "contract Token {}\n")
            dvd_units = sorted([(dvd_target["path"], dvd_target["sha256"]),
                                ("@lib/Token.sol", dvd_dependency["sha256"])])
            dvd_bundle = hashlib.sha256("".join(f"{path}:{digest}\n" for path, digest in dvd_units).encode()).hexdigest()
            evidence_record = {
                "state": "confirmed", "confirmedVulnerability": True,
                "sourceBundleSha256": dvd_bundle, "runnerExitCode": 0,
                "assertions": [{"name": "drain", "passed": True}],
                "transactions": [{"status": 1}],
                "executionBoundary": {"mode": "isolated_in_process", "externalTransactions": False,
                                      "externalSigning": False},
            }
            evidence_bytes = json.dumps(evidence_record).encode()
            evidence_path = root / "training-data/damn-vulnerable-defi/dynamic-evidence/case.json"
            evidence_path.parent.mkdir(parents=True)
            evidence_path.write_bytes(evidence_bytes)
            dvd_manifest = root / "training-data/damn-vulnerable-defi/manifest.json"
            dvd_manifest.write_text(json.dumps({"dataset": "damn-vulnerable-defi", "samples": [{
                "dataset": "damn-vulnerable-defi", "challenge": "case", "repo": "example/dvd",
                "sourceBundleSha256": dvd_bundle, "sourceFiles": [dvd_target],
                "dependencyFiles": [{**dvd_dependency, "compilerSourceUnit": "@lib/Token.sol", "license": "MIT"}],
                "dependencyLicenses": [{"repo": "lib/token", "license": "MIT"}],
                "dynamicState": "confirmed", "dynamicEvidence": str(evidence_path.relative_to(root)),
                "dynamicEvidenceSha256": hashlib.sha256(evidence_bytes).hexdigest(),
                "confirmedVulnerability": True,
            }]}), encoding="utf-8")

            ether_target = add_source("ethernaut", "Level.sol", "contract Level {}\n")
            ether_attack = add_source("ethernaut", "Attack.sol", "contract Attack {}\n")
            ether_bundle = hashlib.sha256("".join(
                f"{item['path']}:{item['sha256']}\n" for item in (ether_target, ether_attack)
            ).encode()).hexdigest()
            ether_manifest = root / "training-data/ethernaut/manifest.json"
            ether_manifest.parent.mkdir(parents=True, exist_ok=True)
            ether_manifest.write_text(json.dumps({"dataset": "ethernaut", "samples": [{
                "dataset": "ethernaut", "challenge": "level", "repo": "example/ethernaut",
                "sourceBundleSha256": ether_bundle, "sourceFiles": [ether_target, ether_attack],
                "dynamicState": "not_run",
            }]}), encoding="utf-8")

            output = root / "training-data/training.jsonl"
            with patch.object(MODULE, "ROOT", root), patch.object(MODULE, "MANIFEST", github_manifest):
                result = MODULE.main(["--output", str(output)])

            self.assertEqual(result, 0)
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual({row["dataset"] for row in rows}, {"damn-vulnerable-defi", "ethernaut", "github-vulnerabilities"})
            dvd = next(row for row in rows if row["dataset"] == "damn-vulnerable-defi")
            self.assertTrue(dvd["confirmedVulnerability"])
            self.assertTrue(dvd["dynamicEvidenceValid"])
            self.assertEqual(len(dvd["dependencyFiles"]), 1)
            self.assertEqual(dvd["dependencyLicenses"][0]["license"], "MIT")
            ether = next(row for row in rows if row["dataset"] == "ethernaut")
            self.assertEqual(len(ether["sources"]), 2)
            self.assertEqual(ether["dynamicState"], "not_run")
            self.assertFalse(ether["confirmedVulnerability"])

    def test_invalid_source_hash_skips_entire_multifile_sample(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sample.sol"
            source.write_text("contract Sample {}\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"samples": [{"sourceFiles": [{
                "objectPath": "sample.sol", "sha256": "0" * 64, "path": "Sample.sol",
            }]}]}), encoding="utf-8")
            output = root / "training.jsonl"
            with patch.object(MODULE, "ROOT", root), patch.object(MODULE, "MANIFEST", manifest):
                MODULE.main(["--output", str(output)])
            self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_overlapping_source_hashes_stay_in_one_split(self):
        rows = [{"_sourceHashes": ["a" * 64, "b" * 64]},
                {"_sourceHashes": ["b" * 64, "c" * 64]},
                {"_sourceHashes": ["c" * 64]}]
        MODULE._assign_splits(rows)
        self.assertEqual(len({row["split"] for row in rows}), 1)


if __name__ == "__main__":
    unittest.main()
