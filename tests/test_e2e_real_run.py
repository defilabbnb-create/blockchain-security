import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import e2e_real_run


class E2ERealRunTests(unittest.TestCase):
    def test_target_concurrency_is_forwarded_to_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets.json"
            source = root / "source.json"
            source.write_text(json.dumps({"sources": {"Vault.sol": {"content": "contract Vault {}"}}}), encoding="utf-8")
            targets.write_text(json.dumps({"targets": [{"id": "real", "address": "0x" + "11" * 20,
                                                         "sourcePath": str(source)}]}), encoding="utf-8")
            captured = {}

            def fake_run(path, **kwargs):
                captured.update(kwargs)
                return {"state": "partial", "targets": [{"target": "real", "stages": {}}]}

            with patch.object(e2e_real_run.pipeline, "run_pipeline", side_effect=fake_run):
                e2e_real_run.run_e2e(targets, root / "output", target_concurrency=3)
            self.assertEqual(captured["target_concurrency"], 3)


if __name__ == "__main__":
    unittest.main()
