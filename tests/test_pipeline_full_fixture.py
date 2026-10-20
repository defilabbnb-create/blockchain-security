import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PipelineFullFixtureTests(unittest.TestCase):
    def test_nine_stage_offline_fixture_completes_with_explicit_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            command = [sys.executable, str(ROOT / "scripts" / "pipeline.py"), "run",
                       "--targets", str(ROOT / "tests/fixtures/pipeline-full/targets.json"),
                       "--stages", "recon,collect,repr,static,dynamic,decompile,review,poc,report",
                       "--mode", "local", "--budget-usd", "5", "--output", str(output)]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            run = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["state"], "completed")
            stages = run["targets"][0]["stages"]
            self.assertTrue(all(row["state"] == "completed" for row in stages.values()))
            self.assertEqual(stages["dynamic"]["outcome"], "passed")
            self.assertEqual(stages["review"]["provider"], "mock_cloud_ai")
            self.assertEqual(stages["poc"]["pocState"], "unconfirmed")
            self.assertTrue((output / "offline-vault" / "reports" / "report.sarif.json").is_file())


if __name__ == "__main__":
    unittest.main()
