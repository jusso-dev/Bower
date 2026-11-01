import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("relp_evidence", Path(__file__).resolve().parents[1] / "monitoring/relp-evidence.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RelpEvidenceTests(unittest.TestCase):
    def test_public_copy_redacts_operator_paths_and_keeps_both_plan_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home" / "operator"
            attempt = root / "private" / "a-steady-attempt1"
            attempt.mkdir(parents=True)
            plan = json.dumps({"steps": [{"command": [str(home / "repo/run.py")]}]}).encode()
            (attempt / "plan.json").write_bytes(plan)
            (attempt / "summary.json").write_text(json.dumps({"scenario": "a-steady", "queries": [], "faults": []}))
            (attempt / "queue-identities.json").write_text(json.dumps({"rows": [
                {"eventId": "a13-n4405x20000", "generatedAt": "t1", "receivedAt": "t2"}]}))
            (attempt / "secret.pem").write_text("never published")
            public = root / "public"
            import sys
            argv = sys.argv
            sys.argv = ["relp-evidence.py", str(root / "private"), str(public), "--home", str(home)]
            try:
                module.main()
            finally:
                sys.argv = argv
            target = public / "scenarios" / "a-steady-attempt1"
            self.assertNotIn(str(home), (target / "plan.json").read_text())
            self.assertFalse((target / "secret.pem").exists())
            self.assertEqual('["a13-n4405x20000", "t1", "t2"]\n', (target / "queue-identities.jsonl").read_text())
            record = json.loads((public / "summary.json").read_text())["scenarios"][0]
            self.assertEqual(hashlib.sha256(plan).hexdigest(), record["planSha256"])
            self.assertEqual(hashlib.sha256((target / "plan.json").read_bytes()).hexdigest(), record["publicPlanSha256"])
            manifest = json.loads((public / "public-manifest.json").read_text())
            self.assertIn("scenarios/a-steady-attempt1/plan.json", manifest)


if __name__ == "__main__":
    unittest.main()
