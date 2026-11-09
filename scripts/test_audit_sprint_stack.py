"""Offline unit tests for branch ancestry and release-history preflight."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from audit_sprint_stack import STACK, audit


def valid_fixture():
    prs = {}
    comparisons = {}
    for i, num in enumerate(STACK):
        prs[str(num)] = {
            "state": "open", "head": {"ref": f"sprint/{num}", "sha": f"{num:040x}"},
            "base": {"ref": "main" if i == 0 else f"sprint/{STACK[i-1]}"}
        }
        if i:
            comparisons[f"{STACK[i-1]}:{num}"] = {"status": "ahead", "behind_by": 0}
    return prs, comparisons


class SprintStackAuditTests(unittest.TestCase):
    def test_valid_stack_is_not_release_approval(self):
        report = audit(*valid_fixture())
        self.assertEqual(report["state"], "stack_consistent")
        self.assertFalse(report["release_ready"])

    def test_divergence_is_blocker(self):
        prs, compare = valid_fixture()
        compare["16:19"] = {"status": "diverged", "ahead_by": 7, "behind_by": 4}
        result = audit(prs, compare)
        self.assertEqual(result["state"], "blocked")
        self.assertTrue(any("reconciliation" in s for s in result["findings"]))

    def test_behind_is_blocker(self):
        prs, compare = valid_fixture()
        compare["28:32"] = {"status": "behind", "behind_by": 2}
        self.assertEqual(audit(prs, compare)["state"], "blocked")

    def test_wrong_base_is_blocker(self):
        prs, compare = valid_fixture()
        prs["24"]["base"]["ref"] = "main"
        self.assertEqual(audit(prs, compare)["state"], "blocked")

    def test_missing_pr_or_compare_is_blocker(self):
        prs, compare = valid_fixture()
        prs.pop("21")
        compare.pop("26:28")
        self.assertEqual(audit(prs, compare)["state"], "blocked")

    def test_non_open_pr_is_blocker(self):
        prs, compare = valid_fixture()
        prs["32"]["state"] = "closed"
        self.assertEqual(audit(prs, compare)["state"], "blocked")

    def test_corrupt_sha_is_blocker(self):
        prs, compare = valid_fixture()
        prs["16"]["head"]["sha"] = "bad"
        self.assertEqual(audit(prs, compare)["state"], "blocked")

    def test_offline_cli_exits_nonzero_on_divergence(self):
        prs, compare = valid_fixture()
        compare["16:19"] = {"status": "diverged", "behind_by": 4}
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / "sample.json"
            fixture.write_text(json.dumps({"prs": prs, "comparisons": compare}))
            script = Path(__file__).with_name("audit_sprint_stack.py")
            proc = subprocess.run([sys.executable, str(script), "--fixture", str(fixture)],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 3)
            self.assertEqual(json.loads(proc.stdout)["state"], "blocked")


if __name__ == "__main__":
    unittest.main()
