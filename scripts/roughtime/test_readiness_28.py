"""Sprint 28 unit tests: ALL observations synthetic, NO live UDP or signoff."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import accept as s23
import readiness_28 as rt

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "config/roughtime-independent-sources.json"
DOSSIER = ROOT / "config/sprint23-operator-dossier.example.json"


def fixture():
    registry = s23.read_json(REGISTRY)
    dossier = s23.read_json(DOSSIER)
    eligible = {
        s23.decode_key(row["public_key"]).hex(): review["operator_id"]
        for row, review in zip(registry["sources"], dossier["sources"])
        if review["supported_client_protocol"]
    }
    return registry, dossier, eligible


def signed(eligible, count=4):
    now = time.time_ns() // 1000
    return {
        "schema": "hc-vtime/native-roughtime-verification/v1",
        "verified_count": count,
        "intervals": [{"key_hex": key, "earliest_us": now - 1_000_000,
                       "latest_us": now + 1_000_000}
                      for key in list(eligible)[:count]],
        "operator_independence_proven": False,
        "same_target_replay_prevented": False,
    }


class RegistryReadiness(unittest.TestCase):
    def test_live_candidate_list_does_not_approve_operators(self):
        _, dossier, eligible = fixture()
        self.assertEqual(len(eligible), 4)
        self.assertFalse(dossier["sources"][0]["supported_client_protocol"])
        self.assertEqual(set(eligible.values()),
                         {"int08h", "roughtime-se", "tanner-ryan",
                          "sturdy-statistics"})
        self.assertEqual(dossier["status"], "PENDING_EXTERNAL_REVIEW")

    def test_pinned_registry_and_dossier_audit(self):
        args = SimpleNamespace(
            registry=REGISTRY, dossier=DOSSIER,
            expected_registry_sha256=s23.digest_file(REGISTRY),
            expected_dossier_sha256=s23.digest_file(DOSSIER),
        )
        _, _, report, eligible = rt.load_sources(args)
        self.assertEqual(len(eligible), 4)
        self.assertFalse(report["operator_independence_proven"])
        with patch.object(args, "expected_dossier_sha256", "0"*64):
            with self.assertRaisesRegex(s23.Blocked, "out-of-band dossier"):
                rt.load_sources(args)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "registry.json"
            changed.write_bytes(REGISTRY.read_bytes() + b" ")
            args.registry = changed
            with self.assertRaisesRegex(s23.Blocked, "external SHA-256"):
                rt.load_sources(args)

    def test_missing_or_incompatible_fourth_root_rejected(self):
        registry, dossier, _ = fixture()
        eligible_dossier = copy.deepcopy(dossier)
        eligible_dossier["sources"][4]["supported_client_protocol"] = False
        with self.assertRaisesRegex(s23.Blocked, "fewer than four"):
            s23.validate_dossier(registry, eligible_dossier,
                                 s23.digest_file(REGISTRY))


class VerifiedResponseSafety(unittest.TestCase):
    def setUp(self):
        _, _, self.eligible = fixture()

    def test_four_real_verifier_records_needed_before_one_outage(self):
        full = rt.assess_verified(signed(self.eligible), self.eligible)
        self.assertTrue(full["four_source_outage_margin_met"])
        self.assertFalse(full["operator_independence_proven"])
        three = rt.assess_verified(signed(self.eligible, 3), self.eligible)
        self.assertTrue(three["three_source_quorum_met"])
        self.assertFalse(three["four_source_outage_margin_met"])

    def test_unknown_key_duplicate_and_false_independence_rejected(self):
        row = signed(self.eligible)
        row["intervals"][0]["key_hex"] = "ef" * 32
        with self.assertRaisesRegex(s23.Blocked, "not eligible"):
            rt.assess_verified(row, self.eligible)
        row = signed(self.eligible)
        row["intervals"][1]["key_hex"] = row["intervals"][0]["key_hex"]
        with self.assertRaisesRegex(s23.Blocked, "duplicate cryptographic"):
            rt.assess_verified(row, self.eligible)
        row = signed(self.eligible)
        row["operator_independence_proven"] = True
        with self.assertRaisesRegex(s23.Blocked, "falsely"):
            rt.assess_verified(row, self.eligible)

    def test_malformed_intervals_and_counter_not_accepted(self):
        row = signed(self.eligible)
        row["verified_count"] = 5
        with self.assertRaisesRegex(s23.Blocked, "counts"):
            rt.assess_verified(row, self.eligible)
        row = signed(self.eligible)
        row["intervals"][0]["earliest_us"] = True
        with self.assertRaisesRegex(s23.Blocked, "interval"):
            rt.assess_verified(row, self.eligible)
        row = signed(self.eligible)
        row["intervals"][0]["key_hex"] = "wrong"
        with self.assertRaisesRegex(s23.Blocked, "interval"):
            rt.assess_verified(row, self.eligible)

    def test_outage_source_must_not_reappear(self):
        row = signed(self.eligible, 3)
        operator = next(iter(self.eligible.values()))
        with self.assertRaisesRegex(s23.Blocked, "unexpectedly signed"):
            rt.assess_verified(row, self.eligible, operator)

    def test_shared_operator_alias_never_counts_twice(self):
        row = signed(self.eligible, 4)
        altered = dict(self.eligible)
        keys = list(altered)
        altered[keys[1]] = altered[keys[0]]
        with self.assertRaisesRegex(s23.Blocked, "duplicate operator"):
            rt.assess_verified(row, altered)


class OutagePolicy(unittest.TestCase):
    def setUp(self):
        _, _, self.eligible = fixture()
        self.rows = rt.assess_verified(signed(self.eligible), self.eligible)
        self.ids = self.rows["verified_operator_ids"]

    def test_four_to_three_only_after_actual_disabled_source(self):
        target = self.ids[0]
        three = {"verified_operator_ids": self.ids[1:],
                 "three_source_quorum_met": True}
        result = rt.overall(self.rows, three, target)
        self.assertEqual(result["one_source_outage_scenario"], "PASS")
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["operator_independence_proven"])
        self.assertTrue(result["simulated_outage_only"])

    def test_three_to_two_or_wrong_reacquisition_fails(self):
        for post in (self.ids[1:3], [self.ids[0], *self.ids[2:]],
                     ["untrusted", *self.ids[1:3]]):
            report = rt.overall(self.rows, {
                "verified_operator_ids": post,
                "three_source_quorum_met": len(post) >= 3,
            }, self.ids[0])
            self.assertEqual(report["one_source_outage_scenario"], "FAIL")
        three_base = dict(self.rows, four_source_outage_margin_met=False)
        result = rt.overall(three_base, {
            "verified_operator_ids": self.ids[1:],
            "three_source_quorum_met": True,
        }, self.ids[0])
        self.assertEqual(result["one_source_outage_scenario"], "FAIL")

    def test_outage_never_changes_trusted_roots(self):
        registry, dossier, _ = fixture()
        modified = s23.make_outage_registry(registry, dossier, "tanner-ryan")
        self.assertEqual(len(modified["sources"]), len(registry["sources"]))
        self.assertEqual([row["public_key"] for row in modified["sources"]],
                         [row["public_key"] for row in registry["sources"]])
        self.assertEqual(modified["sources"][3]["address"], "127.0.0.1:9")

    def test_mocks_are_not_cryptographic_evidence(self):
        # The Python summary cannot self-certify; the production survey
        # invokes the Rust capture AND an independent native replay.
        registry, dossier, eligible = fixture()
        receipt = {
            "schema": "hc-vtime/roughtime-receipt/v1",
            "dna_hex": "ab" * 39, "target_hex": "cd" * 39,
            "nonce_hex": "ef" * 32, "evidence": [],
        }
        completed = SimpleNamespace(returncode=0,
                                    stdout=json.dumps(receipt),
                                    stderr="TEST MOCK ONLY")
        with tempfile.TemporaryDirectory() as directory:
            files = {}
            with patch.object(s23, "native_mode", return_value=completed), \
                 patch.object(s23, "run_verify", return_value=(
                     signed(eligible), SimpleNamespace(returncode=0,
                                                      stderr="TEST MOCK ONLY"))):
                result = rt.one_capture(
                    "baseline", registry, dossier, eligible,
                    "ab" * 39, "cd" * 39, 180, None, files)
            self.assertEqual(result["native_reverification"], "PASS")
            self.assertIn("baseline.receipt.json", files)
            self.assertNotIn("operator_independence_proven", files)
            self.assertFalse(result["historical_same_target_replay_excluded"])


if __name__ == "__main__":
    unittest.main()
