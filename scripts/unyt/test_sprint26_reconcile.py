"""Sprint 26 reconciliation: port PR #62 safeguards into PR #63 workflow.

Every byte in these fixtures is MOCK and NOT Unyt network evidence.
Tests verify offline rejection and permanent financial NO-GO only.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

try:
    from . import sprint26 as s
    from . import test_testnet as prior
except ImportError:
    import sprint26 as s
    import test_testnet as prior


def source_review(config):
    return {
        "schema": s.INTERFACE_SCHEMA,
        "alliance_id": config["network"]["alliance_id"],
        "unyt_release_tag": "v0.114.0",
        "distribution_sha256": "b" * 64,
        "source_commit": "a" * 40,
        "deployment_route": "manually-reviewed-build-panel",
        "native_verifier_source": "https://github.com/unytco/unyt-sandbox",
        "network_model": "agent-centric-rave-with-separate-recipient-accept",
        "reviewer": "offline-test-reviewer",
    }


def fake_action(byte):
    return "uhC" + byte * 53  # MOCK, not an actual hash or signed record


class ReconciledIntakeTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.config = prior.valid_config()
        self.cfg = self.root / "private-config.json"
        self.cfg.write_text(json.dumps(self.config), encoding="utf-8")
        self.review = self.root / "review.json"
        self.review.write_text(json.dumps(source_review(self.config)), encoding="utf-8")
        with patch.object(s, "checkout_sha", return_value="a" * 40):
            self.session = s.build_stage(
                self.cfg, self.review, self.root / "stage", "a" * 40
            )
        self.session_file = self.root / "stage/sprint26_session.json"
        self.evidence = self.root / "native-artifacts"
        self.evidence.mkdir()
        self.scenarios = s.scenario_matrix()

    def store(self, name, payload: bytes):
        (self.evidence / name).write_bytes(payload)
        return {"file": name, "sha256": s.sha256(payload)}

    def make_release(self, scenario="release_first", prefix="a"):
        slots = {
            k: self.store(f"{prefix}-{k}.raw", (
                b'{"statements":[]}' if k == "proof"
                else (b"before-state" if k == "before" else f"MOCK {prefix}-{k}".encode())
            ))
            for k in self.scenarios[scenario]["required_native_files"]
        }
        payout_native = self.store(f"{prefix}-recipient-accept.raw", b"MOCK signed Accept")
        return {
            "schema": s.EVENT_SCHEMA,
            "scenario_id": scenario,
            "alliance_id": self.config["network"]["alliance_id"],
            "agreement": "verified_time_release",
            "agreement_action_hash": fake_action("c"),
            "outcome": "accepted",
            "rave_action_hash": fake_action(prefix),
            "previous_rave_action_hash": None,
            "instance_id": "test-only-release-instance",
            "input_units": self.scenarios[scenario]["expected_input_units"],
            "locked_units": self.scenarios[scenario]["expected_locked_units"],
            "payouts": [{
                "role": "beneficiary", "amount_units": "100", "unit_index": "0",
                "accept_action_hash": fake_action("f" if prefix == "a" else "g"),
                "native_accept_file": payout_native["file"],
                "native_accept_sha256": payout_native["sha256"],
            }],
            "consumed_sources": [fake_action("s")],
            "native_files": slots,
            "peer_agent": "uhCAk" + "9" * 55,
        }

    def observed(self):
        return {
            "files": set(), "raves": set(), "sources": set(), "accepts": set(),
            "resolved_bonds": set(), "previous": {},
            "participants": self.config["participants"],
            "timing": self.config["timing"],
        }

    def validate(self, event, state=None):
        if state is None:
            state = self.observed()
        with patch.object(s.proof_gate, "verify_time_proof",
                          return_value={"lower_bound_us": "1800000000000000"}):
            return s.validate_bundle(
                event, self.session,
                self.scenarios[event["scenario_id"]],
                self.evidence, self.config["participants"], state
            )

    def save_event(self, event):
        (self.evidence / (event["scenario_id"] + ".event.json")).write_bytes(
            s.canonical(event)
        )

    def inventory(self):
        return s.inventory(self.session_file, self.cfg, self.review, self.evidence)

    def test_manifest_is_single_authority_with_all_exact_payouts_and_blockers(self):
        self.assertEqual(len(self.scenarios), 18)
        self.assertTrue(set(self.scenarios) >= {
            "release_first", "release_second", "release_final",
            "release_invalid_signature", "release_duplicate_oracle",
            "release_wrong_dna", "release_wrong_target",
            "release_replayed_proof", "release_expired",
            "bond_challenge_within_window",
        })
        self.assertEqual(self.scenarios["bond_challenge_within_window"]["expected_payouts"], [
            {"role": "reporter", "amount": "50"}, {"role": "treasury", "amount": "450"}
        ])
        self.assertEqual(self.scenarios["release_second"]["previous_case"], "release_first")
        self.assertEqual(self.scenarios["release_final"]["previous_case"], "release_second")
        self.assertEqual(set(self.session["blocked_protocol_scenarios"]), {
            "release_wrong_target", "release_replayed_proof",
            "release_expired", "bond_challenge_within_window",
        })

    def test_partial_inventory_retains_missing_and_protocol_blocked_states(self):
        report = self.inventory()
        self.assertEqual(report["financial_release_gate"], "NO_GO")
        self.assertFalse(report["actual_network_settlement_proven"])
        cases = {case["scenario_id"]: case for case in report["cases"]}
        self.assertEqual(cases["release_first"]["status"], "MISSING_NATIVE_ARTIFACTS")
        self.assertIn("accept:beneficiary", cases["release_first"]["missing_artifacts"])
        self.assertEqual(cases["release_wrong_target"]["status"], "BLOCKED_PROTOCOL")
        self.assertEqual(cases["release_replayed_proof"]["status"], "BLOCKED_PROTOCOL")
        self.assertEqual(cases["release_expired"]["status"], "BLOCKED_PROTOCOL")

    def test_mock_complete_inventory_is_only_ready_for_native_review(self):
        event = self.make_release()
        self.save_event(event)
        report = self.inventory()
        row = next(c for c in report["cases"] if c["scenario_id"] == "release_first")
        self.assertEqual(row["status"], "READY_FOR_INDEPENDENT_NATIVE_REVIEW")
        self.assertEqual(row["missing_artifacts"], [])
        self.assertFalse(report["native_signatures_authenticated"])
        self.assertEqual(report["financial_release_gate"], "NO_GO")

    def test_missing_recipient_accept_file_and_hash_are_not_ready(self):
        event = self.make_release()
        event["payouts"] = []
        self.save_event(event)
        report = self.inventory()
        row = next(c for c in report["cases"] if c["scenario_id"] == "release_first")
        self.assertEqual(row["status"], "MISSING_NATIVE_ARTIFACTS")
        self.assertIn("accept:beneficiary", row["missing_artifacts"])
        event = self.make_release(prefix="b")
        self.save_event(event)
        event["payouts"][0]["native_accept_sha256"] = "a" * 64
        self.save_event(event)
        with self.assertRaises(s.Blocked):
            self.inventory()

    def test_native_artifact_reference_reuse_symlink_and_traversal_fail_closed(self):
        event = self.make_release()
        event["native_files"]["sources"] = copy.deepcopy(event["native_files"]["execution"])
        self.save_event(event)
        with self.assertRaisesRegex(s.Blocked, "reused"):
            self.inventory()
        event = self.make_release(prefix="b")
        event["native_files"]["peer"]["file"] = "../hidden-wallet"
        self.save_event(event)
        with self.assertRaises(s.Blocked):
            self.inventory()
        event = self.make_release(prefix="c")
        original = self.evidence / event["native_files"]["peer"]["file"]
        symlink = self.evidence / "symlink.raw"
        symlink.symlink_to(original)
        event["native_files"]["peer"]["file"] = symlink.name
        self.save_event(event)
        with self.assertRaises(s.Blocked):
            self.inventory()

    def test_duplicate_native_export_across_scenarios_is_rejected(self):
        first = self.make_release()
        second = self.make_release("release_second", "b")
        second["native_files"]["sources"] = copy.deepcopy(first["native_files"]["sources"])
        self.save_event(first)
        self.save_event(second)
        with self.assertRaisesRegex(s.Blocked, "reused"):
            self.inventory()

    def test_tampered_source_or_peer_native_sha_fails(self):
        event = self.make_release()
        self.save_event(event)
        (self.evidence / event["native_files"]["sources"]["file"]).write_bytes(
            b"tampered"
        )
        with self.assertRaisesRegex(s.Blocked, "SHA-256 mismatch"):
            self.inventory()

    def test_missing_or_mismatched_reviewed_interface_and_manifest_fail(self):
        review = json.loads(self.review.read_text())
        review["distribution_sha256"] = "c" * 64
        self.review.write_text(json.dumps(review))
        with self.assertRaisesRegex(s.Blocked, "interface record changed"):
            self.inventory()
        self.review.write_text(json.dumps(source_review(self.config)))
        self.config["timing"]["challenge_period_us"] = "123"
        self.cfg.write_text(json.dumps(self.config))
        with self.assertRaises(s.Blocked):
            self.inventory()

    def test_bad_json_and_fake_network_acceptance_fields_are_rejected(self):
        with self.assertRaises(s.Blocked):
            s.strict_json(b'{"result":"OK","result":"FUNDED"}')
        with self.assertRaises(s.Blocked):
            s.strict_json(b'{"finality": NaN}')
        event = self.make_release()
        event["native_unyt_finality_verified"] = True
        self.save_event(event)
        with self.assertRaises(s.Blocked):
            self.inventory()

    def test_wrong_payout_amount_or_conservation_is_rejected(self):
        event = self.make_release()
        self.assertTrue(self.validate(event)["reconciled"])
        bad = copy.deepcopy(event)
        bad["payouts"][0]["amount_units"] = "150"
        with self.assertRaisesRegex(s.Blocked, "incorrect payees"):
            self.validate(bad)
        bad = copy.deepcopy(event)
        bad["locked_units"] = "199"
        with self.assertRaisesRegex(s.Blocked, "conservation"):
            self.validate(bad)

    def test_duplicate_consumed_source_and_broken_release_chain_fail_closed(self):
        first = self.make_release()
        state = self.observed()
        self.assertTrue(self.validate(first, state)["reconciled"])
        second = self.make_release("release_second", "b")
        second["previous_rave_action_hash"] = first["rave_action_hash"]
        with self.assertRaisesRegex(s.Blocked, "source double consumption"):
            self.validate(second, state)
        second["consumed_sources"] = [fake_action("t")]
        second["previous_rave_action_hash"] = fake_action("x")
        with self.assertRaisesRegex(s.Blocked, "broken chained"):
            self.validate(second, self.observed() | {"previous": {"release_first": first}})

    def test_write_once_blocks_replaced_reports_and_in_repo_paths(self):
        out = self.root / "inventory.json"
        s.write_once(out, {"financial_release_gate": "NO_GO"})
        with self.assertRaisesRegex(s.Blocked, "output exists"):
            s.write_once(out, {"financial_release_gate": "GO"})
        with self.assertRaisesRegex(s.Blocked, "outside the Git checkout"):
            s.write_once(s.ROOT / "should-never-exist.json",
                         {"financial_release_gate": "GO"})


if __name__ == "__main__":
    import unittest
    unittest.main()
