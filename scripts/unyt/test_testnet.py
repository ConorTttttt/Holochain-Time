"""Offline-only regression coverage. Synthetic mock receipts NEVER certify 14B."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    from . import testnet as t
except ImportError:
    import testnet as t


def identity(n: int) -> str:
    # Intentionally NOT a real Holochain-checksummed key: structural test only.
    return "uhCAk" + str(n) * 55


def valid_config() -> dict:
    cfg = t.read_json(t.ROOT / "integration/unyt/testnet.example.json")
    cfg["network"] = {
        "kind": "isolated-test-alliance",
        "alliance_id": "unyt-disposable-fixture-alliance",
        "vtime_dna_hash": "uhC0k" + "D" * 55,
        "unit_index": "0",
    }
    for number, role in enumerate(cfg["participants"], 1):
        cfg["participants"][role] = identity(number)
    cfg["local_adapter"] = {"path": "REPLACE_WITH_LOCAL_ADAPTER", "sha256": "REPLACE"}
    cfg["timing"] = {
        "bond_until_us": "1799776000000000",
        "challenge_period_us": "604800000000",
        "tranche_unlock_times_us": [
            "1792000000000000", "1792003600000000", "1792007200000000"
        ],
    }
    return cfg


class TestConfigAndPlan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.cfg = valid_config()

    def test_placeholder_example_is_not_deployable(self):
        example = t.read_json(t.ROOT / "integration/unyt/testnet.example.json")
        with self.assertRaises(t.GateError):
            t.check_config(example)

    def test_unsafe_network_and_untrusted_roles_fail_closed(self):
        t.check_config(self.cfg)
        bad = copy.deepcopy(self.cfg)
        bad["network"]["kind"] = "production"
        with self.assertRaises(t.GateError):
            t.check_config(bad)
        bad = copy.deepcopy(self.cfg)
        bad["participants"]["witness_oracle_3"] = bad["participants"]["bonded_oracle"]
        with self.assertRaises(t.GateError):
            t.check_config(bad)
        bad = copy.deepcopy(self.cfg)
        bad["limits"]["maximum_aggregate_funded_units"] = "700"
        with self.assertRaises(t.GateError):
            t.check_config(bad)
        bad = copy.deepcopy(self.cfg)
        bad["template_bindings"]["verified_time_release"] = "../../untrusted.json"
        with self.assertRaises(t.GateError):
            t.check_config(bad)

    def test_manifest_pins_all_templates_and_is_immutable(self):
        directory = self.base / "plan"
        manifest = t.build_plan(self.cfg, directory)
        actual = t.verify_manifest(directory / "deployment_manifest.json")
        self.assertEqual(actual, manifest)
        for template in t.TEMPLATES:
            resolved = t.read_json(directory / f"{template}.agreement_rules.json")
            t.check_rules(template, resolved, self.cfg)
            self.assertNotIn("placeholder", json.dumps(resolved))
        with self.assertRaises(t.GateError):
            t.build_plan(self.cfg, directory)
        file = directory / "time_oracle_bond.agreement_rules.json"
        file.write_text(file.read_text() + "\n", encoding="utf-8")
        with self.assertRaises(t.GateError):
            t.verify_manifest(directory / "deployment_manifest.json")

    def test_adapter_cannot_run_without_explicit_approved_hash(self):
        directory = self.base / "plan"
        t.build_plan(self.cfg, directory)
        with self.assertRaises(t.GateError):
            t.submit(self.cfg, directory / "deployment_manifest.json",
                     self.base / "deployment.json", self.cfg["network"]["alliance_id"])


class TestReceipts(unittest.TestCase):
    """Normalized, mock export files exercise invariants, not any real network."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = valid_config()
        self.manifest = t.build_plan(self.config, self.base / "plan")
        self.manifest_path = self.base / "plan/deployment_manifest.json"
        self.evidence_dir = self.base / "artifacts"
        self.evidence_dir.mkdir()
        scenarios = t.read_json(t.SCENARIOS)["cases"]
        self.cases = {s["id"]: s for s in scenarios}
        self.receipts = {
            "schema": t.RECEIPT_SCHEMA,
            "manifest_sha256": self.manifest["manifest_sha256"],
            "network_id": self.config["network"]["alliance_id"],
            "records": [],
        }
        rave_map = {}
        for index, scenario in enumerate(scenarios, 1):
            name = scenario["id"]
            accepted = scenario["expect"] == "accepted"
            rave = "uhCkk" + str(index) * 53 if accepted else None
            role = scenario["agreement"]
            instance = "test-agreement-release" if role == "verified_time_release" else (
                "test-agreement-" + scenario.get("instance", name)
            )
            record = {
                "scenario_id": name,
                "agreement": role,
                "unit_index": "0",
                "status": "accepted" if accepted else "rejected",
                "peer_verdict": "accepted" if accepted else "rejected",
                "rave_action_hash": rave,
                "agreement_instance_id": instance,
                "previous_rave_action_hash": rave_map.get(scenario.get("previous")),
                "payouts": [
                    {
                        "recipient": self.config["participants"][p["role"]],
                        "unit_index": "0",
                        "amount_units": p["amount"],
                    } for p in scenario.get("payouts", [])
                ],
            }
            if accepted:
                record["input_units"] = scenario["input"]
                record["locked_units"] = scenario["locked"]
                record["outcome"] = scenario["expected_outcome"]
                rave_map[name] = rave
            else:
                # Strictly identical canonical snapshots, no fictitious RAVE.
                self.store(record, "pre_state", json.dumps({"balance": "500"}).encode())
                self.store(record, "post_state", json.dumps({"balance": "500"}).encode())
            client = {
                "schema": "hc-vtime/unyt-client-export/v1",
                "network_id": self.config["network"]["alliance_id"],
                "scenario_id": name,
                "status": record["status"],
                "rave_action_hash": rave,
                "agreement": record["agreement"],
                "agreement_instance_id": record["agreement_instance_id"],
                "unit_index": record["unit_index"],
                "previous_rave_action_hash": record["previous_rave_action_hash"],
                "input_units": record.get("input_units"),
                "locked_units": record.get("locked_units"),
                "payouts": record["payouts"],
                "outcome": record.get("outcome"),
                "fixture_only": True,
            }
            self.store(record, "client_export", t.stable_json(client))
            peer = {
                "schema": "hc-vtime/unyt-peer-check/v1",
                "network_id": self.config["network"]["alliance_id"],
                "scenario_id": name,
                "rave_action_hash": rave,
                "client_export_sha256": record["client_export_sha256"],
                "verdict": record["peer_verdict"],
                "peer_agent": identity(9),
                "fixture_only": True,
            }
            self.store(record, "peer_check", t.stable_json(peer))
            self.receipts["records"].append(record)

    def store(self, record: dict, prefix: str, data: bytes):
        filename = f"{record['scenario_id']}.{prefix}.json"
        (self.evidence_dir / filename).write_bytes(data)
        record[prefix + "_file"] = filename
        record[prefix + "_sha256"] = hashlib.sha256(data).hexdigest()

    def refresh_exports(self, item):
        # Re-sign mock identity references only: this is not cryptographic
        # signing and does not represent a genuine client or peer export.
        client = t.read_json(self.evidence_dir / item["client_export_file"])
        for field in ("rave_action_hash", "agreement", "agreement_instance_id",
                      "unit_index", "previous_rave_action_hash", "input_units",
                      "locked_units", "payouts", "outcome"):
            client[field] = item.get(field)
        self.store(item, "client_export", t.stable_json(client))
        peer = t.read_json(self.evidence_dir / item["peer_check_file"])
        peer["rave_action_hash"] = item["rave_action_hash"]
        peer["client_export_sha256"] = item["client_export_sha256"]
        self.store(item, "peer_check", t.stable_json(peer))

    def write_receipts(self):
        p = self.base / "receipts.json"
        p.write_bytes(t.stable_json(self.receipts))
        return p

    def verify(self):
        return t.verify_receipts(self.manifest_path, self.write_receipts(), self.evidence_dir)

    def test_complete_mock_scenarios_are_internally_consistent(self):
        self.assertEqual(len(self.verify()), len(self.cases))

    def test_overpayment_is_rejected_even_when_label_claims_success(self):
        item = next(x for x in self.receipts["records"] if x["scenario_id"] == "release_first")
        item["payouts"][0]["amount_units"] = "200"
        self.refresh_exports(item)
        with self.assertRaisesRegex(t.GateError, "payout receivers|value conservation"):
            self.verify()

    def test_wrong_previous_execution_and_reused_bond_are_rejected(self):
        item = next(x for x in self.receipts["records"] if x["scenario_id"] == "release_second")
        item["previous_rave_action_hash"] = "uhCkk" + "X" * 55
        self.refresh_exports(item)
        with self.assertRaisesRegex(t.GateError, "previous execution"):
            self.verify()
        item["previous_rave_action_hash"] = self.receipts["records"][0]["rave_action_hash"]
        self.refresh_exports(item)
        b = next(x for x in self.receipts["records"] if x["scenario_id"] == "bond_slash_equivocation")
        b["agreement_instance_id"] = "test-agreement-bond-slash-reversal"
        self.refresh_exports(b)
        with self.assertRaisesRegex(t.GateError, "bond was already resolved"):
            self.verify()

    def test_forged_rejection_and_balance_change_are_not_accepted(self):
        item = next(x for x in self.receipts["records"] if x["scenario_id"] == "bond_refund_early")
        item["rave_action_hash"] = "uhCkk" + "X" * 55
        self.refresh_exports(item)
        with self.assertRaisesRegex(t.GateError, "RAVE identity mismatch|rejected execution"):
            self.verify()
        item["rave_action_hash"] = None
        self.refresh_exports(item)
        self.store(item, "post_state", b'{"balance":"499"}')
        with self.assertRaisesRegex(t.GateError, "identical before/after"):
            self.verify()

    def test_cross_network_and_mutated_client_evidence_rejected(self):
        self.receipts["network_id"] = "not-our-test-alliance"
        with self.assertRaisesRegex(t.GateError, "wrong alliance"):
            self.verify()
        self.receipts["network_id"] = self.config["network"]["alliance_id"]
        item = self.receipts["records"][0]
        (self.evidence_dir / item["client_export_file"]).write_bytes(b"altered bytes")
        with self.assertRaisesRegex(t.GateError, "file hash mismatch"):
            self.verify()

    def test_no_partial_matrix_can_claim_acceptance(self):
        self.receipts["records"].pop()
        with self.assertRaisesRegex(t.GateError, "missing scenarios"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
