"""Sprint 23 offline negative tests. NO UDP, secrets or real operator claims."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import accept as s23
import run_conductor as conductor

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "config/roughtime-independent-sources.json"
DOSSIER = ROOT / "config/sprint23-operator-dossier.example.json"
DNA = "84" + "20" + "24" + "11"*32 + "00000000"
TARGET = "84" + "20" + "24" + "22"*32 + "00000000"


def setup():
    reg = s23.read_json(REGISTRY)
    dossier = s23.read_json(DOSSIER)
    return reg, dossier


class RegistryTests(unittest.TestCase):
    def test_candidate_dossier_has_four_eligible_but_no_independence_proof(self):
        reg, dossier = setup()
        result = s23.validate_dossier(reg, dossier, s23.digest_file(REGISTRY))
        self.assertEqual(result["eligible_candidate_count"], 4)
        self.assertEqual(result["excluded_incompatible_operators"], ["cloudflare"])
        self.assertEqual(result["status"], "PENDING_HUMAN_REVIEW")
        self.assertFalse(result["human_review_records_complete"])
        self.assertFalse(result["operator_independence_proven"])

    def test_downgraded_minimum_or_outage_policy_never_accepted(self):
        reg, dossier = setup()
        for field, value in (("min_sources", 2), ("max_faulty", 0),
                             ("max_unavailable", 0)):
            with self.subTest(field=field):
                broken = copy.deepcopy(dossier)
                broken[field] = value
                with self.assertRaisesRegex(s23.Blocked, "must not be downgraded"):
                    s23.validate_dossier(reg, broken, s23.digest_file(REGISTRY))

    def test_registry_duplicate_operator_key_or_udp_address(self):
        reg, dossier = setup()
        for key in ("operator", "public_key", "address", "name"):
            with self.subTest(field=key):
                broken = copy.deepcopy(reg)
                broken["sources"][1][key] = broken["sources"][0][key]
                with self.assertRaisesRegex(s23.Blocked, "duplicate"):
                    s23.validate_dossier(broken, dossier, s23.digest_file(REGISTRY))

    def test_dossier_repeat_operator_id_or_rebind_root(self):
        reg, dossier = setup()
        duplicate = copy.deepcopy(dossier)
        duplicate["sources"][1]["operator_id"] = duplicate["sources"][0]["operator_id"]
        with self.assertRaisesRegex(s23.Blocked, "same real-world operator"):
            s23.validate_dossier(reg, duplicate, s23.digest_file(REGISTRY))
        wrong_key = copy.deepcopy(dossier)
        wrong_key["sources"][1]["public_key"] = reg["sources"][0]["public_key"]
        with self.assertRaisesRegex(s23.Blocked, "duplicate root"):
            s23.validate_dossier(reg, wrong_key, s23.digest_file(REGISTRY))
        wrong_endpoint = copy.deepcopy(dossier)
        wrong_endpoint["sources"][1]["address"] = "attacker.invalid:5319"
        with self.assertRaisesRegex(s23.Blocked, "identity/endpoint"):
            s23.validate_dossier(reg, wrong_endpoint, s23.digest_file(REGISTRY))

    def test_known_unsupported_draft11_not_counted_as_eligible(self):
        reg, dossier = setup()
        broken = copy.deepcopy(dossier)
        broken["sources"][0]["supported_client_protocol"] = True
        with self.assertRaisesRegex(s23.Blocked, "incompatible draft11"):
            s23.validate_dossier(reg, broken, s23.digest_file(REGISTRY))
        broken = copy.deepcopy(dossier)
        broken["sources"][4]["supported_client_protocol"] = False
        with self.assertRaisesRegex(s23.Blocked, "fewer than four protocol-compatible"):
            s23.validate_dossier(reg, broken, s23.digest_file(REGISTRY))

    def test_report_review_fields_cannot_prove_independence(self):
        reg, dossier = setup()
        dossier["status"] = "REVIEWED_APPROVED"
        dossier["reviewers"] = ["Reviewer One", "Reviewer Two"]
        for src in dossier["sources"]:
            if src["supported_client_protocol"]:
                src["protocol_assessment"] = "rfc10049-live-verified"
                src["admin_independence_reviewed"] = True
                src["root_key_control_reviewed"] = True
                src["shared_upstream_reviewed"] = True
                src["live_signature_evidence_sha256"] = "a"*64
                src["infrastructure_evidence_refs"] = ["local-review-reference"]
        outcome = s23.validate_dossier(reg, dossier, s23.digest_file(REGISTRY))
        self.assertTrue(outcome["human_review_records_complete"])
        self.assertFalse(outcome["operator_independence_proven"])

    def test_registry_sha_pin_fail_closed_on_bit_flip(self):
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "registry.json"
            copied.write_bytes(REGISTRY.read_bytes())
            copied.write_bytes(copied.read_bytes() + b"\n ")
            args = type("A", (), {
                "registry": copied,
                "dossier": DOSSIER,
                "expected_registry_sha256": s23.digest_file(REGISTRY),
            })()
            with self.assertRaisesRegex(s23.Blocked, "external SHA-256 pin"):
                s23.prepare(args)

    def test_outage_only_disables_eligible_operator_never_changes_roots(self):
        reg, dossier = setup()
        mutated = s23.make_outage_registry(reg, dossier, "tanner-ryan")
        self.assertEqual(len(mutated["sources"]), len(reg["sources"]))
        self.assertEqual(mutated["sources"][3]["address"], "127.0.0.1:9")
        for source, other in zip(reg["sources"], mutated["sources"]):
            self.assertEqual(source["public_key"], other["public_key"])
        with self.assertRaisesRegex(s23.Blocked, "compatible"):
            s23.make_outage_registry(reg, dossier, "cloudflare")


class ReceiptTests(unittest.TestCase):
    def test_wrong_target_and_dna_replay_fail_before_native_verifier(self):
        fixture = {
            "schema": "hc-vtime/roughtime-receipt/v1",
            "dna_hex": DNA, "target_hex": TARGET, "nonce_hex": "ab"*32,
            "evidence": [],
        }
        s23.receipt_check(fixture, DNA, TARGET)
        with self.assertRaisesRegex(s23.Blocked, "wrong DNA or target"):
            s23.receipt_check(fixture, DNA, "ff"*39)
        with self.assertRaisesRegex(s23.Blocked, "wrong DNA or target"):
            s23.receipt_check(fixture, "ee"*39, TARGET)
        fixture["schema"] = "hc-vtime/roughtime-receipt/v99"
        with self.assertRaisesRegex(s23.Blocked, "schema"):
            s23.receipt_check(fixture, DNA, TARGET)

    def test_structured_native_signer_interval_required_and_no_fake_signoff(self):
        result = {
            "schema": "hc-vtime/native-roughtime-verification/v1",
            "dna_hex": DNA, "target_hex": TARGET, "nonce_hex": "ab"*32,
            "verified_count": 3,
            "intervals": [
                {"key_hex": str(i)*64, "earliest_us": 1_000_000,
                 "latest_us": 2_000_000} for i in (1, 2, 3)
            ],
            "operator_independence_proven": False,
            "same_target_replay_prevented": False,
        }
        row = "HC_RT_VERIFIED " + json.dumps(result)
        self.assertEqual(s23.native_summary(row, DNA, TARGET)["verified_count"], 3)
        with self.assertRaisesRegex(s23.Blocked, "wrong source DNA or target"):
            s23.native_summary(row, "ff"*39, TARGET)
        result["operator_independence_proven"] = True
        with self.assertRaisesRegex(s23.Blocked, "falsely claims"):
            s23.native_summary("HC_RT_VERIFIED " + json.dumps(result), DNA, TARGET)
        result["operator_independence_proven"] = False
        result["intervals"][1]["key_hex"] = result["intervals"][0]["key_hex"]
        with self.assertRaisesRegex(s23.Blocked, "same signer"):
            s23.native_summary("HC_RT_VERIFIED " + json.dumps(result), DNA, TARGET)

    def test_local_clock_staleness_is_advisory_and_conservative(self):
        now = 3_000_000_000
        fresh = {"earliest_us": now - 4_000_000, "latest_us": now + 5_000_000}
        stale = {"earliest_us": now - 30_000_000, "latest_us": now - 20_000_000}
        self.assertTrue(s23.freshness([fresh]*3, now, age_seconds=6))
        self.assertFalse(s23.freshness([fresh, fresh, stale], now, age_seconds=6))
        self.assertFalse(s23.freshness([stale]*3, now, age_seconds=6))
        self.assertTrue(s23.freshness([stale]*3, now, age_seconds=31))

    def test_real_conductor_receipt_requires_trusted_eligible_operators(self):
        reg, dossier = setup()
        raw = [list(s23.decode_key(row["public_key"]))
               for row in reg["sources"][1:4]]
        receipt = {
            "schema": "hc-vtime/roughtime-receipt/v1",
            "dna_hex": DNA, "target_hex": TARGET, "nonce_hex": "ab"*32,
            "evidence": [{"server_public_key": k, "request": [], "response": []}
                         for k in raw],
        }
        metadata = {
            "schema": "hc-vtime/live-conductor-acceptance/v1",
            "dna_hex": DNA, "target_hex": TARGET, "verified_by_peer": True,
            "signed_roots": 3, "operator_independence_proven": False,
            "replay_same_target_prevented_on_chain": False,
        }
        negative = {"schema": "hc-vtime/live-roughtime-negative-tests/v1",
                    **{field: True for field in conductor.EXPECTED_NEGATIVES}}
        log = (
            "HC_RT_RECEIPT " + json.dumps(receipt) + "\n" +
            "HC_RT_CONDUCTOR " + json.dumps(metadata) + "\n" +
            "HC_RT_NEGATIVE " + json.dumps(negative) + "\n"
        )
        conductor.verify_live_records(log, reg, dossier, "a"*64)
        metadata["verified_by_peer"] = False
        with self.assertRaisesRegex(s23.Blocked, "conductor attestation"):
            conductor.verify_live_records(
                log.replace('HC_RT_CONDUCTOR ' + json.dumps({
                    **metadata, "verified_by_peer": True
                }), 'HC_RT_CONDUCTOR ' + json.dumps(metadata)),
                reg, dossier, "a"*64)
        receipt["evidence"][0]["server_public_key"] = list(
            s23.decode_key(reg["sources"][0]["public_key"]))
        bad = log.replace(
            "HC_RT_RECEIPT " + json.dumps({
                **receipt,
                "evidence": [{"server_public_key": k, "request": [], "response": []}
                             for k in raw]
            }),
            "HC_RT_RECEIPT " + json.dumps(receipt)
        )
        with self.assertRaisesRegex(s23.Blocked, "unreviewed or incompatible"):
            conductor.verify_live_records(bad, reg, dossier, "a"*64)


class ReplayLedgerTests(unittest.TestCase):
    def test_same_target_packet_and_same_operation_both_one_shot(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = Path(temp) / "local.db"
            self.assertTrue(s23.claim_local_ledger(
                ledger, DNA, TARGET, "operation-001", "a"*64)["locally_claimed"])
            with self.assertRaisesRegex(s23.Blocked, "duplicate/ambiguous"):
                s23.claim_local_ledger(ledger, DNA, TARGET, "operation-002", "a"*64)
            with self.assertRaisesRegex(s23.Blocked, "duplicate/ambiguous"):
                s23.claim_local_ledger(ledger, DNA, TARGET, "operation-001", "b"*64)
            self.assertTrue(s23.claim_local_ledger(
                ledger, DNA, TARGET, "operation-002", "b"*64)["locally_claimed"])
            self.assertTrue(s23.claim_local_ledger(
                ledger, DNA, "cc"*39, "operation-001", "a"*64)["locally_claimed"])

    def test_local_sqlite_concurrent_claim_has_exactly_one_winner(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = Path(temp) / "claim.db"
            def claim(_):
                try:
                    s23.claim_local_ledger(
                        ledger, DNA, TARGET, "same-operation-001", "b"*64)
                    return True
                except s23.Blocked:
                    return False
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(claim, range(8)))
            self.assertEqual(results.count(True), 1)
            self.assertEqual(results.count(False), 7)

    def test_invalid_or_inside_repo_ledger_refused(self):
        with self.assertRaisesRegex(s23.Blocked, "idempotency operation ID"):
            s23.claim_local_ledger(Path("/tmp/unused.db"), DNA, TARGET, "bad", "b"*64)
        with self.assertRaisesRegex(s23.Blocked, "outside source"):
            s23.claim_local_ledger(ROOT / "scripts/roughtime/test-ledger.db",
                                  DNA, TARGET, "operation-001", "b"*64)

    def test_report_hashes_and_evidence_immutability(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "new-evidence"
            s23.store_report(target, {"status": "BLOCKED"},
                             {"native.log": "test-only stderr"})
            manifest = (target / "SHA256SUMS").read_text()
            self.assertIn("  report.json", manifest)
            self.assertIn("  native.log", manifest)
            with self.assertRaisesRegex(s23.Blocked, "already exists"):
                s23.store_report(target, {"status": "PASS"})
            old = s23.digest_file(target / "native.log")
            (target / "native.log").write_text("tampered")
            self.assertNotEqual(s23.digest_file(target / "native.log"), old)


if __name__ == "__main__":
    unittest.main()
