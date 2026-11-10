"""Offline Sprint 26 gate tests. None exercises a funded Unyt network."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

try:
    from . import sprint26 as g, sprint26_proof as pg, test_testnet as prior
except ImportError:
    import sprint26 as g
    import sprint26_proof as pg
    import test_testnet as prior


def review(config):
    return {
        "schema": g.INTERFACE_SCHEMA,
        "alliance_id": config["network"]["alliance_id"],
        "unyt_release_tag": "v0.111.0",
        "distribution_sha256": "a" * 64,
        "source_commit": "b" * 40,
        "deployment_route": "manually-reviewed-build-panel",
        "native_verifier_source": "https://github.com/unytco/unyt-sandbox",
        "network_model": "agent-centric-rave-with-separate-recipient-accept",
        "reviewer": "reviewer-test",
    }


class ContractGateTests(TestCase):
    def test_required_scenarios_do_not_pretend_target_or_replay_supported(self):
        items = g.scenario_matrix()
        for name in ("release_wrong_target", "release_replayed_proof", "release_expired",
                     "bond_challenge_within_window"):
            self.assertEqual(items[name]["contract_status"], "requires_network_contract")
        self.assertTrue({"release_first", "release_invalid_signature", "release_wrong_dna",
                         "bond_refund_authorized", "bond_slash_invalid_proof"} <= set(items))

    def test_interface_review_does_not_claim_generic_rpc_or_mainnet(self):
        config = prior.valid_config()
        good = review(config)
        g.interface_review(good, config["network"]["alliance_id"])
        wrong = copy.deepcopy(good)
        wrong["deployment_route"] = "https://unyt-mainnet/api/deploy"
        with self.assertRaises(g.Blocked):
            g.interface_review(wrong, config["network"]["alliance_id"])
        wrong = copy.deepcopy(good)
        wrong["network_model"] = "ethereum-global-finality"
        with self.assertRaises(g.Blocked):
            g.interface_review(wrong, config["network"]["alliance_id"])
        wrong = copy.deepcopy(good)
        wrong["alliance_id"] = "another-network"
        with self.assertRaises(g.Blocked):
            g.interface_review(wrong, config["network"]["alliance_id"])

    def test_stage_is_immutable_reviewed_and_funding_false(self):
        with TemporaryDirectory() as temp:
            base = Path(temp)
            config = prior.valid_config()
            cf = base / "testnet.json"
            rf = base / "interface.json"
            cf.write_text(json.dumps(config))
            rf.write_text(json.dumps(review(config)))
            with patch.object(g, "checkout_sha", return_value="a" * 40):
                session = g.build_stage(cf, rf, base / "stage", "a" * 40)
            self.assertFalse(session["financial_execution_authorized"])
            self.assertFalse(session["native_acceptance_verified"])
            self.assertIn("release_replayed_proof", session["blocked_protocol_scenarios"])
            with patch.object(g, "checkout_sha", return_value="a" * 40):
                with self.assertRaises(g.Blocked):
                    g.build_stage(cf, rf, base / "stage", "a" * 40)

    def test_opaque_export_hash_does_not_establish_network_authenticity(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            artifact = folder / "native-record.bin"
            artifact.write_bytes(b"MOCK NOT A NATIVE RECORD")
            digest = g.sha256(artifact.read_bytes())
            self.assertEqual(g.evidence_file(folder, artifact.name, digest),
                             b"MOCK NOT A NATIVE RECORD")
            with self.assertRaises(g.Blocked):
                g.evidence_file(folder, "../secrets.txt", digest)
            with self.assertRaises(g.Blocked):
                g.evidence_file(folder, artifact.name, "0" * 64)
            with self.assertRaises(g.Blocked):
                g.evidence_file(folder, "missing.bin", digest)

    def test_rejected_scenario_cannot_have_rave_or_spent_source(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            d = {}
            for kind in ("before", "after", "execution", "peer", "proof", "agreement"):
                filename = f"{kind}.bin"
                payload = b"same-state" if kind in ("before", "after") else kind.encode()
                (directory / filename).write_bytes(payload)
                d[kind] = {"file": filename, "sha256": g.sha256(payload)}
            config = prior.valid_config()
            scenario = g.scenario_matrix()["release_invalid_signature"]
            stage = {"alliance_id": config["network"]["alliance_id"], "unit_index": "0"}
            event = {
                "schema": g.EVENT_SCHEMA,
                "scenario_id": scenario["id"],
                "alliance_id": stage["alliance_id"],
                "agreement": scenario["agreement"],
                "agreement_action_hash": "uhC" + "a" * 52,
                "outcome": "rejected",
                "rave_action_hash": None,
                "previous_rave_action_hash": None,
                "instance_id": "a-test-instance-123",
                "input_units": None,
                "locked_units": None,
                "payouts": [],
                "consumed_sources": [],
                "native_files": d,
                "peer_agent": "uhCAk" + "9" * 55,
            }
            state = {"participants": config["participants"], "timing": config["timing"]}
            self.assertTrue(g.validate_bundle(
                event, stage, scenario, directory, config["participants"], state
            )["reconciled"])
            forged = copy.deepcopy(event)
            forged["rave_action_hash"] = "uhC" + "z" * 52
            with self.assertRaises(g.Blocked):
                g.validate_bundle(forged, stage, scenario, directory, config["participants"], state)
            forged = copy.deepcopy(event)
            forged["consumed_sources"] = ["uhC" + "b" * 52]
            with self.assertRaises(g.Blocked):
                g.validate_bundle(forged, stage, scenario, directory, config["participants"], state)
            (directory / "after.bin").write_bytes(b"balance changed")
            with self.assertRaises(g.Blocked):
                g.validate_bundle(event, stage, scenario, directory, config["participants"], state)


class RealSignatureVectorTests(TestCase):
    def setUp(self):
        try:
            self.msgpack, _, self.edpub = pg.crypto_modules()
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            self.signer_cls = Ed25519PrivateKey
        except pg.ProofRejected as error:
            self.skipTest(str(error))
        fixture = json.loads(
            (g.ROOT / "integration/interop/fixtures/v1_oracle.json").read_text()
        )
        wire = self.msgpack.unpackb(base64.b64decode(fixture["wire_base64"]), raw=False)
        first = wire["items"][0]["oracle"]
        self.signed = {"statement": first["statement"], "signature": list(first["signature"])}
        self.fixture = fixture
        self.assertEqual(fixture["dna"], first["statement"]["dna"])

    def sign_as(self, statement, signer):
        payload = OrderedDict((field, statement[field]) for field in pg.FIELD_ORDER)
        signature = signer.sign(self.msgpack.packb(payload, use_bin_type=True))
        return {"statement": statement, "signature": list(signature)}

    def key_text(self, seed):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        signer = self.signer_cls.from_private_bytes(bytes([seed] * 32))
        key = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        digest = hashlib.blake2b(key, digest_size=16).digest()
        loc = bytes(digest[i] ^ digest[i+4] ^ digest[i+8] ^ digest[i+12] for i in range(4))
        return signer, "u" + base64.urlsafe_b64encode(
            b"\x84\x20\x24" + key + loc
        ).decode().rstrip("=")

    def test_signed_python_fixture_verifies_against_native_v2_encoding(self):
        one = pg.verify_time_proof(
            {"statements": [self.signed]}, self.fixture["dna"],
            [self.signed["statement"]["oracle"]], min_sources=1, max_faulty=0,
        )
        self.assertEqual(one["lower_bound_us"], self.signed["statement"]["earliest"])
        self.assertFalse(one["agreement_target_authenticated"])
        self.assertFalse(one["network_replay_exclusion_authenticated"])

    def test_forged_signature_foreign_network_and_duplicate_oracle_fail(self):
        entry = copy.deepcopy(self.signed)
        entry["signature"][0] ^= 1
        with self.assertRaises(pg.ProofRejected):
            pg.verify_statement(entry, self.fixture["dna"],
                                {self.signed["statement"]["oracle"]})
        with self.assertRaises(pg.ProofRejected):
            pg.verify_statement(self.signed, "uhC0kBAD",
                                {self.signed["statement"]["oracle"]})
        with self.assertRaises(pg.ProofRejected):
            pg.verify_time_proof(
                {"statements": [self.signed, self.signed]}, self.fixture["dna"],
                [self.signed["statement"]["oracle"]], min_sources=2,
            )

    def test_two_independently_signed_oracles_compute_conservative_lower_bound(self):
        another, another_id = self.key_text(23)
        later = copy.deepcopy(self.signed["statement"])
        later["oracle"] = another_id
        later["earliest"] = str(int(later["earliest"]) + 100)
        later["latest"] = str(int(later["latest"]) + 100)
        second = self.sign_as(later, another)
        proof = pg.verify_time_proof(
            {"statements": [self.signed, second]}, self.fixture["dna"],
            [self.signed["statement"]["oracle"], another_id],
            min_sources=2, max_faulty=1,
        )
        self.assertEqual(proof["valid_oracle_count"], 2)
        self.assertEqual(proof["lower_bound_us"], self.signed["statement"]["earliest"])
        self.assertFalse(proof["agreement_target_authenticated"])

    def test_two_signed_equivocating_batch_statements_form_valid_slash_preflight(self):
        signer, public_text = self.key_text(7)
        self.assertEqual(public_text, self.signed["statement"]["oracle"])
        alternate = copy.deepcopy(self.signed["statement"])
        alternate["earliest"] = str(int(alternate["earliest"]) + 20)
        alternate["latest"] = str(int(alternate["latest"]) + 20)
        other = self.sign_as(alternate, signer)
        claimed = pg.verify_bond_claim(
            {"kind": "slash", "a": self.signed, "b": other},
            self.fixture["dna"], public_text, [],
        )
        self.assertEqual(claimed["finding"], "equivocation")
        with self.assertRaises(pg.ProofRejected):
            pg.verify_bond_claim(
                {"kind": "slash", "a": self.signed, "b": self.signed},
                self.fixture["dna"], public_text, [],
            )


if __name__ == "__main__":
    import unittest
    unittest.main()
