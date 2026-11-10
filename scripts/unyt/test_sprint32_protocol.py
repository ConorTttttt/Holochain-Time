"""Sprint 32A deterministic MOCK-only protocol negative vectors (NO Unyt funds)."""
from __future__ import annotations

import base64
import copy
import hashlib
from unittest import TestCase

try:
    from . import sprint32_protocol as p
except ImportError:
    import sprint32_protocol as p


def typed(prefix: bytes, marker: int) -> str:
    body = bytes([marker]) * 32
    digest = hashlib.blake2b(body, digest_size=16).digest()
    checksum = bytes(digest[k] ^ digest[k + 4] ^
                     digest[k + 8] ^ digest[k + 12] for k in range(4))
    return "u" + base64.urlsafe_b64encode(
        prefix + body + checksum).decode("ascii").rstrip("=")


def agent(n: int) -> str:
    return typed(b"\x84\x20\x24", n)


def action(n: int) -> str:
    return typed(b"\x84\x29\x24", n)


def binding() -> dict:
    return {
        "schema": p.BINDING_SCHEMA,
        "alliance_id": "private-test-alliance",
        "agreement_instance_id": "agreement-instance-001",
        "agreement_action_hash": action(1),
        "oracle_dna_hash": agent(2),
        "target_action_hash": action(3),
        "agreement_template_sha256": "a" * 64,
        "agreement_rules_sha256": "b" * 64,
        "schedule_sha256": "c" * 64,
        "purpose": "verified_time_release",
        "request_nonce_hex": "d" * 64,
    }


def expected_context(b: dict) -> dict:
    return {k: v for k, v in b.items()
            if k not in ("schema", "request_nonce_hex")}


def financial() -> dict:
    return {
        "schema": p.OBSERVATION_SCHEMA,
        "alliance_id": "private-test-alliance",
        "agreement_instance_id": "agreement-instance-001",
        "agreement_action_hash": action(1),
        "rave_action_hash": action(4),
        "unit_index": "0",
        "input_units": "300",
        "locked_units": "200",
        "payouts": [{"recipient": agent(5), "amount_units": "100"}],
        "accepts": [{"accept_action_hash": action(6),
                     "rave_action_hash": action(4),
                     "recipient": agent(5), "amount_units": "100"}],
        "consumed_sources": [action(7)],
        "independent_peer_agent": agent(8),
    }


def expected_event(ev: dict) -> dict:
    return {k: ev[k] for k in (
        "alliance_id", "agreement_instance_id", "agreement_action_hash", "unit_index")}


def candidate() -> dict:
    return {
        "schema": p.POLICY_SCHEMA,
        "status": "DRAFT_REQUIRES_ECONOMIC_APPROVAL",
        "expiry_option": "refund-unreleased-to-grantor",
        "expiry_us": "1000",
        "bond_until_us": "2000",
        "challenge_period_us": "100",
        "slash_deadline_option": "close-at-bond-until-plus-period",
    }


class TargetBindingProposalTests(TestCase):
    def test_commitment_deterministic_but_unapproved(self):
        b = binding()
        one = p.verify_proposed_context(b, expected_context(b))
        two = p.verify_proposed_context(b, expected_context(b))
        self.assertEqual(one["candidate_commitment_sha256"],
                         two["candidate_commitment_sha256"])
        self.assertFalse(one["target_binding_authenticated_by_current_v2"])
        self.assertFalse(one["native_unyt_action_authenticated"])
        self.assertFalse(one["release_authorized"])
        # Repeating an authenticated historical v2 time bound is NOT a
        # native Unyt source double spend; this digest is not a replay lock.
        self.assertEqual(one, two)

    def test_wrong_target_agreement_dna_alliance_rules_schedule_fail(self):
        b = binding()
        expected = expected_context(b)
        changed = {
            "alliance_id": "other-alliance",
            "agreement_instance_id": "other-instance",
            "agreement_action_hash": action(9),
            "oracle_dna_hash": agent(9),
            "target_action_hash": action(9),
            "agreement_template_sha256": "f" * 64,
            "agreement_rules_sha256": "f" * 64,
            "schedule_sha256": "f" * 64,
            "purpose": "bond_refund_witness",
        }
        for field, replacement in changed.items():
            with self.subTest(field=field):
                mutated = copy.deepcopy(b)
                mutated[field] = replacement
                with self.assertRaisesRegex(p.Rejected, "wrong " + field):
                    p.verify_proposed_context(mutated, expected)

    def test_signature_not_implicitly_proven_by_unsigned_wrapper(self):
        b = binding()
        b["oracle_signature_valid"] = True
        with self.assertRaisesRegex(p.Rejected, "missing or unexpected"):
            p.target_commitment(b)
        b = binding()
        b["schema"] = "hc-vtime/oracle-statement/v2"
        with self.assertRaisesRegex(p.Rejected, "unsupported"):
            p.target_commitment(b)

    def test_hash_and_nonce_are_canonical(self):
        b = binding()
        b["target_action_hash"] = agent(3)
        with self.assertRaisesRegex(p.Rejected, "prefix"):
            p.target_commitment(b)
        b = binding()
        b["oracle_dna_hash"] = action(3)
        with self.assertRaisesRegex(p.Rejected, "prefix"):
            p.target_commitment(b)
        b = binding()
        b["request_nonce_hex"] = "AB" * 32
        with self.assertRaisesRegex(p.Rejected, "digest"):
            p.target_commitment(b)


class NativeEvidenceBoundaryTests(TestCase):
    def test_structural_conservation_cannot_claim_native_acceptance(self):
        ev = financial()
        outcome = p.offline_observation(ev, expected_event(ev))
        self.assertEqual(outcome["allocated_units"], 100)
        self.assertEqual(outcome["locked_units"], 200)
        for field in ("native_rave_authenticated", "native_accept_authenticated",
                      "source_double_spend_excluded_network_wide",
                      "independent_peer_verified", "actual_settlement_verified",
                      "release_ready"):
            self.assertFalse(outcome[field])

    def test_native_source_reuse_is_distinct_from_time_proof_reuse(self):
        ev = financial()
        p.offline_observation(ev, expected_event(ev))
        with self.assertRaisesRegex(p.Rejected, "reused consumed source"):
            p.offline_observation(ev, expected_event(ev),
                                  prior_sources={action(7)})
        ev["consumed_sources"].append(action(7))
        with self.assertRaisesRegex(p.Rejected, "duplicate consumed source"):
            p.offline_observation(ev, expected_event(ev))

    def test_missing_or_mismatched_recipient_accept_rejected(self):
        ev = financial()
        expected = expected_event(ev)
        for field, replacement in (
            ("rave_action_hash", action(9)), ("recipient", agent(9)),
            ("amount_units", "99"),
        ):
            with self.subTest(field=field):
                bad = copy.deepcopy(ev)
                bad["accepts"][0][field] = replacement
                with self.assertRaisesRegex(p.Rejected, "not bound"):
                    p.offline_observation(bad, expected)
        bad = copy.deepcopy(ev)
        bad["accepts"] = []
        with self.assertRaisesRegex(p.Rejected, "one distinct"):
            p.offline_observation(bad, expected)

    def test_conservation_and_numeric_canonicalization(self):
        ev = financial()
        expected = expected_event(ev)
        for field, replacement in (
            ("locked_units", "201"), ("input_units", "299"),
            ("input_units", "0300"), ("locked_units", -1),
        ):
            with self.subTest(field=field):
                bad = copy.deepcopy(ev)
                bad[field] = replacement
                with self.assertRaises(p.Rejected):
                    p.offline_observation(bad, expected)

    def test_reused_accept_and_wrong_peer_fails(self):
        ev = financial()
        ev["payouts"].append(copy.deepcopy(ev["payouts"][0]))
        ev["accepts"].append(copy.deepcopy(ev["accepts"][0]))
        ev["locked_units"] = "100"
        with self.assertRaisesRegex(p.Rejected, "reused"):
            p.offline_observation(ev, expected_event(ev))
        ev = financial()
        ev["independent_peer_agent"] = action(8)
        with self.assertRaisesRegex(p.Rejected, "prefix"):
            p.offline_observation(ev, expected_event(ev))

    def test_unknown_finality_flag_and_wrong_agreement_fail(self):
        ev = financial()
        expected = expected_event(ev)
        ev["global_finality_verified"] = True
        with self.assertRaisesRegex(p.Rejected, "unexpected"):
            p.offline_observation(ev, expected)
        ev = financial()
        ev["agreement_instance_id"] = "other-instance-001"
        with self.assertRaisesRegex(p.Rejected, "wrong agreement_instance_id"):
            p.offline_observation(ev, expected)


class UnapprovedEconomicCounterfactualTests(TestCase):
    def test_expiry_before_and_at_boundary(self):
        c = candidate()
        before = p.economic_counterfactual(c, "999")
        after = p.economic_counterfactual(c, "1000")
        self.assertEqual(before["release_state"], "before_expiry")
        self.assertIn("proposed_refund", after["release_state"])
        self.assertFalse(after["policy_approved"])
        self.assertFalse(after["native_unyt_settlement_verified"])

    def test_freeze_alternative_preserves_unapproved_status(self):
        c = candidate()
        c["expiry_option"] = "freeze-unreleased-for-governance"
        self.assertEqual(p.economic_counterfactual(c, "2000")["release_state"],
                         "proposed_freeze_no_auto_payment")

    def test_exact_challenge_boundary_and_current_rhai_gap(self):
        c = candidate()
        self.assertEqual(p.economic_counterfactual(c, "1999")["bond_state"],
                         "before_bond_end")
        self.assertEqual(p.economic_counterfactual(c, "2000")["bond_state"],
                         "challenge_window")
        self.assertEqual(p.economic_counterfactual(c, "2099")["bond_state"],
                         "challenge_window")
        at = p.economic_counterfactual(c, "2100")
        self.assertEqual(at["bond_state"], "after_challenge_window")
        self.assertTrue(at["deadline_inclusive_for_refund_proposal"])
        self.assertFalse(at["current_rhai_slash_deadline_enforced"])
        self.assertFalse(at["caller_supplied_timestamp_authoritative"])

    def test_no_autoapproval_or_overflow(self):
        c = candidate()
        c["status"] = "APPROVED"
        with self.assertRaisesRegex(p.Rejected, "cannot be silently"):
            p.economic_counterfactual(c, "2100")
        c = candidate()
        c["bond_until_us"] = str(2**53 - 2)
        c["challenge_period_us"] = "100"
        with self.assertRaisesRegex(p.Rejected, "overflows"):
            p.economic_counterfactual(c, "2100")
        c = candidate()
        c["expiry_option"] = "invented-distribution"
        with self.assertRaisesRegex(p.Rejected, "unsupported"):
            p.economic_counterfactual(c, "2100")
