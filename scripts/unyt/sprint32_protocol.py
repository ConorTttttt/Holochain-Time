#!/usr/bin/env python3
"""Sprint 32A: UNAPPROVED financial-protocol proposals and offline invariants.

The v2 oracle statement authenticates a DNA, oracle, nonce, and time interval;
it does NOT authenticate this proposed target-binding context. No function
here executes a Unyt transfer or authenticates a native RAVE/Accept action.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

try:
    from .sprint26_proof import public_raw
except ImportError:
    from sprint26_proof import public_raw

BINDING_SCHEMA = "hc-vtime/unyt-agreement-target-proposal/v1"
OBSERVATION_SCHEMA = "hc-vtime/unyt-offline-financial-observation/v1"
POLICY_SCHEMA = "hc-vtime/unyt-economic-policy-candidate/v1"
COMMITMENT_DOMAIN = b"hc-vtime/unyt-target-commitment/v1\x00"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NONNEG = re.compile(r"(?:0|[1-9][0-9]*)\Z")
IDENTITY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}\Z")
MAX_UNITS = 1_000_000
MAX_TIME = 2**53


class Rejected(ValueError):
    """Unsafe, ambiguous, or unapproved offline input."""


def require(condition: bool, why: str) -> None:
    if not condition:
        raise Rejected(why)


def exact(obj: Any, fields: set[str], label: str) -> None:
    require(type(obj) is dict and set(obj) == fields,
            label + ": missing or unexpected fields")


def decimal(value: Any, label: str, maximum: int) -> int:
    require(type(value) is str and NONNEG.fullmatch(value) is not None,
            label + ": canonical nonnegative decimal string required")
    number = int(value)
    require(number <= maximum, label + ": exceeds allowed bound")
    return number


def digest(value: Any, label: str) -> str:
    require(type(value) is str and SHA256.fullmatch(value) is not None,
            label + ": requires SHA-256 digest")
    return value


def identity(value: Any, label: str) -> str:
    require(type(value) is str and IDENTITY.fullmatch(value) is not None,
            label + ": malformed identifier")
    return value


def typed_hash(value: Any, prefix: bytes, label: str) -> str:
    try:
        public_raw(value, prefix, label)
    except ValueError as error:
        raise Rejected(str(error)) from error
    return value


def target_commitment(payload: dict) -> dict:
    """Compute ONLY an unsigned candidate commitment, never verification."""
    exact(payload, {
        "schema", "alliance_id", "agreement_instance_id",
        "agreement_action_hash", "oracle_dna_hash",
        "target_action_hash", "agreement_template_sha256",
        "agreement_rules_sha256", "schedule_sha256",
        "purpose", "request_nonce_hex",
    }, "target binding")
    require(payload["schema"] == BINDING_SCHEMA, "unsupported target-binding version")
    identity(payload["alliance_id"], "alliance")
    identity(payload["agreement_instance_id"], "agreement instance")
    typed_hash(payload["agreement_action_hash"], b"\x84\x29\x24",
               "Unyt agreement action")
    typed_hash(payload["oracle_dna_hash"], b"\x84\x20\x24",
               "oracle DNA")
    typed_hash(payload["target_action_hash"], b"\x84\x29\x24",
               "Holochain target action")
    for field in ("agreement_template_sha256", "agreement_rules_sha256",
                  "schedule_sha256"):
        digest(payload[field], field)
    require(payload["purpose"] in ("verified_time_release", "bond_refund_witness"),
            "unrecognized financial purpose")
    digest(payload["request_nonce_hex"], "request nonce (32 bytes hex)")
    # Strict canonical serialization is part of the proposed v3 migration;
    # Ed25519 must sign a reviewed message that actually CONTAINS this
    # commitment. Existing signed v2 messages do not contain it.
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    require(len(raw) < 4096, "oversized target binding")
    return {
        "schema": "hc-vtime/unyt-target-preflight/v1",
        "candidate_commitment_sha256": hashlib.sha256(
            COMMITMENT_DOMAIN + raw).hexdigest(),
        "target_binding_authenticated_by_current_v2": False,
        "agreement_action_authenticated": False,
        "native_unyt_action_authenticated": False,
        "release_authorized": False,
        "status": "PROPOSED_COMMITMENT_ONLY_REQUIRES_SIGNED_V3_AND_REVIEW",
    }


def verify_proposed_context(payload: dict, expected: dict) -> dict:
    """Check exact-context equality; does NOT bind unsigned fields to v2."""
    exact(expected, {
        "alliance_id", "agreement_instance_id",
        "agreement_action_hash", "oracle_dna_hash",
        "target_action_hash", "agreement_template_sha256",
        "agreement_rules_sha256", "schedule_sha256", "purpose",
    }, "expected agreement context")
    result = target_commitment(payload)
    for field, value in expected.items():
        require(payload[field] == value, "wrong " + field + " in binding candidate")
    return result


def offline_observation(event: dict, expected: dict,
                        prior_sources: set[str] | None = None) -> dict:
    """Offline normalized accounting consistency, NOT a native signature check.

    Event is operator-supplied. A real release-matched Unyt native verifier
    must separately authenticate RAVE, source chains and recipient Accepts.
    """
    exact(event, {
        "schema", "alliance_id", "agreement_instance_id",
        "agreement_action_hash", "rave_action_hash", "unit_index",
        "input_units", "locked_units", "payouts", "accepts",
        "consumed_sources", "independent_peer_agent",
    }, "financial observation")
    exact(expected, {"alliance_id", "agreement_instance_id",
                     "agreement_action_hash", "unit_index"},
          "expected financial context")
    require(event["schema"] == OBSERVATION_SCHEMA,
            "unsupported offline observation version")
    for field in expected:
        require(event[field] == expected[field],
                "wrong " + field + " in financial observation")
    identity(event["alliance_id"], "alliance")
    identity(event["agreement_instance_id"], "agreement instance")
    typed_hash(event["agreement_action_hash"], b"\x84\x29\x24", "agreement")
    typed_hash(event["rave_action_hash"], b"\x84\x29\x24", "RAVE")
    typed_hash(event["independent_peer_agent"], b"\x84\x20\x24", "peer")
    require(event["unit_index"] == "0",
            "unexpected isolated-alliance unit index")
    incoming = decimal(event["input_units"], "input units", MAX_UNITS)
    locked = decimal(event["locked_units"], "locked units", MAX_UNITS)
    require(type(event["consumed_sources"]) is list
            and 1 <= len(event["consumed_sources"]) <= 32,
            "source list must be bounded and nonempty")
    sources = event["consumed_sources"]
    for source in sources:
        typed_hash(source, b"\x84\x29\x24", "consumed source")
    require(len(sources) == len(set(sources)), "duplicate consumed source")
    require(not (set(sources) & (prior_sources or set())),
            "reused consumed source across supplied local observations")
    payouts = event["payouts"]
    accepts = event["accepts"]
    require(type(payouts) is list and 1 <= len(payouts) <= 32
            and type(accepts) is list and len(accepts) == len(payouts),
            "every positive allocation needs one distinct native Accept")
    total = 0
    seen_accepts = set()
    for payout, accept in zip(payouts, accepts):
        exact(payout, {"recipient", "amount_units"}, "payout")
        exact(accept, {"accept_action_hash", "rave_action_hash",
                       "recipient", "amount_units"}, "recipient Accept")
        typed_hash(payout["recipient"], b"\x84\x20\x24", "payout recipient")
        typed_hash(accept["recipient"], b"\x84\x20\x24", "Accept recipient")
        typed_hash(accept["accept_action_hash"], b"\x84\x29\x24",
                   "Accept action")
        amount = decimal(payout["amount_units"], "allocation", MAX_UNITS)
        require(amount > 0, "zero-value allocation invalid")
        total += amount
        require(accept["rave_action_hash"] == event["rave_action_hash"]
                and accept["recipient"] == payout["recipient"]
                and accept["amount_units"] == payout["amount_units"],
                "recipient Accept not bound to RAVE, recipient and amount")
        require(accept["accept_action_hash"] not in seen_accepts,
                "recipient Accept reused for multiple allocations")
        seen_accepts.add(accept["accept_action_hash"])
    require(total + locked == incoming,
            "unit conservation violated: payouts + locked != input")
    return {
        "status": "OFFLINE_STRUCTURE_ONLY_NATIVE_VERIFICATION_REQUIRED",
        "input_units": incoming,
        "allocated_units": total,
        "locked_units": locked,
        "source_count_in_supplied_sample": len(sources),
        "recipient_accept_count_in_supplied_sample": len(accepts),
        "native_rave_authenticated": False,
        "native_accept_authenticated": False,
        "source_double_spend_excluded_network_wide": False,
        "independent_peer_verified": False,
        "actual_settlement_verified": False,
        "release_ready": False,
    }


def economic_counterfactual(candidate: dict, at_us: str) -> dict:
    """Compare UNAPPROVED expiry and challenge options, no Rhai enforcement."""
    exact(candidate, {
        "schema", "status", "expiry_option", "expiry_us",
        "bond_until_us", "challenge_period_us", "slash_deadline_option",
    }, "economic candidate")
    require(candidate["schema"] == POLICY_SCHEMA
            and candidate["status"] == "DRAFT_REQUIRES_ECONOMIC_APPROVAL",
            "financial policy cannot be silently approved")
    require(candidate["expiry_option"] in (
        "freeze-unreleased-for-governance", "refund-unreleased-to-grantor"),
        "unsupported proposal for release expiry")
    require(candidate["slash_deadline_option"] in (
        "close-at-bond-until-plus-period", "existing-unbounded-until-refund"),
        "unsupported candidate challenge semantics")
    expiry = decimal(candidate["expiry_us"], "expiry", MAX_TIME-1)
    end = decimal(candidate["bond_until_us"], "bond term end", MAX_TIME-1)
    period = decimal(candidate["challenge_period_us"], "challenge period", MAX_TIME-1)
    require(end + period < MAX_TIME, "challenge deadline overflows signed time range")
    at = decimal(at_us, "hypothetical authoritative observation time", MAX_TIME-1)
    release = ("before_expiry" if at < expiry else
               "proposed_freeze_no_auto_payment" if
               candidate["expiry_option"] == "freeze-unreleased-for-governance"
               else "proposed_refund_requires_native_authorized_execution")
    slash_window = ("before_bond_end" if at < end else
                    "challenge_window" if at < end + period else
                    "after_challenge_window")
    return {
        "status": "UNAPPROVED_COUNTERFACTUAL_ONLY",
        "release_state": release,
        "bond_state": slash_window,
        "deadline_inclusive_for_refund_proposal": at >= end + period,
        "current_rhai_slash_deadline_enforced": False,
        "caller_supplied_timestamp_authoritative": False,
        "native_unyt_settlement_verified": False,
        "policy_approved": False,
    }
