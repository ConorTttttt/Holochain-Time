#!/usr/bin/env python3
"""Sprint 26: fail-closed Unyt funded-testnet preparation and evidence audit.

NO network submission, wallet API, signing, hidden RPC or simulated settlement.
This script validates operator-normalized exports and opaque native-file hashes.
It CANNOT verify native Unyt signed actions or DHT peer acceptance; only a
separately reviewed real Unyt client/peer verifier may do that. Never treat
OFFLINE_RECONCILIATION_ONLY as financial acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from . import testnet, sprint26_proof as proof_gate
except ImportError:
    import testnet
    import sprint26_proof as proof_gate
# Reuse merged Sprint 14A template checks and independently check Ed25519.

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "integration/unyt/sprint26_scenarios.json"
SESSION_SCHEMA = "hc-vtime/unyt-sprint26-session/v1"
EVENT_SCHEMA = "hc-vtime/unyt-sprint26-event/v1"
INTERFACE_SCHEMA = "hc-vtime/unyt-sprint26-interface-review/v1"
SCENARIO_SCHEMA = "hc-vtime/unyt-sprint26-scenarios/v2"
SHA = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
ACTION = re.compile(r"uhC[A-Za-z0-9_-]{45,}\Z")
AMOUNT = re.compile(r"(?:0|[1-9][0-9]*)\Z")


class Blocked(ValueError):
    """No accepted evidence is inferred when an invariant fails."""


def require(ok: bool, why: str) -> None:
    if not ok:
        raise Blocked(why)


def strict_keys(obj: dict, expected: set[str], where: str) -> None:
    require(isinstance(obj, dict) and set(obj) == expected,
            f"{where}: unknown or missing normalized field")


def strict_json(data: bytes) -> dict:
    """Reject ambiguous duplicate JSON keys/nonfinite numbers in evidence."""
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, f"duplicate JSON key {key!r}")
            obj[key] = value
        return obj

    def nonfinite(value):
        raise Blocked(f"nonfinite JSON value {value}")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def read_json(path: Path) -> dict:
    try:
        require(path.is_file() and not path.is_symlink(),
                f"{path.name}: regular nonsymlink JSON required")
        require(0 < path.stat().st_size <= 4 * 1024 * 1024,
                f"{path.name}: JSON size outside allowed range")
        data = strict_json(path.read_bytes())
        require(isinstance(data, dict), f"{path.name}: expected object")
        return data
    except (OSError, UnicodeError, ValueError) as error:
        raise Blocked(f"cannot read structured evidence {path.name}: {error}") from error


def decimal(value: Any, where: str) -> int:
    require(isinstance(value, str) and AMOUNT.fullmatch(value) is not None,
            f"{where}: canonical nonnegative decimal string required")
    amount = int(value)
    require(amount <= 1_000_000, f"{where}: exceeds isolated-test budget")
    return amount


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def verified_sha(path: Path, expected: str) -> bytes:
    require(isinstance(expected, str) and SHA.fullmatch(expected) is not None,
            "missing canonical SHA-256")
    require(path.is_file() and not path.is_symlink(), f"{path.name}: no regular evidence file")
    require(path.stat().st_size <= 4 * 1024 * 1024, f"{path.name}: evidence exceeds size cap")
    data = path.read_bytes()
    require(0 < len(data) and sha256(data) == expected,
            f"{path.name}: empty or SHA-256 mismatch")
    return data


def evidence_file(evidence_dir: Path, filename: str, digest: str) -> bytes:
    require(isinstance(filename, str) and filename not in (".", "..")
            and 0 < len(filename) <= 180 and Path(filename).name == filename
            and not filename.startswith(".")
            and "/" not in filename and "\\" not in filename,
            "evidence must be a single, non-hidden basename")
    require(evidence_dir.is_dir() and not evidence_dir.is_symlink(),
            "evidence directory must be a nonsymlink directory")
    directory = evidence_dir.resolve(strict=True)
    return verified_sha(directory / filename, digest)


def outside_checkout(output: Path) -> None:
    target = output.resolve()
    require(target != ROOT and ROOT not in target.parents,
            "operator artifacts must be written outside the Git checkout")
    require(output.parent.is_dir() and not output.parent.is_symlink(),
            "output parent must already be a regular directory")


def write_once(output: Path, value: dict) -> None:
    """PR #62 safeguard: no overwrite, no write inside reviewed source."""
    outside_checkout(output)
    try:
        with output.open("x", encoding="utf-8") as stream:
            stream.write(canonical(value).decode("utf-8"))
    except FileExistsError as error:
        raise Blocked("output exists; refusing to overwrite native evidence") from error


def checked_file(root: Path, filename: str, digest: str, used: set[str]) -> bytes:
    """PR #62 safeguard: one native file may not masquerade as multiple slots."""
    require(isinstance(filename, str) and filename not in used,
            "native export file reused across evidence slots")
    data = evidence_file(root, filename, digest)
    used.add(filename)
    return data


def checkout_sha(expected: str) -> str:
    require(GIT_SHA.fullmatch(expected or "") is not None, "exact 40-hex SHA required")
    current = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    require(current == expected, "Git checkout does not match pinned SHA")
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT, text=True
    ).strip()
    require(not status, "source tree is dirty; record an exact clean commit")
    return current


def scenario_matrix() -> dict[str, dict]:
    doc = read_json(SCENARIOS)
    require(doc.get("schema") == SCENARIO_SCHEMA, "wrong Sprint 26 scenario matrix")
    values = doc.get("cases")
    require(doc.get("contract_blocker_issue") == 61, "issue #61 protocol blocker removed")
    require(isinstance(values, list) and len(values) == 18,
            "exact reviewed 18-case Sprint 26 matrix required")
    output: dict[str, dict] = {}
    for row in values:
        require(isinstance(row, dict), "malformed scenario")
        strict_keys(row, {
            "id", "agreement", "expected_result", "origin_case", "contract_status",
            "total_paid_units", "expected_locked_units", "requires_native_rave_and_accept",
            "expected_input_units", "expected_payouts", "previous_case",
            "required_native_files",
        } | ({"blocker_issue"} if row.get("contract_status") == "requires_network_contract"
             else set()), "scenario")
        name = row["id"]
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]*", name) is not None
                and name not in output, "invalid or duplicate scenario")
        require(row["agreement"] in testnet.TEMPLATES, "unexpected agreement")
        require(row["expected_result"] in ("accepted", "rejected"), "invalid expected result")
        require(row["contract_status"] in ("available", "requires_network_contract"),
                "missing protocol capability status")
        require(set(row["required_native_files"]) == {
            "agreement", "before", "after", "execution", "peer", "proof", "sources",
        } and len(row["required_native_files"]) == 7,
                "native event evidence contract changed")
        require(row["requires_native_rave_and_accept"] is (row["expected_result"] == "accepted"),
                "RAVE/Accept requirements differ from expected result")
        require(isinstance(row["expected_payouts"], list)
                and isinstance(row["total_paid_units"], str), "missing explicit payout expectation")
        total = sum(decimal(p["amount"], "expected payout") for p in row["expected_payouts"]
                    if isinstance(p, dict) and set(p) == {"role", "amount"})
        require(len(row["expected_payouts"]) ==
                sum(isinstance(p, dict) and set(p) == {"role", "amount"}
                    and p["role"] in ("beneficiary", "bonded_oracle", "reporter", "treasury")
                    for p in row["expected_payouts"]),
                "invalid or untrusted payout roles")
        require(total == decimal(row["total_paid_units"], "planned amount"),
                "scenario payout total mismatch")
        if row["expected_result"] == "accepted":
            require(row["expected_input_units"] is not None
                    and decimal(row["expected_input_units"], "expected input")
                    == total + decimal(row["expected_locked_units"], "expected locked")
                    and len(row["expected_payouts"]) > 0,
                    "accepted scenario must fully specify exact conservation and recipients")
        else:
            require(row["expected_input_units"] is None and row["expected_payouts"] == []
                    and row["previous_case"] is None
                    and row["expected_locked_units"] == "",
                    "rejection scenario must not claim value transitions")
        if row["contract_status"] == "requires_network_contract":
            require(row.get("blocker_issue") == 61, "unsupported case missing issue #61")
        output[name] = row
    mandatory_blockers = {
        "release_wrong_target", "release_replayed_proof",
        "release_expired", "bond_challenge_within_window",
    }
    require({name for name, row in output.items()
             if row["contract_status"] == "requires_network_contract"}
            == mandatory_blockers, "protocol-blocked cases were reclassified")
    return output


def interface_review(doc: dict, alliance: str) -> dict:
    """An operator-reviewed DISCOVERY record; NOT proof of network capability."""
    strict_keys(doc, {
        "schema", "alliance_id", "unyt_release_tag", "distribution_sha256",
        "source_commit", "deployment_route", "native_verifier_source",
        "network_model", "reviewer",
    }, "interface review")
    require(doc["schema"] == INTERFACE_SCHEMA, "unsupported native interface review schema")
    require(doc["alliance_id"] == alliance, "interface review refers to wrong alliance")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", doc["unyt_release_tag"]) is not None,
            "pin an exact Unyt Sandbox release")
    for field in ("distribution_sha256",):
        require(isinstance(doc[field], str) and SHA.fullmatch(doc[field]) is not None,
                f"{field}: expected pinned SHA-256")
    require(GIT_SHA.fullmatch(doc["source_commit"]) is not None,
            "native Unyt source must be pinned to a full Git SHA")
    require(doc["deployment_route"] in ("manually-reviewed-build-panel", "operator-approved-local-adapter"),
            "no verified generic Unyt deployment API; no invented endpoints")
    require(doc["network_model"] == "agent-centric-rave-with-separate-recipient-accept",
            "Unyt has no global blockchain finality receipt")
    require(isinstance(doc["native_verifier_source"], str)
            and doc["native_verifier_source"].startswith("https://github.com/")
            and len(doc["native_verifier_source"]) < 512,
            "review the actual native SDK/peer-verification source")
    require(isinstance(doc["reviewer"], str) and len(doc["reviewer"]) >= 8,
            "human interface reviewer required")
    return doc


def build_stage(config_path: Path, review_path: Path, output: Path, expected_sha: str) -> dict:
    checkout_sha(expected_sha)
    config = testnet.check_config(read_json(config_path))
    review = interface_review(read_json(review_path), config["network"]["alliance_id"])
    cases = scenario_matrix()
    require(not output.exists(), "never overwrite a previously prepared agreement plan")
    outside_checkout(output)
    output.mkdir()
    # Keep operator supplied data and private testnet identifiers out of Git.
    testnet.build_plan(config, output / "agreements")
    manifest = testnet.verify_manifest(output / "agreements/deployment_manifest.json")
    stage = {
        "schema": SESSION_SCHEMA,
        "git_sha": expected_sha,
        "alliance_id": config["network"]["alliance_id"],
        "vtime_dna": config["network"]["vtime_dna_hash"],
        "unit_index": config["network"]["unit_index"],
        "release_tag": review["unyt_release_tag"],
        "interface_review_sha256": sha256(canonical(review)),
        "manifest_sha256": manifest["manifest_sha256"],
        "scenario_sha256": sha256(SCENARIOS.read_bytes()),
        "scenario_ids": sorted(cases),
        "financial_execution_authorized": False,
        "network_transactions_performed": False,
        "native_acceptance_verified": False,
        "blocked_protocol_scenarios": sorted(
            sid for sid, item in cases.items()
            if item["contract_status"] == "requires_network_contract"
        ),
    }
    (output / "sprint26_session.json").write_bytes(canonical(stage))
    return stage


def validate_bundle(bundle: dict, stage: dict, scenario: dict, root: Path,
                    participants: dict, observed: dict) -> dict:
    name = scenario["id"]
    strict_keys(bundle, {
        "schema", "scenario_id", "alliance_id", "agreement", "agreement_action_hash",
        "outcome", "rave_action_hash", "previous_rave_action_hash",
        "instance_id", "input_units", "locked_units", "payouts",
        "consumed_sources", "native_files", "peer_agent",
    }, f"{name} event")
    require(bundle["schema"] == EVENT_SCHEMA, f"{name}: wrong event schema")
    require(bundle["scenario_id"] == name and bundle["alliance_id"] == stage["alliance_id"],
            f"{name}: wrong identity or alliance")
    require(bundle["agreement"] == scenario["agreement"], f"{name}: wrong agreement")
    require(ACTION.fullmatch(bundle["agreement_action_hash"] or "") is not None,
            f"{name}: missing agreement action identifier")
    require(bundle["outcome"] == scenario["expected_result"],
            f"{name}: wrong outcome")
    require(isinstance(bundle["instance_id"], str) and len(bundle["instance_id"]) > 10,
            f"{name}: missing unique agreement instance")
    require(isinstance(bundle["consumed_sources"], list)
            and all(isinstance(x, str) and ACTION.fullmatch(x) for x in bundle["consumed_sources"]),
            f"{name}: missing genuine consumed source identities")
    require(len(bundle["consumed_sources"]) == len(set(bundle["consumed_sources"])),
            f"{name}: repeated source inside one execution")
    native = bundle["native_files"]
    require(isinstance(native, dict)
            and set(native) == set(scenario["required_native_files"]),
            f"{name}: complete native evidence files required")
    for kind, descriptor in native.items():
        strict_keys(descriptor, {"file", "sha256"}, f"{name}:{kind}")
        checked_file(root, descriptor["file"], descriptor["sha256"],
                     observed.setdefault("files", set()))
    require(isinstance(bundle["peer_agent"], str)
            and bundle["peer_agent"].startswith("uhCAk")
            and bundle["peer_agent"] not in set(participants.values()),
            f"{name}: independent observing Unyt agent required")

    if scenario["expected_result"] == "accepted":
        try:
            signed_proof = strict_json(
                evidence_file(root, native["proof"]["file"], native["proof"]["sha256"])
            )
        except (ValueError, UnicodeDecodeError) as error:
            raise Blocked(f"{name}: signed proof export malformed: {error}") from error
        principals = observed["participants"]
        if scenario["agreement"] == "verified_time_release":
            signing_oracles = [
                principals["bonded_oracle"], principals["witness_oracle_2"],
                principals["witness_oracle_3"],
            ]
            signed = proof_gate.verify_time_proof(
                signed_proof, stage["vtime_dna"], signing_oracles,
                min_sources=2, max_faulty=1,
            )
            tranche = {
                "release_first": 0, "release_second": 1, "release_final": 2
            }.get(name)
            if tranche is not None:
                require(
                    int(signed["lower_bound_us"]) >= int(
                        observed["timing"]["tranche_unlock_times_us"][tranche]
                    ),
                    f"{name}: signed lower bound does not unlock claimed tranche",
                )
        else:
            signed = proof_gate.verify_bond_claim(
                signed_proof, stage["vtime_dna"], principals["bonded_oracle"],
                [principals["witness_oracle_2"],
                 principals["witness_oracle_3"],
                 principals["witness_oracle_4"]],
            )
            if name == "bond_refund_authorized":
                need_after = (
                    int(observed["timing"]["bond_until_us"])
                    + int(observed["timing"]["challenge_period_us"])
                )
                require(int(signed["lower_bound_us"]) >= need_after,
                        "bond refund precedes challenge window end")
            if name in ("bond_slash_reversal", "bond_challenge_within_window"):
                require(signed.get("finding") in (
                    "time_reversal", "floor_dropped", "self_contradiction",
                ), f"{name}: malformed slash rationale")
            if name == "bond_slash_equivocation":
                require(signed.get("finding") == "equivocation",
                        "wrong claimed equivocation proof")

    if scenario["expected_result"] == "rejected":
        require(bundle["rave_action_hash"] is None and bundle["previous_rave_action_hash"] is None,
                f"{name}: rejected proof must not become an accepted RAVE")
        require(bundle["payouts"] == [] and bundle["consumed_sources"] == [],
                f"{name}: rejected execution consumed source or paid funds")
        require(evidence_file(root, native["before"]["file"], native["before"]["sha256"])
                == evidence_file(root, native["after"]["file"], native["after"]["sha256"]),
                f"{name}: rejected operation changed canonical normalized state")
        require(bundle["input_units"] is None and bundle["locked_units"] is None,
                f"{name}: rejected operation must not assert value transitions")
        return {"scenario": name, "reconciled": True}

    require(ACTION.fullmatch(bundle["rave_action_hash"] or "") is not None,
            f"{name}: accepted execution missing RAVE action")
    require(bundle["rave_action_hash"] not in observed["raves"], f"{name}: replayed RAVE identifier")
    observed["raves"].add(bundle["rave_action_hash"])
    require(len(bundle["consumed_sources"]) >= 1, f"{name}: no spent input source")
    for source in bundle["consumed_sources"]:
        require(source not in observed["sources"], f"{name}: source double consumption")
        observed["sources"].add(source)
    require(isinstance(bundle["payouts"], list), f"{name}: missing payouts")
    actual = set()
    paid = 0
    for item in bundle["payouts"]:
        strict_keys(item, {
            "role", "amount_units", "accept_action_hash", "unit_index",
            "native_accept_file", "native_accept_sha256",
        }, f"{name}:payout")
        require(item["role"] in participants, f"{name}: unexpected payment role")
        amount = decimal(item["amount_units"], f"{name}:payout")
        require(amount > 0 and item["unit_index"] == stage["unit_index"],
                f"{name}: zero payout or currency mismatch")
        require(ACTION.fullmatch(item["accept_action_hash"] or "") is not None,
                f"{name}: missing separate recipient Accept action")
        checked_file(root, item["native_accept_file"], item["native_accept_sha256"],
                     observed.setdefault("files", set()))
        require(item["accept_action_hash"] not in observed["accepts"],
                f"{name}: duplicate Accept action")
        observed["accepts"].add(item["accept_action_hash"])
        entry = (item["role"], str(amount))
        require(entry not in actual, f"{name}: duplicate payout")
        actual.add(entry)
        paid += amount
    expected = {(row["role"], row["amount"]) for row in scenario["expected_payouts"]}
    require(actual == expected and paid == decimal(scenario["total_paid_units"], f"{name}: paid"),
            f"{name}: incorrect payees or amounts")
    locked = decimal(bundle["locked_units"], f"{name}: locked")
    input_amount = decimal(bundle["input_units"], f"{name}: input")
    require(input_amount == locked + paid, f"{name}: unit conservation failed")
    if scenario["expected_locked_units"]:
        require(locked == decimal(scenario["expected_locked_units"], f"{name}: planned lock"),
                f"{name}: carried locked value changed")
    require(input_amount == decimal(scenario["expected_input_units"], f"{name}: planned input"),
            f"{name}: wrong agreement source amount")
    preceding = scenario["previous_case"]
    if preceding is None:
        require(bundle["previous_rave_action_hash"] is None,
                f"{name}: unexpected prior RAVE")
    else:
        require(preceding in observed["previous"],
                f"{name}: predecessor must execute first")
        previous = observed["previous"][preceding]
        require(bundle["previous_rave_action_hash"] == previous["rave_action_hash"],
                f"{name}: broken chained RAVE history")
        require(bundle["instance_id"] == previous["instance_id"],
                f"{name}: changed agreement instance mid-release")
    observed["previous"][name] = bundle
    if scenario["agreement"] == "time_oracle_bond":
        require(bundle["instance_id"] not in observed["resolved_bonds"],
                f"{name}: double-resolved bonded source")
        observed["resolved_bonds"].add(bundle["instance_id"])
    return {"scenario": name, "reconciled": True}


def checked_session(stage_path: Path, config_path: Path,
                    review_path: Path) -> tuple[dict, dict, dict[str, dict]]:
    stage = read_json(stage_path)
    strict_keys(stage, {
        "schema", "git_sha", "alliance_id", "vtime_dna", "unit_index",
        "release_tag", "interface_review_sha256", "manifest_sha256",
        "scenario_sha256", "scenario_ids", "financial_execution_authorized",
        "network_transactions_performed", "native_acceptance_verified",
        "blocked_protocol_scenarios",
    }, "reviewed session")
    require(stage["schema"] == SESSION_SCHEMA, "incorrect session schema")
    require(stage["financial_execution_authorized"] is False
            and stage["native_acceptance_verified"] is False
            and stage["network_transactions_performed"] is False,
            "session cannot authorize funding or attest network execution")
    require(stage["scenario_sha256"] == sha256(SCENARIOS.read_bytes()),
            "scenario definitions changed")
    require(isinstance(stage["git_sha"], str)
            and GIT_SHA.fullmatch(stage["git_sha"]) is not None,
            "missing exact SHA provenance")
    config = testnet.check_config(read_json(config_path))
    require(stage["alliance_id"] == config["network"]["alliance_id"]
            and stage["vtime_dna"] == config["network"]["vtime_dna_hash"]
            and stage["unit_index"] == config["network"]["unit_index"],
            "config identity differs from reviewed session")
    review = interface_review(read_json(review_path), stage["alliance_id"])
    require(stage["interface_review_sha256"] == sha256(canonical(review))
            and stage["release_tag"] == review["unyt_release_tag"],
            "reviewed Unyt build, source or interface record changed")
    manifest = testnet.verify_manifest(stage_path.parent / "agreements/deployment_manifest.json")
    require(stage["manifest_sha256"] == manifest["manifest_sha256"],
            "template/rules changed after planning")
    for field in ("network", "participants", "timing", "limits"):
        require(manifest[field] == config[field],
                f"config {field} changed after reviewed agreement plan")
    scenarios = scenario_matrix()
    require(stage["scenario_ids"] == sorted(scenarios), "scenario matrix incomplete")
    require(stage["blocked_protocol_scenarios"] == sorted(
        name for name, row in scenarios.items()
        if row["contract_status"] == "requires_network_contract"
    ), "issue #61 protocol blockers changed in session")
    return stage, config, scenarios


def audit(stage_path: Path, config_path: Path, review_path: Path,
          receipts_dir: Path) -> dict:
    stage, config, scenarios = checked_session(stage_path, config_path, review_path)
    observed = {
        "raves": set(), "accepts": set(), "sources": set(), "files": set(),
        "resolved_bonds": set(), "previous": {},
        "participants": config["participants"], "timing": config["timing"],
    }
    require(receipts_dir.is_dir() and not receipts_dir.is_symlink(),
            "operator must supply an external native evidence directory")
    extra = {p.name for p in receipts_dir.iterdir() if p.name.endswith(".event.json")}
    expected = {name + ".event.json" for name in scenarios}
    require(extra == expected, f"missing/unexpected event manifests: {sorted(expected ^ extra)}")
    output = []
    for name, scenario in scenarios.items():
        record = read_json(receipts_dir / (name + ".event.json"))
        output.append(validate_bundle(record, stage, scenario, receipts_dir,
                                      config["participants"], observed))
    blocked = sorted(name for name, case in scenarios.items()
                     if case["contract_status"] == "requires_network_contract")
    return {
        "schema": "hc-vtime/unyt-sprint26-evidence-audit/v1",
        "status": "OFFLINE_RECONCILIATION_ONLY_NETWORK_REVIEW_REQUIRED",
        "scenario_count": len(output),
        "blocked_network_contract_scenarios": blocked,
        "release_ready": False,
        "native_unyt_signature_verified": False,
        "independent_peer_revalidation_proven": False,
        "actual_network_state_transitions_proven": False,
        "warning": "Native files and JSON comparisons do not authenticate Unyt actions, peer reads or recipient Accept signatures. Run a reviewed native client verifier and obtain independent reviewer sign-off.",
    }


def inventory(stage_path: Path, config_path: Path, review_path: Path,
              receipts_dir: Path) -> dict:
    """PR #62's partial artifact inventory integrated with PR #63's event schema.

    Missing files are reported as missing, never accepted; malformed/tampered
    evidence is an error. A full inventory is NOT a signed network validation.
    One native export basename cannot satisfy two independently required slots.
    """
    stage, config, scenarios = checked_session(stage_path, config_path, review_path)
    require(receipts_dir.is_dir() and not receipts_dir.is_symlink(),
            "operator must supply a nonsymlink native evidence directory")
    extra = {p.name for p in receipts_dir.iterdir() if p.name.endswith(".event.json")}
    expected = {name + ".event.json" for name in scenarios}
    require(extra <= expected, f"unreviewed event manifests: {sorted(extra - expected)}")
    files: set[str] = set()
    cases = []
    for name, case in scenarios.items():
        row_path = receipts_dir / (name + ".event.json")
        expected_slots = set(case["required_native_files"])
        required_accepts = {str(p["role"]) for p in case["expected_payouts"]}
        missing = []
        if not row_path.exists():
            missing = ["event_manifest"] + sorted(expected_slots) + [
                f"accept:{role}" for role in sorted(required_accepts)
            ]
        else:
            event = read_json(row_path)
            strict_keys(event, {
                "schema", "scenario_id", "alliance_id", "agreement",
                "agreement_action_hash", "outcome", "rave_action_hash",
                "previous_rave_action_hash", "instance_id", "input_units",
                "locked_units", "payouts", "consumed_sources", "native_files",
                "peer_agent",
            }, f"{name}:event index")
            require(event["schema"] == EVENT_SCHEMA
                    and event["scenario_id"] == name
                    and event["alliance_id"] == stage["alliance_id"]
                    and event["agreement"] == case["agreement"]
                    and event["outcome"] == case["expected_result"],
                    f"{name}: event index identity/outcome mismatch")
            native = event["native_files"]
            require(isinstance(native, dict) and set(native) <= expected_slots,
                    f"{name}: invalid native export slot")
            for slot in sorted(expected_slots):
                if slot not in native:
                    missing.append(slot)
                    continue
                item = native[slot]
                strict_keys(item, {"file", "sha256"}, f"{name}:{slot}")
                checked_file(receipts_dir, item["file"], item["sha256"], files)

            payouts = event["payouts"]
            require(isinstance(payouts, list), f"{name}: payouts must be an array")
            expected_roles = {
                (p["role"], p["amount"]) for p in case["expected_payouts"]
            }
            observed_roles = set()
            for payout in payouts:
                strict_keys(payout, {
                    "role", "amount_units", "unit_index", "accept_action_hash",
                    "native_accept_file", "native_accept_sha256",
                }, f"{name}:recipient Accept")
                role_amount = (payout["role"], payout["amount_units"])
                require(role_amount in expected_roles and role_amount not in observed_roles
                        and payout["unit_index"] == stage["unit_index"],
                        f"{name}: unexpected or repeated payout")
                observed_roles.add(role_amount)
                require(ACTION.fullmatch(payout["accept_action_hash"] or "") is not None,
                        f"{name}: missing native recipient Accept action identity")
                checked_file(receipts_dir, payout["native_accept_file"],
                             payout["native_accept_sha256"], files)
            missing.extend(
                f"accept:{role}" for role, amount in sorted(expected_roles - observed_roles)
            )
            if case["expected_result"] == "rejected":
                require(event["rave_action_hash"] is None
                        and event["previous_rave_action_hash"] is None
                        and event["consumed_sources"] == []
                        and event["input_units"] is None
                        and event["locked_units"] is None,
                        f"{name}: rejected claim implies a spent source or accepted RAVE")
                if "before" in native and "after" in native:
                    before = evidence_file(receipts_dir, native["before"]["file"],
                                           native["before"]["sha256"])
                    after = evidence_file(receipts_dir, native["after"]["file"],
                                          native["after"]["sha256"])
                    require(before == after, f"{name}: changed financial state on rejection")
            else:
                require(ACTION.fullmatch(event["rave_action_hash"] or "") is not None,
                        f"{name}: missing RAVE action identity")
        status = ("BLOCKED_PROTOCOL" if case["contract_status"] == "requires_network_contract"
                  else "MISSING_NATIVE_ARTIFACTS" if missing
                  else "READY_FOR_INDEPENDENT_NATIVE_REVIEW")
        cases.append({
            "scenario_id": name,
            "status": status,
            "missing_artifacts": sorted(missing),
        })
    return {
        "schema": "hc-vtime/unyt-sprint26-native-inventory/v1",
        "git_sha": stage["git_sha"],
        "alliance_id": stage["alliance_id"],
        "scenario_sha256": stage["scenario_sha256"],
        "financial_release_gate": "NO_GO",
        "status": "OPAQUE_NATIVE_ARTIFACT_INVENTORY_ONLY",
        "native_signatures_authenticated": False,
        "peer_state_authenticated": False,
        "recipient_accept_signatures_authenticated": False,
        "actual_network_settlement_proven": False,
        "cases": cases,
        "warning": "Native file digests and labels are untrusted offline assertions; external native Unyt/Holochain validation and issue #61 review remain mandatory.",
    }


def stage_signed_input(config_path: Path, proof_path: Path,
                       scenario_id: str, output: Path) -> dict:
    """Build an operator-reviewable native Unyt parked-data payload.

    This NEVER parks data or invokes an actual Unyt network. A local reviewed
    client must bind and author the parked link, then independently verify its
    action; do not treat this output as acceptance, funding or settlement.
    """
    config = testnet.check_config(read_json(config_path))
    scenarios = scenario_matrix()
    require(scenario_id in scenarios, "unknown intended agreement scenario")
    case = scenarios[scenario_id]
    require(case["expected_result"] == "accepted",
            "do not turn a negative/adversarial scenario into authorized spending")
    require(case["contract_status"] == "available",
            "unsupported target/replay/expiry/challenge condition must not be submitted")
    require(not output.exists() and output.parent.is_dir(),
            "output must be a new file in an operator-controlled external directory")
    require(ROOT != output.resolve() and ROOT not in output.resolve().parents,
            "never write operational proof data into the Git checkout")
    original_bytes = proof_path.read_bytes()
    require(0 < len(original_bytes) <= 128 * 1024, "signed proof input exceeds size limit")
    try:
        claim = json.loads(original_bytes)
    except (UnicodeDecodeError, ValueError) as error:
        raise Blocked(f"malformed signed evidence JSON: {error}") from error
    principals = config["participants"]
    dna = config["network"]["vtime_dna_hash"]
    if case["agreement"] == "verified_time_release":
        result = proof_gate.verify_time_proof(
            claim, dna, [principals["bonded_oracle"],
                         principals["witness_oracle_2"], principals["witness_oracle_3"]]
        )
        index = {"release_first": 0, "release_second": 1, "release_final": 2}.get(scenario_id)
        if index is not None:
            require(int(result["lower_bound_us"]) >= int(
                config["timing"]["tranche_unlock_times_us"][index]
            ), "signed evidence is too early for intended tranche")
        input_rule = "time_proof"
    else:
        result = proof_gate.verify_bond_claim(
            claim, dna, principals["bonded_oracle"],
            [principals["witness_oracle_2"],
             principals["witness_oracle_3"],
             principals["witness_oracle_4"]],
        )
        if scenario_id == "bond_refund_authorized":
            limit = int(config["timing"]["bond_until_us"]) + int(
                config["timing"]["challenge_period_us"]
            )
            require(int(result["lower_bound_us"]) >= limit,
                    "refund cannot execute before challenge window ends")
        input_rule = "claim"
    payload = {
        "schema": "hc-vtime/unyt-sprint26-parked-input/v1",
        "scenario_id": scenario_id,
        "alliance_id": config["network"]["alliance_id"],
        "dna": dna,
        "agreement": case["agreement"],
        "input_rule": input_rule,
        "data": claim,
        "source_sha256": sha256(original_bytes),
        "v2_oracle_signatures_preflighted": True,
        "network_target_authenticated": False,
        "network_submission_performed": False,
        "funding_authorized": False,
    }
    with output.open("x", encoding="utf-8") as file:
        file.write(canonical(payload).decode("utf-8"))
    return {
        "status": "SIGNED_INPUT_PREPARED_NOT_SUBMITTED",
        "file": str(output),
        "sha256": sha256(output.read_bytes()),
        "network_target_authenticated": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prep = commands.add_parser("prepare", help="source-pin planned Unyt agreements; NO network calls")
    prep.add_argument("--config", type=Path, required=True)
    prep.add_argument("--interface-review", type=Path, required=True)
    prep.add_argument("--output-dir", type=Path, required=True)
    prep.add_argument("--expected-sha", required=True)
    verify = commands.add_parser("audit", help="reconcile opaque native exports, NOT network attestation")
    verify.add_argument("--session", type=Path, required=True)
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--evidence-dir", type=Path, required=True)
    park = commands.add_parser("stage-proof", help="prepare v2 signed Rhai parked data; NO Unyt calls")
    park.add_argument("--config", type=Path, required=True)
    park.add_argument("--proof", type=Path, required=True)
    park.add_argument("--scenario", required=True)
    park.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "prepare":
            report = build_stage(args.config, args.interface_review,
                                 args.output_dir.resolve(), args.expected_sha)
            print(json.dumps(report, sort_keys=True, indent=2))
        elif args.operation == "stage-proof":
            report = stage_signed_input(args.config, args.proof, args.scenario,
                                        args.output.resolve())
            print(json.dumps(report, sort_keys=True, indent=2))
        else:
            result = audit(args.session, args.config, args.evidence_dir)
            print(json.dumps(result, sort_keys=True, indent=2))
    except (Blocked, testnet.GateError, proof_gate.ProofRejected, OSError, ValueError, KeyError,
            TypeError, subprocess.CalledProcessError) as error:
        print(f"SPRINT26 BLOCKED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
