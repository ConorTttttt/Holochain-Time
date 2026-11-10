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
SCENARIO_SCHEMA = "hc-vtime/unyt-sprint26-scenarios/v1"
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


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
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
            and not filename.startswith(".")
            and "/" not in filename and "\\" not in filename,
            "evidence must be a single, non-hidden basename")
    directory = evidence_dir.resolve(strict=True)
    return verified_sha(directory / filename, digest)


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
    require(isinstance(values, list) and len(values) >= 16, "incomplete scenarios")
    output: dict[str, dict] = {}
    for row in values:
        require(isinstance(row, dict) and row.get("id") not in output,
                "duplicate/malformed scenario")
        require(row.get("agreement") in testnet.TEMPLATES, "unexpected agreement")
        require(row.get("expected_result") in ("accepted", "rejected"), "invalid expected result")
        require(row.get("contract_status") in ("available", "requires_network_contract"),
                "missing protocol capability status")
        output[row["id"]] = row
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
    output.mkdir(parents=True)
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
    require(isinstance(native, dict) and set(native) == {
        "before", "after", "execution", "peer", "proof", "agreement",
    }, f"{name}: complete native evidence files required")
    for kind, descriptor in native.items():
        strict_keys(descriptor, {"file", "sha256"}, f"{name}:{kind}")
        evidence_file(root, descriptor["file"], descriptor["sha256"])
    require(isinstance(bundle["peer_agent"], str)
            and bundle["peer_agent"].startswith("uhCAk")
            and bundle["peer_agent"] not in set(participants.values()),
            f"{name}: independent observing Unyt agent required")

    if scenario["expected_result"] == "accepted":
        try:
            signed_proof = json.loads(
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
        evidence_file(root, item["native_accept_file"], item["native_accept_sha256"])
        require(item["accept_action_hash"] not in observed["accepts"],
                f"{name}: duplicate Accept action")
        observed["accepts"].add(item["accept_action_hash"])
        entry = (item["role"], str(amount))
        require(entry not in actual, f"{name}: duplicate payout")
        actual.add(entry)
        paid += amount
    expected = {
        (row["role"], row["amount"])
        for row in observed["baseline"][name]["payouts"]
    } if name in observed["baseline"] else {}
    if expected:
        require(actual == expected, f"{name}: incorrect payees or amounts")
    else:
        require(paid == decimal(scenario["total_paid_units"], f"{name}: expected paid"),
                f"{name}: incorrect claimed payout total")
    locked = decimal(bundle["locked_units"], f"{name}: locked")
    input_amount = decimal(bundle["input_units"], f"{name}: input")
    require(input_amount == locked + paid, f"{name}: unit conservation failed")
    if scenario["expected_locked_units"]:
        require(locked == decimal(scenario["expected_locked_units"], f"{name}: planned lock"),
                f"{name}: carried locked value changed")
    if name in observed["baseline"]:
        original = observed["baseline"][name]
        require(input_amount == decimal(original["input"], f"{name}: source value"),
                f"{name}: wrong agreement source amount")
        preceding = original.get("previous")
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


def audit(stage_path: Path, config_path: Path, receipts_dir: Path) -> dict:
    stage = read_json(stage_path)
    require(stage.get("schema") == SESSION_SCHEMA, "incorrect session schema")
    require(stage.get("financial_execution_authorized") is False
            and stage.get("native_acceptance_verified") is False,
            "a source-controlled plan cannot authorize funding or attest validation")
    require(stage.get("scenario_sha256") == sha256(SCENARIOS.read_bytes()),
            "scenario definitions changed")
    require(stage.get("git_sha") and GIT_SHA.fullmatch(stage["git_sha"]),
            "missing exact SHA provenance")
    config = testnet.check_config(read_json(config_path))
    require(stage["alliance_id"] == config["network"]["alliance_id"]
            and stage["vtime_dna"] == config["network"]["vtime_dna_hash"],
            "config identity differs from the agreed plan")
    manifest = testnet.verify_manifest(stage_path.parent / "agreements/deployment_manifest.json")
    require(stage["manifest_sha256"] == manifest["manifest_sha256"],
            "template/rules changed after planning")
    scenarios = scenario_matrix()
    require(set(stage["scenario_ids"]) == set(scenarios), "scenario matrix incomplete")
    origin = read_json(testnet.SCENARIOS)
    baseline = {case["id"]: case for case in origin["cases"]}
    observed = {
        "raves": set(), "accepts": set(), "sources": set(),
        "resolved_bonds": set(), "baseline": baseline, "previous": {},
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
    args = parser.parse_args(argv)
    try:
        if args.operation == "prepare":
            report = build_stage(args.config, args.interface_review,
                                 args.output_dir.resolve(), args.expected_sha)
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
