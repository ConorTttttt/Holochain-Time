#!/usr/bin/env python3
"""Sprint 14A: prepare Unyt test-alliance agreements and audit RAVE receipts.

Standard library only. Never loads wallets, private keys or authentication
tokens. Deployment submission requires an operator-supplied, hash-pinned LOCAL
adapter. There is no claimed generic Unyt HTTP/testnet API.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "integration/unyt/scenarios.json"
CONFIG_SCHEMA = "hc-vtime/unyt-testnet-config/v1"
MANIFEST_SCHEMA = "hc-vtime/unyt-deployment-manifest/v1"
RECEIPT_SCHEMA = "hc-vtime/unyt-testnet-receipts/v1"
DEPLOY_SCHEMA = "hc-vtime/unyt-deployment-result/v1"
TEMPLATES = ("verified_time_release", "time_oracle_bond")
CANONICAL_RULES = {
    name: f"unyt/{name}/agreements/example_agreement_rules_1.json"
    for name in TEMPLATES
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")


class GateError(ValueError):
    """Any failure keeps the acceptance gate closed."""


def need(condition: bool, why: str) -> None:
    if not condition:
        raise GateError(why)


def obj(value, why: str) -> dict:
    need(isinstance(value, dict), why)
    return value


def as_list(value, why: str) -> list:
    need(isinstance(value, list), why)
    return value


def read_json(path: Path) -> dict:
    try:
        return obj(json.loads(path.read_text(encoding="utf-8")), f"{path}: expected object")
    except (ValueError, OSError) as exc:
        raise GateError(f"could not parse {path}: {exc}") from exc


def stable_json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def amount(value, what: str, *, allow_zero=True) -> int:
    need(isinstance(value, str) and DECIMAL.fullmatch(value) is not None, f"{what}: non-canonical integer amount")
    number = int(value)
    need(number <= 1_000_000 and (number > 0 or allow_zero), f"{what}: outside testnet unit budget")
    return number


def agent_key(value, what: str) -> str:
    # Structural check only. The running Holochain/Unyt client must validate
    # encoded hashes and checksum; this tool cannot confer key authenticity.
    need(
        isinstance(value, str) and value.startswith("uhCAk")
        and len(value) >= 50 and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None
        and "placeholder" not in value.lower() and "replace" not in value.lower(),
        f"{what}: replace with a real Unyt/Holochain public agent key",
    )
    return value


def check_config(config: dict) -> dict:
    need(config.get("schema") == CONFIG_SCHEMA, "unknown testnet config schema")
    network = obj(config.get("network"), "missing network")
    need(network.get("kind") == "isolated-test-alliance", "refusing a non-isolated test alliance")
    alliance = network.get("alliance_id")
    need(
        isinstance(alliance, str) and len(alliance) >= 12
        and not any(s in alliance.lower() for s in ("replace", "placeholder", "mainnet", "production")),
        "alliance_id must identify a real, isolated test alliance",
    )
    dna = network.get("vtime_dna_hash")
    need(
        isinstance(dna, str) and dna.startswith("uhC0k")
        and len(dna) >= 50 and "placeholder" not in dna.lower()
        and "replace" not in dna.lower(),
        "vtime_dna_hash must be a concrete test DNA hash",
    )
    need(network.get("unit_index") == "0", "fixture matrix uses unyt index 0 only")
    people = obj(config.get("participants"), "missing participants")
    fields = (
        "beneficiary", "grantor", "bonded_oracle", "witness_oracle_2",
        "witness_oracle_3", "witness_oracle_4", "reporter", "treasury",
    )
    need(set(people) == set(fields), "participants must define only the expected eight roles")
    for field in fields:
        agent_key(people[field], field)
    need(
        len({people[k] for k in ("bonded_oracle", "witness_oracle_2", "witness_oracle_3", "witness_oracle_4")}) == 4,
        "bonded oracle and witness oracle identities must be distinct",
    )
    need(people["beneficiary"] != people["grantor"], "separate grantor and beneficiary test agents")
    need(people["reporter"] != people["bonded_oracle"], "reporter must be independent of bonded oracle")
    need(people["treasury"] != people["reporter"], "treasury and reporter must be distinct")

    limits = obj(config.get("limits"), "missing monetary limits")
    release = amount(limits.get("release_deposit_units"), "release deposit", allow_zero=False)
    bond = amount(limits.get("bond_deposit_units"), "bond deposit", allow_zero=False)
    reward = amount(limits.get("reporter_reward_units"), "reporter reward")
    cap = amount(limits.get("maximum_aggregate_funded_units"), "funding cap", allow_zero=False)
    need((release, bond, reward) == (300, 500, 50), "Sprint 14A fixtures require exact 300/500/50 test units")
    # A cap is a planned limit, NOT permission to fund anything.
    need(cap >= release + bond and cap <= 1_000, "funding cap must cover 300+500 and be <=1000")
    timing = obj(config.get("timing"), "missing bond/schedule timings")
    until = timing.get("bond_until_us")
    challenge = timing.get("challenge_period_us")
    unlocks = as_list(timing.get("tranche_unlock_times_us"), "missing three unlock times")
    for name, value in [("bond_until_us", until), ("challenge_period_us", challenge)]:
        need(isinstance(value, str) and DECIMAL.fullmatch(value) is not None and int(value) < 2**53,
             f"{name} must be a canonical <2^53 microsecond timestamp/duration")
    need(int(challenge) > 0, "challenge period must be positive")
    need(len(unlocks) == 3, "three tranches required")
    for v in unlocks:
        need(isinstance(v, str) and DECIMAL.fullmatch(v) is not None and 0 < int(v) < 2**53,
             "each unlock time must be a canonical, positive <2^53 decimal microsecond timestamp")
    need(unlocks == sorted(unlocks, key=int) and len(set(unlocks)) == 3,
         "unlock times must be strictly increasing")

    binds = obj(config.get("template_bindings"), "missing template bindings")
    need(binds == CANONICAL_RULES, "template_bindings must point to the two reviewed in-repo examples")
    obj(config.get("local_adapter"), "missing optional local_adapter object")
    return config


def replace_strings(value, substitutions: dict):
    if isinstance(value, str):
        return substitutions.get(value, value)
    if isinstance(value, list):
        return [replace_strings(x, substitutions) for x in value]
    if isinstance(value, dict):
        return {k: replace_strings(v, substitutions) for k, v in value.items()}
    return value


def substitutions(config: dict) -> dict:
    p = config["participants"]
    return {
        "uhCAk_placeholder_oracle_1": p["bonded_oracle"],
        "uhCAk_placeholder_oracle_2": p["witness_oracle_2"],
        "uhCAk_placeholder_oracle_3": p["witness_oracle_3"],
        "uhCAk_placeholder_oracle_4": p["witness_oracle_4"],
        "uhCAk_placeholder_grantor_agent_key": p["grantor"],
        "uhCAk_placeholder_beneficiary_agent_key": p["beneficiary"],
        "uhCAk_placeholder_community_treasury": p["treasury"],
        "uhC0k_placeholder_vtime_dna_hash": config["network"]["vtime_dna_hash"],
        "1799776000000000": config["timing"]["bond_until_us"],
        "604800000000": config["timing"]["challenge_period_us"],
        "50": config["limits"]["reporter_reward_units"],
    }


def check_rules(name: str, rules: dict, config: dict) -> None:
    text = json.dumps(rules)
    need("placeholder" not in text.lower() and "REPLACE_" not in text, f"{name} has unresolved placeholders")
    ins = {r["name"]: r["instruction"] for r in rules["input_rules"]}
    p = config["participants"]
    need(ins["min_oracles"]["Fixed"] == 2 and ins["max_faulty"]["Fixed"] == 1, "oracle fault policy changed")
    need(ins["oracle_dnas"]["Fixed"] == [config["network"]["vtime_dna_hash"]], "foreign oracle DNA")
    if name == "verified_time_release":
        need(ins["oracle_keys"]["Fixed"] == [p["bonded_oracle"], p["witness_oracle_2"], p["witness_oracle_3"]],
             "release oracle set changed")
        need(rules["executor_rules"]["AuthorizedExecutor"] == p["beneficiary"], "unauthorized release executor")
        expected = {"grantor_spender": p["grantor"], "grantor": p["grantor"], "time_prover": p["beneficiary"]}
    else:
        need(ins["bonded_oracle"]["Fixed"] == p["bonded_oracle"], "bond signer mismatch")
        need(ins["witness_oracles"]["Fixed"] == [p["witness_oracle_2"], p["witness_oracle_3"], p["witness_oracle_4"]],
             "bond witness list changed")
        need(ins["slash_beneficiary"]["Fixed"] == p["treasury"], "slash beneficiary changed")
        need(ins["reporter_reward"]["Fixed"] == "50", "unexpected reward")
        need(ins["bond_until"]["Fixed"] == config["timing"]["bond_until_us"], "bond until mismatch")
        need(ins["challenge_period_us"]["Fixed"] == config["timing"]["challenge_period_us"], "challenge duration mismatch")
        need(rules["executor_rules"] == {"Any": None}, "bond executor rules changed")
        expected = {"bond_oracle_spender": p["bonded_oracle"]}
    role_ids = [role["ct_role_id"] for role in rules["roles"]]
    need(len(role_ids) == len(set(role_ids)) and set(role_ids) == set(expected),
         f"{name}: missing or repeated role")
    for role in rules["roles"]:
        k = role["ct_role_id"]
        need(role["qualification"]["Authorized"] == [expected[k]],
             f"{name}: unexpected {k} spending/parking authority")


def build_plan(config: dict, output: Path) -> dict:
    check_config(config)
    need(not output.exists(), "output directory must be new (never overwrite recorded artifacts)")
    output.mkdir(parents=True)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "network": config["network"],
        "participants": config["participants"],
        "limits": config["limits"],
        "timing": config["timing"],
        "templates": {},
        "scenario_file_sha256": sha_file(SCENARIOS),
        "funding_authorized": False,
    }
    subs = substitutions(config)
    for name in TEMPLATES:
        prefix = ROOT / "unyt" / name
        origin = ROOT / CANONICAL_RULES[name]
        rules = replace_strings(read_json(origin), subs)
        check_rules(name, rules, config)
        resolved = stable_json(rules)
        target = output / f"{name}.agreement_rules.json"
        target.write_bytes(resolved)
        manifest["templates"][name] = {
            "rhai_sha256": sha_file(prefix / "execution_code.rhai"),
            "runtime_input_sha256": sha_file(prefix / "runtime_input_signature.json"),
            "output_signature_sha256": sha_file(prefix / "output_signature.json"),
            "definition_input_sha256": sha_file(prefix / "agreement_definition_input.json"),
            "rules_sha256": sha_bytes(resolved),
            "rules_filename": target.name,
        }

    schedule = {
        "unyt_index": "0",
        "receiver": config["participants"]["beneficiary"],
        "tranches": [
            {"unlock_time": t, "amount": "100"}
            for t in config["timing"]["tranche_unlock_times_us"]
        ],
    }
    (output / "parked_schedule.example.json").write_bytes(stable_json(schedule))
    manifest["parked_schedule_sha256"] = sha_file(output / "parked_schedule.example.json")
    manifest["manifest_sha256"] = sha_bytes(stable_json(manifest))
    (output / "deployment_manifest.json").write_bytes(stable_json(manifest))
    return manifest


def verify_manifest(manifest_path: Path) -> dict:
    manifest = read_json(manifest_path)
    need(manifest.get("schema") == MANIFEST_SCHEMA, "unknown deployment manifest schema")
    fingerprint = manifest.pop("manifest_sha256", None)
    need(isinstance(fingerprint, str) and HEX64.fullmatch(fingerprint) is not None
         and sha_bytes(stable_json(manifest)) == fingerprint, "deployment manifest fingerprint invalid")
    manifest["manifest_sha256"] = fingerprint
    need(manifest.get("funding_authorized") is False, "manifest must never authorize funding")
    need(manifest.get("scenario_file_sha256") == sha_file(SCENARIOS), "scenario file changed")
    templates = obj(manifest.get("templates"), "missing template fingerprints")
    need(set(templates) == set(TEMPLATES), "unexpected template set")
    for name, data in templates.items():
        prefix = ROOT / "unyt" / name
        for filename, key in (
            ("execution_code.rhai", "rhai_sha256"),
            ("runtime_input_signature.json", "runtime_input_sha256"),
            ("output_signature.json", "output_signature_sha256"),
            ("agreement_definition_input.json", "definition_input_sha256"),
        ):
            need(sha_file(prefix / filename) == data[key], f"{name} {filename} fingerprint changed")
        need(data["rules_filename"] == f"{name}.agreement_rules.json", "unexpected rules filename")
        need(sha_file(manifest_path.parent / data["rules_filename"]) == data["rules_sha256"],
             f"{name} agreement rules mutated after planning")
    need(sha_file(manifest_path.parent / "parked_schedule.example.json") == manifest["parked_schedule_sha256"],
         "parked schedule mutated after planning")
    return manifest


def submit(config: dict, manifest_path: Path, output: Path, confirm_network: str) -> None:
    check_config(config)
    manifest = verify_manifest(manifest_path)
    need(
        manifest["network"] == config["network"]
        and manifest["participants"] == config["participants"]
        and manifest["timing"] == config["timing"]
        and manifest["limits"] == config["limits"],
        "test-alliance config, role, value or timing changed after plan",
    )
    need(confirm_network == config["network"]["alliance_id"], "explicit network confirmation mismatch")
    need(not output.exists(), "deployment output must not already exist")
    adapter = config["local_adapter"]
    executable = Path(adapter.get("path", ""))
    fingerprint = adapter.get("sha256")
    need(executable.is_absolute() and executable.is_file() and os.access(executable, os.X_OK),
         "approved local adapter must be an absolute executable file")
    need(isinstance(fingerprint, str) and HEX64.fullmatch(fingerprint) is not None
         and sha_file(executable) == fingerprint, "local adapter SHA-256 mismatch")
    # No shell, stdin, wallet files, HTTP calls, secret arguments, or inherited
    # token environment. Adapter communicates with an ALREADY authorized local
    # Unyt application; this step only submits template and agreement setup.
    safe_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", ""), "LANG": "C"}
    run = subprocess.run(
        [str(executable), "deploy", "--manifest", str(manifest_path.resolve()),
         "--output", str(output.resolve())],
        env=safe_env, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=120,
    )
    need(run.returncode == 0, f"adapter failed (exit {run.returncode}); no deployment attested")
    result = read_json(output)
    need(result.get("schema") == DEPLOY_SCHEMA, "adapter result schema mismatch")
    need(result.get("network_id") == manifest["network"]["alliance_id"], "adapter reported wrong network")
    for field in ("template_action_hashes", "agreement_action_hashes"):
        ids = obj(result.get(field), f"adapter output missing {field}")
        need(set(ids) == set(TEMPLATES), f"adapter returned incomplete {field}")
        for value in ids.values():
            need(isinstance(value, str) and value.startswith("uhC") and len(value) > 45,
                 f"adapter reported invalid {field} identifier")
    # No independent network read has happened. Do not claim confirmation.


def evidence_file(evidence_dir: Path, item: dict, prefix: str) -> bytes:
    rel = item.get(f"{prefix}_file")
    digest = item.get(f"{prefix}_sha256")
    need(isinstance(rel, str) and rel != "" and Path(rel).name == rel
         and not rel.startswith("."), f"{prefix}: use one basename inside evidence directory")
    need(isinstance(digest, str) and HEX64.fullmatch(digest) is not None, f"{prefix}: missing SHA-256")
    file = evidence_dir / rel
    need(not file.is_symlink() and file.resolve().parent == evidence_dir.resolve(),
         f"{prefix}: evidence must be a regular file inside the supplied evidence directory")
    need(file.is_file(), f"{prefix}: evidence file missing")
    data = file.read_bytes()
    need(0 < len(data) <= 4 * 1024 * 1024, f"{prefix}: invalid evidence size")
    need(sha_bytes(data) == digest, f"{prefix}: file hash mismatch")
    return data


def verify_receipts(manifest_path: Path, receipt_path: Path, evidence_dir: Path) -> list[str]:
    manifest = verify_manifest(manifest_path)
    report = read_json(receipt_path)
    need(report.get("schema") == RECEIPT_SCHEMA, "wrong receipt schema")
    need(report.get("network_id") == manifest["network"]["alliance_id"], "wrong alliance in receipt report")
    need(report.get("manifest_sha256") == manifest["manifest_sha256"], "receipt refers to different manifest")
    scenario_file = read_json(SCENARIOS)
    need(scenario_file["schema"] == "hc-vtime/unyt-financial-scenarios/v1", "scenario schema mismatch")
    scenarios = {v["id"]: v for v in scenario_file["cases"]}
    records = as_list(report.get("records"), "receipt records must be an array")
    seen = {}
    rave_ids = set()
    settled_bonds = set()
    payout_roles = {
        "beneficiary": "beneficiary", "reporter": "reporter",
        "treasury": "treasury", "bonded_oracle": "bonded_oracle",
    }
    for record in records:
        obj(record, "receipt record must be an object")
        name = record.get("scenario_id")
        need(name in scenarios and name not in seen, f"unknown or repeated scenario {name}")
        scenario = scenarios[name]
        seen[name] = record
        need(record.get("agreement") == scenario["agreement"], f"{name}: agreement mismatch")
        need(record.get("unit_index") == manifest["network"]["unit_index"], f"{name}: wrong currency unit")
        # This is a SHA-256 comparison of an operator-exported artifact, NOT
        # proof of signature validity or Holochain DHT acceptance.
        client_bytes = evidence_file(evidence_dir, record, "client_export")
        peer_bytes = evidence_file(evidence_dir, record, "peer_check")
        # The *normalized* export must identify the same event as the record.
        # A real Unyt client or peer must supply these files; none of this
        # authenticates an untrusted exporter or verifies Holochain signatures.
        try:
            client = obj(json.loads(client_bytes), f"{name}: invalid client export")
            peer = obj(json.loads(peer_bytes), f"{name}: invalid peer export")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GateError(f"{name}: malformed exported evidence: {exc}") from exc
        need(client.get("schema") == "hc-vtime/unyt-client-export/v1"
             and peer.get("schema") == "hc-vtime/unyt-peer-check/v1",
             f"{name}: wrong normalized evidence schema")
        need(client.get("network_id") == report["network_id"]
             and peer.get("network_id") == report["network_id"],
             f"{name}: exported evidence from another alliance")
        need(client.get("scenario_id") == name and peer.get("scenario_id") == name,
             f"{name}: exported evidence does not match scenario")
        need(client.get("rave_action_hash") == record.get("rave_action_hash")
             and peer.get("rave_action_hash") == record.get("rave_action_hash"),
             f"{name}: RAVE identity mismatch between independent exports")
        for field in ("agreement", "agreement_instance_id", "unit_index",
                      "previous_rave_action_hash", "input_units", "locked_units",
                      "payouts", "outcome"):
            need(client.get(field) == record.get(field),
                 f"{name}: client export disagrees about {field}")
        need(peer.get("client_export_sha256") == record["client_export_sha256"],
             f"{name}: peer check does not refer to client export")
        need(record.get("peer_verdict") == ("accepted" if scenario["expect"] == "accepted" else "rejected")
             and client.get("status") == record.get("status")
             and peer.get("verdict") == record.get("peer_verdict"),
             f"{name}: client/peer verdict mismatch")
        reviewer = agent_key(peer.get("peer_agent"), f"{name}: peer observer")
        need(reviewer not in set(manifest["participants"].values()),
             f"{name}: peer must be a separate observing agent")
        if scenario["expect"] == "rejected":
            need(record.get("status") == "rejected", f"{name}: invalid proof was not rejected")
            need(record.get("rave_action_hash") is None and record.get("payouts") == [],
                 f"{name}: rejected execution must have no settled RAVE/payout")
            before = evidence_file(evidence_dir, record, "pre_state")
            after = evidence_file(evidence_dir, record, "post_state")
            need(before == after,
                 f"{name}: rejection must have identical before/after canonical balance state")
            continue
        need(record.get("status") == "accepted", f"{name}: expected successful RAVE")
        rave = record.get("rave_action_hash")
        need(isinstance(rave, str) and rave.startswith("uhC") and len(rave) > 45,
             f"{name}: missing/invalid action hash")
        need(rave not in rave_ids, f"{name}: RAVE action hash reused")
        rave_ids.add(rave)
        expected_prev = scenario.get("previous")
        actual_prev = record.get("previous_rave_action_hash")
        if expected_prev is None:
            need(actual_prev is None, f"{name}: unexpected previous RAVE")
        else:
            need(expected_prev in seen, f"{name}: predecessor must be present in preceding records")
            need(actual_prev == seen[expected_prev].get("rave_action_hash"),
                 f"{name}: previous execution source mismatch")
            need(record.get("agreement_instance_id") == seen[expected_prev].get("agreement_instance_id"),
                 f"{name}: changing agreement instance within one release chain")
        instance = record.get("agreement_instance_id")
        need(isinstance(instance, str) and len(instance) >= 12, f"{name}: missing agreement instance ID")
        if scenario["agreement"] == "time_oracle_bond":
            need(instance not in settled_bonds, f"{name}: bond was already resolved")
            settled_bonds.add(instance)
        units = amount(record.get("input_units"), f"{name}: input", allow_zero=False)
        locked = amount(record.get("locked_units"), f"{name}: locked")
        need(units == amount(scenario["input"], f"{name}: expected input")
             and locked == amount(scenario["locked"], f"{name}: expected locked"),
             f"{name}: input or locked units differ from scenario")
        payouts = as_list(record.get("payouts"), f"{name}: payouts")
        expected = {
            (manifest["participants"][payout_roles[p["role"]]], p["amount"])
            for p in scenario["payouts"]
        }
        actual = set()
        paid = 0
        for payout in payouts:
            obj(payout, f"{name}: malformed payout")
            recipient = agent_key(payout.get("recipient"), f"{name}: recipient")
            num = amount(payout.get("amount_units"), f"{name}: payout", allow_zero=False)
            need(payout.get("unit_index") == "0", f"{name}: incorrect payout currency")
            actual.add((recipient, str(num)))
            paid += num
        need(len(actual) == len(payouts) and actual == expected, f"{name}: payout receivers/values do not match")
        need(paid + locked == units, f"{name}: value conservation failed")
        need(record.get("outcome") == scenario["expected_outcome"], f"{name}: wrong state-transition outcome")

    need(set(seen) == set(scenarios), f"missing scenarios: {sorted(set(scenarios) - set(seen))}")
    return list(seen)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="command", required=True)
    valid = cmds.add_parser("validate", help="validate config without network interaction")
    valid.add_argument("--config", type=Path, required=True)
    plan = cmds.add_parser("plan", help="render verified, source-pinned agreement manifests")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--output-dir", type=Path, required=True)
    deploy = cmds.add_parser("submit", help="invoke operator-approved local deployment adapter")
    deploy.add_argument("--config", type=Path, required=True)
    deploy.add_argument("--manifest", type=Path, required=True)
    deploy.add_argument("--output", type=Path, required=True)
    deploy.add_argument("--confirm-test-alliance", required=True)
    deploy.add_argument("--ack-no-funding", action="store_true")
    verify = cmds.add_parser("verify", help="validate exported scenario receipts and conservation")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--receipts", type=Path, required=True)
    verify.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            check_config(read_json(args.config))
            print("CONFIG VALID (public identity checks only; no network authentication)")
        elif args.command == "plan":
            manifest = build_plan(read_json(args.config), args.output_dir.resolve())
            print(f"PLAN WRITTEN: {args.output_dir} sha256={manifest['manifest_sha256']}")
        elif args.command == "submit":
            need(args.ack_no_funding, "submit requires --ack-no-funding")
            submit(read_json(args.config), args.manifest, args.output, args.confirm_test_alliance)
            print("ADAPTER REPORTED DEPLOYMENT; independently validate on the Unyt alliance")
        else:
            completed = verify_receipts(args.manifest, args.receipts, args.evidence_dir)
            print(f"RECEIPT CONSISTENCY PASS: {len(completed)} scenarios; network and signature verification still required")
    except (GateError, OSError, KeyError, IndexError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL CLOSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
