#!/usr/bin/env python3
"""Offline, fail-closed Unyt testnet configuration and deployment preparation.

No network access, keys, wallet secrets, signing or funded transaction submission.
The deployment plan is NOT a proof of on-chain deployment.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DECIMAL = re.compile(r"(0|[1-9][0-9]*)\Z")
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
KEY = re.compile(r"uhCAk[A-Za-z0-9_-]{40,}\Z")
DNA = re.compile(r"uhC0k[A-Za-z0-9_-]{40,}\Z")
SECRET = re.compile(r"(?i)(private.key|secret.key|seed.phrase|mnemonic|wallet.password|access.token|api.token|bearer)")
KINDS = ("verified_time_release", "time_oracle_bond")
INPUTS = {
    "verified_time_release": {
        "oracle_keys", "oracle_dnas", "max_faulty", "min_oracles",
    },
    "time_oracle_bond": {
        "bonded_oracle", "unyt_index", "reporter_reward",
        "slash_beneficiary", "bond_until", "challenge_period_us",
        "witness_oracles", "oracle_dnas", "max_faulty", "min_oracles",
    },
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def natural(value, name, positive=False):
    require(isinstance(value, str) and DECIMAL.fullmatch(value) is not None,
            f"{name} must be a canonical nonnegative decimal string")
    result = int(value)
    require(not positive or result > 0, f"{name} must be positive")
    require(result < 2**53, f"{name} is outside the exact Rhai numeric range")
    return result

def participant(value, name, pattern=KEY):
    require(isinstance(value, str) and pattern.fullmatch(value) is not None,
            f"{name} must be a Holochain text key (not a placeholder)")
    return value

def unique_keys(values, name, pattern=KEY):
    require(isinstance(values, list) and len(values) > 0, f"{name} must be nonempty")
    for item in values:
        participant(item, name, pattern)
    require(len(values) == len(set(values)), f"{name} has duplicate keys")

def validate(config):
    require(isinstance(config, dict), "config must be an object")
    require(set(config) == {
        "schema", "network", "agreement", "roles", "fixed", "test_amount",
        "deployment",
    }, "unknown or missing configuration fields")
    require(config["schema"] == "hc-vtime/unyt-testnet/v1", "wrong config schema")
    network = config["network"]
    require(isinstance(network, dict) and set(network) == {"name", "genesis_hash"},
            "network needs name and genesis_hash")
    require(isinstance(network["name"], str) and network["name"].strip()
            and "mainnet" not in network["name"].lower()
            and "production" not in network["name"].lower(),
            "explicit non-production testnet name required")
    require(isinstance(network["genesis_hash"], str)
            and HEX64.fullmatch(network["genesis_hash"]), "pin 32-byte testnet genesis hash")
    kind = config["agreement"]
    require(kind in KINDS, "unknown agreement template")
    roles = config["roles"]
    require(isinstance(roles, dict), "roles must be object")
    expected = ({"grantor", "beneficiary", "time_prover"}
                if kind == "verified_time_release"
                else {"bonded_oracle", "reporter", "slash_beneficiary"})
    require(set(roles) == expected, "role set does not match agreement")
    for label, value in roles.items():
        participant(value, f"roles.{label}")
    fixed = config["fixed"]
    require(isinstance(fixed, dict) and set(fixed) == INPUTS[kind],
            "fixed parameters do not match the agreement definition")
    unique_keys(fixed["oracle_dnas"], "oracle_dnas", DNA)
    max_faulty = fixed["max_faulty"]
    min_oracles = fixed["min_oracles"]
    require(type(max_faulty) is int and type(min_oracles) is int
            and 0 <= max_faulty <= 32 and max_faulty + 1 <= min_oracles <= 32,
            "invalid fault bound or oracle quorum")
    if kind == "verified_time_release":
        unique_keys(fixed["oracle_keys"], "oracle_keys")
        require(len(fixed["oracle_keys"]) >= min_oracles, "not enough approved oracle keys")
        require(roles["beneficiary"] == roles["time_prover"],
                "example template time_prover must be authorized beneficiary")
    else:
        participant(fixed["bonded_oracle"], "bonded_oracle")
        participant(fixed["slash_beneficiary"], "slash_beneficiary")
        unique_keys(fixed["witness_oracles"], "witness_oracles")
        require(fixed["bonded_oracle"] == roles["bonded_oracle"]
                and fixed["slash_beneficiary"] == roles["slash_beneficiary"],
                "bonded oracle / beneficiary inconsistent with roles")
        require(fixed["bonded_oracle"] not in fixed["witness_oracles"],
                "bonded oracle must not count as its own refund witness")
        require(len(fixed["witness_oracles"]) >= min_oracles,
                "not enough refund witnesses")
        natural(fixed["unyt_index"], "unyt_index")
        natural(fixed["reporter_reward"], "reporter_reward", positive=True)
        natural(fixed["bond_until"], "bond_until", positive=True)
        natural(fixed["challenge_period_us"], "challenge_period_us", positive=True)
        require(natural(fixed["reporter_reward"], "reporter_reward")
                <= natural(config["test_amount"], "test_amount", positive=True),
                "reporter reward exceeds bond")
        require(natural(fixed["bond_until"], "bond_until")
                + natural(fixed["challenge_period_us"], "challenge_period_us")
                < 2**53, "bond challenge deadline overflows exact numeric range")
    natural(config["test_amount"], "test_amount", positive=True)
    deployment = config["deployment"]
    require(isinstance(deployment, dict) and set(deployment) == {"adapter", "approval"},
            "deployment requires adapter and approval")
    require(deployment["adapter"] == "manual-authorized-client",
            "no supported automatic testnet client has been verified")
    require(deployment["approval"] == "required-at-execution",
            "live funding must require separate authorization")
    # Defense in depth: key material must not be embedded in any config.
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                require(not SECRET.search(key), f"secret-like configuration field: {key}")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(config)
    return config

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def prepare(config, output):
    kind = config["agreement"]
    base = ROOT / "unyt" / kind
    paths = {
        key: base / filename for key, filename in {
            "code": "execution_code.rhai",
            "definition": "agreement_definition_input.json",
            "rules_template": "agreements/example_agreement_rules_1.json",
            "input_signature": "runtime_input_signature.json",
            "output_signature": "output_signature.json",
        }.items()
    }
    for path in paths.values():
        require(path.is_file(), f"missing template: {path}")
    # Validate role and Fixed shape against the actual checked-in template,
    # rather than assuming our configuration and its schema cannot drift.
    rules = json.loads(paths["rules_template"].read_text())
    declared = {
        item["name"]: item["instruction"] for item in rules["input_rules"]
    }
    require(set(config["fixed"]).issubset(declared), "unknown Fixed input")
    for key in config["fixed"]:
        require("Fixed" in declared[key], f"{key} is not Fixed in template")
    # Instantiate only the checked-in agreement RULES. No API calls or
    # deployment occur. The executable Rhai is not modified.
    if kind == "verified_time_release":
        role_keys = {
            "grantor_spender": config["roles"]["grantor"],
            "grantor": config["roles"]["grantor"],
            "time_prover": config["roles"]["time_prover"],
        }
        expected_executor = "AuthorizedExecutor"
    else:
        role_keys = {"bond_oracle_spender": config["roles"]["bonded_oracle"]}
        expected_executor = "Any"
    actual_roles = {role["ct_role_id"] for role in rules["roles"]}
    require(actual_roles == set(role_keys), "agreement role template drift")
    for role in rules["roles"]:
        require("Authorized" in role["qualification"],
                "example role is not authorized")
        role["qualification"]["Authorized"] = [role_keys[role["ct_role_id"]]]
    require(expected_executor in rules["executor_rules"], "executor rule changed")
    if expected_executor == "AuthorizedExecutor":
        rules["executor_rules"]["AuthorizedExecutor"] = config["roles"]["beneficiary"]
    for item in rules["input_rules"]:
        if item["name"] in config["fixed"]:
            item["instruction"]["Fixed"] = config["fixed"][item["name"]]
    rendered = json.dumps(rules, indent=2, sort_keys=True) + "\n"
    require("placeholder" not in rendered.lower(),
            "unreplaced placeholder in generated agreement rules")
    rendered_path = output.with_name(output.stem + "-agreement-rules.json")
    rendered_path.write_text(rendered)
    plan = {
        "schema": "hc-vtime/unyt-deployment-plan/v1",
        "status": "OFFLINE_ONLY_NOT_DEPLOYED",
        "network": config["network"],
        "agreement": kind,
        "template_sha256": {key: sha(path) for key, path in paths.items()},
        "rendered_agreement_rules": str(rendered_path),
        "rendered_rules_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
        "roles": config["roles"],
        "fixed": config["fixed"],
        "maximum_test_amount": config["test_amount"],
        "actions": [
            "Confirm genesis hash through an independent testnet node",
            "Review agreement rules, code hashes, roles, and input Fixed values",
            "Manually define agreement through an authorized Unyt testnet client",
            "Obtain operator approval before signing or moving test funds",
            "Record agreement address, deployment tx hash, and independently verified receipt",
        ],
    }
    output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path, help="write an offline deployment plan")
    args = parser.parse_args()
    config = validate(json.loads(args.config.read_text()))
    if args.output:
        prepare(config, args.output)
        print(f"OFFLINE PLAN ONLY: {args.output}")
    else:
        print("VALID OFFLINE TESTNET CONFIG (nothing deployed or funded)")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"REJECTED: {exc}")
