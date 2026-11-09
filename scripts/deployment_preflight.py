#!/usr/bin/env python3
"""Fail-closed, no-network deployment preflight for hc-vtime DNA release config.

Pure Python standard library. Validates an intentionally restricted YAML
subset used by the repository DNA manifests. Unknown YAML constructs fail
instead of being loosely regex-extracted. A PASS is about static configuration,
NOT proof of administrative independence, network readiness or safe funds.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

from check_test_dna_config import ConfigError, agent_key, rt_key

ROOT = Path(__file__).resolve().parent.parent
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
ENVIRONMENTS = ("production", "staging", "development")
PROPERTIES = {
    "roughtime_servers", "oracles", "max_faulty", "min_sources",
    "max_radius_ms", "max_skew_ms", "oracle_radius_ms",
}
NUMERIC = PROPERTIES - {"roughtime_servers", "oracles"}
POLICY_FIELDS = {"schema", "environment", "network_id", "manifest_sha256", "sources"}
SOURCE_FIELDS = {
    "kind", "key", "operator_id", "operator_label",
    "key_provenance", "review_ref", "endpoint", "protocol",
}
APPROVAL_FIELDS = {
    "schema", "environment", "manifest_sha256", "policy_sha256",
    "approval_status", "reviewers", "source_reviews",
}
REVIEW_FIELDS = {
    "operator_id", "key_control_checked", "admin_separation_checked",
    "shared_upstream_checked", "live_protocol_verified", "evidence_sha256",
}
MAX_MANIFEST_BYTES = 128 * 1024
MAX_JSON_BYTES = 128 * 1024


class PreflightError(ValueError):
    pass


def require(test, message):
    if not test:
        raise PreflightError(message)


def file_bytes(path, limit):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"{path}: missing/linked file")
    require(path.stat().st_size <= limit, f"{path}: file exceeds preflight limit")
    return path.read_bytes()


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def reject_dupes(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise PreflightError(f"duplicate JSON key: {k}")
        result[k] = v
    return result


def load_json(blob, name):
    try:
        value = json.loads(blob.decode("utf-8"), object_pairs_hook=reject_dupes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PreflightError(f"{name}: invalid JSON: {exc}") from exc
    require(type(value) is dict, f"{name}: expected object")
    return value


def object_fields(value, name, required, allowed=None):
    require(type(value) is dict, f"{name}: expected object")
    require(set(required) <= set(value), f"{name}: missing {sorted(set(required) - set(value))}")
    if allowed is not None:
        require(set(value) <= set(allowed), f"{name}: unknown fields {sorted(set(value) - set(allowed))}")
    return value


def text_scalar(value, name, *, min_length=1, max_length=512):
    require(type(value) is str and min_length <= len(value) <= max_length,
            f"{name}: invalid or missing string")
    require(not re.search(r"REPLACE|PLACEHOLDER|TODO|FIXME|DO-NOT-DEPLOY", value, re.I),
            f"{name}: placeholder or explicitly test-only value")
    require(not any(ord(ch) < 32 for ch in value), f"{name}: control characters")
    return value


def parse_dna_manifest(blob):
    """Read only the repo's controlled YAML 1.2 scalar/list subset.

    This is deliberately NOT a YAML parser. Duplicate keys, tags, anchors,
    aliases, mappings in critical lists and unsupported syntax are rejected.
    The full DNA manifest is additionally fingerprinted byte-for-byte.
    """
    require(len(blob) <= MAX_MANIFEST_BYTES, "DNA manifest too large")
    try:
        txt = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreflightError("DNA manifest is not UTF-8") from exc
    require("\t" not in txt and "\r" not in txt, "YAML tabs/CR unsupported")
    require(not re.search(r"\$\{|<%|%>|!!|<<:|(?:^|\s)[&*!][A-Za-z0-9_]", txt),
            "YAML anchors, aliases, tags and variable interpolation unsupported")
    lines = txt.splitlines()
    tokens = []
    for no, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "---" and not tokens:
            continue
        require(stripped not in ("---", "..."), "multi-document YAML forbidden")
        indent = len(raw) - len(raw.lstrip(" "))
        require(indent in (0, 2, 4, 6), f"YAML unsupported indentation at line {no}")
        # Comment markers are allowed only outside quoted scalar values.
        line = raw.rstrip()
        # Source keys are ASCII base64; no semantic key contains '#'.
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        tokens.append((indent, line.strip(), no))
    require(tokens, "empty DNA manifest")
    root = {}
    for indent, line, _ in tokens:
        if indent == 0:
            m = re.fullmatch(r"([a-z_]+):(?:\s*(.*))?", line)
            require(m is not None, "unsupported root YAML structure")
            key = m.group(1)
            require(key not in root, f"duplicate DNA root field {key}")
            root[key] = m.group(2) or ""
    require(set(root) == {"manifest_version", "name", "integrity", "coordinator"},
            "DNA root must have manifest_version, name, integrity, coordinator only")
    require(root["manifest_version"] == '"0"' and root["name"] == "vtime",
            "unexpected DNA manifest_version or DNA name")
    require(root["integrity"] == "" and root["coordinator"] == "",
            "DNA integrity and coordinator must be YAML maps")
    in_integrity = False
    in_properties = False
    in_sources = None
    props = {}
    sections = {}
    network_seed = None
    for indent, line, no in tokens:
        if indent == 0:
            in_integrity = line == "integrity:"
            in_properties = False
            in_sources = None
            continue
        if not in_integrity:
            continue
        if indent == 2:
            in_properties = line == "properties:"
            in_sources = None
            m = re.fullmatch(r"([a-z_]+):(?:\s*(.*))?", line)
            require(m is not None, f"invalid integrity field on {no}")
            key = m.group(1)
            require(key in {"network_seed", "properties", "zomes"},
                    f"unknown integrity field {key}")
            require(key not in sections, f"duplicate integrity field {key}")
            sections[key] = True
            if key == "network_seed":
                raw_seed = (m.group(2) or "").strip()
                require(raw_seed == "~" or
                        re.fullmatch(r'"[A-Za-z0-9._:/-]{1,200}"', raw_seed) is not None,
                        "network_seed must be '~' or a simple quoted string")
                network_seed = None if raw_seed == "~" else raw_seed[1:-1]
            elif key == "properties":
                require(not (m.group(2) or "").strip(), "properties must be a YAML map")
            continue
        if indent == 4 and in_properties:
            m = re.fullmatch(r"([a-z_]+):(?:\s*(.*))?", line)
            require(m is not None, f"invalid DNA properties field at {no}")
            key = m.group(1)
            value = (m.group(2) or "").strip()
            require(key in PROPERTIES, f"unknown DNA property {key}")
            require(key not in props, f"duplicate DNA property {key}")
            if key in ("roughtime_servers", "oracles"):
                require(value in ("", "[]"), f"{key}: expected string list or []")
                props[key] = []
                in_sources = key if value == "" else None
            else:
                require(re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value) is not None,
                        f"{key}: expected non-negative canonical integer")
                props[key] = int(value)
                in_sources = None
            continue
        if indent == 6 and in_properties and in_sources:
            m = re.fullmatch(r'- "([A-Za-z0-9_+/\-=]+)"', line)
            require(m is not None, f"unsupported DNA source list value at {no}")
            props[in_sources].append(m.group(1))
            continue
        if in_properties:
            raise PreflightError(f"unsupported DNA properties YAML syntax at line {no}")
    require(set(sections) == {"network_seed", "properties", "zomes"},
            "incomplete integrity block")
    require(set(props) == PROPERTIES,
            f"missing DNA properties: {sorted(PROPERTIES - set(props))}")
    return {"name": root["name"], "network_seed": network_seed, "properties": props}


def decode_sources(props):
    identities = []
    for kind, field in (("roughtime", "roughtime_servers"), ("oracle", "oracles")):
        for entry in props[field]:
            require("REPLACE" not in entry.upper() and "PLACEHOLDER" not in entry.upper(),
                    f"{field}: signing key placeholder")
            try:
                raw = rt_key(entry) if kind == "roughtime" else agent_key(entry)
            except (ConfigError, ValueError, TypeError, AttributeError) as exc:
                raise PreflightError(f"{field}: invalid public key: {exc}") from exc
            identities.append((kind, entry, raw))
    raw = [item[2] for item in identities]
    require(len(raw) == len(set(raw)), "duplicate raw signer identity across all roles")
    return identities


def safe_endpoint(endpoint, environment):
    require(type(endpoint) is str, "Roughtime endpoint must be a hostname:port string")
    m = re.fullmatch(r"([a-zA-Z0-9.-]{3,253}):([0-9]{2,5})", endpoint)
    require(m is not None, "Roughtime endpoint must be simple hostname:port")
    host, port = m.group(1).lower(), int(m.group(2))
    require(1 <= port <= 65535, "invalid Roughtime UDP port")
    if environment != "development":
        require(host not in ("localhost", "local", "example.com") and
                not host.endswith((".localhost", ".local", ".invalid", ".example", ".test")),
                "non-development Roughtime endpoint must not be a local/example service")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            require("." in host and ".." not in host, "Roughtime endpoint needs qualified hostname")
        else:
            require(ip.is_global, "non-development endpoint must not be private/loopback")
    return f"{host}:{port}"


def validate_policy(policy, manifest, manifest_hash, denied_raw, environment,
                    *, allow_dev_test_keys=False):
    object_fields(policy, "policy", POLICY_FIELDS, POLICY_FIELDS)
    require(policy["schema"] == "hc-vtime/deployment-policy/v1", "unsupported policy schema")
    require(policy["environment"] == environment and environment in ENVIRONMENTS,
            "environment mismatch / unsupported environment")
    text_scalar(policy["network_id"], "network_id", min_length=12, max_length=120)
    require(HEX64.fullmatch(str(policy["manifest_sha256"])) is not None and
            policy["manifest_sha256"] == manifest_hash,
            "deployment policy does not pin exact DNA manifest SHA-256")
    seed = manifest["network_seed"]
    if environment != "development":
        text_scalar(seed, "integrity.network_seed", min_length=24, max_length=200)
        require(len(set(seed)) >= 8, "network_seed too predictable or non-unique")
    elif seed is not None:
        text_scalar(seed, "integrity.network_seed", min_length=8)
    props = manifest["properties"]
    f, n = props["max_faulty"], props["min_sources"]
    require(1 <= f <= 5, "max_faulty must be between 1 and 5")
    require(3 <= n <= 32 and n >= 2*f+1,
            "min_sources must be >= 3 and >= 2*max_faulty+1")
    identities = decode_sources(props)
    require(n + f <= len(identities) <= 32,
            "need min_sources + max_faulty distinct trusted signers (and <=32)")
    require(sum(kind == "roughtime" for kind, _, _ in identities) >= 3,
            "at least 3 real Roughtime signing roots are required")
    require(0 < props["max_radius_ms"] <= 60000 and
            0 < props["max_skew_ms"] <= 5000 and
            0 < props["oracle_radius_ms"] <= 10000,
            "unsupported production time radius or skew thresholds")
    raw_bytes = {raw for _, _, raw in identities}
    insecure = sorted(raw_bytes & denied_raw)
    require(environment == "development" and allow_dev_test_keys or not insecure,
            "known insecure Ed25519 test identity in DNA trusted keys")
    require(environment == "development" and allow_dev_test_keys or
            not any(raw == b"\x00"*32 or len(set(raw)) <= 1 for raw in raw_bytes),
            "insecure zero/repeating raw signing key")
    registry = policy["sources"]
    require(type(registry) is list and len(registry) == len(identities),
            "operator registry must have one record per trusted DNA signing root")
    dna_by_key = {raw: kind for kind, _, raw in identities}
    seen_keys = set()
    ids = set()
    labels = set()
    endpoints = set()
    for i, item in enumerate(registry):
        object_fields(item, f"sources[{i}]",
                      {"kind", "key", "operator_id", "operator_label",
                       "key_provenance", "review_ref"}, SOURCE_FIELDS)
        kind = item["kind"]
        require(kind in ("roughtime", "oracle"), f"sources[{i}]: invalid kind")
        try:
            raw = rt_key(item["key"]) if kind == "roughtime" else agent_key(item["key"])
        except (ConfigError, ValueError, AttributeError, TypeError) as exc:
            raise PreflightError(f"sources[{i}]: invalid signing key: {exc}") from exc
        require(raw in dna_by_key and dna_by_key[raw] == kind,
                f"sources[{i}]: source key/kind not pinned in exact DNA")
        require(raw not in seen_keys, f"sources[{i}]: duplicate signer record")
        seen_keys.add(raw)
        operator_id = text_scalar(item["operator_id"], "operator_id", min_length=3, max_length=64)
        require(re.fullmatch(r"[a-z][a-z0-9-]{2,63}", operator_id) is not None,
                f"sources[{i}]: operator_id must be a stable lowercase slug")
        operator_label = text_scalar(item["operator_label"], "operator_label", min_length=3,
                                     max_length=120).strip().casefold()
        require(operator_id not in ids and operator_label not in labels,
                f"sources[{i}]: duplicate operator identity or label")
        ids.add(operator_id)
        labels.add(operator_label)
        provenance = text_scalar(item["key_provenance"], "key_provenance",
                                 min_length=10, max_length=500)
        require(provenance.startswith("https://"), f"sources[{i}]: HTTPS key provenance required")
        text_scalar(item["review_ref"], "review_ref", min_length=10, max_length=500)
        if kind == "roughtime":
            require(item.get("protocol") in ("rfc10049", "draft15"),
                    f"sources[{i}]: unsupported/unknown Roughtime protocol (draft11 is not supported)")
            endpoint = safe_endpoint(item.get("endpoint"), environment)
            require(endpoint not in endpoints, f"sources[{i}]: repeated Roughtime endpoint")
            endpoints.add(endpoint)
        else:
            require("protocol" not in item and "endpoint" not in item,
                    f"sources[{i}]: oracle must not carry Roughtime endpoint/protocol")
    require(seen_keys == set(dna_by_key), "DNA and operator registry key sets differ")
    return {"sources_count": len(identities),
            "roughtime_sources": sum(kind == "roughtime" for kind, _, _ in identities),
            "oracle_sources": sum(kind == "oracle" for kind, _, _ in identities),
            "configured_distinct_operator_ids": len(ids),
            "max_faulty": f, "min_sources": n,
            "known_test_identities_rejected": not (environment == "development" and allow_dev_test_keys),
            "operator_independence_proven": False}


def validate_approval(approval, environment, policy_hash, manifest_hash, policy):
    object_fields(approval, "approval", APPROVAL_FIELDS, APPROVAL_FIELDS)
    require(approval["schema"] == "hc-vtime/deployment-approval/v1" and
            approval["environment"] == environment, "approval schema/environment mismatch")
    require(approval["policy_sha256"] == policy_hash and
            approval["manifest_sha256"] == manifest_hash,
            "approval must bind exact policy and DNA manifest SHA-256")
    require(approval["approval_status"] == "approved", "reviewers have not approved deployment")
    reviewers = approval["reviewers"]
    require(type(reviewers) is list and len(reviewers) >= 2,
            "production release needs two human reviewer records")
    seen = set()
    for item in reviewers:
        object_fields(item, "reviewer", {"name", "review_ref"}, {"name", "review_ref"})
        person = text_scalar(item["name"], "reviewer.name", min_length=4, max_length=120).casefold()
        text_scalar(item["review_ref"], "reviewer.review_ref", min_length=10, max_length=500)
        require(person not in seen, "reviewer identities are not distinct")
        seen.add(person)
    reviews = approval["source_reviews"]
    require(type(reviews) is list and len(reviews) == len(policy["sources"]),
            "one source review required for each pinned operator")
    ids = set()
    for item in reviews:
        object_fields(item, "source review", REVIEW_FIELDS, REVIEW_FIELDS)
        name = item["operator_id"]
        require(name not in ids, "duplicate operator review")
        ids.add(name)
        for field in ("key_control_checked", "admin_separation_checked",
                      "shared_upstream_checked", "live_protocol_verified"):
            require(item[field] is True, f"operator {name}: {field} not approved")
        require(type(item["evidence_sha256"]) is str and
                HEX64.fullmatch(item["evidence_sha256"]) is not None,
                f"operator {name}: missing pinned external evidence digest")
    require(ids == {x["operator_id"] for x in policy["sources"]},
            "approval operator registry differs from reviewed policy")
    return {"review_records": len(reviews), "reviewer_records": len(reviewers),
            "operator_independence_proven": False,
            "human_assertions_reviewed": True}


def preflight(manifest_path, policy_path, approval_path, environment,
              *, expected_manifest_sha256=None, expected_policy_sha256=None,
              allow_development_test_keys=False):
    require(environment in ENVIRONMENTS, "unsupported deployment environment")
    manifest_bytes = file_bytes(manifest_path, MAX_MANIFEST_BYTES)
    policy_bytes = file_bytes(policy_path, MAX_JSON_BYTES)
    mh, ph = sha256(manifest_bytes), sha256(policy_bytes)
    if environment == "production":
        require(type(expected_manifest_sha256) is str and
                HEX64.fullmatch(expected_manifest_sha256) is not None and
                mh == expected_manifest_sha256,
                "production requires externally pinned, matching manifest SHA-256")
        require(type(expected_policy_sha256) is str and
                HEX64.fullmatch(expected_policy_sha256) is not None and
                ph == expected_policy_sha256,
                "production requires externally pinned, matching policy SHA-256")
    elif expected_manifest_sha256 is not None:
        require(mh == expected_manifest_sha256, "manifest checksum mismatch")
    if expected_policy_sha256 is not None:
        require(ph == expected_policy_sha256, "policy checksum mismatch")
    policy = load_json(policy_bytes, "deployment policy")
    manifest = parse_dna_manifest(manifest_bytes)
    deny_blob = file_bytes(ROOT / "deployment/known_insecure_keys.json", MAX_JSON_BYTES)
    deny = load_json(deny_blob, "known unsafe public keys")
    require(deny.get("schema") == "hc-vtime/known-insecure-key-catalog/v1",
            "missing/invalid insecure-keys catalog")
    require(type(deny.get("ed25519_public_keys_b64")) is list and
            len(deny["ed25519_public_keys_b64"]) >= 20,
            "incomplete public test-key deny catalog")
    try:
        denied_raw = {base64.b64decode(k, validate=True)
                      for k in deny["ed25519_public_keys_b64"]}
    except (ValueError, TypeError) as exc:
        raise PreflightError("insecure-key deny catalog malformed") from exc
    require(all(len(key) == 32 for key in denied_raw), "invalid insecure-key catalog")
    data = validate_policy(policy, manifest, mh, denied_raw, environment,
                           allow_dev_test_keys=allow_development_test_keys)
    if approval_path is None:
        require(environment != "production", "production review approval file is required")
        approval = {"approval_status": "NOT PROVIDED", "operator_independence_proven": False}
    else:
        approval_blob = file_bytes(approval_path, MAX_JSON_BYTES)
        approval = validate_approval(load_json(approval_blob, "approval"), environment,
                                     ph, mh, policy)
    return {
        "schema": "hc-vtime/deployment-preflight/v1",
        "status": "PREFLIGHT_PASS",
        "environment": environment, "manifest_sha256": mh,
        "policy_sha256": ph, "approval_status": approval.get("approval_status", "approved"),
        "approval_record_sha256": sha256(file_bytes(approval_path, MAX_JSON_BYTES))
        if approval_path else None,
        "insecure_key_catalog_sha256": sha256(deny_blob),
        "source_checks": data,
        "operator_independence_proven": False,
        "signed_live_source_verification_proven": False,
        "safe_to_install_proven": False,
        "note": "Only static deployment checks and operator-authored assertions passed. Independent operational/key-control verification, actual signed Roughtime receipts and network safety require separate evidence.",
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--approval", type=Path)
    ap.add_argument("--environment", choices=ENVIRONMENTS, required=True)
    ap.add_argument("--expected-manifest-sha256")
    ap.add_argument("--expected-policy-sha256")
    ap.add_argument("--allow-development-test-keys", action="store_true",
                    help="only for explicitly selected development, NEVER production")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    result = None
    try:
        require(not args.allow_development_test_keys or args.environment == "development",
                "--allow-development-test-keys forbidden in production or staging")
        result = preflight(
            args.manifest, args.policy, args.approval, args.environment,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_policy_sha256=args.expected_policy_sha256,
            allow_development_test_keys=args.allow_development_test_keys)
        code = 0
    except (PreflightError, OSError, ValueError, TypeError, KeyError) as exc:
        code = 3
        result = {"schema": "hc-vtime/deployment-preflight/v1",
                  "status": "BLOCKED", "environment": args.environment,
                  "operator_independence_proven": False,
                  "safe_to_install_proven": False,
                  "reason": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.output:
        if args.output.exists() or args.output.is_symlink():
            print("BLOCKED: output exists; never overwrite preflight evidence", file=sys.stderr)
            return 3
        try:
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
        except OSError as exc:
            print("BLOCKED: could not write output: " + str(exc), file=sys.stderr)
            return 3
    return code


if __name__ == "__main__":
    raise SystemExit(main())
