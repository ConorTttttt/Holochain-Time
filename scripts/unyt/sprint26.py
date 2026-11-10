#!/usr/bin/env python3
"""Sprint 26: FAIL-CLOSED intake for native Unyt test-alliance evidence.

This script neither reads wallets nor creates transactions. It checks only that
opaque native exports are immutably indexed; no JSON report from this tool is
proof of a RAVE, signature, independent peer, recipient Accept or balance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from . import testnet
except ImportError:
    import testnet

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "integration/unyt/sprint26_scenarios.json"
INDEX_SCHEMA = "hc-vtime/unyt-sprint26-native-evidence-index/v1"
REPORT_SCHEMA = "hc-vtime/unyt-sprint26-audit-report/v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
REQUIRED = {
    "payout_accepted": ("native_rave", "native_sources", "recipient_accept", "independent_peer_check", "balance_before", "balance_after"),
    "refund_accepted": ("native_rave", "native_sources", "recipient_accept", "independent_peer_check", "balance_before", "balance_after"),
    "challenge_succeeded": ("native_rave", "native_sources", "recipient_accept_reporter", "recipient_accept_treasury", "independent_peer_check", "balance_before", "balance_after"),
    "rejected_no_debit": ("native_failure", "native_sources", "independent_peer_check", "balance_before", "balance_after"),
    "defined_expiry_outcome": ("native_result", "native_sources", "independent_peer_check", "balance_before", "balance_after"),
}


class GateError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise GateError(reason)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError(f"unreadable JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path}: expected object")
    return value


def matrix() -> list[dict]:
    value = read_json(MATRIX)
    require(value.get("schema") == "hc-vtime/unyt-sprint26-scenarios/v1", "unreviewed scenario matrix")
    cases = value.get("cases")
    require(isinstance(cases, list) and len(cases) >= 8, "incomplete scenario matrix")
    names = set()
    for case in cases:
        require(isinstance(case, dict) and isinstance(case.get("id"), str)
                and re.fullmatch(r"[a-z_]+", case["id"]) is not None, "invalid scenario ID")
        require(case["id"] not in names, "repeated scenario ID")
        names.add(case["id"])
        require(case.get("expected") in REQUIRED, "unrecognized expected outcome")
        require(case.get("support") in ("requires_live_test", "protocol_blocked"),
                "invalid support classification")
    return cases


def scaffold(manifest: dict) -> dict:
    require(manifest.get("schema") == testnet.MANIFEST_SCHEMA, "wrong deployment manifest")
    require(manifest.get("funding_authorized") is False, "manifest cannot authorize funding")
    return {
        "schema": INDEX_SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "network_id": manifest["network"]["alliance_id"],
        "vtime_dna_hash": manifest["network"]["vtime_dna_hash"],
        "unyt_app_release": "REPLACE_WITH_LOCAL_UNYT_RELEASE",
        "unyt_app_artifact_sha256": "REPLACE_WITH_LOCAL_UNYT_ARTIFACT_SHA256",
        "cases": {case["id"]: {"artifacts": {}} for case in matrix()},
    }


def safe_artifact(directory: Path, ref: dict, case_id: str, kind: str) -> tuple[str, str]:
    require(isinstance(ref, dict) and set(ref) == {"file", "sha256"},
            f"{case_id}/{kind}: expected only file and sha256")
    name, digest = ref["file"], ref["sha256"]
    require(isinstance(name, str) and len(name) <= 180 and name == Path(name).name
            and not name.startswith(".") and "\\" not in name and "/" not in name,
            f"{case_id}/{kind}: unsafe filename")
    require(isinstance(digest, str) and HEX64.fullmatch(digest) is not None,
            f"{case_id}/{kind}: invalid SHA-256")
    target = directory / name
    require(not target.is_symlink() and target.is_file()
            and target.resolve().parent == directory.resolve(),
            f"{case_id}/{kind}: file outside evidence directory or missing")
    require(0 < target.stat().st_size <= 8 * 1024 * 1024,
            f"{case_id}/{kind}: empty or oversized native export")
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    require(actual == digest, f"{case_id}/{kind}: file SHA-256 changed")
    return name, digest


def audit(index: dict, manifest: dict, evidence_dir: Path) -> dict:
    """Check evidence intake completeness, NEVER assert financial acceptance."""
    require(index.get("schema") == INDEX_SCHEMA, "wrong evidence index schema")
    require(index.get("manifest_sha256") == manifest.get("manifest_sha256"), "manifest mismatch")
    require(index.get("network_id") == manifest["network"]["alliance_id"], "wrong test alliance")
    require(index.get("vtime_dna_hash") == manifest["network"]["vtime_dna_hash"], "wrong vtime DNA")
    require(VERSION.fullmatch(str(index.get("unyt_app_release", ""))) is not None,
            "pin the actual local Unyt release")
    require(isinstance(index.get("unyt_app_artifact_sha256"), str)
            and HEX64.fullmatch(index["unyt_app_artifact_sha256"]) is not None,
            "pin the actual Unyt app build artifact SHA-256")
    cases = index.get("cases")
    expected = matrix()
    require(isinstance(cases, dict) and set(cases) == {case["id"] for case in expected},
            "missing or extra scenario entries")
    require(evidence_dir.is_dir() and not evidence_dir.is_symlink(), "invalid evidence directory")
    results = []
    # Do not let one native export masquerade as many independently sourced records.
    seen_files: set[str] = set()
    for case in expected:
        cid = case["id"]
        item = cases[cid]
        require(isinstance(item, dict) and set(item) == {"artifacts"}, f"{cid}: unexpected case fields")
        artifacts = item["artifacts"]
        require(isinstance(artifacts, dict), f"{cid}: artifacts must be object")
        required = set(REQUIRED[case["expected"]])
        require(set(artifacts) <= required, f"{cid}: unrecognized artifact types")
        for kind, ref in artifacts.items():
            name, _ = safe_artifact(evidence_dir, ref, cid, kind)
            require(name not in seen_files, f"{cid}/{kind}: native export reused across evidence slots")
            seen_files.add(name)
        missing = sorted(required - set(artifacts))
        if case["support"] == "protocol_blocked":
            status = "BLOCKED_PROTOCOL"
        elif missing:
            status = "MISSING_NATIVE_ARTIFACTS"
        else:
            status = "READY_FOR_INDEPENDENT_NATIVE_REVIEW"
        results.append({"scenario_id": cid, "expected": case["expected"],
                        "status": status, "missing_artifacts": missing})
    return {
        "schema": REPORT_SCHEMA,
        "financial_release_gate": "NO_GO",
        "trust_level": "OPAQUE_NATIVE_FILE_HASH_INTAKE_ONLY",
        "manifest_sha256": manifest["manifest_sha256"],
        "network_id": index["network_id"],
        "cases": results,
        "warnings": [
            "No signed Unyt/Holochain action or recipient Accept was cryptographically verified here.",
            "No peer identity, state transition, financial finality or absence of accepted RAVEs was established.",
            "An authorized independent native Unyt client and human security/economic reviewers are required.",
            "Wrong-target binding, one-use proof semantics and release expiry remain protocol blockers.",
        ],
    }


def write_once(path: Path, body: dict) -> None:
    # No overwrite of acceptance evidence; keep it in ignored local folders.
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as fp:
            json.dump(body, fp, sort_keys=True, indent=2)
            fp.write("\n")
    except FileExistsError as exc:
        raise GateError("output exists; refusing to overwrite audit evidence") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "audit"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--manifest", required=True, type=Path)
        cmd.add_argument("--output", required=True, type=Path)
        if name == "audit":
            cmd.add_argument("--index", required=True, type=Path)
            cmd.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = testnet.verify_manifest(args.manifest)
        if args.command == "prepare":
            write_once(args.output, scaffold(manifest))
            print("EVIDENCE INDEX SCAFFOLDED; no deployment, funding, or verification")
        else:
            report = audit(read_json(args.index), manifest, args.evidence_dir)
            write_once(args.output, report)
            counts = {v: sum(c["status"] == v for c in report["cases"])
                      for v in {c["status"] for c in report["cases"]}}
            print(f"NO-GO: native evidence inventory only: {json.dumps(counts, sort_keys=True)}")
        return 0
    except (GateError, testnet.GateError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"FAIL CLOSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
