#!/usr/bin/env python3
"""Exact-lock graph inventory from cargo metadata (never guess license data)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from source_policy import GRAPHS, packages_from_lock, review_expression

HEADERS = (
    "graph", "crate", "version", "source", "checksum_sha256",
    "spdx_expression", "license_file_declared", "observed_license_or_notice_files",
    "direct_or_transitive", "dependency_kinds", "target_qualifiers", "enabled_features",
    "license_review_status", "manual_file_review", "attribution_and_notices",
)


def inventory(graph: str, lock_content: str, metadata: dict) -> list[dict]:
    if graph not in GRAPHS:
        raise ValueError("unknown graph")
    pkgs = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(pkgs, list) or not isinstance(resolve, dict):
        raise ValueError("incomplete cargo metadata; inventory not verified")
    by_key = {(p["name"], p["version"], p.get("source")): p for p in pkgs}
    by_id = {p["id"]: p for p in pkgs}
    if len(by_key) != len(pkgs):
        raise ValueError("nonunique cargo metadata keys")
    nodes = {n["id"]: n for n in resolve["nodes"]}
    ws = set(metadata.get("workspace_members", []))
    direct = set(ws)
    for node_id in ws:
        for d in nodes.get(node_id, {}).get("deps", []):
            direct.add(d["pkg"])
    kinds_by_id = {}
    targets_by_id = {}
    for node in nodes.values():
        for dep in node.get("deps", []):
            dep_id = dep["pkg"]
            for k in dep.get("dep_kinds", []):
                kinds_by_id.setdefault(dep_id, set()).add(k.get("kind") or "normal")
                targets_by_id.setdefault(dep_id, set()).add(
                    k.get("target") or "unqualified")
    rows = []
    for p in packages_from_lock(lock_content):
        key = (p["name"], p["version"], p.get("source"))
        m = by_key.get(key)
        if m is None:
            raise ValueError(f"metadata missing lockfile package {key}")
        pkg_id = m["id"]
        manifest_path = Path(m["manifest_path"])
        package_dir = manifest_path.parent
        found = []
        for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*"):
            found.extend(f.name for f in package_dir.glob(pattern) if f.is_file())
        expression = m.get("license") or None
        status = review_expression(expression)
        # license_file may exist for packages that do not specify 'license'.
        declared = m.get("license_file") or ""
        if declared and not Path(declared).is_file():
            status = "REVIEW_REQUIRED_DECLARED_LICENSE_FILE_MISSING"
        rows.append({
            "graph": graph, "crate": m["name"], "version": m["version"],
            "source": m.get("source") or "LOCAL_PATH",
            "checksum_sha256": p.get("checksum") or "",
            "spdx_expression": expression or "UNKNOWN_MISSING_METADATA",
            "license_file_declared": str(declared),
            "observed_license_or_notice_files": "|".join(sorted(set(found))),
            "direct_or_transitive": "direct_or_workspace" if pkg_id in direct else "transitive",
            "dependency_kinds": "|".join(sorted(kinds_by_id.get(pkg_id, []))),
            "target_qualifiers": "|".join(sorted(targets_by_id.get(pkg_id, []))),
            "enabled_features": "|".join(sorted(nodes.get(pkg_id, {}).get("features", []))),
            "license_review_status": status,
            "manual_file_review": "YES" if status != "PROPOSED_POLICY_MATCH_APPROVAL_PENDING"
                                  or bool(found) or bool(declared) else "NOTICE_REVIEW_PENDING",
            "attribution_and_notices": "REVIEW_REQUIRED_BEFORE_DISTRIBUTION",
        })
    # Reject metadata packages not represented in lock: no selective omission.
    if len(rows) != len(pkgs):
        raise ValueError(f"lock/metadata package count differs {len(rows)} != {len(pkgs)}")
    return sorted(rows, key=lambda p: (p["graph"], p["crate"], p["version"], p["source"]))


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as h:
        writer = csv.DictWriter(h, fieldnames=HEADERS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
