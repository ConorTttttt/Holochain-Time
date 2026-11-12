#!/usr/bin/env python3
"""Static audit: no locked conductor dependency enables the optional QUIC
ACK-frequency sending extension (regression check for HCVT-S37-NOQ-ACKFREQ).

Scans the Rust sources of every registry crate in a conductor ``Cargo.lock``
(from the local Cargo registry source cache, populated by ``cargo fetch``) and
fails when any non-test source constructs an ``AckFrequencyConfig`` or calls
``ack_frequency_config(Some ...)``. It also fails when the locked QUIC
implementation differs from the version whose gating was manually reviewed,
forcing a fresh review on every iroh/kitsune2/holochain upgrade.

This is a configuration regression check. It is not a vulnerability test, it
does not exercise the network, and a PASS is not an approval.

Exit codes: 0 PASS, 2 FAIL, 3 invalid input (e.g. sources not fetched).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

SCHEMA = "hc-vtime/quic-transport-config-audit/v1"
# QUIC implementation versions whose send-side gating was manually reviewed
# (pending.ack_frequency is only set when TransportConfig.ack_frequency_config
# is Some). Any other version requires a new review before this can pass.
REVIEWED = {"noq-proto": {"1.4.0"}}
# Crates that define the API; their own definitions/tests are not call sites.
DEFINING = {"noq-proto", "quinn-proto"}
ENABLE = [
    re.compile(r"ack_frequency_config\s*\(\s*Some\b"),
    re.compile(r"AckFrequencyConfig\s*::\s*default\s*\("),
    re.compile(r"\bAckFrequencyConfig\s*\{"),
]
DEFINITION = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?(struct|impl\b)")
TEST_PARTS = {"tests", "test", "benches", "examples", "fuzz"}


class AuditError(ValueError):
    pass


def locked_crates(lock: Path) -> list[tuple[str, str]]:
    try:
        data = tomllib.loads(lock.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AuditError(f"cannot read {lock}: {exc}") from exc
    return sorted((p["name"], p["version"]) for p in data.get("package", [])
                  if str(p.get("source", "")).startswith("registry+"))


def scan_crate(src: Path, name: str) -> list[str]:
    hits = []
    for path in sorted(src.rglob("*.rs")):
        rel = path.relative_to(src)
        if TEST_PARTS & set(rel.parts) or rel.name in ("tests.rs", "test.rs"):
            continue
        in_cfg_test = False
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#[cfg(test)]"):
                in_cfg_test = True  # conservative: rest of file is test-only
            if in_cfg_test or stripped.startswith("//"):
                continue
            if name in DEFINING and DEFINITION.match(line):
                continue
            if any(p.search(line) for p in ENABLE):
                hits.append(f"{name}/{rel}:{number}: {stripped[:160]}")
    return hits


def audit(lock: Path, registry_src: Path) -> dict:
    crates = locked_crates(lock)
    if not crates:
        raise AuditError("lockfile lists no registry crates")
    missing = [f"{n}-{v}" for n, v in crates if not (registry_src / f"{n}-{v}").is_dir()]
    if missing:
        raise AuditError(f"{len(missing)} locked crates not in registry source cache "
                         f"(run cargo fetch --locked): {missing[:5]}")
    problems = []
    versions = {}
    for name, version in crates:
        if name in REVIEWED:
            versions.setdefault(name, []).append(version)
            if version not in REVIEWED[name]:
                problems.append(f"{name} {version} has not been manually reviewed for "
                                f"ACK-frequency send gating (reviewed: {sorted(REVIEWED[name])})")
        problems += scan_crate(registry_src / f"{name}-{version}", name)
    for name in REVIEWED:
        if name not in versions:
            problems.append(f"{name} not present in lockfile; the reviewed QUIC stack changed")
    return {"schema": SCHEMA, "lockfile": str(lock), "crates_scanned": len(crates),
            "quic_versions": versions, "violations": problems,
            "result": "FAIL" if problems else "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--registry-src", type=Path, required=True,
                        help="e.g. ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.lock, args.registry_src)
    except AuditError as exc:
        print(json.dumps({"schema": SCHEMA, "result": "INVALID", "reason": str(exc)}))
        return 3
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    return 2 if report["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
