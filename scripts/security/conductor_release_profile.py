#!/usr/bin/env python3
"""Conductor release-profile checker (Sprint 38 security clearance).

Checks that a Holochain conductor build matches the dependency profile that
was actually security-reviewed, and reports the facts reviewers need to
evaluate inherited advisories. Pure Python standard library; no network.

Hard requirements (exit 2 when violated):

* the conductor lockfile pins ``holochain`` 0.7.1 and resolves the reviewed
  QUIC stack floor: ``noq-proto`` >= 1.4.0, ``iroh`` >= 1.4.1 and
  ``kitsune2_transport_iroh`` >= 0.5.3.  The lockfile packaged inside the
  upstream ``holochain`` 0.7.1 crate (what ``cargo install --locked`` uses)
  resolves an OLDER QUIC stack and therefore does not match the reviewed
  profile;
* a conductor binary, when supplied, embeds the same floor (detected from the
  crate paths the Rust compiler records for panic locations);
* the deployment environment does not set ``HOLOCHAIN_INFLUXIVE_CHILD_SVC``
  (any value enables it), which downloads and runs external binaries and is
  the only caller of the ``zip`` crate on Windows.

* a supplied binary keeps its symbol table and links no ``quinn_proto``,
  ``ruzstd`` or ``zip`` symbols. Absence is enforced because proposed
  dispositions rely on it; absence is supporting evidence, NOT proof of
  non-reachability.

Facts reported but NOT treated as clearance (an approval is never inferred):

* the SQLCipher / SQLite core compiled in (identified from SQLITE_SOURCE_ID);
* target-triple exposure to the Windows-only ``zip`` 8.6.0 advisories.  The
  supported-platform policy is NOT approved, so the platform is reported as
  ``PLATFORM_POLICY_APPROVAL_PENDING`` and Windows is reported as exposed.

Exit codes: 0 profile satisfied, 2 profile violated, 3 invalid input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

SCHEMA = "hc-vtime/conductor-release-profile/v1"
HOLOCHAIN_VERSION = "0.7.1"
# Minimum versions of the reviewed QUIC stack (integration/conductor/Cargo.lock).
MIN_VERSIONS = {
    "noq-proto": (1, 4, 0),
    "iroh": (1, 4, 1),
    "kitsune2_transport_iroh": (0, 5, 3),
}
FORBIDDEN_ENV = {
    "HOLOCHAIN_INFLUXIVE_CHILD_SVC":
        "downloads and executes external InfluxDB binaries; on Windows it is the "
        "only caller of zip 8.6.0 (RUSTSEC-2026-0367/0368/0369/0429)",
}
# SQLITE_SOURCE_ID prefixes of amalgamations we can identify.
SQLITE_SOURCE_IDS = {
    "2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a":
        {"sqlite": "3.46.1", "sqlcipher": "4.6.1", "crate": "libsqlite3-sys 0.35.0 (bundled-sqlcipher)"},
    "2025-06-28 14:00:48 2af157d77fb1304a74176eaee7fbc7c7e932d946bf25325e9c26c91db19e":
        {"sqlite": "3.50.2", "sqlcipher": None, "crate": "libsqlite3-sys 0.35.0 (bundled, plain SQLite)"},
}
# Crates whose advisories are proposed as not applicable partly because the
# release linker drops them (dead-code elimination). The binary check enforces
# that this remains true for the exact executable; it does not prove that code
# which IS linked is unreachable.
UNLINKED_CRATES = ("quinn_proto", "ruzstd", "zip")
WINDOWS = re.compile(r"-windows-")
SUPPORTED_CANDIDATES = re.compile(r"-(unknown-linux-(gnu|musl)|apple-darwin)\Z")
CRATE_PATH = re.compile(rb"(noq-proto|noq|iroh|kitsune2_transport_iroh|quinn-proto|"
                        rb"libsqlite3-sys|zip|ruzstd|holochain)-(\d+)\.(\d+)\.(\d+)[/\\]")
SOURCE_ID = re.compile(rb"20\d\d-\d\d-\d\d \d\d:\d\d:\d\d [0-9a-f]{60,64}")


class ProfileError(ValueError):
    """Invalid input (exit 3)."""


def parse_version(text: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", text)
    if not match:
        raise ProfileError(f"unparseable version {text!r}")
    return tuple(int(x) for x in match.groups())  # type: ignore[return-value]


def fmt(version: tuple[int, ...]) -> str:
    return ".".join(str(x) for x in version)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def lock_versions(lock_path: Path) -> dict[str, set[str]]:
    try:
        data = tomllib.loads(lock_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"cannot read lockfile {lock_path}: {exc}") from exc
    packages = data.get("package")
    if not isinstance(packages, list) or not packages:
        raise ProfileError("lockfile has no [[package]] entries")
    out: dict[str, set[str]] = {}
    for pkg in packages:
        if not isinstance(pkg, dict) or "name" not in pkg or "version" not in pkg:
            raise ProfileError("malformed [[package]] entry")
        out.setdefault(pkg["name"], set()).add(pkg["version"])
    return out


def floor_violations(found: dict[str, set[str]], where: str) -> list[str]:
    problems = []
    for name, floor in MIN_VERSIONS.items():
        versions = found.get(name)
        if not versions:
            problems.append(f"{where}: {name} not present (reviewed profile requires >= {fmt(floor)})")
            continue
        for version in sorted(versions):
            if parse_version(version) < floor:
                problems.append(f"{where}: {name} {version} is below reviewed floor {fmt(floor)}")
    return problems


def check_lock(lock_path: Path) -> dict:
    found = lock_versions(lock_path)
    problems = []
    if found.get("holochain") != {HOLOCHAIN_VERSION}:
        problems.append(f"lockfile: holochain must be exactly {HOLOCHAIN_VERSION}, "
                        f"found {sorted(found.get('holochain', []))}")
    problems += floor_violations(found, "lockfile")
    sqlite = sorted(found.get("libsqlite3-sys", []))
    return {
        "lockfile": str(lock_path),
        "lockfile_sha256": sha256_file(lock_path),
        "violations": problems,
        "facts": {
            "quic_stack": {n: sorted(found.get(n, [])) for n in MIN_VERSIONS},
            "quinn-proto_locked": sorted(found.get("quinn-proto", [])),
            "zip_locked": sorted(found.get("zip", [])),
            "ruzstd_locked": sorted(found.get("ruzstd", [])),
            "libsqlite3-sys_locked": sqlite,
        },
    }


def crate_symbol_count(symbols: list[bytes], crate: str) -> int:
    """Count demangled symbols with a path rooted at ``crate::``.

    A crate root must not be preceded by an identifier character or ``::``,
    so ``core::iter::adapters::zip::Zip``, ``Option::zip`` and ``gzip`` are
    not counted as the ``zip`` crate.
    """
    root = re.compile(rb"(?<![A-Za-z0-9_:])" + re.escape(crate.encode()) + rb"::")
    return sum(1 for line in symbols if root.search(line))


def symbol_counts(binary: Path) -> dict[str, int | None]:
    crates = ("quinn_proto", "noq_proto", "ruzstd", "zip")
    nm = shutil.which("nm")
    if nm is None:
        return dict.fromkeys(crates)
    proc = subprocess.run([nm, "-C", "--defined-only", str(binary)], capture_output=True,
                          check=False)
    if proc.returncode != 0:
        return dict.fromkeys(crates)
    symbols = proc.stdout.splitlines()
    return {crate: crate_symbol_count(symbols, crate) for crate in crates}


def check_binary(binary: Path) -> dict:
    try:
        blob = binary.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read binary {binary}: {exc}") from exc
    embedded: dict[str, set[str]] = {}
    for match in CRATE_PATH.finditer(blob):
        name = match.group(1).decode()
        embedded.setdefault(name, set()).add(".".join(g.decode() for g in match.groups()[1:]))
    problems = floor_violations(embedded, "binary")
    if embedded.get("holochain") and embedded["holochain"] != {HOLOCHAIN_VERSION}:
        problems.append(f"binary: embeds holochain {sorted(embedded['holochain'])}, "
                        f"expected {HOLOCHAIN_VERSION}")
    counts = symbol_counts(binary)
    if not counts.get("noq_proto"):
        problems.append("binary: no symbol table (stripped, or nm unavailable); linked-code "
                        "assumptions below cannot be verified")
    else:
        for crate in UNLINKED_CRATES:
            if counts.get(crate):
                problems.append(f"binary: {counts[crate]} {crate} symbols linked; the reviewed "
                                f"profile assumes {crate} is not linked (re-review required)")
    source_ids = sorted({m.group(0).decode() for m in SOURCE_ID.finditer(blob)})
    sqlite = []
    for sid in source_ids:
        info = next((v for k, v in SQLITE_SOURCE_IDS.items() if sid.startswith(k)), None)
        sqlite.append({"source_id": sid, "identified": info})
    return {
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(blob).hexdigest(),
        "violations": problems,
        "facts": {
            "embedded_crate_versions": {k: sorted(v) for k, v in sorted(embedded.items())},
            "symbol_counts": counts,
            "symbol_note": "symbol absence supports, but does not prove, non-reachability",
            "sqlite_source_ids": sqlite,
        },
    }


def parse_env_file(path: Path) -> dict[str, str]:
    env = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise ProfileError(f"cannot read env file {path}: {exc}") from exc
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            raise ProfileError(f"{path}:{number}: not KEY=VALUE")
        key, value = line.split("=", 1)
        env[key.strip()] = value
    return env


def check_env(env: dict[str, str], origin: str) -> dict:
    problems = [f"{origin}: {key} is set ({why})"
                for key, why in FORBIDDEN_ENV.items() if key in env]
    return {"origin": origin, "violations": problems}


def check_target(triple: str) -> dict:
    if not re.fullmatch(r"[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+(-[a-z0-9_]+)?", triple):
        raise ProfileError(f"invalid target triple {triple!r}")
    if WINDOWS.search(triple):
        exposure = "EXPOSED: zip 8.6.0 compiled (Windows-only holochain_metrics dependency)"
    elif SUPPORTED_CANDIDATES.search(triple):
        exposure = "zip 8.6.0 not compiled for this triple (cargo tree --target evidence)"
    else:
        exposure = "UNASSESSED target triple"
    return {
        "target_triple": triple,
        "zip_advisory_exposure": exposure,
        "platform_policy": "PLATFORM_POLICY_APPROVAL_PENDING",
        "violations": [] if not exposure.startswith(("EXPOSED", "UNASSESSED")) else
        [f"target {triple}: {exposure}; no approved supported-platform policy"],
    }


def run(args: argparse.Namespace) -> dict:
    sections = {}
    if args.lock:
        sections["lock"] = check_lock(args.lock)
    if args.binary:
        sections["binary"] = check_binary(args.binary)
    if args.env_file:
        sections["env_file"] = check_env(parse_env_file(args.env_file), str(args.env_file))
    if args.check_process_env:
        import os
        sections["process_env"] = check_env(dict(os.environ), "process environment")
    if args.target:
        sections["target"] = check_target(args.target)
    if not sections:
        raise ProfileError("nothing to check: pass --lock, --binary, --env-file, "
                           "--check-process-env and/or --target")
    violations = [v for s in sections.values() for v in s["violations"]]
    return {
        "schema": SCHEMA,
        "result": "PROFILE_VIOLATED" if violations else "PROFILE_SATISFIED",
        "violations": violations,
        "sections": sections,
        "clears_supply_chain_gate": False,
        "note": "A satisfied profile is a precondition for proposed dispositions, "
                "not an approval of any advisory.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lock", type=Path, help="conductor Cargo.lock")
    parser.add_argument("--binary", type=Path, help="conductor executable to inspect")
    parser.add_argument("--env-file", type=Path, help="deployment KEY=VALUE environment file")
    parser.add_argument("--check-process-env", action="store_true")
    parser.add_argument("--target", help="target triple of the conductor build")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except ProfileError as exc:
        print(json.dumps({"schema": SCHEMA, "result": "INVALID", "reason": str(exc)}))
        return 3
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    return 2 if report["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
