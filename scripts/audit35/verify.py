#!/usr/bin/env python3
"""Independent integrity and exact-commit reproduction of Sprint 35 audit source bundle.

A PASS means the SOURCE archive and lockfile inventory match this checkout.
It never certifies Rust/WASM/Unyt execution, a security review or release.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib

FILES = ("source.tar.gz", "dependencies.json", "provenance.json")
LOCKS = ("Cargo.lock", "integration/conductor/Cargo.lock", "integration/load/Cargo.lock")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SCHEMA = "hc-vtime/sprint35-audit-source/v1"


class VerificationError(ValueError):
    pass


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git(repo: Path, *args: str) -> bytes:
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=120)
    if p.returncode:
        raise VerificationError(f"git {args[0]} failed: {p.stderr.decode('utf-8', 'replace')[:200]}")
    return p.stdout


def safe_member(m: tarfile.TarInfo) -> bool:
    name = m.name
    parts = PurePosixPath(name).parts
    return (bool(parts) and not name.startswith("/") and "\\" not in name
            and all(p not in (".", "..") for p in parts)
            and (m.isfile() or m.isdir()) and not m.issym() and not m.islnk())


def verify(repo: Path, expected: str, bundle: Path) -> dict:
    if not SHA40.fullmatch(expected):
        raise VerificationError("expected Git commit must be 40 lowercase hex digits")
    repo = repo.resolve(strict=True)
    bundle = bundle.resolve(strict=True)
    if not bundle.is_dir() or bundle.is_symlink() or repo == bundle or repo in bundle.parents:
        raise VerificationError("audit bundle must be an outside directory")
    names = {p.name for p in bundle.iterdir()}
    if names != set(FILES) | {"SHA256SUMS"}:
        raise VerificationError("bundle must contain exactly the expected four files")
    for name in names:
        f = bundle / name
        if not f.is_file() or f.is_symlink() or f.stat().st_size > 100 * 1024 * 1024:
            raise VerificationError(f"unsafe, oversized or missing evidence: {name}")
    if git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip() != expected:
        raise VerificationError("verification clone HEAD differs from expected commit")
    if git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise VerificationError("cannot reproduce archive in a shallow checkout")
    if git(repo, "status", "--porcelain", "--untracked-files=all").strip():
        raise VerificationError("verification clone is dirty")
    observed = (bundle / "SHA256SUMS").read_bytes()
    expected_sums = b"".join(
        f"{digest((bundle / filename).read_bytes())}  {filename}\n".encode()
        for filename in FILES
    )
    if observed != expected_sums:
        raise VerificationError("missing, reordered, extra or corrupted SHA256SUMS entries")
    provenance = json.loads((bundle / "provenance.json").read_text(encoding="utf-8"))
    inventory = json.loads((bundle / "dependencies.json").read_text(encoding="utf-8"))
    if not isinstance(provenance, dict) or provenance.get("schema") != SCHEMA:
        raise VerificationError("unexpected source provenance schema")
    if provenance.get("source_commit") != expected or provenance.get("release_decision") != "NO-GO":
        raise VerificationError("provenance commit or non-release verdict mismatch")
    for flag in (
        "source_reproduced_independently", "rust_tests_executed", "wasm_build_executed",
        "dna_pack_executed", "unyt_funded_executed", "external_antirollback_verified",
        "independent_audit_completed", "binary_reproducibility_verified",
        "production_release_ready", "financial_release_allowed",
    ):
        if provenance.get(flag) is not False:
            raise VerificationError(f"unsupported success flag: {flag}")
    if provenance.get("source_packaged") is not True:
        raise VerificationError("source packaging not declared")
    if inventory.get("source_commit") != expected or inventory.get("vulnerabilities_assessed") is not False:
        raise VerificationError("dependency inventory false provenance/scan claim")
    if provenance.get("dependency_inventory_sha256") != digest((bundle / "dependencies.json").read_bytes()):
        raise VerificationError("dependency inventory digest mismatch")

    compressed = (bundle / "source.tar.gz").read_bytes()
    if len(compressed) < 10 or compressed[:3] != b"\x1f\x8b\x08" or compressed[4:8] != b"\0"*4:
        raise VerificationError("source not deterministic gzip with mtime 0")
    if provenance.get("source_tar_sha256") != digest(compressed):
        raise VerificationError("source archive hash differs from provenance")
    # Rebuild the tracked archive from Git, rather than trusting the supplied
    # hashes. The original script cannot substitute arbitrary untracked files.
    original_tar = git(repo, "archive", "--format=tar", expected)
    regenerated = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=regenerated, mtime=0, compresslevel=9) as g:
        g.write(original_tar)
    if regenerated.getvalue() != compressed:
        raise VerificationError("source archive differs from exact-commit Git source")

    actual_locks = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
        for item in archive:
            if not safe_member(item):
                raise VerificationError(f"unsafe archive member: {item.name}")
            if item.size > 100 * 1024 * 1024:
                raise VerificationError("oversized archived member")
            total += item.size
            if total > 100 * 1024 * 1024:
                raise VerificationError("archive exceeds inspected size bound")
            if item.name in LOCKS:
                stream = archive.extractfile(item)
                if stream is None:
                    raise VerificationError(f"missing lockfile body: {item.name}")
                actual_locks[item.name] = stream.read()
    if set(actual_locks) != set(LOCKS):
        raise VerificationError("missing mandatory locked dependency graphs")
    locks = inventory.get("locks")
    if not isinstance(locks, list) or [entry.get("path") for entry in locks if isinstance(entry, dict)] != list(LOCKS):
        raise VerificationError("lockfile inventory incomplete or inconsistent")
    for entry in locks:
        raw = actual_locks[entry["path"]]
        if digest(raw) != entry.get("sha256"):
            raise VerificationError(f"lockfile digest mismatch: {entry['path']}")
        doc = tomllib.loads(raw.decode("utf-8"))
        packages = sorted(
            [{"name": p["name"], "version": p["version"],
              "source": p.get("source", "local"), "checksum": p.get("checksum")}
             for p in doc["package"]],
            key=lambda p: (p["name"], p["version"], p["source"]),
        )
        if entry.get("package_count") != len(packages) or entry.get("packages") != packages:
            raise VerificationError(f"dependency list mismatch: {entry['path']}")
    return {
        "status": "EXACT_SOURCE_REPRODUCED",
        "source_commit": expected,
        "source_tar_sha256": digest(compressed),
        "dependency_locks_verified": list(LOCKS),
        "production_release_ready": False,
        "independent_security_audit_completed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        report = verify(options.repo, options.expected_sha, options.bundle)
    except (OSError, VerificationError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            UnicodeError, tarfile.TarError, tomllib.TOMLDecodeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc), "release_ready": False}), file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
