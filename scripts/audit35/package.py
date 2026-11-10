#!/usr/bin/env python3
"""Sprint 35: fail-closed, exact-commit source and dependency audit bundle.

This is a REVIEW INPUT, not a production DNA/hApp, security audit, SBOM
certification or live deployment. Requires Python 3.11+, Git and a clean,
non-shallow local clone. No keys, external network or cargo runner needed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "hc-vtime/sprint35-audit-source/v1"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
REQUIRED_LOCKS = (
    "Cargo.lock",
    "integration/conductor/Cargo.lock",
    "integration/load/Cargo.lock",
)
FILES = ("source.tar.gz", "dependencies.json", "provenance.json")
MAX_SOURCE = 100 * 1024 * 1024


class PackageError(ValueError):
    pass


def run(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        check=False, timeout=120,
    )
    if proc.returncode:
        raise PackageError(f"git {args[0]} failed: {proc.stderr.decode('utf-8', 'replace')[:400]}")
    return proc.stdout


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def source_archive(repo: Path, commit: str) -> bytes:
    """Git tracked tree only, gzip header timestamp=0; no local build outputs."""
    tar = run(repo, "archive", "--format=tar", commit)
    if not tar or len(tar) > MAX_SOURCE:
        raise PackageError("empty or oversized tracked source archive")
    dst = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=dst, compresslevel=9, mtime=0) as handle:
        handle.write(tar)
    return dst.getvalue()


def lock_inventory(repo: Path, commit: str) -> dict:
    locks = []
    for relative in REQUIRED_LOCKS:
        raw = run(repo, "show", f"{commit}:{relative}")
        document = tomllib.loads(raw.decode("utf-8"))
        if not isinstance(document.get("package"), list) or not document["package"]:
            raise PackageError(f"{relative}: empty or invalid dependency lockfile")
        packages = []
        for pkg in document["package"]:
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str) or not isinstance(pkg.get("version"), str):
                raise PackageError(f"{relative}: unrecognized lockfile package")
            packages.append({
                "name": pkg["name"], "version": pkg["version"],
                "source": pkg.get("source", "local"),
                "checksum": pkg.get("checksum"),
            })
        packages.sort(key=lambda row: (row["name"], row["version"], row["source"]))
        locks.append({
            "path": relative, "sha256": sha(raw),
            "package_count": len(packages), "packages": packages,
        })
    return {
        "schema": "hc-vtime/sprint35-lock-inventory/v1",
        "source_commit": commit,
        "locks": locks,
        "scope": "Three committed Cargo.lock files; no artifact build or dependency source inspection",
        "standalone_fuzz_lockfile": "NOT PINNED/NOT INCLUDED",
        "cargo_audit": {"status": "NOT RUN", "advisory_freshness_verified": False},
        "cargo_deny": {"status": "NOT RUN", "license_and_origin_reviewed": False},
        "sbom": "LOCKFILE INVENTORY ONLY; not a validated CycloneDX/SPDX SBOM",
        "vulnerabilities_assessed": False,
    }


def create(repo: Path, expected_sha: str, output: Path) -> dict:
    if not SHA40.fullmatch(expected_sha):
        raise PackageError("expected SHA must be an exact 40-digit lowercase Git SHA")
    repo = repo.resolve(strict=True)
    if run(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise PackageError("shallow repository: full audited history unavailable")
    head = run(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if head != expected_sha:
        raise PackageError(f"HEAD {head} differs from reviewed exact commit")
    if run(repo, "status", "--porcelain", "--untracked-files=all").strip():
        raise PackageError("working tree is dirty, including untracked files")
    output = output.resolve()
    if output == repo or repo in output.parents:
        raise PackageError("audit bundle must be outside the source repository")
    if output.exists() or output.is_symlink():
        raise PackageError("audit bundle directory already exists; never overwrite")
    if not output.parent.is_dir():
        raise PackageError("audit bundle parent directory must already exist")

    archived = source_archive(repo, head)
    inventory = json_bytes(lock_inventory(repo, head))
    manifest = {
        "schema": SCHEMA,
        "source_commit": head,
        "source_tar_sha256": sha(archived),
        "git_version": run(repo, "--version").decode().strip(),
        "python_version": sys.version.split()[0],
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_archive": "source.tar.gz",
        "source_archive_scope": "git archive of committed tracked source; no binary outputs or untracked files",
        "archive_gzip_mtime": 0,
        "dependency_inventory_sha256": sha(inventory),
        "source_packaged": True,
        "source_reproduced_independently": False,
        "rust_tests_executed": False,
        "wasm_build_executed": False,
        "dna_pack_executed": False,
        "unyt_funded_executed": False,
        "external_antirollback_verified": False,
        "independent_audit_completed": False,
        "binary_reproducibility_verified": False,
        "production_release_ready": False,
        "financial_release_allowed": False,
        "release_decision": "NO-GO",
        "blockers": ["#1 release gate", "#22 Actions runner", "#61 Unyt policy",
                     "#70 oracle runtime/external checkpoint", "independent audit"],
    }
    provenance = json_bytes(manifest)
    output.mkdir(mode=0o700)
    try:
        for filename, contents in zip(FILES, (archived, inventory, provenance)):
            (output / filename).write_bytes(contents)
        checks = "\n".join(
            f"{sha((output / filename).read_bytes())}  {filename}"
            for filename in FILES
        ) + "\n"
        (output / "SHA256SUMS").write_text(checks, encoding="ascii")
    except BaseException:
        shutil.rmtree(output)
        raise
    return manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=ROOT)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        result = create(args.repo, args.expected_sha, args.output_dir)
    except (PackageError, OSError, subprocess.TimeoutExpired, UnicodeError, tomllib.TOMLDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc), "release_ready": False}), file=sys.stderr)
        return 3
    print(json.dumps({
        "status": "SOURCE_AUDIT_BUNDLE_CREATED_NOT_RELEASED",
        "source_commit": result["source_commit"],
        "bundle": str(args.output_dir.resolve()),
        "release_ready": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
