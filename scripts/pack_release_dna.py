#!/usr/bin/env python3
"""Guarded DNA packer: preflight BEFORE the external hc dna pack command.

Operators calling hc directly BYPASS this check. Deployment automation must
use this entry point and inspect report artifacts before installation.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from deployment_preflight import PreflightError, preflight, require, sha256, file_bytes

ROOT = Path(__file__).resolve().parent.parent
INTEGRITY = "target/wasm32-unknown-unknown/release/vtime_integrity.wasm"
COORDINATOR = "target/wasm32-unknown-unknown/release/vtime.wasm"


def pack(args):
    output = args.output_dir.resolve()
    require(not output.exists() and not output.is_symlink(),
            "output already exists; release evidence is immutable")
    require(output != ROOT and ROOT not in output.parents,
            "output must be outside source checkout")
    require(not args.allow_development_test_keys or args.environment == "development",
            "test signer opt-in allowed only in development")
    pre = preflight(
        args.manifest, args.policy, args.approval, args.environment,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_policy_sha256=args.expected_policy_sha256,
        allow_dev_test_keys=args.allow_development_test_keys)
    manifest_data = file_bytes(args.manifest, 128 * 1024)
    text = manifest_data.decode("utf-8")
    for wasm_path in (INTEGRITY, COORDINATOR):
        require(text.count("path: ../../../" + wasm_path) == 1,
                f"manifest must reference reviewed WASM path {wasm_path}")
    require(sum(line.strip().startswith("path:") for line in text.splitlines()) == 2,
            "unexpected extra WASM path in DNA manifest")

    wasm = {}
    sources = {"integrity": ROOT / INTEGRITY, "coordinator": ROOT / COORDINATOR}
    for label, source in sources.items():
        contents = file_bytes(source, 100 * 1024 * 1024)
        require(contents[:4] == b"\x00asm" and len(contents) >= 8,
                f"{label} WASM has no valid WebAssembly header")
        wasm[label] = {"sha256": sha256(contents), "bytes": len(contents)}
    if args.environment == "production":
        require(args.expected_integrity_wasm_sha256 == wasm["integrity"]["sha256"] and
                args.expected_coordinator_wasm_sha256 == wasm["coordinator"]["sha256"],
                "reviewed exact WASM SHA-256 pins required for production")
    require(shutil.which("hc") is not None, "hc CLI is unavailable")
    try:
        git_sha = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                          text=True, stderr=subprocess.DEVNULL).strip()
        if args.environment == "production":
            require(args.expected_commit_sha == git_sha and len(git_sha) == 40,
                    "production source commit SHA differs from approved full SHA")
            require(not subprocess.check_output(
                ["git", "-C", str(ROOT), "status", "--porcelain",
                 "--untracked-files=all"], text=True).strip(),
                "production source worktree must be clean")
    except subprocess.CalledProcessError as exc:
        raise PreflightError("cannot establish clean exact source commit") from exc

    output.mkdir(parents=True)
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix="staging-", dir=output))
        workdir = staging / "dnas/vtime/workdir"
        workdir.mkdir(parents=True)
        (workdir / "dna.yaml").write_bytes(manifest_data)
        for label, source in sources.items():
            target = staging / (INTEGRITY if label == "integrity" else COORDINATOR)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            require(sha256(target.read_bytes()) == wasm[label]["sha256"],
                    f"{label} changed while staging release")
        with (output / "pack.log").open("wb") as log:
            command = subprocess.run(["hc", "dna", "pack", str(workdir)],
                                     cwd=staging, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT,
                                     timeout=300, check=False)
        require(command.returncode == 0, f"hc dna pack failed: exit {command.returncode}")
        packed = workdir / "vtime.dna"
        require(packed.is_file() and packed.stat().st_size > 0,
                "DNA pack returned without a bundle")
        shutil.copyfile(packed, output / "vtime.dna")
        result = {
            "schema": "hc-vtime/guarded-release-pack/v1",
            "status": "PACKED_BUT_NOT_DEPLOYED", "environment": args.environment,
            "source_commit_sha": git_sha,
            "dna_manifest_sha256": pre["manifest_sha256"],
            "policy_sha256": pre["policy_sha256"],
            "approval_record_sha256": pre["approval_record_sha256"],
            "insecure_key_catalog_sha256": pre["insecure_key_catalog_sha256"],
            "wasm": wasm, "dna_bundle_sha256": sha256((output / "vtime.dna").read_bytes()),
            "operator_independence_proven": False, "network_installation_proven": False,
            "note": "Verify real external signed receipts and independently review approvals before installation."
        }
        (output / "preflight.json").write_text(
            json.dumps(pre, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (output / "pack.json").write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        with (output / "SHA256SUMS").open("w", encoding="utf-8") as sums:
            for file in sorted(output.iterdir()):
                if file.is_file() and file.name != "SHA256SUMS":
                    sums.write(f"{sha256(file.read_bytes())}  {file.name}\n")
        return result
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--approval", type=Path)
    ap.add_argument("--environment", choices=("production", "staging", "development"), required=True)
    ap.add_argument("--expected-manifest-sha256")
    ap.add_argument("--expected-policy-sha256")
    ap.add_argument("--expected-integrity-wasm-sha256")
    ap.add_argument("--expected-coordinator-wasm-sha256")
    ap.add_argument("--expected-commit-sha")
    ap.add_argument("--allow-development-test-keys", action="store_true")
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        result = pack(args)
    except (OSError, PreflightError, ValueError, TypeError,
            subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc),
                          "operator_independence_proven": False,
                          "network_installation_proven": False}, sort_keys=True))
        return 3
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
