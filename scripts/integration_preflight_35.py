#!/usr/bin/env python3
"""Sprints 28–35 Codex acceptance on a clean exact-SHA consolidated candidate.

Reuses Sprint 17 core and Sprint 27 evidence auditors; never promotes mock,
ignored, offline, or source-only results to live/production acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import integration_validate as s17
import release_acceptance_27 as s27
from make_reviewed_pins_35 import BASE, AUTHORITATIVE, validate_manifest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hc-vtime/integration-preflight-28-35/v1"
CORE = tuple(s27.CORE)
LEGACY = ("config_negative", "roughtime_offline", "monitoring_offline",
          "unyt_offline", "restart_recovery", "concurrent_seals", "oracle_journal")
NEW = ("s28_python", "s28_crypto", "s28_independent", "s28_interop",
       "s29_runtime", "s29_restart", "s29_process_crash", "s29_backup",
       "s30_admission", "s31_native", "s31_conductor_security",
       "s32_policy", "s32_native", "s33_python", "s33_audit",
       "s33_conductor", "conductor_tests", "conductor_clippy",
       "s34_incidents", "s35_source_package", "s35_supply_chain")
DEVELOPMENT = ("source", "reviewed_ancestry", *CORE[1:], *LEGACY, *NEW)
EXTERNAL = {
    "oracle_checkpoint": "actual external monotonic checkpoint and deployed signer replay not independently validated",
    "live_roughtime_operators": "live native-signed Roughtime, outage and distinct operator-control dossiers pending",
    "funded_unyt": "native RAVE, recipient-signed Accept, independent peer and funded execution pending",
    "actual_network_partition": "real isolated QUIC/Iroh network partition with signed app probe not executed",
    "dht_spam_10000": "separate opt-in real 10k-link feature-gated DHT stress lab not executed",
    "unclean_conductor_kill": "separate unclean standalone conductor kill/restart evidence not reviewed",
    "production_monitoring": "authenticated deployed runtime event hooks and live incident delivery not validated",
    "binary_reproducibility": "deterministic source archive is not byte-identical reproducible WASM/DNA/hApp",
    "independent_audit": "security, cryptographic and Unyt economic external approvals outstanding",
    "production_keys_configuration": "real key custody, signing integration and production configuration unapproved",
}


def gate(state: str, reason: str, classification: str, **extra) -> dict:
    return s27.gate(state, reason, classification, **extra)


def missing(reason: str, classification: str = "NOT_EXECUTED") -> dict:
    return s27.missing(reason, classification)


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stage(repo: Path, out: Path, name: str, argv: list[str], *,
          paths: tuple[str, ...] = (), tools: tuple[str, ...] = ("python3",),
          env: dict | None = None, timeout: int = 3600, kind: str = "python",
          required_names: tuple[str, ...] = ()) -> dict:
    """A zero exit is necessary, never sufficient: prove tests really executed."""
    for rel in paths:
        p = repo / rel
        if not p.is_file() or p.is_symlink():
            return missing(f"{name}: required integrated test/source absent: {rel}",
                           "NOT_IN_CANDIDATE")
    result = s27.command(name, argv, repo, out, timeout=timeout, env=env,
                         tools=tools)
    if result["status"] != "PASS":
        return result
    log = (out / (name + ".log")).read_text(encoding="utf-8", errors="replace")
    if kind == "python":
        seen = (re.search(r"\bRan\s+([1-9]\d*)\s+tests?\b", log)
                and re.search(r"^OK\s*$", log, re.M))
        failed = "FAILED (" in log or "Traceback (most recent call last)" in log
    elif kind == "rust":
        seen = re.search(r"test result: ok\.\s+[1-9]\d* passed; 0 failed;", log)
        failed = "test result: FAILED" in log
    else:
        raise ValueError("unknown stage kind")
    def test_seen(name: str) -> bool:
        expr = (r"\b" + re.escape(name) +
                (r"\b[^\n]*\.\.\.\s+ok\b" if kind == "python"
                 else r"\s+\.\.\.\s+ok\b"))
        return bool(re.search(expr, log))
    if not seen or failed or any(not test_seen(name) for name in required_names):
        return gate("FAIL", "zero/missing required executed tests or failed suite",
                    "INVALID_EVIDENCE", run=result, required_names=list(required_names))
    return gate("PASS", "native/offline tests executed, not production acceptance",
                "EXECUTED_PASS", run=result, execution_kind=kind,
                required_names=list(required_names))


def python_tests(repo: Path, out: Path, name: str, folder: str,
                 pattern: str, required_path: str) -> dict:
    return stage(repo, out, name,
                 [sys.executable, "-B", "-m", "unittest", "discover",
                  "-s", folder, "-p", pattern, "-v"],
                 paths=(required_path,), tools=("python3",), kind="python",
                 timeout=1200)


def rust_tests(repo: Path, out: Path, name: str, argv: list[str],
               required_path: str, *, env: dict | None = None,
               required_names: tuple[str, ...] = ()) -> dict:
    return stage(repo, out, name, argv, paths=(required_path,),
                 tools=("cargo", "rustc"), kind="rust", env=env,
                 timeout=3600, required_names=required_names)


def validate_default_wasm(repo: Path, core: dict) -> None:
    """Disallow Sprint 31 feature-enabled test exports in default production WASM."""
    wasm = core["checks"]["wasm"]
    if wasm.get("status") != "PASS":
        return
    argv = wasm.get("command")
    if argv != ["cargo", "build", "--release", "--locked",
                "--target", "wasm32-unknown-unknown", "-p", "vtime_integrity",
                "-p", "vtime"]:
        raise ValueError("default WASM gate did not use production-default build command")
    for pkg in ("vtime_integrity", "vtime"):
        artifact = repo / "target/wasm32-unknown-unknown/release" / (pkg + ".wasm")
        if (not artifact.is_file() or artifact.stat().st_size < 8
                or artifact.read_bytes()[:4] != b"\x00asm"):
            raise ValueError("missing production-default WASM artifact: " + pkg)
        binary = artifact.read_bytes()
        if any(marker in binary for marker in (
                b"test_only_spam_seal_links", b"test_only_spam_anchor_links")):
            raise ValueError("test-only DHT exports contaminate production-default WASM")


def validate_reviewed_pin(repo: Path, manifest: dict, expected: str,
                          allow_partial: bool) -> dict:
    try:
        validate_manifest(manifest, candidate=expected, allow_partial=allow_partial)
        if not shutil.which("gh"):
            raise ValueError("authenticated gh CLI needed for fresh PR verification")
        fetched = subprocess.run(["git", "fetch", "origin", "--prune"], cwd=repo,
                                 capture_output=True, text=True, check=False, timeout=600)
        if fetched.returncode:
            raise ValueError("cannot refresh authoritative origin refs")
        if (s17.git_object(repo, "refs/remotes/origin/main") != BASE
                or s17.git(repo, "merge-base", "--is-ancestor", BASE, expected).returncode != 0):
            raise ValueError("origin/main changed or base not candidate ancestor")
        for row in manifest["branches"]:
            sha = row["sha"]
            current = subprocess.run(
                ["gh", "api", f"repos/ConorTttttt/Holochain-Time/pulls/{row['pr']}"],
                cwd=repo, capture_output=True, text=True, check=False, timeout=90)
            if current.returncode:
                raise ValueError(f"PR #{row['pr']}: LIVE GitHub HEAD unavailable")
            live = json.loads(current.stdout)
            if (live.get("state") != "open"
                    or live.get("head", {}).get("sha") != sha
                    or live.get("head", {}).get("ref") != row["branch"]
                    or live.get("head", {}).get("repo", {}).get("full_name")
                    != "ConorTttttt/Holochain-Time"):
                raise ValueError(f"PR #{row['pr']}: live HEAD moved or changed identity")
            actual = s17.git_object(repo, "refs/remotes/origin/" + row["branch"])
            if actual != sha:
                raise ValueError(f"PR #{row['pr']}: remote tracking tip missing/moved")
            for left, right, required in ((BASE, sha, True),
                                          (sha, expected, row["included"])):
                rc = s17.git(repo, "merge-base", "--is-ancestor", left, right).returncode
                if rc not in (0, 1) or (rc == 0) != required:
                    raise ValueError(f"PR #{row['pr']}: candidate ancestry differs from review")
        excludes = ["^" + BASE] + ["^" + row["sha"] for row in manifest["branches"]]
        extras = s17.git(repo, "rev-list", "--reverse", expected, *excludes)
        if extras.returncode or extras.stdout.split() != manifest["integration_only_commits"]:
            raise ValueError("unexpected integration-only commits in candidate")
        return gate("PASS", "all eight PR identities/scopes and exact local refs/ancestry verified",
                    "PROVENANCE_PASS", branches=manifest["branches"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return gate("FAIL", str(exc), "PROVENANCE_FAILURE")


def audit_source_package(repo: Path, out: Path, sha: str) -> dict:
    script = "scripts/audit35/run_local.sh"
    runner = repo / script
    if not runner.is_file() or runner.is_symlink():
        return missing("Sprint 35 local source/package runner not integrated", "NOT_IN_CANDIDATE")
    bundle = out / "source-bundle"
    run = s27.command("s35_source_package", ["bash", script, sha, str(bundle)],
                      repo, out, timeout=1800, tools=("bash", "python3", "git"))
    if run["status"] != "PASS":
        return run
    try:
        log = (out / "s35_source_package.log").read_text(errors="replace")
        if (f"SOURCE_AUDIT_BUNDLE_VERIFIED_ONLY sha={sha}" not in log
                or "PRODUCTION_RELEASE=NO-GO" not in log
                or not re.search(r"\bRan\s+[1-9]\d*\s+tests?\b", log)
                or not re.search(r"^OK\s*$", log, re.M)):
            raise ValueError("source packaging script did not execute required regressions")
        required = {"source.tar.gz", "dependencies.json", "provenance.json", "SHA256SUMS"}
        if {p.name for p in bundle.iterdir()} != required:
            raise ValueError("incomplete source package evidence")
        for name in required:
            if (bundle / name).is_symlink() or not (bundle / name).is_file():
                raise ValueError("invalid source evidence member")
        lines = (bundle / "SHA256SUMS").read_text().splitlines()
        expected_rows = {f"{s17.sha_file(bundle / filename)}  {filename}"
                         for filename in required - {"SHA256SUMS"}}
        if set(lines) != expected_rows or len(lines) != len(expected_rows):
            raise ValueError("source package checksum inventory missing, forged or altered")
        proven = json.loads((bundle / "provenance.json").read_text())
        if proven.get("git_sha", proven.get("source_commit")) != sha:
            raise ValueError("source packaging exact SHA mismatch")
        return gate("PASS", "reproduced source archive ONLY, not binary reproducibility",
                    "EXECUTED_PASS", run=run, package_sha256=s17.sha_file(
                        bundle / "source.tar.gz"), binary_reproducible=False)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return gate("FAIL", str(exc), "INVALID_EVIDENCE", run=run)


def audit_supply_chain(repo: Path, out: Path, sha: str) -> dict:
    script = "scripts/audit35/supply_chain.py"
    if not (repo / script).is_file():
        return missing("Sprint 35 supply-chain runner missing", "NOT_IN_CANDIDATE")
    dest = out / "supply-chain"
    run = s27.command("s35_supply_chain",
                      [sys.executable, "-B", script, "--expected-sha", sha,
                       "--output-dir", str(dest)], repo, out, timeout=4500,
                      tools=("python3", "git"))
    if run["status"] == "NOT RUN":
        return run
    try:
        record = s27.read_json(dest / "report.json")
        if (record.get("schema") != "hc-vtime/sprint35-supply-chain-run/v1"
                or record.get("source_commit") != sha
                or record.get("production_release_ready") is not False):
            raise ValueError("supply-chain report provenance/claims invalid")
        stages = record.get("stages")
        names = {"metadata_workspace", "metadata_conductor", "metadata_load",
                 "rustsec_workspace", "rustsec_conductor", "rustsec_load",
                 "license_and_source_policy"}
        if not isinstance(stages, dict) or set(stages) != names:
            raise ValueError("missing/extra supply-chain audit stages")
        for item in stages.values():
            if item.get("status") == "PASS":
                logfile = item.get("log")
                if (type(item.get("exit_code")) is not int or item["exit_code"] != 0
                        or not isinstance(logfile, str)
                        or Path(logfile).name != logfile
                        or s17.sha_file(dest / logfile) != item.get("log_sha256")):
                    raise ValueError("unexecuted/fabricated supply-chain PASS")
        if any(item.get("status") == "FAIL" for item in stages.values()):
            return gate("FAIL", "supply-chain command failed", "EXECUTED_FAILURE",
                        run=run, stages=stages)
        if run["status"] != "PASS" or any(item["status"] != "PASS" for item in stages.values()):
            return missing("one or more cargo-audit, cargo-deny or metadata scans NOT RUN",
                           "MISSING_TOOL_OR_DEPENDENCY")
        return gate("PASS", "supply-chain scan commands executed; advisories require review",
                    "EXECUTED_PASS", run=run, stages=stages, advisory_reviewed=False)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return gate("FAIL", str(exc), "INVALID_EVIDENCE", run=run)


def audit_ops34(repo: Path, out: Path, sha: str) -> dict:
    script = "scripts/run_sprint34.sh"
    if not (repo / script).is_file():
        return missing("Sprint 34 incident drill runner absent", "NOT_IN_CANDIDATE")
    folder = out / "ops34"
    run = s27.command("s34_incidents", ["bash", script], repo, out,
                      env={**os.environ, "HC_VTIME_EXPECTED_SHA": sha,
                           "HC_VTIME_SPRINT34_REPORT_DIR": str(folder),
                           "PYTHONDONTWRITEBYTECODE": "1"},
                      timeout=1800, tools=("bash", "python3", "git", "sha256sum"))
    if run["status"] != "PASS":
        return run
    try:
        audit = s27.read_json(folder / "audit.json")
        if (audit.get("status") != "INJECTED_INCIDENTS_PASS"
                or audit.get("exact_git_sha") != sha
                or audit.get("production_release_ready") is not False):
            raise ValueError("injected incident audit does not match exact candidate")
        sums = (folder / "SHA256SUMS").read_text().splitlines()
        if not sums:
            raise ValueError("incident exercise has no hash inventory")
        seen_paths = set()
        for item in sums:
            match = re.fullmatch(r"([a-f0-9]{64})  (.+)", item)
            if not match:
                raise ValueError("invalid incident hash row")
            rel = Path(match[2])
            if rel.is_absolute() or ".." in rel.parts or str(rel) in seen_paths:
                raise ValueError("unsafe/duplicate incident evidence path")
            seen_paths.add(str(rel))
            target = folder / rel
            if (not target.is_file() or target.is_symlink()
                    or s17.sha_file(target) != match[1]):
                raise ValueError("incident evidence changed or missing")
        present = {str(f.relative_to(folder)) for f in folder.rglob("*")
                   if f.is_file() and f.name != "SHA256SUMS"}
        if seen_paths != present:
            raise ValueError("incident exercise hash inventory is incomplete")
        return gate("PASS", "authenticated TEST-only injected alerts, not live runtime",
                    "EXECUTED_PASS", run=run, audit_sha256=s17.sha_file(
                        folder / "audit.json"), real_runtime_verified=False)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return gate("FAIL", str(exc), "INVALID_EVIDENCE", run=run)


def readiness(checks: dict, *, complete: bool) -> tuple[bool, str, list[dict]]:
    blockers = []
    if not complete:
        blockers.append({"gate": "reviewed_scope", "status": "NOT RUN",
                         "classification": "REVIEWED_PARTIAL_ONLY",
                         "reason": "partial integration is not eight-PR consolidation"})
    for name in DEVELOPMENT:
        item = checks.get(name, {})
        state = item.get("status", "NOT RUN")
        if state not in ("PASS", "FAIL", "NOT RUN"):
            state = "FAIL"
        proven = state == "PASS" and item.get("classification") in (
            "PROVENANCE_PASS", "EXECUTED_PASS")
        if not proven:
            blockers.append({"gate": name, "status": state if state != "PASS" else "FAIL",
                             "classification": item.get("classification", "MISSING_RESULT"),
                             "reason": item.get("reason", "missing/untrusted gate")})
    verdict = ("FAILED" if any(b["status"] == "FAIL" for b in blockers)
               else "INCOMPLETE" if blockers else "READY")
    return not blockers, verdict, blockers


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=ROOT)
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--pins", required=True, type=Path)
    ap.add_argument("--report-dir", required=True, type=Path)
    ap.add_argument("--allow-partial", action="store_true")
    ap.add_argument("--native-only", action="store_true")
    ap.add_argument("--ci-run-id", type=int)
    ap.add_argument("--attempts", type=int, default=120)
    ap.add_argument("--enable-fork-lab", action="store_true")
    ap.add_argument("--confirm-disposable-test-only", action="store_true")
    args = ap.parse_args(argv)
    repo = args.repo.resolve()
    out = args.report_dir.expanduser().resolve()
    if (not repo.is_dir() or out.exists() or out.is_symlink()
            or out == repo or repo in out.parents or not s27.SHA40.fullmatch(args.expected_sha)
            or not 100 <= args.attempts <= 2000):
        ap.error("exact SHA, existing repo, unused external report and 100..2000 attempts required")
    if args.enable_fork_lab and not args.confirm_disposable_test_only:
        ap.error("fork lab requires --confirm-disposable-test-only and separate disposable keys")
    out.mkdir(parents=True)
    out.chmod(0o700)
    report = {"schema": SCHEMA, "baseline_main": BASE,
              "candidate_sha": args.expected_sha, "started_at_utc": utc(),
              "completed_at_utc": None, "checks": {}, "external_acceptance": {},
              "tool_versions": s27.tool_versions(), "ci": missing("no verified runner execution", "NO_CI_RUN"),
              "development_integration_ready": False, "development_integration_verdict": "INCOMPLETE",
              "production_release_ready": False, "production_release_verdict": "NO-GO",
              "development_blockers": [], "release_blockers": [],
              "binary_reproducibility_proven": False, "release_ready": False}
    checks = report["checks"]
    complete = False
    try:
        source = s17.check_source(repo, args.expected_sha)
        checks["source"] = gate(source["status"], source["reason"],
                                "PROVENANCE_PASS" if source["status"] == "PASS"
                                else "PROVENANCE_FAILURE", evidence=source)
        if checks["source"]["status"] != "PASS":
            raise ValueError("exact-SHA source check failed; no tests may be certified")
        if args.pins.is_symlink() or not args.pins.is_file() or args.pins.stat().st_size > 128_000:
            raise ValueError("reviewed pin manifest missing/unsafe")
        pins = args.pins.resolve()
        if pins == repo or repo in pins.parents:
            raise ValueError("pin manifest must be externally stored")
        manifest = s27.read_json(pins)
        checks["reviewed_ancestry"] = validate_reviewed_pin(
            repo, manifest, args.expected_sha, args.allow_partial)
        complete = manifest.get("development_scope_complete") is True
        report["reviewed_pins_sha256"] = s17.sha_file(pins)
        report["scope_mode"] = manifest.get("scope", {}).get("mode")
        report["authoritative_pr_heads"] = manifest.get("branches")
        if checks["reviewed_ancestry"]["status"] != "PASS":
            raise ValueError("reviewed eight-PR ancestry not proven; no tests may be certified")
        if not complete:
            raise ValueError("reviewed partial scope: full consolidation acceptance NOT RUN")
        # Reuse original Sprint 17 full default-feature native/WASM/signed-DNA pipeline.
        corepins = out / "core-pins.json"
        corepins.write_text(json.dumps({
            "schema": "hc-vtime/integration-pins/v1",
            "candidate_sha": args.expected_sha, "base": manifest["base"],
            "branches": [{"branch": row["branch"], "sha": row["sha"]}
                         for row in manifest["branches"]]}, indent=2) + "\n")
        cmd = [sys.executable, "-B", "scripts/integration_validate.py",
               "--repo", str(repo), "--expected-sha", args.expected_sha,
               "--pins", str(corepins), "--report-dir", str(out / "core")]
        if args.native_only:
            cmd.append("--native-only")
        if args.ci_run_id is not None:
            cmd.extend(["--ci-run-id", str(args.ci_run_id)])
        report["core_invocation"] = s27.command("core_entrypoint", cmd, repo, out,
                                                 timeout=14400, tools=("python3", "git"))
        if (out / "core/report.json").is_file():
            mapped, ci = s27.audited_core(out / "core", args.expected_sha, repo)
            checks.update(mapped)
            core_raw = s27.read_json(out / "core/report.json")
            validate_default_wasm(repo, core_raw)
            report["ci"] = gate(ci.get("status", "NOT RUN"),
                                ci.get("reason", "GitHub runner not verified"),
                                "CI_EXECUTED" if ci.get("status") == "PASS"
                                else "CI_NOT_RUN" if ci.get("status") == "NOT RUN"
                                else "CI_EXECUTED_FAILURE", original=ci)
            if report["core_invocation"]["status"] == "FAIL" and all(
                    row["status"] == "PASS" for row in mapped.values()):
                checks["reviewed_ancestry"] = gate(
                    "FAIL", "core wrapper failed despite green stages", "INVALID_EVIDENCE")
        else:
            raise ValueError("Sprint 17 core emitted no auditable exact-SHA report")
        checks["config_negative"] = s27.negative_configuration(repo, out)
        checks["roughtime_offline"] = s27.run_roughtime_offline(repo, out, args.expected_sha)
        checks["monitoring_offline"] = s27.run_monitoring_offline(repo, out, args.expected_sha)
        checks["unyt_offline"] = s27.run_unyt_offline(repo, out, args.expected_sha)

        checks["s28_python"] = python_tests(repo, out, "s28_python", "scripts/roughtime",
                                           "test_readiness_28.py",
                                           "scripts/roughtime/test_readiness_28.py")
        for name, suite in (("s28_crypto", "roughtime_acceptance"),
                            ("s28_independent", "independent_sources"),
                            ("s28_interop", "roughenough_interop")):
            checks[name] = rust_tests(repo, out, name,
                ["cargo", "test", "-p", "vtime_core", "--locked", "--test", suite],
                f"crates/vtime_core/tests/{suite}.rs")
        for name, suite in (("s29_runtime", "runtime_integration"),
                            ("s29_restart", "restart_safety"),
                            ("s29_process_crash", "process_crash"),
                            ("s29_backup", "backup_migration")):
            checks[name] = rust_tests(repo, out, name,
                ["cargo", "test", "-p", "vtime_oracle_state", "--locked", "--test", suite,
                 "--", "--test-threads=1"],
                f"crates/vtime_oracle_state/tests/{suite}.rs")
        checks["s30_admission"] = stage(
            repo, out, "s30_admission",
            [sys.executable, "-B", "-m", "unittest", "discover", "-s",
             "scripts/load", "-p", "test_admission30.py", "-v"],
            paths=("scripts/load/test_admission30.py",), tools=("python3",),
            kind="python",
            required_names=("test_sigkill_after_write_fence_requires_reconciliation",),
            timeout=1800)
        checks["s31_native"] = rust_tests(repo, out, "s31_native",
             ["cargo", "test", "-p", "vtime", "--locked", "--lib"],
             "dnas/vtime/zomes/coordinator/vtime/src/lib.rs")
        checks["s32_policy"] = python_tests(repo, out, "s32_policy",
             "scripts/unyt", "test_sprint32_protocol.py",
             "scripts/unyt/test_sprint32_protocol.py")
        checks["s32_native"] = rust_tests(repo, out, "s32_native",
             ["cargo", "test", "-p", "unyt_harness", "--locked"],
             "unyt/harness/src/native32.rs")
        checks["s33_python"] = python_tests(repo, out, "s33_python",
             "scripts", "test_chaos33*.py", "scripts/test_chaos33_netns.py")
        checks["s33_audit"] = python_tests(repo, out, "s33_audit",
             "scripts", "test_audit_chaos33.py", "scripts/test_audit_chaos33.py")
        checks["s34_incidents"] = audit_ops34(repo, out, args.expected_sha)
        checks["s35_source_package"] = audit_source_package(repo, out, args.expected_sha)
        checks["s35_supply_chain"] = audit_supply_chain(repo, out, args.expected_sha)
        signed_ok = all(checks.get(g, {}).get("status") == "PASS"
                        for g in ("wasm", "signed_quorum", "fresh_dna"))
        if signed_ok:
            dna = out / "core/signed/vtime.dna"
            checks["restart_recovery"] = s27.rust_recovery(repo, out, dna)
            checks["concurrent_seals"] = s27.run_load(repo, out, args.expected_sha,
                                                      dna, args.attempts)
            checks["oracle_journal"] = s27.run_oracle_journal(repo, out, args.expected_sha)
            env = {**os.environ, "HC_VTIME_SIGNED_TEST_ONLY": "1",
                   "HC_VTIME_TEST_DNA": str(dna), "PYTHONDONTWRITEBYTECODE": "1"}
            checks["s31_conductor_security"] = rust_tests(
                repo, out, "s31_conductor_security",
                ["cargo", "test", "--manifest-path", "integration/conductor/Cargo.toml",
                 "--locked", "--test", "security_witness", "--", "--test-threads=1"],
                "integration/conductor/tests/security_witness.rs", env=env)
            checks["s33_conductor"] = rust_tests(
                repo, out, "s33_conductor",
                ["cargo", "test", "--manifest-path", "integration/conductor/Cargo.toml",
                 "--locked", "--test", "chaos_recovery", "--", "--test-threads=1"],
                "integration/conductor/tests/chaos_recovery.rs", env=env,
                required_names=("delayed_dht_rejoin_retains_ancestry_and_rejects_false_witnesses",
                                "absence_of_author_health_never_becomes_clean_recovery"))
            checks["conductor_tests"] = rust_tests(
                repo, out, "conductor_tests",
                ["cargo", "test", "--manifest-path", "integration/conductor/Cargo.toml",
                 "--locked", "--", "--test-threads=1"],
                "integration/conductor/Cargo.toml", env=env)
            conductor_clippy = s27.command(
                "conductor_clippy",
                ["cargo", "clippy", "--manifest-path", "integration/conductor/Cargo.toml",
                 "--all-targets", "--locked", "--", "-D", "warnings"],
                repo, out, timeout=3600, tools=("cargo", "rustc"))
            if conductor_clippy["status"] == "PASS":
                checks["conductor_clippy"] = gate(
                    "PASS", "independent conductor clippy warnings denied",
                    "EXECUTED_PASS", run=conductor_clippy)
            else:
                checks["conductor_clippy"] = conductor_clippy
            report["fork_warrant"] = s27.run_fork(
                repo, out, args.expected_sha, dna, enabled=args.enable_fork_lab)
        else:
            for name in ("restart_recovery", "concurrent_seals", "oracle_journal",
                         "s31_conductor_security", "s33_conductor",
                         "conductor_tests", "conductor_clippy"):
                checks[name] = missing("signed default WASM, quorum and fresh DNA prerequisite NOT PASS",
                                       "DEPENDENCY_NOT_VERIFIED")
            report["fork_warrant"] = missing("requires signed default WASM + explicit authorization")
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        report["fatal_error"] = str(exc)
        checks.setdefault("reviewed_ancestry", gate("FAIL", str(exc), "PROVENANCE_FAILURE"))
    finally:
        for name in DEVELOPMENT:
            checks.setdefault(name, missing("missing test/dependency or runner did not reach gate"))
        source_final = s17.check_source(repo, args.expected_sha)
        if source_final["status"] != "PASS":
            checks["source"] = gate("FAIL", "checkout changed during acceptance",
                                    "PROVENANCE_FAILURE", evidence=source_final)
        ready, verdict, blockers = readiness(checks, complete=complete)
        report["development_integration_ready"] = ready
        report["development_integration_verdict"] = verdict
        report["development_blockers"] = blockers
        report["external_acceptance"] = {
            name: missing(reason, "EXTERNAL_INDEPENDENT_ACCEPTANCE_PENDING")
            for name, reason in EXTERNAL.items()}
        report["production_release_ready"] = False
        report["production_release_verdict"] = "NO-GO"
        report["release_blockers"] = [
            {"gate": name, "status": item["status"], "reason": item["reason"],
             "classification": item.get("classification", "UNKNOWN")}
            for name, item in checks.items() if item["status"] != "PASS"
        ] + [
            {"gate": name, "status": "NOT RUN", "reason": item["reason"],
             "classification": item["classification"]}
            for name, item in report["external_acceptance"].items()
        ]
        if report["ci"]["status"] != "PASS":
            report["release_blockers"].append({
                "gate": "github_actions", "status": report["ci"]["status"],
                "reason": report["ci"]["reason"],
                "classification": report["ci"]["classification"]})
        report["completed_at_utc"] = utc()
        try:
            lines = ["# Sprints 28–35 — exact-commit integration preflight", "",
                     f"Candidate: {args.expected_sha}",
                     f"Baseline main: {BASE}",
                     f"Development: {verdict}; production: NO-GO", "",
                     "| Gate | Status | Classification |",
                     "| --- | --- | --- |"]
            for name, item in checks.items():
                lines.append(f"| {name} | {item['status']} | {item.get('classification', '')} |")
            lines.extend(["", "External acceptance remains independent and unverified.",
                          "Production release remains NO-GO.", ""])
            (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
            (out / "report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            sums = [f"{s17.sha_file(p)}  {p.relative_to(out)}"
                    for p in sorted(out.rglob("*")) if p.is_file()
                    and p != out / "SHA256SUMS"]
            (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(f"REPORT FAILED: {exc}", file=sys.stderr)
            return 1
    print(f"Development {report['development_integration_verdict']} "
          f"| production NO-GO | SHA {args.expected_sha} | {out}")
    return {"READY": 0, "FAILED": 1, "INCOMPLETE": 2}[
        report["development_integration_verdict"]]


if __name__ == "__main__":
    sys.exit(main())
