#!/usr/bin/env python3
"""Sprint 27: exact-SHA combined acceptance, not production certification.

Runs existing exact-commit integration tooling and, only when present in the
SAME checkout, the specialized Holochain acceptance runners. Never deploys,
funds Unyt, changes Git refs, or marks release_ready true. Stdlib only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from integration_validate import check_source, sha_file

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hc-vtime/sprint27-combined-acceptance/v1"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
STEP_ORDER = (
    "source", "reviewed_ancestry", "python_tests", "rust_format", "conductor_format",
    "rust_tests", "clippy", "wasm", "signed_quorum", "fresh_dna",
    "config_negative", "restart_recovery", "fork_warrant",
    "concurrent_seals", "oracle_journal", "oracle_runtime_restart_replay",
    "funded_unyt",
)
CORE = {
    "reviewed_ancestry": "ancestry", "python_tests": "python_tests",
    "rust_format": "workspace_format", "conductor_format": "conductor_format",
    "rust_tests": "native_tests", "clippy": "clippy", "wasm": "wasm",
    "signed_quorum": "signed_conductor", "fresh_dna": "fresh_dna",
}
GITHUB_BLOCKERS = {
    "release_gate": "https://github.com/ConorTttttt/Holochain-Time/issues/1",
    "throughput": "https://github.com/ConorTttttt/Holochain-Time/issues/5",
    "conductor": "https://github.com/ConorTttttt/Holochain-Time/issues/7",
    "actions_runner": "https://github.com/ConorTttttt/Holochain-Time/issues/22",
    "unyt_protocol": "https://github.com/ConorTttttt/Holochain-Time/issues/61",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def gate(state: str, reason: str, classification: str, **extra) -> dict:
    if state not in ("PASS", "FAIL", "NOT RUN"):
        raise ValueError("invalid gate state")
    return {"status": state, "classification": classification, "reason": reason, **extra}


def missing(reason: str, category: str = "BLOCKED_DEPENDENCY") -> dict:
    return gate("NOT RUN", reason, category)


def read_json(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8_000_000:
        raise ValueError(f"missing/unsafe evidence file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object in {path}")
    return data


def get_sha(repo: Path) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "HEAD^{commit}"],
                           capture_output=True, text=True, check=False, timeout=15)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def command(name: str, args: list[str], repo: Path, out: Path,
            timeout: int = 3600, env: dict | None = None,
            tools: tuple[str, ...] = ()) -> dict:
    absent = [tool for tool in tools if shutil.which(tool) is None]
    if absent:
        return missing("missing required executables: " + ", ".join(absent), "MISSING_TOOL")
    log = out / (name + ".log")
    started = time.monotonic()
    try:
        with log.open("xb") as stream:
            p = subprocess.run(args, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                               stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                               check=False)
        state = "PASS" if p.returncode == 0 else "FAIL"
        return gate(state, f"command exited {p.returncode}",
                    "EXECUTED_PASS" if state == "PASS" else "EXECUTED_FAILURE",
                    command=args, exit_code=p.returncode, elapsed_seconds=round(time.monotonic()-started, 2),
                    log=log.name, log_sha256=sha_file(log))
    except subprocess.TimeoutExpired:
        return gate("FAIL", f"command timed out after {timeout}s", "EXECUTED_TIMEOUT",
                    command=args, log=log.name, log_sha256=sha_file(log),
                    elapsed_seconds=round(time.monotonic()-started, 2))
    except (OSError, ValueError) as exc:
        return missing(f"command never started: {exc}", "STARTUP_FAILURE")


def audited_core(path: Path, sha: str, repo: Path) -> tuple[dict, dict]:
    """Reject a superficially green wrapper without the expected exact-SHA artifacts."""
    raw = read_json(path / "report.json")
    if raw.get("schema") != "hc-vtime/local-integration-report/v1" or raw.get("candidate_sha") != sha:
        raise ValueError("Sprint 17 report schema/commit mismatch")
    checks = raw.get("checks", {})
    if (not isinstance(checks, dict)
            or not isinstance(checks.get("source"), dict)
            or checks["source"].get("status") != "PASS"
            or raw.get("release_ready") is not False):
        raise ValueError("Sprint 17 source provenance or non-release verdict invalid")
    mapped = {}
    for destination, origin in CORE.items():
        item = checks.get(origin, {})
        status = item.get("status")
        if status == "PASS":
            if origin in ("python_tests", "workspace_format", "conductor_format", "native_tests",
                          "clippy", "wasm", "signed_conductor", "fresh_dna"):
                logfile = item.get("log")
                if not isinstance(logfile, str) or Path(logfile).name != logfile:
                    raise ValueError(f"{origin}: no executed log reference")
                logpath = path / logfile
                if not logpath.is_file() or sha_file(logpath) != item.get("log_sha256"):
                    raise ValueError(f"{origin}: executed log missing or modified")
            mapped[destination] = gate("PASS", item.get("reason", "verified stage"),
                                       "EXECUTED_PASS" if origin != "ancestry" else "PROVENANCE_PASS",
                                       sprint17_gate=origin, evidence=item)
        elif status in ("FAIL", "NOT RUN"):
            mapped[destination] = gate(status, item.get("reason", "unverified stage"),
                                       "EXECUTED_FAILURE" if status == "FAIL" else "NOT_EXECUTED",
                                       sprint17_gate=origin, evidence=item)
        else:
            raise ValueError(f"{origin}: unknown/missing status")
    if mapped["wasm"]["status"] == "PASS":
        for pkg in ("vtime_integrity", "vtime"):
            target = repo / "target/wasm32-unknown-unknown/release" / (pkg + ".wasm")
            if not target.is_file() or target.stat().st_size < 8 or target.read_bytes()[:4] != b"\x00asm":
                raise ValueError(f"{pkg}: WASM build reported PASS but valid artifact missing")
            mapped["wasm"].setdefault("artifact_sha256", {})[pkg] = sha_file(target)
    if mapped["signed_quorum"]["status"] == "PASS":
        signed = path / "signed"
        for file in ("vtime.dna", "dna.yaml", "keys-public.json", "provenance.txt",
                     "signed-quorum.log", "conductor-smoke.log"):
            if not (signed / file).is_file() or (signed / file).is_symlink():
                raise ValueError(f"signed quorum missing native evidence {file}")
        provenance = (signed / "provenance.txt").read_text(encoding="utf-8")
        for marker in (f"git_sha={sha}", "signed_quorum_command_exit=0",
                       "conductor_smoke_command_exit=0"):
            if marker not in provenance.splitlines():
                raise ValueError("signed quorum origin/actual executed status not proven: " + marker)
        mapped["signed_quorum"]["test_dna_sha256"] = sha_file(signed / "vtime.dna")
    if mapped["fresh_dna"]["status"] == "PASS":
        dna = read_json(path / "fresh-dna/dna-comparison.json")
        if (dna.get("expected_sha") != sha or dna.get("status") != "PASS"
                or dna.get("checks", {}).get("archive_byte_identical") is not True):
            raise ValueError("fresh DNA independent pack did not verify exact SHA and byte equality")
        first = path / "signed/vtime.dna"
        second = path / "fresh-dna/fresh-vtime.dna"
        if not first.is_file() or not second.is_file() or first.read_bytes() != second.read_bytes():
            raise ValueError("fresh DNA artifact differs from signed conductor DNA")
        mapped["fresh_dna"]["packed_dna_sha256"] = sha_file(second)
    return mapped, raw.get("ci", {})


def negative_configuration(repo: Path, out: Path) -> dict:
    """Passing unit tests alone does not prove unsafe production example rejects."""
    stage = command("config_tests",
                    [sys.executable, "-B", "-m", "unittest", "scripts.test_deployment_preflight", "-v"],
                    repo, out, timeout=600, tools=("python3",))
    if stage["status"] != "PASS":
        return stage
    args = [sys.executable, "-B", "scripts/deployment_preflight.py",
            "--environment", "production",
            "--manifest", "deployment/environments/production.dna.example.yaml",
            "--policy", "deployment/environments/production.policy.example.json"]
    check = command("config_invalid_example", args, repo, out, timeout=90, tools=("python3",))
    if check["status"] == "NOT RUN":
        return check
    if check["status"] != "FAIL" or check.get("exit_code") != 3:
        return gate("FAIL", "unsafe production example was not rejected with preflight exit 3",
                    "POLICY_VIOLATION", test=stage, attempt=check)
    log = (out / "config_invalid_example.log").read_text(encoding="utf-8")
    try:
        result = json.loads(log)
    except json.JSONDecodeError:
        return gate("FAIL", "invalid-production rejection had no structured BLOCKED result",
                    "INVALID_EVIDENCE", test=stage, attempt=check)
    if result.get("status") != "BLOCKED" or result.get("safe_to_install_proven") is not False:
        return gate("FAIL", "unsafe example rejection semantics not confirmed", "INVALID_EVIDENCE",
                    test=stage, attempt=check)
    return gate("PASS", "offline negative config suite executed and unsafe production blocked",
                "EXECUTED_PASS", test=stage, rejection=check)


def rust_recovery(repo: Path, out: Path, dna: Path) -> dict:
    env = os.environ.copy()
    env.update({"HC_VTIME_TEST_DNA": str(dna), "HC_VTIME_SIGNED_TEST_ONLY": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    result = command("restart_recovery",
                     ["cargo", "test", "--manifest-path", "integration/conductor/Cargo.toml",
                      "--locked", "--test", "resilience", "--", "--nocapture", "--test-threads=1"],
                     repo, out, timeout=1800, env=env, tools=("cargo",))
    if result["status"] != "PASS":
        return result
    log = (out / "restart_recovery.log").read_text(encoding="utf-8", errors="replace")
    tests = ("stop_restart_recovers_signed_proofs_and_missing_witnesses_fail_closed",
             "disabled_bootstrap_isolation_then_manual_peer_rejoin")
    if not all(re.search(r"test " + t + r" \.\.\. ok\b", log) for t in tests):
        return gate("FAIL", "required real conductor restart/rejoin tests not seen as executed",
                    "INVALID_EVIDENCE", run=result)
    return gate("PASS", "real signed-conductor recovery/rejoin tests executed",
                "EXECUTED_PASS", run=result, observed_tests=list(tests))


def external_report(log_path: Path, label: str, parent: Path) -> Path:
    log = log_path.read_text(encoding="utf-8", errors="replace")
    found = re.findall(re.escape(label) + r": (.+?) \(failed", log)
    if len(found) != 1:
        raise ValueError("runner did not report one unique new evidence directory")
    raw_path = Path(found[0])
    if raw_path.is_symlink():
        raise ValueError("runner evidence directory cannot be a symlink")
    path = raw_path.resolve()
    if path.parent != parent or not path.is_dir():
        raise ValueError("runner evidence directory is outside allowed parent")
    return path


def native_report_files(folder: Path) -> str:
    """Verify the specialized runner's complete immutable SHA256SUMS inventory."""
    sums = folder / "SHA256SUMS"
    if not sums.is_file() or sums.is_symlink():
        raise ValueError("specialized runner has no checksum manifest")
    rows = sums.read_text(encoding="utf-8").splitlines()
    if not rows:
        raise ValueError("specialized runner checksums empty")
    referenced = set()
    for row in rows:
        m = re.fullmatch(r"([a-f0-9]{64})  (.+)", row)
        if not m:
            raise ValueError("malformed external SHA256SUMS")
        relative = Path(m[2])
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in referenced:
            raise ValueError("unsafe/duplicate external evidence path")
        source = folder / relative
        if source.is_symlink() or not source.is_file() or source.resolve().parent != folder.resolve():
            raise ValueError("external native evidence entry missing or linked")
        if sha_file(source) != m[1]:
            raise ValueError("external native evidence changed after checksum")
        referenced.add(relative.as_posix())
    present = {str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file()
               and p.name != "SHA256SUMS"}
    if present != referenced:
        raise ValueError("external evidence checksum inventory incomplete")
    return sha_file(sums)


def run_fork(repo: Path, out: Path, sha: str, dna: Path, *, enabled: bool) -> dict:
    script = repo / "scripts/run_fork_recovery.sh"
    if not script.is_file():
        return missing("Sprint 22 fork/warrant runner not integrated at this SHA", "NOT_IN_CANDIDATE")
    if not enabled:
        return missing("real same-agent fork lab requires explicit --enable-fork-lab",
                       "OPERATOR_OPT_IN_REQUIRED")
    result = command("fork_warrant",
                     ["bash", str(script), "--expected-sha", sha, "--dna", str(dna),
                      "--ack-public-test-keys", "--full", "--allow-same-key-fork-lab"],
                     repo, out, timeout=3600, tools=("bash", "cargo", "python3", "rustc", "git", "sha256sum"))
    if result["status"] != "PASS":
        return result
    try:
        folder = external_report(out / "fork_warrant.log", "Fork/recovery report", repo.parent)
        if not folder.name.startswith("hc-vtime-fork-recovery-" + sha[:12] + "-"):
            raise ValueError("fork evidence name does not bind expected commit")
        sums_sha = native_report_files(folder)
        audit = read_json(folder / "audit.json")
        if (audit.get("schema") != "hc-vtime-sprint22-audit-v1"
                or audit.get("status") != "FORK_WARRANT_RESTART_PASS"
                or audit.get("warrant_detection_proven") is not True):
            raise ValueError("actual positive DHT warrant not established by Sprint 22 audit")
        if f"git_sha={sha}" not in (folder / "provenance.txt").read_text().splitlines():
            raise ValueError("fork evidence is from a different checkout")
        return gate("PASS", "full real-conductor fork with positive warrant evidence",
                    "EXECUTED_PASS", run=result, external_audit_sha256=sha_file(folder / "audit.json"),
                    external_checksums_sha256=sums_sha, external_report=str(folder),
                    warrant_detection_proven=True)
    except (OSError, ValueError, KeyError) as exc:
        return gate("FAIL", str(exc), "INVALID_EVIDENCE", run=result)


def run_load(repo: Path, out: Path, sha: str, dna: Path, attempts: int) -> dict:
    script = repo / "scripts/load/run_21.py"
    if not script.is_file():
        return missing("Sprint 21 >=100 queued seal runner not integrated at this SHA",
                       "NOT_IN_CANDIDATE")
    destination = out / "throughput"
    run = command("concurrent_seals",
                  [sys.executable, "-B", str(script), "--dna", str(dna),
                   "--expected-sha", sha, "--attempts", str(attempts),
                   "--insecure-test-fixtures", "--out", str(destination)],
                  repo, out, timeout=3900, tools=("cargo", "python3", "rustc", "git"))
    if run["status"] != "PASS":
        return run
    try:
        record = read_json(destination / "report.json")
        numbers = record.get("queued_gate")
        if not isinstance(numbers, dict):
            raise ValueError("seal throughput queued_gate is not an executed result")
        if (record.get("schema") != "hc-vtime/sprint21-seal-throughput/v1"
                or record.get("commit") != sha or record.get("status") != "PASS"
                or numbers.get("status") != "PASS" or numbers.get("successful", 0) < 100
                or numbers.get("unique_action_hashes", 0) < 100
                or numbers.get("third_party_verified_receipts", 0) < 12
                or record.get("requested") != attempts or not (destination / "samples.csv").is_file()
                or record.get("dna_sha256") != sha_file(dna)):
            raise ValueError("real seal samples/unique hashes/third-party checks insufficient")
        return gate("PASS", ">=100 real successful concurrent callers, signed seals and third-party checks",
                    "EXECUTED_PASS", run=run, attempts=attempts,
                    successes=numbers["successful"], third_party=numbers["third_party_verified_receipts"],
                    samples_sha256=sha_file(destination / "samples.csv"),
                    measured_report_sha256=sha_file(destination / "report.json"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return gate("FAIL", str(exc), "INVALID_EVIDENCE", run=run)


def run_oracle_journal(repo: Path, out: Path, sha: str) -> dict:
    script = repo / "scripts/oracle_state/run.sh"
    if not script.is_file():
        return missing("Sprint 24 oracle persistent journal not integrated at this SHA",
                       "NOT_IN_CANDIDATE")
    run = command("oracle_journal", ["bash", str(script), "--expected-sha", sha],
                  repo, out, timeout=3600, tools=("cargo", "bash", "python3", "rustc", "git", "sha256sum", "uname"))
    if run["status"] != "PASS":
        return run
    try:
        folder = external_report(out / "oracle_journal.log", "Sprint 24 evidence", repo.parent)
        if not folder.name.startswith("hc-vtime-oracle-s24-" + sha[:12] + "-"):
            raise ValueError("oracle journal evidence name does not bind expected commit")
        sums_sha = native_report_files(folder)
        record = read_json(folder / "audit.json")
        if (record.get("schema") != "hc-vtime-sprint24-audit-v1"
                or record.get("status") != "LOCAL_PERSISTENCE_REGRESSION_PASS"
                or record.get("git_sha") != sha
                or record.get("durable_state_tests_executed") is not True
                or record.get("real_conductor_signing_integration_proven") is not False):
            raise ValueError("oracle journal native restart/crash/replay evidence invalid")
        return gate("PASS", "native durable-journal recovery/replay tests executed (NOT runtime integration)",
                    "EXECUTED_PASS", run=run, audit_sha256=sha_file(folder / "audit.json"), checksums_sha256=sums_sha,
                    external_report=str(folder), runtime_integrated=False)
    except (OSError, ValueError, KeyError) as exc:
        return gate("FAIL", str(exc), "INVALID_EVIDENCE", run=run)


def overall(checks: dict) -> str:
    if any(v["status"] == "FAIL" for v in checks.values()):
        return "FAIL"
    if any(v["status"] == "NOT RUN" for v in checks.values()):
        return "INCOMPLETE"
    return "LOCAL_TESTS_COMPLETE_NO_RELEASE_APPROVAL"


def write_reports(out: Path, report: dict) -> None:
    lines = [
        "# Sprint 27 — Combined Holochain Time acceptance", "",
        f"**Exact SHA:** `{report['candidate_sha']}`",
        f"**Local verdict:** **{report['overall']}**",
        "**Production release:** **NO-GO** (never certified by this runner)",
        f"**GitHub Actions:** {report['ci']['status']} — {report['ci']['classification']}",
        "",
        "| Gate | Result | Classification | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for name in STEP_ORDER:
        check = report["checks"][name]
        reason = str(check.get("reason", "")).replace("|", "/").replace("\n", " ")
        lines.append(f"| {name} | {check['status']} | {check['classification']} | {reason} |")
    lines.extend(["", "## Unresolved release blockers", ""])
    lines.extend("- " + b["reason"] + " (" + b["reference"] + ")"
                 for b in report["release_blockers"])
    lines.extend(["", "No funded Unyt result or independent production security/economic review is implied.",
                  "Signed test-DNA fixtures use deliberately insecure local keys.", ""])
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
    sums = []
    for file in sorted(out.rglob("*")):
        if file.is_symlink():
            raise ValueError("evidence directory contains symlink: " + str(file))
        if file.is_file() and file.name != "SHA256SUMS":
            sums.append(f"{sha_file(file)}  {file.relative_to(out).as_posix()}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=ROOT)
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--pins", type=Path, help="independently reviewed remote tip manifest required by Sprint 17")
    ap.add_argument("--report-dir", type=Path, help="new path outside checkout (never overwrites)")
    ap.add_argument("--ci-run-id", type=int)
    ap.add_argument("--attempts", type=int, default=120)
    ap.add_argument("--enable-fork-lab", action="store_true",
                    help="authorize destructive SAME-AGENT fork on test-only DNA, never production")
    ap.add_argument("--unyt-evidence", type=Path,
                    help="optional LOCAL evidence index for independent reviewer; NOT auto-accepted")
    args = ap.parse_args(argv)
    repo = args.repo.resolve()
    if not SHA40.fullmatch(args.expected_sha) or args.attempts < 100 or args.attempts > 2000:
        ap.error("expected SHA must be 40 lowercase hex; --attempts must be 100..2000")
    if not repo.is_dir():
        ap.error("repository does not exist")
    out = args.report_dir.resolve() if args.report_dir else Path(
        tempfile.mkdtemp(prefix="hc-vtime-sprint27-", dir=repo.parent))
    if out == repo or repo in out.parents or out.is_symlink():
        ap.error("report must be outside checkout")
    if args.report_dir:
        if out.exists():
            ap.error("report path must not already exist")
        out.mkdir(parents=True)
    os.chmod(out, 0o700)
    report = {"schema": SCHEMA, "candidate_sha": args.expected_sha, "started_at_utc": now(),
              "completed_at_utc": None, "checks": {}, "ci": missing("CI not audited", "NO_CI_RUN"),
              "release_ready": False, "financial_release_allowed": False,
              "source_checkout_modified": False, "overall": "INCOMPLETE",
              "provenance": {"git_head_at_start": get_sha(repo),
                             "cargo_lock_sha256": (sha_file(repo / "Cargo.lock")
                                                   if (repo / "Cargo.lock").is_file() else None)},
              "release_blockers": []}
    checks = report["checks"]
    try:
        source = check_source(repo, args.expected_sha)
        checks["source"] = gate(source["status"], source["reason"],
                                "PROVENANCE_PASS" if source["status"] == "PASS" else "PROVENANCE_FAILURE",
                                evidence=source)
        if checks["source"]["status"] == "PASS":
            if args.pins is None:
                checks.update({name: missing("reviewed --pins required before combined execution",
                                             "MISSING_REVIEWED_PINS")
                               for name in CORE})
            else:
                cmd = [sys.executable, "-B", "scripts/integration_validate.py",
                       "--repo", str(repo), "--expected-sha", args.expected_sha,
                       "--pins", str(args.pins.resolve()), "--report-dir", str(out / "sprint17")]
                if args.ci_run_id is not None:
                    cmd.extend(["--ci-run-id", str(args.ci_run_id)])
                runner = command("sprint17_entrypoint", cmd, repo, out, timeout=14400,
                                 tools=("python3", "git"))
                report["sprint17_invocation"] = runner
                if (out / "sprint17/report.json").is_file():
                    try:
                        mapped, ci = audited_core(out / "sprint17", args.expected_sha, repo)
                        checks.update(mapped)
                        report["ci"] = gate(ci.get("status", "NOT RUN"), ci.get("reason", "no CI evidence"),
                                            ("CI_BEFORE_RUNNER" if ci.get("audit_state") == "before_runner"
                                             else "CI_EXECUTED" if ci.get("status") == "PASS"
                                             else "CI_PENDING_OR_UNVERIFIED" if ci.get("status") == "NOT RUN"
                                             else "CI_EXECUTED_FAILURE"), original=ci)
                        if runner["status"] == "FAIL" and all(
                                x["status"] == "PASS" for x in mapped.values()):
                            checks["reviewed_ancestry"] = gate(
                                "FAIL", "Sprint 17 process failed despite all reported PASS",
                                "INVALID_EVIDENCE")
                    except (OSError, ValueError, TypeError, KeyError) as exc:
                        checks.update({name: gate("FAIL", f"untrusted Sprint 17 output: {exc}",
                                                  "INVALID_EVIDENCE") for name in CORE})
                else:
                    checks.update({name: (gate("FAIL", "Sprint 17 ran but did not emit a report",
                                               "INVALID_EVIDENCE") if runner["status"] == "FAIL"
                                          else missing("Sprint 17 could not start", "STARTUP_FAILURE"))
                                   for name in CORE})
            checks["config_negative"] = negative_configuration(repo, out)
            deps = (checks.get("wasm", {}).get("status") == "PASS"
                    and checks.get("signed_quorum", {}).get("status") == "PASS"
                    and checks.get("fresh_dna", {}).get("status") == "PASS")
            if deps:
                dna = out / "sprint17/signed/vtime.dna"
                checks["restart_recovery"] = rust_recovery(repo, out, dna)
                checks["fork_warrant"] = run_fork(repo, out, args.expected_sha, dna,
                                                 enabled=args.enable_fork_lab)
                checks["concurrent_seals"] = run_load(repo, out, args.expected_sha,
                                                      dna, args.attempts)
                checks["oracle_journal"] = run_oracle_journal(repo, out, args.expected_sha)
            else:
                for name in ("restart_recovery", "fork_warrant", "concurrent_seals", "oracle_journal"):
                    checks[name] = missing("WASM/signed quorum/fresh DNA prerequisite not PASS")
        else:
            for name in (*CORE, "config_negative", "restart_recovery", "fork_warrant",
                         "concurrent_seals", "oracle_journal"):
                checks[name] = missing("source SHA/clean-worktree preflight failed")
        checks["oracle_runtime_restart_replay"] = missing(
            "native journal and conductor restart tests do not prove oracle signing runtime "
            "durability/replay integration or external anti-rollback", "PROTOCOL_INTEGRATION_PENDING")
        checks["funded_unyt"] = missing(
            "funded Unyt test-alliance RAVE + separate recipient Accept + peer validation "
            "requires authorized local operator and independent review",
            "EXTERNAL_FINANCIAL_ACCEPTANCE_PENDING")
        if args.unyt_evidence:
            evidence = args.unyt_evidence.resolve()
            if evidence.is_file() and not evidence.is_symlink():
                checks["funded_unyt"]["submitted_index_sha256"] = sha_file(evidence)
                checks["funded_unyt"]["submitted_index"] = str(evidence)
                checks["funded_unyt"]["reason"] += "; submitted file not authenticated"
            else:
                checks["funded_unyt"] = gate("FAIL", "supplied Unyt evidence file absent or symlink",
                                              "INVALID_EVIDENCE")
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        report["fatal_error"] = str(exc)
        checks.setdefault("source", gate("FAIL", str(exc), "RUNNER_FAILURE"))
    finally:
        for name in STEP_ORDER:
            checks.setdefault(name, missing("runner terminated before this gate", "RUNNER_INCOMPLETE"))
        report["completed_at_utc"] = now()
        report["provenance"]["git_head_at_end"] = get_sha(repo)
        try:
            dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain",
                                    "--untracked-files=all"], capture_output=True, text=True,
                                   check=False, timeout=20)
            report["source_checkout_modified"] = bool(dirty.returncode or dirty.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            report["source_checkout_modified"] = True
        if report["source_checkout_modified"]:
            checks["source"] = gate("FAIL", "source checkout became dirty during acceptance",
                                    "PROVENANCE_FAILURE")
        if report["provenance"]["git_head_at_end"] != args.expected_sha:
            checks["source"] = gate("FAIL", "HEAD changed during acceptance run",
                                    "PROVENANCE_FAILURE")
        report["overall"] = overall(checks)
        blockers = report["release_blockers"]
        for name in STEP_ORDER:
            if checks[name]["status"] != "PASS":
                reference = (GITHUB_BLOCKERS["unyt_protocol"] if name == "funded_unyt"
                             else GITHUB_BLOCKERS["throughput"] if name == "concurrent_seals"
                             else GITHUB_BLOCKERS["conductor"] if name in (
                                 "fork_warrant", "restart_recovery", "oracle_runtime_restart_replay")
                             else GITHUB_BLOCKERS["release_gate"])
                blockers.append({"gate": name, "reason": checks[name]["reason"],
                                 "classification": checks[name]["classification"],
                                 "reference": reference})
        if report["ci"]["status"] != "PASS":
            blockers.append({"gate": "github_actions", "reason": report["ci"]["reason"],
                             "classification": report["ci"]["classification"],
                             "reference": GITHUB_BLOCKERS["actions_runner"]})
        blockers.append({"gate": "independent_security_economic_review",
                         "reason": "external financial/security/economic release review not performed",
                         "classification": "EXTERNAL_REVIEW_PENDING",
                         "reference": GITHUB_BLOCKERS["release_gate"]})
        try:
            write_reports(out, report)
        except (OSError, ValueError) as exc:
            print(f"ERROR: unable to finalize evidence: {exc}", file=sys.stderr)
            return 1
    print(f"Sprint 27 {report['overall']} for {args.expected_sha}; production NO-GO")
    print("Evidence:", out)
    return 1 if report["overall"] == "FAIL" else 2 if report["overall"] == "INCOMPLETE" else 0


if __name__ == "__main__":
    sys.exit(main())
