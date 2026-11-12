#!/usr/bin/env python3
"""Single-command local validation of a reviewed, integrated Holochain Time SHA.

Never merges branches, updates main, deploys a DNA, or moves funds.
Writes PASS/FAIL/NOT RUN evidence outside the source checkout. A local PASS
does not imply external independence, live Roughtime, funded Unyt, or release
approval. Requires externally pinned and reviewed branch ancestry.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

SHA = re.compile(r"[a-f0-9]{40}\Z")
BRANCH = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._/-]*\Z")
SCHEMA = "hc-vtime/integration-pins/v1"
REQUIRED = (
    "source", "ancestry", "python_tests", "workspace_format",
    "conductor_format", "native_tests", "clippy", "wasm",
    "signed_conductor", "fresh_dna",
)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], text=True,
                          capture_output=True, check=False)


def git_object(repo, ref):
    result = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return result.stdout.strip() if result.returncode == 0 else None


def status(state, reason, **extra):
    assert state in ("PASS", "FAIL", "NOT RUN")
    return {"status": state, "reason": reason, **extra}


def check_source(repo, expected):
    if not SHA.fullmatch(expected):
        return status("FAIL", "expected SHA must be a full 40-character lowercase commit ID")
    if git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        return status("FAIL", "no local Git worktree found")
    head = git_object(repo, "HEAD")
    if head != expected:
        return status("FAIL", f"checkout HEAD {head} differs from expected {expected}")
    worktree = git(repo, "status", "--porcelain", "--untracked-files=all")
    if worktree.returncode or worktree.stdout.strip():
        return status("FAIL", "worktree is dirty (tracked or untracked source); commit or clean before certifying")
    unmerged = git(repo, "ls-files", "-u")
    if unmerged.returncode or unmerged.stdout.strip():
        return status("FAIL", "unmerged index entries present")
    if not (repo / "Cargo.lock").is_file():
        return status("FAIL", "Cargo.lock missing")
    if git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        return status("FAIL", "shallow checkout cannot prove complete ancestry; fetch unshallow history")
    return status("PASS", "exact checked-out commit; clean index and worktree", head=head,
                  cargo_lock_sha256=sha_file(repo / "Cargo.lock"))


def check_pins(repo, expected, pins_path):
    if pins_path is None:
        return status("NOT RUN", "no reviewed --pins file provided; ancestry cannot be certified")
    try:
        raw = pins_path.read_bytes()
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
            raise ValueError("invalid integration pin manifest schema")
        if manifest.get("candidate_sha") != expected:
            raise ValueError("pin manifest candidate SHA does not match --expected-sha")
        base = manifest.get("base")
        if not isinstance(base, dict) or base.get("branch") != "main" or not SHA.fullmatch(
                str(base.get("sha", ""))):
            raise ValueError("base must name main with a full pinned SHA")
        entries = manifest.get("branches")
        if not isinstance(entries, list) or len(entries) == 0 or len(entries) > 64:
            raise ValueError("list 1 to 64 independently reviewed branch tips")
        names = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("branch entry must be a map")
            branch, sha = entry.get("branch"), entry.get("sha")
            if (not isinstance(branch, str) or not BRANCH.fullmatch(branch)
                    or branch.startswith("/") or branch.endswith("/")
                    or ".." in branch or "//" in branch or branch == "main"):
                raise ValueError(f"invalid pinned branch {branch!r}")
            if branch in names:
                raise ValueError(f"duplicate pinned branch {branch}")
            names.add(branch)
            if not isinstance(sha, str) or not SHA.fullmatch(sha):
                raise ValueError(f"{branch}: pin must be a full lowercase SHA")
        pins = [base, *entries]
        evidence = []
        findings = []
        for item in pins:
            branch, sha = item["branch"], item["sha"]
            ref = "refs/remotes/origin/" + branch
            actual = git_object(repo, ref)
            included = git(repo, "merge-base", "--is-ancestor", sha, expected)
            item_state = {
                "branch": branch, "expected_sha": sha,
                "origin_tip": actual,
                "tip_matches_pin": actual == sha,
                "included_in_candidate": included.returncode == 0,
            }
            evidence.append(item_state)
            if actual != sha:
                findings.append(f"{branch}: origin tracking ref absent/moved, expected {sha}, found {actual}")
            if included.returncode != 0:
                findings.append(f"{branch}: pinned SHA is not an ancestor of candidate")
        if findings:
            return status("FAIL", "; ".join(findings), pins_sha256=hashlib.sha256(raw).hexdigest(),
                          branches=evidence)
        return status("PASS", "all pinned remote tips match and are ancestors of candidate",
                      pins_sha256=hashlib.sha256(raw).hexdigest(), branches=evidence)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return status("FAIL", f"invalid reviewed pin manifest: {exc}")


def aggregate(checks):
    states = [checks[name]["status"] for name in REQUIRED]
    if "FAIL" in states:
        return "FAIL"
    if "NOT RUN" in states:
        return "NOT RUN"
    return "PASS"


def ci_classification(result):
    state = result.get("state")
    if state == "passed":
        return status("PASS", "GitHub CI executed required steps on exact SHA",
                      audit_state=state)
    if state in ("before_runner", "pending", "incomplete"):
        return status("NOT RUN", "No usable exact-commit CI evidence: " +
                      str(result.get("reason", state)), audit_state=state)
    return status("FAIL", "CI failed or does not match exact SHA: " +
                  str(result.get("reason", state)), audit_state=state)


def run_command(name, argv, repo, report, *, required_tools=(), env=None,
                timeout=3600):
    missing = [x for x in required_tools if shutil.which(x) is None]
    if missing:
        return status("NOT RUN", "required tools missing: " + ", ".join(missing))
    logfile = report / (name + ".log")
    start = time.monotonic()
    try:
        with logfile.open("wb") as handle:
            completed = subprocess.run(argv, cwd=repo, env=env, timeout=timeout,
                                       stdin=subprocess.DEVNULL, stdout=handle,
                                       stderr=subprocess.STDOUT, check=False)
        state = "PASS" if completed.returncode == 0 else "FAIL"
        return status(state, f"command exited {completed.returncode}",
                      exit_code=completed.returncode, command=argv,
                      log=logfile.name, log_sha256=sha_file(logfile),
                      elapsed_seconds=round(time.monotonic() - start, 2))
    except subprocess.TimeoutExpired:
        return status("FAIL", f"command exceeded {timeout}s time limit",
                      command=argv, log=logfile.name,
                      log_sha256=sha_file(logfile),
                      elapsed_seconds=round(time.monotonic() - start, 2))
    except OSError as exc:
        return status("NOT RUN", f"command could not start: {exc}")


def audit_ci(opts, repo, report):
    if opts.ci_run_id is None:
        return status("NOT RUN", "no GitHub Actions run supplied; local checks are independent")
    argv = [sys.executable, str(repo / "scripts/audit_ci.py"),
            "--repo", opts.ci_repo, "--run-id", str(opts.ci_run_id),
            "--expected-sha", opts.expected_sha,
            "--output", str(report / "ci-audit.json")]
    if opts.ci_run_json or opts.ci_jobs_json:
        if not opts.ci_run_json or not opts.ci_jobs_json:
            return status("FAIL", "offline CI audit needs both run and jobs JSON")
        argv.extend(["--run-json", str(opts.ci_run_json),
                     "--jobs-json", str(opts.ci_jobs_json)])
    elif shutil.which("gh") is None:
        return status("NOT RUN", "gh CLI unavailable; cannot verify GitHub CI execution")
    cmd = run_command("ci-audit", argv, repo, report, timeout=120)
    result_path = report / "ci-audit.json"
    if result_path.is_file():
        try:
            audited = json.loads(result_path.read_text(encoding="utf-8"))
            state = ci_classification(audited)
            state["run_id"] = opts.ci_run_id
            state["log"] = cmd.get("log")
            state["audit_file_sha256"] = sha_file(result_path)
            return state
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
    return status("NOT RUN" if cmd["status"] == "NOT RUN" else "FAIL",
                  "GitHub metadata unavailable or invalid; do not count CI as executed",
                  run_id=opts.ci_run_id)


def write_final(report, info):
    markdown = [
        "# Holochain Time — Sprint 17 local integration evidence",
        "",
        f"- Exact candidate SHA: {info['candidate_sha']}",
        f"- Report generated (UTC): {info['completed_at_utc']}",
        f"- Overall **local integration** result: **{info['overall']}**",
        f"- CI audit: **{info['ci']['status']}** ({info['ci']['reason']})",
        "- Release ready: **NO** (external and independent acceptance not proven)",
        "- Git branches merged or main updated by this tool: **NO**",
        "",
        "| Gate | Result | Explanation |",
        "| --- | --- | --- |",
    ]
    for name in REQUIRED:
        item = info["checks"][name]
        explanation = str(item.get("reason", "")).replace("|", "/").replace("\n", " ")
        markdown.append(f"| {name} | {item['status']} | {explanation} |")
    markdown += [
        "",
        "Missing tool, skipped gate or unavailable CI is **NOT RUN**, never PASS.",
        "A tool returning a compiler, test or validation error is **FAIL**.",
        "Even local PASS is not proof of independent Roughtime operators,",
        "resilience under real partitions, funded Unyt settlement, or release approval.",
        "Inspect raw logs and SHA256SUMS independently before promotion.",
        "",
    ]
    (report / "report.md").write_text("\n".join(markdown), encoding="utf-8")
    (report / "report.json").write_text(
        json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence = []
    for file in sorted(report.rglob("*")):
        if file.is_symlink():
            raise ValueError("symlink discovered inside report: " + str(file))
        if file.is_file() and file.name != "SHA256SUMS":
            evidence.append(f"{sha_file(file)}  {file.relative_to(report).as_posix()}")
    (report / "SHA256SUMS").write_text("\n".join(evidence) + "\n", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path,
                    default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--expected-sha", required=True,
                    help="full reviewed candidate HEAD SHA, never a moving branch name")
    ap.add_argument("--pins", type=Path,
                    help="out-of-tree JSON with exact remote sprint heads and baseline main")
    ap.add_argument("--report-dir", type=Path,
                    help="unused directory OUTSIDE the checkout; autogenerated if omitted")
    ap.add_argument("--native-only", action="store_true",
                    help="skip WASM, conductor and DNA; overall cannot be PASS")
    ap.add_argument("--ci-run-id", type=int,
                    help="optional independent exact-SHA CI audit, not a local gate")
    ap.add_argument("--ci-repo", default="ConorTttttt/Holochain-Time")
    ap.add_argument("--ci-run-json", type=Path, help="offline CI fixture")
    ap.add_argument("--ci-jobs-json", type=Path, help="offline CI jobs fixture")
    opts = ap.parse_args(argv)
    repo = opts.repo.resolve()
    if not repo.is_dir():
        ap.error("--repo must identify a local clone directory")
    if opts.report_dir:
        report = opts.report_dir.resolve()
        if report == repo or repo in report.parents:
            ap.error("--report-dir must be outside the Git checkout")
        if report.exists():
            ap.error("--report-dir must be new; never overwrite old evidence")
        report.mkdir(parents=True)
    else:
        report = Path(tempfile.mkdtemp(prefix="hc-vtime-integration-",
                                        dir=str(repo.parent)))
    info = {
        "schema": "hc-vtime/local-integration-report/v1",
        "candidate_sha": opts.expected_sha,
        "started_at_utc": utc(),
        "completed_at_utc": None,
        "root_cargo_lock_sha256": sha_file(repo / "Cargo.lock") if
        (repo / "Cargo.lock").is_file() else None,
        "host": {"platform": platform.platform(),
                 "python": sys.version.split()[0],
                 "rustc": None, "cargo": None, "hc": None},
        "checks": {},
        "ci": status("NOT RUN", "not evaluated"),
        "overall": "NOT RUN",
        "release_ready": False,
        "main_updated": False,
        "source_merges_performed": False,
    }
    try:
        for tool in ("rustc", "cargo", "hc"):
            if shutil.which(tool):
                ver = subprocess.run([tool, "--version"], capture_output=True,
                                     text=True, check=False, timeout=15)
                info["host"][tool] = (ver.stdout or ver.stderr).strip().splitlines()[:2]
        info["checks"]["source"] = check_source(repo, opts.expected_sha)
        info["checks"]["ancestry"] = (
            check_pins(repo, opts.expected_sha,
                       opts.pins.resolve() if opts.pins else None)
            if info["checks"]["source"]["status"] == "PASS"
            else status("NOT RUN", "source integrity gate failed")
        )
        ready = (info["checks"]["source"]["status"] == "PASS"
                 and info["checks"]["ancestry"]["status"] == "PASS")
        steps = [
            # Discover every Python suite: scripts/ plus the sprint tool
            # directories that are not packages (load, security, license36/37, interop).
            ("python_tests", ["bash", "-c",
                              "set -e; for d in scripts scripts/load scripts/security scripts/license36 scripts/license37; do "
                              f"{sys.executable} -m unittest discover -s \"$d\" -p 'test_*.py' -v; done"],
             ("python3", "bash")),
            ("workspace_format", ["cargo", "fmt", "--all", "--", "--check"], ("cargo",)),
            ("conductor_format", ["cargo", "fmt", "--manifest-path",
                                  "integration/conductor/Cargo.toml", "--", "--check"], ("cargo",)),
            ("native_tests", ["cargo", "test", "--workspace", "--locked"], ("cargo",)),
            ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked",
                        "--", "-D", "warnings"], ("cargo",)),
        ]
        for name, argv, tools in steps:
            info["checks"][name] = (
                run_command(name, argv, repo, report, required_tools=tools)
                if ready else status("NOT RUN", "exact-SHA/ancestry preflight did not pass")
            )
        if not ready or opts.native_only:
            reason = "native-only explicitly skipped integration gates" if (
                ready and opts.native_only) else "exact-SHA/ancestry preflight did not pass"
            for name in ("wasm", "signed_conductor", "fresh_dna"):
                info["checks"][name] = status("NOT RUN", reason)
        else:
            env = os.environ.copy()
            env["RUSTFLAGS"] = '--cfg getrandom_backend="custom" -C link-arg=--import-undefined'
            wasm = ["cargo", "build", "--release", "--locked",
                    "--target", "wasm32-unknown-unknown",
                    "-p", "vtime_integrity", "-p", "vtime"]
            info["checks"]["wasm"] = run_command(
                "wasm", wasm, repo, report,
                required_tools=("cargo", "rustup"), env=env)
            if info["checks"]["wasm"]["status"] == "PASS":
                env = os.environ.copy()
                env["HC_VTIME_EXPECTED_SHA"] = opts.expected_sha
                env["HC_VTIME_SIGNED_REPORT_DIR"] = str(report / "signed")
                info["checks"]["signed_conductor"] = run_command(
                    "signed_conductor",
                    ["bash", "scripts/run_signed_quorum.sh"], repo, report,
                    required_tools=("bash", "git", "cargo", "hc", "python3"),
                    env=env)
            else:
                info["checks"]["signed_conductor"] = status(
                    "NOT RUN", "WASM validation did not pass")
            signed_path = report / "signed"
            if info["checks"]["signed_conductor"]["status"] == "PASS":
                needed = ("vtime.dna", "dna.yaml", "keys-public.json", "provenance.txt",
                          "signed-quorum.log", "conductor-smoke.log")
                if not all((signed_path / x).is_file() for x in needed):
                    info["checks"]["signed_conductor"] = status(
                        "FAIL", "runner exited successfully but signed artifacts are incomplete")
            if info["checks"]["signed_conductor"]["status"] == "PASS":
                info["checks"]["fresh_dna"] = run_command(
                    "fresh_dna",
                    [sys.executable, "scripts/repack_test_dna.py",
                     "--repo", str(repo), "--signed-report", str(signed_path),
                     "--output-dir", str(report / "fresh-dna"),
                     "--expected-sha", opts.expected_sha],
                    repo, report, required_tools=("git", "hc", "python3"))
            else:
                info["checks"]["fresh_dna"] = status(
                    "NOT RUN", "signed conductor or DNA artifact validation did not pass")
        info["ci"] = audit_ci(opts, repo, report)
        info["overall"] = aggregate(info["checks"])
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        for name in REQUIRED:
            info["checks"].setdefault(name, status("NOT RUN", "unexpected runner exception"))
        info["overall"] = "FAIL"
        info["fatal_error"] = str(error)
    finally:
        for name in REQUIRED:
            info["checks"].setdefault(name, status("NOT RUN", "runner did not reach gate"))
        info["completed_at_utc"] = utc()
        write_final(report, info)
    print(f"Local integration: {info['overall']} | SHA: {opts.expected_sha}")
    print(f"Evidence: {report}")
    print(f"GitHub CI: {info['ci']['status']} ({info['ci']['reason']})")
    return {"PASS": 0, "FAIL": 1, "NOT RUN": 2}[info["overall"]]


if __name__ == "__main__":
    sys.exit(main())
