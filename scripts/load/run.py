#!/usr/bin/env python3
"""Sprint 13: exact-commit, test-only conductor load runner and evidence report.

Only Python standard library is needed; Rust/Holochain build tools are external.
Runs the actual Holochain 0.7.1 Sweettest suite, never a mocked endpoint.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
PREFIXES = ("HC_LOAD_SAMPLE ", "HC_LOAD_META ", "HC_ADVERSARIAL ")


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(p * len(ordered)) - 1)], 3)


def summaries(samples: list[dict]) -> dict:
    groups: dict[str, list[dict]] = collections.defaultdict(list)
    for sample in samples:
        groups[str(sample["kind"])].append(sample)
    result = {}
    for kind, group in sorted(groups.items()):
        latencies = [float(s["latency_ms"]) for s in group]
        errors = collections.Counter(
            str(s.get("error") or "unspecified")[:180]
            for s in group if not s["ok"]
        )
        result[kind] = {
            "attempted": len(group),
            "successful_or_correctly_rejected": sum(bool(s["ok"]) for s in group),
            "failed_or_unexpected": sum(not s["ok"] for s in group),
            "latency_ms": {
                "p50": percentile(latencies, 0.50),
                "p95": percentile(latencies, 0.95),
                "p99": percentile(latencies, 0.99),
                "min": round(min(latencies), 3),
                "max": round(max(latencies), 3),
            },
            "error_counts": dict(errors.most_common(20)),
        }
    return result


def process_tree(pid: int) -> tuple[int, float] | None:
    """Best-effort Linux /proc RSS and cumulative user+system CPU for descendants.

    Includes cargo, its test binary and child conductors. A process that exited
    between polls can be missed; these are sampled, not whole-run exact totals.
    """
    if sys.platform != "linux":
        return None
    try:
        pages = os.sysconf("SC_PAGE_SIZE")
        ticks = os.sysconf("SC_CLK_TCK")
        nodes = {}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                raw = (entry / "stat").read_text()
                fields = raw[raw.rfind(")") + 2:].split()
                ppid = int(fields[1])
                cpu_ticks = int(fields[11]) + int(fields[12])
                rss_pages = int((entry / "statm").read_text().split()[1])
                nodes[int(entry.name)] = (ppid, cpu_ticks, rss_pages)
            except (OSError, ValueError, IndexError):
                continue
        selected = {pid}
        while True:
            next_selected = selected | {
                child for child, (parent, _, _) in nodes.items() if parent in selected
            }
            if next_selected == selected:
                break
            selected = next_selected
        return (
            sum(nodes[p][2] * pages for p in selected if p in nodes),
            sum(nodes[p][1] / ticks for p in selected if p in nodes),
        )
    except (OSError, ValueError):
        return None


def run_command(name: str, command: list[str], env: dict, out: Path, timeout: int) -> dict:
    logfile = out / (name + ".log")
    start = time.monotonic()
    peak_rss = 0
    max_cpu = 0.0
    last = None
    peak_cpu_percent = 0.0
    stopped = threading.Event()
    with logfile.open("w", encoding="utf-8") as stream:
        proc = subprocess.Popen(
            command, cwd=ROOT, env=env, stdout=stream,
            stderr=subprocess.STDOUT, start_new_session=True
        )

        def monitor() -> None:
            nonlocal peak_rss, max_cpu, last, peak_cpu_percent
            while not stopped.is_set():
                now = time.monotonic()
                snapshot = process_tree(proc.pid)
                if snapshot:
                    rss, cpu = snapshot
                    peak_rss = max(peak_rss, rss)
                    max_cpu = max(max_cpu, cpu)
                    if last and cpu >= last[1] and now > last[0]:
                        peak_cpu_percent = max(
                            peak_cpu_percent, 100 * (cpu - last[1]) / (now - last[0])
                        )
                    last = (now, cpu)
                stopped.wait(0.25)

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        timed_out = False
        try:
            exit_code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            exit_code = proc.wait()
        finally:
            stopped.set()
            thread.join(timeout=2)
    return {
        "name": name, "command": command,
        "exit_code": exit_code, "timed_out": timed_out,
        "elapsed_s": round(time.monotonic() - start, 3),
        "peak_rss_bytes_sampled": peak_rss if sys.platform == "linux" else None,
        "cpu_seconds_max_observed": round(max_cpu, 3) if sys.platform == "linux" else None,
        "peak_cpu_percent_sampled": round(peak_cpu_percent, 1)
        if sys.platform == "linux" else None,
        "resource_scope": "cargo process plus observed descendants; 250ms samples",
        "log": logfile.name,
    }


def extract_samples(out: Path, stages: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    samples, meta, errors = [], [], []
    for stage in stages:
        path = out / stage["log"]
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, 1):
                for prefix in PREFIXES:
                    index = line.find(prefix)
                    if index < 0:
                        continue
                    try:
                        value = json.loads(line[index + len(prefix):])
                        if prefix == PREFIXES[0]:
                            samples.append(value)
                        else:
                            meta.append(value)
                    except json.JSONDecodeError:
                        errors.append(f"{path.name}:{line_number}: invalid {prefix.strip()} JSON")
                    break
    return samples, meta, errors


def render_markdown(report: dict) -> str:
    lines = [
        "# Sprint 13 — Observed load baseline",
        "",
        f"- Exact commit: \`{report['commit']}\`",
        f"- UTC date: {report['utc']} (test-only local signers, **not** independent operators)",
        f"- DNA SHA-256: \`{report['dna_sha256']}\`",
        f"- Host: {report['platform']}",
        f"- Attempts requested: {report['attempts_requested']} concurrent seal calls over 3 conductors",
        f"- Run verdict: **{report['status']}**",
        "",
        "| Workload | Attempts | Expected success/rejection | Fail/unexpected | p50 ms | p95 ms | p99 ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in report.get("workloads", {}).items():
        latency = row["latency_ms"]
        lines.append(
            f"| {name} | {row['attempted']} | {row['successful_or_correctly_rejected']} | "
            f"{row['failed_or_unexpected']} | {latency['p50']} | {latency['p95']} | {latency['p99']} |"
        )
    lines += [
        "", "## Resource samples", "",
        "CPU percentage is process-tree CPU time divided by wall time; 100% = one logical core. "
        "CPU and RSS are approximate 250 ms samples, not exact per-zome costs.",
        "", "| Stage | Wall s | Peak RSS MiB | Peak CPU % | Exit |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for stage in report["stages"]:
        rss = stage["peak_rss_bytes_sampled"]
        rss_label = round(rss / 1048576, 2) if rss is not None else "unavailable"
        lines.append(
            f"| {stage['name']} | {stage['elapsed_s']} | {rss_label} | "
            f"{stage['peak_cpu_percent_sampled']} | {stage['exit_code']} |"
        )
    lines += [
        "", "## Interpretation",
        "", "- No throughput, latency or memory acceptance target is assumed in advance.",
        "- Seal failures include legitimate source-chain concurrency contention; inspect "
        "individual error fields before treating a failure as a security defect.",
        "- The native ancestry boundary test covers the 256-action budget and overflow. "
        "This run does **not** prove a real 256-action network traversal.",
        "- Native packet checks exercise rejection before signatures; they do **not** "
        "simulate network UDP saturation, byte-level fuzzing, or a live Roughtime outage.",
        "- Test keys are public and on one host. External source independence, production "
        "scale and cross-host resource usage are **not** demonstrated.",
        "- Review failures and environmental limitations before proposing operational limits.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dna", required=True, type=Path, help="packed signed test-only vtime.dna")
    parser.add_argument("--attempts", type=int, default=120)
    parser.add_argument("--out", type=Path, help="new results directory; defaults outside repo")
    parser.add_argument("--expected-sha", help="reject checkout not at this exact commit")
    parser.add_argument("--insecure-test-fixtures", action="store_true",
                        help="required acknowledgement: public test keys, never production")
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    args = parser.parse_args()
    if not args.insecure_test_fixtures:
        parser.error("--insecure-test-fixtures required (never use production keys)")
    if not (100 <= args.attempts <= 2000):
        parser.error("--attempts must be in 100..2000")
    if args.timeout_seconds < 30:
        parser.error("--timeout-seconds must be >=30")
    sha = git("rev-parse", "HEAD")
    expected = args.expected_sha or os.environ.get("HC_VTIME_EXPECTED_SHA")
    if expected and sha != expected:
        parser.error(f"checkout SHA {sha} differs from expected {expected}")
    if git("status", "--porcelain", "--untracked-files=all"):
        parser.error("dirty source checkout: run on a clean exact-commit branch")
    dna = args.dna.resolve(strict=True)
    if not dna.is_file():
        parser.error("DNA bundle is not a file")
    for executable in ("cargo", "rustc", "git"):
        if not shutil.which(executable):
            parser.error(f"missing tool: {executable}")
    utc = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out.resolve() if args.out else ROOT.parent / f"hc-vtime-load-{sha[:12]}-{utc}"
    if out.exists():
        parser.error(f"refusing existing results path: {out}")
    if ROOT == out or ROOT in out.parents:
        parser.error("results must be outside repository")
    out.mkdir(parents=True)
    env = os.environ.copy()
    env.update({
        "HC_VTIME_TEST_DNA": str(dna), "HC_VTIME_SIGNED_TEST_ONLY": "1",
        "HC_VTIME_LOAD_ATTEMPTS": str(args.attempts)
    })
    manifest = str(ROOT / "integration/load/Cargo.toml")
    stages: list[dict] = []
    report = {
        "schema": "hc-vtime-sprint13-load-v1", "commit": sha,
        "utc": utc, "dna_sha256": sha256(dna),
        "platform": platform.platform(), "python": platform.python_version(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
        "load_lock_sha256": sha256(ROOT / "integration/load/Cargo.lock"),
        "attempts_requested": args.attempts,
        "status": "incomplete", "stages": stages,
        "resource_sampling": "Linux /proc process tree (RSS and CPU); unavailable on non-Linux",
        "external_roughtime_independence_proven": False,
    }
    try:
        commands = [
            ("build", ["cargo", "test", "--manifest-path", manifest, "--locked",
                       "--tests", "--no-run"], args.timeout_seconds * 3),
            ("seal_load", ["cargo", "test", "--manifest-path", manifest, "--locked",
                           "--test", "seal_load", "--", "--exact", "concurrent_seal_load",
                           "--nocapture", "--test-threads=1"], args.timeout_seconds),
            ("adversarial", ["cargo", "test", "--manifest-path", manifest, "--locked",
                             "--test", "adversarial", "--", "--nocapture",
                             "--test-threads=1"], args.timeout_seconds),
            ("ancestry_budget", ["cargo", "test", "--manifest-path",
                                  str(ROOT / "Cargo.toml"), "--locked", "-p", "vtime",
                                  "ancestry_requests_are_bounded_without_overflow",
                                  "--", "--nocapture"], args.timeout_seconds),
        ]
        for name, command, timeout in commands:
            stage = run_command(name, command, env, out, timeout)
            stages.append(stage)
            if stage["exit_code"] != 0 or stage["timed_out"]:
                report["failure_stage"] = name
                break
        samples, meta, decode_errors = extract_samples(out, stages)
        report["workloads"] = summaries(samples)
        report["emitted_metadata"] = meta
        report["sample_decode_errors"] = decode_errors
        counts = collections.Counter(s["kind"] for s in samples)
        report["observed_counts"] = dict(counts)
        expected_counts = {"seal_action": args.attempts,
                           "oversized_witnesses": 64, "oversized_roughtime_items": 64}
        report["missing_samples"] = {
            kind: amount - counts[kind] for kind, amount in expected_counts.items()
            if counts[kind] != amount
        }
        if (len(stages) == len(commands)
                and all(s["exit_code"] == 0 and not s["timed_out"] for s in stages)
                and not decode_errors and not report["missing_samples"]):
            report["status"] = "completed_with_observed_failures" if (
                report["workloads"]["seal_action"]["failed_or_unexpected"]
            ) else "completed"
        else:
            report["status"] = "failed_or_incomplete"
        with (out / "samples.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=[
                "attempt", "kind", "conductor", "ok", "latency_ms",
                "action_hash", "error", "unexpected_accepted_or_wrong_failure"
            ], extrasaction="ignore")
            writer.writeheader()
            writer.writerows(samples)
        return 0 if report["status"].startswith("completed") else 1
    finally:
        (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (out / "baseline.md").write_text(render_markdown(report))
        hashes = [
            f"{sha256(path)}  {path.name}" for path in sorted(out.iterdir())
            if path.is_file() and path.name != "SHA256SUMS"
        ]
        (out / "SHA256SUMS").write_text("\n".join(hashes) + "\n")
        print(f"Load report: {out} [{report['status']}]", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
