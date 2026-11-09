#!/usr/bin/env python3
"""Sprint 21: exact-SHA real-conductor seal throughput runner (Python stdlib).

This runner never deploys DNA, funds accounts or claims external operator
independence. It requires a successful same-commit signed fixture provenance.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

import run as legacy

ROOT = Path(__file__).resolve().parents[2]
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
SAMPLE_COLUMNS = [
    "attempt", "kind", "conductor", "ok", "action_hash", "error", "error_code",
    "latency_ms", "queue_wait_ms", "service_ms", "queue_depth_at_admission",
    "admitted", "write_attempts", "head_moved_retries",
]


def require(test, message):
    if not test:
        raise ValueError(message)


def check_fixture(dna, exact_sha):
    require(dna.name == "vtime.dna" and dna.is_file(),
            "expected signed-fixture vtime.dna, not arbitrary production bundle")
    manifest, provenance = dna.parent / "dna.yaml", dna.parent / "provenance.txt"
    require(manifest.is_file() and provenance.is_file(),
            "signed fixture manifest/provenance missing")
    text = manifest.read_text(encoding="utf-8")
    require(text.startswith(
        "# HC_VTIME_SIGNED_TEST_ONLY -- known insecure keys -- NEVER DEPLOY\n"
    ), "DNA must be explicitly marked public-key test-only")
    require("DO-NOT-DEPLOY-signed-quorum-" in text,
            "throwaway signed test network seed missing")
    pairs = {}
    for line in provenance.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            require(key not in pairs, f"duplicate provenance key {key}")
            pairs[key] = value
    require(pairs.get("git_sha") == exact_sha, "fixture source SHA mismatch")
    require(pairs.get("packed_dna_sha256") == legacy.sha256(dna),
            "packed DNA SHA-256 differs from fixture provenance")
    require(pairs.get("signed_quorum_command_exit") == "0" and
            pairs.get("conductor_smoke_command_exit") == "0",
            "fixture signed/conductor verification not recorded PASS")
    return {
        "git_sha": exact_sha,
        "bundle_sha256": legacy.sha256(dna),
        "manifest_sha256": legacy.sha256(manifest),
        "provenance_sha256": legacy.sha256(provenance),
        "operator_independence_proven": False,
    }


def validate_queued(samples, meta, requested):
    """Fail closed on missing, replayed, unsuccessful or synthetic samples."""
    findings = []
    queued = [s for s in samples if s.get("kind") == "queued_seal_action"]
    if len(queued) != requested:
        findings.append(f"expected {requested} queued samples, saw {len(queued)}")
    ids, hashes, lanes = set(), set(), collections.Counter()
    retries, durations = 0, {"latency_ms": [], "queue_wait_ms": [], "service_ms": []}
    for sample in queued:
        ix = sample.get("attempt")
        if type(ix) is not int or ix < 0 or ix >= requested or ix in ids:
            findings.append(f"invalid/duplicate attempt id: {ix!r}")
        ids.add(ix)
        lane = sample.get("conductor")
        if type(lane) is not int or lane not in (0, 1, 2):
            findings.append(f"invalid author chain lane at {ix}")
        else:
            lanes[lane] += 1
        if sample.get("ok") is not True or sample.get("admitted") is not True:
            findings.append(f"seal {ix} was rejected/failed")
        if sample.get("error") is not None or sample.get("error_code") is not None:
            findings.append(f"seal {ix} has an error")
        hash_text = sample.get("action_hash")
        if not isinstance(hash_text, str) or len(hash_text) < 40 or hash_text in hashes:
            findings.append(f"missing/duplicate action hash at {ix}")
        else:
            hashes.add(hash_text)
        tries, retry = sample.get("write_attempts"), sample.get("head_moved_retries")
        if (type(tries) is not int or type(retry) is not int
                or retry < 0 or retry > 3 or tries != retry + 1):
            findings.append(f"invalid HeadMoved retry counts at {ix}")
        else:
            retries += retry
        depth = sample.get("queue_depth_at_admission")
        if type(depth) is not int or depth <= 0 or depth > requested:
            findings.append(f"invalid bounded queue depth at {ix}")
        for field in durations:
            value = sample.get(field)
            if type(value) not in (int, float) or not 0 <= value < 600_000:
                findings.append(f"bad {field} at {ix}")
            else:
                durations[field].append(float(value))
    if ids != set(range(requested)):
        findings.append("request identities incomplete/non-contiguous")
    if len(hashes) != requested:
        findings.append("fewer than requested unique action hashes")
    if len(lanes) != 3:
        findings.append("not all three conductor source chains submitted seals")
    records = [x for x in meta if x.get("kind") == "queued_seal_action"]
    if len(records) != 1:
        findings.append("missing or ambiguous queued meta record")
    metadata = records[0] if len(records) == 1 else {}
    for field, desired in (
        ("requested", requested), ("successful", requested), ("failed", 0),
        ("unique_success_action_hashes", requested),
        ("conductor_count", 3), ("head_moved_retries", retries),
    ):
        if metadata.get(field) != desired:
            findings.append(f"{field} metadata mismatch")
    receipts = metadata.get("third_party_verified_receipts")
    if type(receipts) is not int or receipts < 12:
        findings.append("insufficient third-party verified real seals")
    if metadata.get("external_roughtime_network") is not False or (
        metadata.get("production_independence_proven") is not False
    ):
        findings.append("insecure fixture incorrectly claims external independence")
    wall, throughput = (
        metadata.get("completion_wall_ms"),
        metadata.get("successful_seals_per_second"),
    )
    if (type(wall) not in (int, float) or wall <= 0 or
            type(throughput) not in (int, float) or throughput <= 0):
        findings.append("missing measured wall time and throughput")
    return {
        "status": "PASS" if not findings else "FAIL",
        "findings": findings[:300],
        "requested": requested,
        "successful": sum(x.get("ok") is True for x in queued),
        "unique_action_hashes": len(hashes),
        "head_moved_retries": retries,
        "author_lanes": dict(sorted(lanes.items())),
        "third_party_verified_receipts": receipts,
        "throughput_seals_per_second": throughput,
        "latency_ms": {
            field: {
                "p50": legacy.percentile(values, 0.5),
                "p95": legacy.percentile(values, 0.95),
                "p99": legacy.percentile(values, 0.99),
            }
            for field, values in durations.items()
        },
    }


def report_md(report):
    gate = report.get("queued_gate") or {}
    lines = [
        "# Sprint 21 — Real-conductor queued seal throughput",
        "",
        f"- Status: **{report['status']}**",
        f"- Exact candidate SHA: {report['commit']}",
        f"- Test-only DNA SHA-256: {report['dna_sha256']}",
        f"- Concurrent caller tasks: {report['requested']} across three real conductors",
        f"- Successful seals: {gate.get('successful', 'NOT RUN')}",
        f"- Unique action hashes: {gate.get('unique_action_hashes', 'NOT RUN')}",
        f"- Third-party verified receipts: {gate.get('third_party_verified_receipts', 'NOT RUN')}",
        f"- Observed throughput (seals/s): {gate.get('throughput_seals_per_second', 'NOT RUN')}",
        f"- HeadMoved retries: {gate.get('head_moved_retries', 'NOT RUN')}",
        "",
        "| Measure | p50 ms | p95 ms | p99 ms |",
        "| --- | ---: | ---: | ---: |",
    ]
    for field, label in (("latency_ms", "Caller end-to-end"),
                         ("queue_wait_ms", "Queue wait"),
                         ("service_ms", "Conductor execution")):
        d = gate.get("latency_ms", {}).get(field, {})
        lines.append(f"| {label} | {d.get('p50')} | {d.get('p95')} | {d.get('p99')} |")
    lines += [
        "", "## Evidence stages", "",
        "| Stage | Exit | Seconds | Peak sampled RSS bytes | Peak sampled CPU % |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for stage in report["stages"]:
        lines.append(
            f"| {stage['name']} | {stage['exit_code']} | {stage['elapsed_s']} | "
            f"{stage['peak_rss_bytes_sampled']} | {stage['peak_cpu_percent_sampled']} |"
        )
    lines += [
        "",
        "These are >=100 concurrent CALLERS, not >=100 simultaneous writes on one agent source chain.",
        "A local per-agent queue serializes actual Holochain writes; different author chains proceed concurrently.",
        "No live Roughtime UDP, independent operators, cross-host coordination, durable queue or production SLA is proven.",
        "Signatures are known insecure test fixtures. Every result is tied to exact SHA and recorded file hashes.",
        "",
        "## Findings",
    ]
    lines.extend("- " + x for x in (gate.get("findings") or report["errors"] or ["None"]))
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dna", type=Path, required=True)
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--attempts", type=int, default=120)
    ap.add_argument("--insecure-test-fixtures", action="store_true")
    ap.add_argument("--timeout-seconds", type=int, default=1800)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--compare-unqueued", action="store_true")
    args = ap.parse_args(argv)
    if not args.insecure_test_fixtures:
        ap.error("--insecure-test-fixtures acknowledgement required")
    if not FULL_SHA.fullmatch(args.expected_sha) or (
        legacy.git("rev-parse", "HEAD") != args.expected_sha
    ):
        ap.error("checkout must equal reviewed full commit SHA")
    if not 100 <= args.attempts <= 2000:
        ap.error("attempt count must be 100..=2000")
    if args.timeout_seconds < 60:
        ap.error("--timeout-seconds must be at least 60")
    if legacy.git("status", "--porcelain", "--untracked-files=all"):
        ap.error("dirty source checkout cannot certify throughput")
    if legacy.git("rev-parse", "--is-shallow-repository") == "true":
        ap.error("shallow checkout cannot establish complete provenance")
    for command in ("git", "cargo", "rustc"):
        if shutil.which(command) is None:
            ap.error(f"missing {command}; use compatible Holochain 0.7 toolchain")
    dna = args.dna.resolve(strict=True)
    try:
        fixture = check_fixture(dna, args.expected_sha)
    except (OSError, ValueError) as error:
        ap.error(f"invalid unsigned or stale test fixture: {error}")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out.resolve() if args.out else ROOT.parent / (
        f"hc-vtime-sprint21-{args.expected_sha[:12]}-{timestamp}-{os.getpid()}"
    )
    if out.exists() or out == ROOT or ROOT in out.parents:
        ap.error("evidence output must be new and outside repository")
    out.mkdir(parents=True)
    env = os.environ.copy()
    env.update({
        "HC_VTIME_TEST_DNA": str(dna),
        "HC_VTIME_SIGNED_TEST_ONLY": "1",
        "HC_VTIME_LOAD_ATTEMPTS": str(args.attempts),
        "HC_VTIME_SEAL_QUEUE_CAPACITY": str(args.attempts),
        "HC_VTIME_SEAL_MAX_WAIT_MS": "360000",
    })
    manifest = str(ROOT / "integration/load/Cargo.toml")
    stages = [
        ("queue_policy", [
            "cargo", "test", "--locked", "--manifest-path", manifest,
            "--test", "queue_policy", "--", "--nocapture", "--test-threads=1",
        ]),
    ]
    if args.compare_unqueued:
        stages.append(("original_unqueued", [
            "cargo", "test", "--locked", "--manifest-path", manifest,
            "--test", "seal_load", "--", "--exact", "concurrent_seal_load",
            "--nocapture", "--test-threads=1",
        ]))
    stages.extend([
        ("queued_real_seals", [
            "cargo", "test", "--locked", "--manifest-path", manifest,
            "--test", "queued_seal_load", "--", "--exact",
            "queued_concurrent_seal_load", "--nocapture", "--test-threads=1",
        ]),
        ("invalid_evidence", [
            "cargo", "test", "--locked", "--manifest-path", manifest,
            "--test", "adversarial", "--", "--nocapture", "--test-threads=1",
        ]),
    ])
    report = {
        "schema": "hc-vtime/sprint21-seal-throughput/v1",
        "status": "NOT RUN", "commit": args.expected_sha,
        "utc": timestamp, "requested": args.attempts,
        "dna_sha256": fixture["bundle_sha256"], "fixture": fixture,
        "platform": platform.platform(), "python": platform.python_version(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
        "load_cargo_lock_sha256": legacy.sha256(ROOT / "integration/load/Cargo.lock"),
        "stages": [], "queued_gate": None, "errors": [],
        "release_ready": False,
        "external_roughtime_operator_independence_proven": False,
    }
    try:
        report["status"] = "FAIL"
        for name, command in stages:
            stage = legacy.run_command(name, command, env, out, args.timeout_seconds)
            report["stages"].append(stage)
            if stage["exit_code"] or stage["timed_out"]:
                report["errors"].append(f"{name} execution failed: see {stage['log']}")
                break
        samples, meta, errors = legacy.extract_samples(out, report["stages"])
        report["errors"].extend(errors)
        report["queued_gate"] = validate_queued(samples, meta, args.attempts)
        report["workloads"] = legacy.summaries(samples) if samples else {}
        report["metadata"] = meta
        if args.compare_unqueued:
            raw = report["workloads"].get("seal_action", {})
            report["original_same_sha"] = {
                "success": raw.get("successful_or_correctly_rejected"),
                "failure": raw.get("failed_or_unexpected"),
                "note": "observational comparison; separate freshly installed conductors on same host",
            }
        with (out / "samples.csv").open("w", newline="", encoding="utf-8") as target:
            writer = csv.DictWriter(target, fieldnames=SAMPLE_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(s for s in samples if s.get("kind") == "queued_seal_action")
        if (len(report["stages"]) == len(stages) and
                not report["errors"] and report["queued_gate"]["status"] == "PASS"):
            report["status"] = "PASS"
        return 0 if report["status"] == "PASS" else 1
    finally:
        (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (out / "results.md").write_text(report_md(report))
        sums = [
            f"{legacy.sha256(path)}  {path.name}"
            for path in sorted(out.iterdir())
            if path.is_file() and path.name != "SHA256SUMS"
        ]
        (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
        print(f"Sprint 21 evidence: {out} [{report['status']}]", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
