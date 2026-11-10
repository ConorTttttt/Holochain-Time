#!/usr/bin/env python3
"""SIGKILL/restart a dedicated, disposable *standalone* Holochain conductor.

Requires an operator-provided real app probe. The Holochain process itself is
verified via /proc/PID/exe; a shell-wrapper or dummy worker cannot masquerade
as a conductor. Probe output is untrusted unless separately audited.
Linux only. Never use on production conductors or keys.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

SCHEMA = "hc-vtime/chaos33-sigkill/v1"
PROBE_SCHEMA = "hc-vtime/chaos33-signed-probe/v1"


def parsed_argv(raw: str) -> list[str]:
    data = json.loads(raw)
    if (not isinstance(data, list) or not data or
            any(not isinstance(x, str) or not x for x in data)):
        raise ValueError("command must be a nonempty JSON array of argv strings")
    return data


def fingerprint(probe: dict) -> tuple[str, str, str, int, int]:
    if probe.get("schema") != PROBE_SCHEMA:
        raise ValueError("wrong health/proof probe schema")
    if probe.get("evidence_complete") is not False:
        raise ValueError("health probe attempted to claim globally complete evidence")
    if probe.get("verdict_scope") != "caller_supplied":
        raise ValueError("health probe must disclose caller-supplied scope")
    keys = ["dna", "agent", "target", "not_before_us", "not_after_us"]
    if any(k not in probe for k in keys):
        raise ValueError("health probe is missing evidence identity or bounds")
    if any(not isinstance(probe[k], str) or not probe[k]
           for k in ["dna", "agent", "target"]):
        raise ValueError("invalid nonempty identity")
    for key in ["not_before_us", "not_after_us"]:
        if type(probe[key]) is not int:
            raise ValueError("time bounds must be signed integers")
    if probe["not_before_us"] > probe["not_after_us"]:
        raise ValueError("inconsistent signed time interval")
    if probe.get("author_chain_flagged") is not False:
        raise ValueError("author health not explicitly unflagged; blocked/unknown")
    return (probe["dna"], probe["agent"], probe["target"],
            probe["not_before_us"], probe["not_after_us"])


def check_executable(pid: int, expected: Path) -> bool:
    try:
        running = Path(os.readlink(f"/proc/{pid}/exe")).resolve(strict=True)
        return running.samefile(expected)
    except (OSError, ValueError):
        return False


def live_probe(argv: list[str], timeout: float) -> tuple[dict, tuple]:
    response = subprocess.run(argv, text=True, capture_output=True,
                              timeout=timeout, check=False)
    if response.returncode != 0:
        raise RuntimeError(f"probe exited {response.returncode}; no positive recovery evidence")
    try:
        data = json.loads(response.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("probe did not return a single JSON object") from error
    if not isinstance(data, dict):
        raise ValueError("probe JSON must be an object")
    return data, fingerprint(data)


def start_conductor(argv: list[str], log_path: Path, binary: Path) -> subprocess.Popen:
    with log_path.open("wb") as file:
        process = subprocess.Popen(argv, stdout=file, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
    # Wait only for initial executable identity, not for gossip/application readiness.
    for _ in range(40):
        if process.poll() is not None:
            raise RuntimeError("conductor quit before readiness probe")
        if check_executable(process.pid, binary):
            return process
        time.sleep(0.05)
    raise RuntimeError("child did not exec the expected standalone conductor binary")


def terminate(process: subprocess.Popen) -> None:
    if process.poll() is None:
        # Exactly the direct standalone conductor PID, not its parent shell.
        os.kill(process.pid, signal.SIGKILL)
    process.wait(timeout=15)


def execute(args) -> tuple[dict, int]:
    report = {"schema": SCHEMA, "status": "BLOCKED",
              "actual_sigkill_observed": False,
              "same_persistent_data_root_reused": False,
              "probe_is_external_and_not_independently_verified": True,
              "partition_proven": False, "database_corruption_recovery_proven": False,
              "global_evidence_completeness_proven": False, "release_approved": False}
    first = None
    second = None
    try:
        binary = args.binary.resolve(strict=True)
        root = args.data_root.resolve(strict=True)
        report_dir = args.report_dir.absolute()
        if binary.name != "holochain" or not binary.is_file():
            raise ValueError("expected direct Holochain 0.7 standalone executable")
        if not root.is_dir() or not (root / ".hc-vtime-disposable-chaos33").is_file():
            raise ValueError("missing disposable data root sentinel")
        if report_dir.exists() or root in report_dir.parents or report_dir == root:
            raise ValueError("report directory must be unused and outside data root")
        cmd = parsed_argv(args.command_json)
        probe = parsed_argv(args.probe_json)
        if not Path(cmd[0]).resolve(strict=True).samefile(binary):
            raise ValueError("command must start the direct holochain binary")
        if "--config-path" not in cmd:
            raise ValueError("standalone command must identify its explicit --config-path")
        position = cmd.index("--config-path")
        if position + 1 >= len(cmd):
            raise ValueError("missing conductor config path")
        config_path = Path(cmd[position + 1]).resolve(strict=True)
        config = config_path.read_text()
        if str(root) not in config:
            raise ValueError("config does not bind the disposable persistent data root")
        if args.timeout <= 1 or args.timeout > 120:
            raise ValueError("probe timeout outside safe 1..120 second range")

        report_dir.mkdir(mode=0o700, parents=True)
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["data_root_label"] = root.name  # never publish credentials or DB payloads
        first = start_conductor(cmd, report_dir / "precrash-conductor.log", binary)
        before, baseline = live_probe(probe, args.timeout)
        report["precrash_probe"] = before
        if first.poll() is not None:
            raise RuntimeError("conductor exited during health/proof probe")
        first_pid = first.pid
        terminate(first)
        report["sigkill_exit_code"] = first.returncode
        if first.returncode != -signal.SIGKILL:
            raise RuntimeError("process did not terminate as SIGKILL")
        report["actual_sigkill_observed"] = True

        second = start_conductor(cmd, report_dir / "recovered-conductor.log", binary)
        if second.pid == first_pid:
            raise RuntimeError("new conductor PID unexpectedly identical to killed process")
        after, recovered = live_probe(probe, args.timeout)
        report["after_restart_probe"] = after
        if baseline != recovered:
            raise RuntimeError("persistent signing identity / evidence bounds changed after restart")
        report["same_persistent_data_root_reused"] = True
        report["recovered_supplied_evidence_matches_precrash"] = True
        report["status"] = "SIGKILL_RESTART_PROBE_MATCH"
        return report, 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
            json.JSONDecodeError) as error:
        report["problems"] = [str(error)]
        return report, 3
    finally:
        if first is not None and first.poll() is None:
            terminate(first)
        if second is not None and second.poll() is None:
            terminate(second)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--command-json", required=True)
    parser.add_argument("--probe-json", required=True)
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--ack-disposable-test-data", action="store_true")
    args = parser.parse_args(argv)
    if not args.ack_disposable_test_data:
        parser.error("explicit --ack-disposable-test-data required")
    report, code = execute(args)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    (args.report_dir / "sigkill-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
