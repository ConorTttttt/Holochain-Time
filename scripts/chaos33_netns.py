#!/usr/bin/env python3
"""Linux three-conductor network namespace lab: verified kernel 2+1 split.

A, B and C must be real, separately launched test-only Holochain processes.
The host bridge has NO default route for peers, so external relay bypass is
not available. App proof validity comes from an operator-provided test client;
the kernel partition alone is NOT a DHT recovery certificate.
Requires Linux, root/CAP_NET_ADMIN, iproute2, ping, Holochain 0.7 executable.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

SCHEMA = "hc-vtime/chaos33-netns/v1"
PROBE_SCHEMA = "hc-vtime/chaos33-partition-probe/v1"
IPS = {"a": "10.238.33.11", "b": "10.238.33.12", "c": "10.238.33.13"}
PHASES = ("baseline", "split", "rejoined")


def run(*args, check=True, timeout=20):
    result = subprocess.run(list(args), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {args[0:3]} code={result.returncode}: "
                           f"{result.stderr[-400:]}")
    return result


def check_probe(phase: str, payload: dict) -> tuple:
    if not isinstance(payload, dict) or payload.get("schema") != PROBE_SCHEMA:
        raise ValueError("unrecognized signed-evidence probe payload")
    if payload.get("phase") != phase or payload.get("evidence_complete") is not False:
        raise ValueError("probe phase mismatch or global completeness claim")
    if payload.get("verdict_scope") != "caller_supplied":
        raise ValueError("probe does not identify caller-supplied evidence")
    if not all(isinstance(payload.get(k), str) and payload[k]
               for k in ("dna", "target", "agent")):
        raise ValueError("missing test DNA, agent or action identifier")
    if phase == "split":
        if payload.get("observation") != "new_remote_witness_unavailable_rejected":
            raise ValueError("split must explicitly reject a newly missing remote witness")
        if not isinstance(payload.get("witness_hash"), str) or not payload["witness_hash"]:
            raise ValueError("split must identify the withheld witness")
        return (payload["dna"], payload["agent"], payload["target"])
    if payload.get("observation") != "signed_supplied_bounds_verified":
        raise ValueError("rejoin/baseline missing positive signed witness observation")
    if payload.get("author_chain_flagged") is not False:
        raise ValueError("chain activity is flagged or unknown")
    if any(type(payload.get(k)) is not int for k in ("not_before_us", "not_after_us")):
        raise ValueError("missing numeric signed bounds")
    if payload["not_before_us"] > payload["not_after_us"]:
        raise ValueError("inconsistent signed interval")
    return (payload["dna"], payload["agent"], payload["target"],
            payload["not_before_us"], payload["not_after_us"])


def config_binds_root(config: str, root: Path) -> bool:
    """Check an explicit top-level data_root_path, never a comment/substring."""
    for line in config.splitlines():
        if line.startswith("data_root_path:"):
            value = line.partition(":")[2].strip()
            if value.startswith(("'", '"')) and value.endswith(value[0]):
                value = value[1:-1]
            return value == str(root)
    return False


def read_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != "hc-vtime/chaos33-netns-config/v1":
        raise ValueError("wrong manifest schema")
    if set(manifest.get("conductors", {})) != set(IPS):
        raise ValueError("need three conductor command arrays a, b and c")
    for node, argv in manifest["conductors"].items():
        if not isinstance(argv, list) or not argv or any(
            not isinstance(part, str) or not part for part in argv
        ):
            raise ValueError(f"invalid argv for {node}")
        binary = Path(argv[0]).resolve(strict=True)
        if not binary.is_file() or binary.name != "holochain":
            raise ValueError(f"{node} is not a standalone holochain binary")
        if "--config-path" not in argv:
            raise ValueError(f"{node} command lacks --config-path")
        config_index = argv.index("--config-path") + 1
        if config_index >= len(argv):
            raise ValueError("conductor config path is absent")
        config = Path(argv[config_index]).resolve(strict=True).read_text()
        # Each process must have a unique disposable data root explicitly
        # designated by its config, not a shared or production database.
        root = Path(manifest.get("data_roots", {}).get(node, "")).resolve(strict=True)
        if not (root / ".hc-vtime-disposable-chaos33").is_file() or not config_binds_root(config, root):
            raise ValueError(f"{node} config is not bound to a sentinel-marked disposable root")
    if len({manifest["data_roots"][n] for n in IPS}) != 3:
        raise ValueError("conductor data roots cannot be shared")
    probe = manifest.get("probe_command")
    if probe is not None and (
        not isinstance(probe, list) or not probe or
        any(not isinstance(s, str) or not s for s in probe)
    ):
        raise ValueError("probe_command must be an argv array or null")
    return manifest


class Lab:
    def __init__(self, report: Path):
        suffix = f"{os.getpid() % 90000 + 10000:05d}"
        self.bridge = "h33br" + suffix
        self.netns = {node: "h33" + node + suffix for node in IPS}
        self.links = {node: "h33" + node + suffix for node in IPS}
        self.report = report
        self.processes = {}
        self.created = []

    def setup(self):
        run("ip", "link", "add", self.bridge, "type", "bridge")
        self.created.append(("bridge", self.bridge))
        run("ip", "link", "set", self.bridge, "up")
        # NO IP forwarding and NO default gateway in isolated namespaces.
        for node, ns in self.netns.items():
            run("ip", "netns", "add", ns)
            self.created.append(("netns", ns))
            root_side = self.links[node]
            peer_side = "p" + root_side
            run("ip", "link", "add", root_side, "type", "veth",
                "peer", "name", peer_side)
            run("ip", "link", "set", root_side, "master", self.bridge)
            run("ip", "link", "set", root_side, "up")
            run("ip", "link", "set", peer_side, "netns", ns)
            run("ip", "-n", ns, "link", "set", peer_side, "name", "eth0")
            run("ip", "-n", ns, "addr", "add", IPS[node] + "/24", "dev", "eth0")
            run("ip", "-n", ns, "link", "set", "eth0", "up")
            run("ip", "-n", ns, "link", "set", "lo", "up")

    def ping(self, source: str, dest: str) -> bool:
        return run("ip", "netns", "exec", self.netns[source],
                   "ping", "-n", "-c", "1", "-W", "2", IPS[dest],
                   check=False, timeout=6).returncode == 0

    def assert_paths(self, isolated: bool) -> dict:
        results = {f"{a}_to_{b}": self.ping(a, b)
                   for a, b in (("a", "b"), ("a", "c"), ("b", "c"), ("c", "a"))}
        expected = {"a_to_b": True, "a_to_c": not isolated,
                    "b_to_c": not isolated, "c_to_a": not isolated}
        if results != expected:
            raise RuntimeError(f"kernel network isolation did not match {expected}: {results}")
        return results

    def start(self, manifest: dict):
        for node, ns in self.netns.items():
            logfile = self.report / f"conductor_{node}.log"
            output = logfile.open("wb")
            try:
                proc = subprocess.Popen(
                    ["ip", "netns", "exec", ns, *manifest["conductors"][node]],
                    stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    start_new_session=True)
            finally:
                output.close()
            self.processes[node] = proc
        time.sleep(2)
        self.assert_alive()

    def assert_alive(self):
        for node, proc in self.processes.items():
            if proc.poll() is not None:
                raise RuntimeError(f"conductor {node} quit: exit={proc.returncode}")
            try:
                executable = Path(os.readlink(f"/proc/{proc.pid}/exe")).resolve(strict=True)
            except (OSError, ValueError) as error:
                raise RuntimeError(f"conductor {node} has no accessible executable") from error
            if executable.name != "holochain":
                raise RuntimeError(f"conductor {node} PID is not a standalone holochain process")

    def phase(self, phase: str, manifest: dict):
        cmd = manifest.get("probe_command")
        if cmd is None:
            return None
        env = os.environ.copy()
        for name, ns in self.netns.items():
            env["HC33_NETNS_" + name.upper()] = ns
            env["HC33_IP_" + name.upper()] = IPS[name]
        env["HC33_PHASE"] = phase
        output = subprocess.run([s.replace("{phase}", phase) for s in cmd],
                                cwd=self.report, env=env,
                                capture_output=True, text=True, timeout=120)
        (self.report / f"probe_{phase}.stdout").write_text(output.stdout)
        (self.report / f"probe_{phase}.stderr").write_text(output.stderr)
        if output.returncode:
            raise RuntimeError(f"external Holochain app probe failed in {phase}")
        try:
            payload = json.loads(output.stdout)
        except json.JSONDecodeError as error:
            raise ValueError("Holochain app probe did not emit one JSON object") from error
        check_probe(phase, payload)
        return payload

    def cleanup(self):
        for proc in self.processes.values():
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=10)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=10)
        for kind, name in reversed(self.created):
            run("ip", "netns", "del", name, check=False) if kind == "netns" else run(
                "ip", "link", "del", name, check=False
            )


def execute(args) -> tuple[dict, int]:
    result = {
        "schema": SCHEMA, "status": "BLOCKED", "source": "Linux netns + external conductor",
        "real_network_kernel_partition_proven": False,
        "holochain_app_rejoin_proven": False,
        "external_probe_independently_authenticated": False,
        "signed_evidence_globally_complete": False,
        "release_approved": False,
    }
    lab = None
    try:
        if os.geteuid() != 0 or not shutil.which("ip") or not shutil.which("ping"):
            raise ValueError("Linux root/CAP_NET_ADMIN, iproute2 and ping are required")
        manifest = read_manifest(args.manifest)
        if args.report_dir.exists():
            raise ValueError("report directory must not exist")
        args.report_dir.mkdir(mode=0o700, parents=True)
        lab = Lab(args.report_dir)
        lab.setup()
        result["before_ping"] = lab.assert_paths(isolated=False)
        lab.start(manifest)
        baseline = lab.phase("baseline", manifest)
        lab.assert_alive()
        run("ip", "-n", lab.netns["c"], "link", "set", "eth0", "down")
        result["split_ping"] = lab.assert_paths(isolated=True)
        lab.assert_alive()
        result["real_network_kernel_partition_proven"] = True
        split = lab.phase("split", manifest)
        lab.assert_alive()
        run("ip", "-n", lab.netns["c"], "link", "set", "eth0", "up")
        result["rejoined_ping"] = lab.assert_paths(isolated=False)
        rejoined = lab.phase("rejoined", manifest)
        lab.assert_alive()
        if baseline is not None and split is not None and rejoined is not None:
            base_id = check_probe("baseline", baseline)
            split_id = check_probe("split", split)
            recovered_id = check_probe("rejoined", rejoined)
            if base_id != recovered_id or base_id[:2] != split_id[:2]:
                raise ValueError("DNA/agent identity or signed bounds changed across split")
            if (split.get("witness_hash") == baseline.get("witness_hash")
                    or rejoined.get("verified_recovered_witness_hash") != split["witness_hash"]):
                raise ValueError("rejoined probe must verify exactly the withheld witness")
            result["holochain_app_rejoin_proven"] = True
            result["status"] = "KERNEL_PARTITION_AND_EXTERNAL_PROBE_PASS"
        else:
            result["status"] = "KERNEL_PARTITION_ONLY_APP_PROOF_NOT_RUN"
        return result, 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["problems"] = [str(error)]
        return result, 3
    finally:
        if lab is not None:
            lab.cleanup()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--ack-disposable-netns-lab", action="store_true")
    args = parser.parse_args(argv)
    if not args.ack_disposable_netns_lab:
        parser.error("explicit --ack-disposable-netns-lab required")
    report, status = execute(args)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    (args.report_dir / "netns-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
