# Sprint 33 — Conductor chaos and disaster recovery (Agent W)

**Status:** GitHub-first test/harness candidate; local execution and security acceptance not performed. **Production release remains NO-GO.** Based on main `bae1e5b9380e92cbee511e07fea1681011d4d6d0`. Pinned: Holochain/HDK 0.7.1, HDI 0.8.1. No production coordinator, integrity zome or DNA-property edits.

## Existing implementation audit

Current main already includes:
- Sprint 12 actual three-agent Sweettest: graceful restart and durable signed bounds; missing witnesses; delayed discovery/rejoin; ancestry over 256 actions; isolated same-agent fork lab.
- Sprint 22 actual fork/warrant lab (ignored/opt-in) plus restart persistence test, with real integrated warrant and positive-count requirement. Do **not** count synthetic same-agent conflict fixtures as real warrants.
- Explicit proof hashes are cryptographically verified, ancestry-checked, bound to target and author; `evidence_complete=false` is mandatory. `NoContradictionInSuppliedProofs` does **not** mean network-wide consistency.

Historical `rendezvous(false)` prevents peer discovery, not established QUIC/Iroh transport. `shutdown()/startup()` is graceful, not SIGKILL. A logical corrupt DB fixture is not proof that the conductor handles a damaged SQLite store safely.

## New GitHub artifacts

1. `integration/conductor/tests/chaos_recovery.rs`: new three-**real**-conductor signed test. Before peer exchange, remote evidence is unavailable and must reject. On delayed convergence it checks actual earlier signed anchor ancestry and third-party seal; later same-author anchor, foreign-author anchor, and non-existent seal must **all** reject. Observer restart/rejoin must keep the original signed bounds and discover an anchor authored while it was offline. A separate unit test ensures unknown chain health is never treated as clean.
2. `scripts/chaos33_db_audit.py` + unit tests: offline manifest SHA-256 / size comparison and read-only SQLite `integrity_check`. Mutated but structurally valid data, destroyed DB, symlink and missing file all fail. This is a **pre-restore gate only**; an intact SQLite file does not prove Holochain signed-chain correctness. Collect snapshots only from stopped disposable environments, never manipulate a live DB or commit keystores.
3. `scripts/chaos33_sigkill.py` + unit tests: opt-in standalone-Linux process supervisor. Requires a real binary named `holochain`, a sentinel-marked disposable data root, config explicitly bound to the same root, and an external authenticated-app probe. Checks `/proc/PID/exe`, sends genuine `SIGKILL`, asserts exit `-9`, restarts same root and compares exact DNA, agent, target and signed bounds. Rejects unknown/flagged chain health, different DNA/target/bounds, or completeness claims. **External probe is operator-supplied and not independently authenticated by this script**.
4. `scripts/chaos33_netns.py` + unit tests: opt-in **Linux** network namespaces (three separate Holochain processes, a local bridge/veth subnet without a default route). First proves A↔B↔C packet reachability, lowers C's interface, proves A→B remains available while A/B→C and C→A are blocked **while all three processes remain alive**, restores C and proves connectivity. Optional probe command is required to report actual evidence-level recovery; without it status is `KERNEL_PARTITION_ONLY_APP_PROOF_NOT_RUN`. Missing/tampered/ambiguous probe data is **BLOCKED**. This prevents the older discovery-isolation fixture from being reported as a physical transport split.
5. `scripts/run_chaos33.sh` and `scripts/audit_chaos33.py`: exact-SHA conductor baseline runner and fail-closed JSON auditor, with Python negative tests, format, native tests, Clippy, signed conductor scenarios and SHA-256 artifact manifests. The extra destructive fork test is an explicit opt-in; true SIGKILL and root-owned namespace labs are separate opt-in execution steps, not part of the default runner.

## Execute baseline in a disposable Holochain 0.7 Holonix environment

On a clean reviewed Sprint 33 SHA:
```bash
export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
bash scripts/run_signed_quorum.sh
# Copy the exact report path shown by the script (contains signed-test-only vtime.dna)
bash scripts/run_chaos33.sh --expected-sha "$HC_VTIME_EXPECTED_SHA" \
  --signed-report-dir /absolute/path/to/hc-vtime-signed-quorum-report \
  --ack-public-test-keys
# Additional destructive known-key-fork test:
bash scripts/run_chaos33.sh --expected-sha "$HC_VTIME_EXPECTED_SHA" \
  --signed-report-dir /absolute/path/to/hc-vtime-signed-quorum-report \
  --ack-public-test-keys --full --allow-same-key-fork-lab
```

Both run modes require signed quorum provenance bound to the *same exact full commit SHA*, and cannot certify SIGKILL, transport partition, database recovery or financial acceptance. Retain logs, check the emitted `audit.json` for `BASELINE_PASS` vs `FORK_WARRANT_PASS`, and independently inspect all machine-readable flags. Re-run on any merged candidate.

## Forced SIGKILL lab (opt-in, separate processes)

Prepare one throwaway, absolutely non-production Holochain 0.7 standalone conductor config with `data_root_path` set to a disposable root, create `.hc-vtime-disposable-chaos33` inside that root, and supply an application test client probe that returns one JSON object:

```json
{
  "schema": "hc-vtime/chaos33-signed-probe/v1",
  "dna": "test-dna", "agent": "test-agent", "target": "signed-test-target",
  "not_before_us": 100, "not_after_us": 200,
  "author_chain_flagged": false, "verdict_scope": "caller_supplied",
  "evidence_complete": false
}
```

The **probe** must actually call the test-only application's `verify_time_with_witnesses` and independently confirm the signed witness references; fabricated JSON is not conductor acceptance. Example invocation:

```bash
python3 -B scripts/chaos33_sigkill.py \
  --binary /absolute/path/to/holochain \
  --data-root /absolute/disposable/conductor-a \
  --command-json '["/absolute/path/to/holochain","--config-path","/absolute/disposable/conductor-a.yaml"]' \
  --probe-json '["/absolute/path/to/test-client-probe","--check","signed-witness"]' \
  --report-dir /absolute/new/chaos33-sigkill-report --ack-disposable-test-data
```

No raw DB, keys or app tokens are printed to the report. Keep report directories private and outside the checkout. The supervisor kills only the fixture executable, not any unrelated service, and shuts down the restarted test worker before exiting. Recovering a **missing peer** or processing a corrupted DB requires extra conductor-specific tests not provided by a single-process equality probe.

## Real Linux 2+1 transport split (opt-in, root-only)

`scripts/chaos33_netns.py` requires a manifest with the exact three disposable conductor commands and disjoint sentinel-marked config roots:

```json
{
  "schema": "hc-vtime/chaos33-netns-config/v1",
  "data_roots": {
    "a": "/absolute/disposable/a",
    "b": "/absolute/disposable/b",
    "c": "/absolute/disposable/c"
  },
  "conductors": {
    "a": ["/absolute/path/to/holochain","--config-path","/absolute/disposable/a.yaml"],
    "b": ["/absolute/path/to/holochain","--config-path","/absolute/disposable/b.yaml"],
    "c": ["/absolute/path/to/holochain","--config-path","/absolute/disposable/c.yaml"]
  },
  "probe_command": ["/absolute/path/to/signed-chaos-probe", "--phase", "{phase}"]
}
```

Use `probe_command: null` only for kernel partition plumbing tests, never for DHT acceptance. The 0.7 Iroh/QUIC bootstrap and relay config must be **compatible with the isolated lab subnet**. There is **no external gateway**; a public relay is not a valid partition lab endpoint. The probe can read `HC33_NETNS_A/B/C` and `HC33_IP_A/B/C` to connect to lab agents. It must produce, for phases `baseline`, `split`, `rejoined`, a JSON object with schema `hc-vtime/chaos33-partition-probe/v1`, `phase`, `dna`, `agent`, `target`, `verdict_scope=caller_supplied`, and `evidence_complete=false`.

For baseline/rejoined the app probe must report `observation=signed_supplied_bounds_verified`, `author_chain_flagged=false`, `not_before_us` and `not_after_us` as integers. For split, the probe must write a **new remote witness unavailable to the isolated peer**, query its exact action hash, and return `observation=new_remote_witness_unavailable_rejected` and `witness_hash`; after rejoin, return `verified_recovered_witness_hash` equal to that hash. The namespace harness verifies the data contract and network connectivity, **not independent source-key cryptography**.

```bash
sudo python3 -B scripts/chaos33_netns.py \
  --manifest /absolute/disposable/chaos33-netns.json \
  --report-dir /absolute/new/chaos33-netns-report \
  --ack-disposable-netns-lab
```

Inspect the report and per-conductor logs; a `KERNEL_PARTITION_AND_EXTERNAL_PROBE_PASS` **still requires independent review** of probe authenticity, integration, warrants, relay isolation, and signed time evidence before acceptance.

## Outstanding acceptance and release gates

- [x] Extend signed real-conductor delayed-gossip, missing-witness, and wrong-ancestry checks.
- [x] Build standalone SIGKILL supervisor, 2+1 Linux netns harness, and offline corrupt-file rejection.
- [x] Include negative tests that reject false completeness, wrong identity and unknown chain activity.
- [ ] Execute Python, Rust and WASM/build tests on exact SHA; record failures or successes, no synthetic PASS.
- [ ] Execute actual process kill/restart and inspect Holochain DB + keystore behavior, not only external probe output.
- [ ] Execute actual QUIC/Iroh partition with local bootstrap/relay, independent signed probe and verified DHT reconciliation.
- [ ] Exercise malicious same-key fork *across a verified physical partition*, then check actual warrant persisted after recovery.
- [ ] Inject corruption into an **offline disposable Holochain store copy** and show startup refuses it; never corrupt the original.
- [ ] Independently review host network/latency and validator behavior; repeat on merged candidate.
- [ ] Keep production and financial release NO-GO.

Do not infer global time consistency or unconditional rejoin success from an observed honest witness. The tests are explicitly scoped to their observed signed hashes and surviving authority state.
