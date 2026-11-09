# Sprint 13 — Performance and adversarial-load runbook

**Status: implementation prepared; no measured host/conductor baseline yet.**
Do not infer throughput or safety from unexecuted test source. This sprint
does not change production zomes, integrity rules, or release readiness.

## Scope

- `integration/load/tests/seal_load.rs`: launches **120 overlapping**
  `seal_action` requests (configurable 100–2,000) across **three real Holochain
  0.7.1 Sweettest conductors**. It first creates valid, signed on-DHT anchor
  targets, exchanges peer information, and waits for consistency. Reuses three
  *test-only* signatures per target. Records every attempt's wall latency,
  success/error, origin conductor and successful action hash. It measures
  operation admission and validation, not live Roughtime UDP or signer throughput.
- `integration/load/tests/adversarial.rs`: 128 overlapping over-budget
  conductor requests: 64 lists of 33 explicit seals and 64 sets of 33
  Roughtime readings. Each must be rejected with the **expected** bounded-input
  error, not merely any error. Native repeated attacks verify packet sizes
  over 4 KiB request / 16 KiB response are rejected before cryptographic
  verification, plus the 32-evidence-item bound (512 iterations × 3 checks).
- Native coordinator regression `ancestry_requests_are_bounded_without_overflow`
  covers the **256-action** ancestry budget and overflow. No long-chain
  256-hop live traversal is claimed. The maximum of eight supplied anchor
  witnesses is separate from the maximum traversal *length*.
- Python standard-library runner collects a complete sample CSV, per-kind
  p50/p95/p99 nearest-rank latencies, error distributions, stage logs,
  process-tree CPU and sampled peak RSS. It produces `report.json`,
  `baseline.md`, and `SHA256SUMS` **outside the repository**.

## Prerequisites

Start in a clean, exact-commit clone of this branch. Use a Holochain 0.7
toolchain (HDK =0.7.1 / HDI =0.8.1), Rust, `cargo`, `hc`, Git and Python 3.10+.
For repeatability, prefer a fixed Holonix environment:

```bash
nix develop "github:holochain/holonix?ref=main-0.7"
python3 -m unittest discover -s scripts/load -p 'test_*.py' -v
```

Produce a **test-only** DNA using the repository's already reviewed
manifest-generation path. The signed runner prints an evidence directory that
retains `vtime.dna`, even after its disposable worktree is deleted:

```bash
export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
bash scripts/run_signed_quorum.sh
# Find the reported directory, then use its packed vtime.dna.
python3 scripts/load/run.py \
  --expected-sha "$HC_VTIME_EXPECTED_SHA" \
  --dna "../hc-vtime-signed-quorum-<SHA>-<UTC>-<PID>/vtime.dna" \
  --attempts 120 \
  --insecure-test-fixtures
```

Replace the example DNA pathname with the *actual* recorded output, not a
placeholder or a production DNA. The harness refuses a dirty checkout,
missing bundle/tools, mismatched expected SHA, fewer than 100 attempts, or
results written into the repository. The explicit insecure-fixtures flag
is mandatory. These public-seed signing keys **must never be deployed**.

The runner warms the Rust test binaries with `cargo test --no-run --locked`
then executes the seal load, adversarial suite, and coordinator ancestry budget
regression separately. A nonzero command, timeout, missing sample, wrong
adversarial rejection, or incomplete suite marks the run failed/incomplete.
If some concurrent *valid* seal attempts fail through source-chain contention,
the run records those failures and can still complete as
`completed_with_observed_failures` when at least one genuine attempt succeeded.
Do not misclassify a measured application error as a test-runner failure.

## Interpreting the baseline

Latency percentiles use nearest-rank on **all attempts**, including failures,
not just successful calls; refer to `samples.csv` and `error_counts` before
comparing platforms. Report environment (CPU model, core count, RAM, kernel,
container/VM, disk type) alongside the generated host and toolchain metadata,
and run at least three repetitions on one controlled machine. Save the complete
report directories and note whether compilation was cached.

CPU is wall-normalized usage of the observed process tree: 100% equals one
logical core, so multiple cores can exceed 100%. RSS is the sum of resident
memory for alive descendants sampled every 250ms on **Linux only**. Neither
metric is a precise per-zome allocation, nor guaranteed to catch transient
child process peaks. `build` resource usage belongs to compiler cost, **not**
steady-state conductor performance. On non-Linux hosts CPU/RSS are explicitly
unavailable, not silently zero. SHA256SUMS detects accidental report edits,
but is not a trusted attestation of runner or host.

This is a local, three-conductor workload on one machine, not a realistic
geographically distributed network. Roughtime signers are deterministic fixtures
hosted by the same process; independent-source acceptance is Sprint 11. Long
network disruption/recovery belongs to Sprint 12. Live UDP flooding, 10k-link
index scans, actual high-cardinality ancestry traversal, cross-host performance,
and production threat models remain unmeasured. Initial safe operating limits
must follow repeated measurements, not invented service-level targets.

## Acceptance and handoff

The sprint has a reproducible harness only when the pinned dependency
resolution, offline reporter checks, Rust test build, real conductor runs,
sample completeness, safety rejection assertions, and output hashing all pass
on the **same** recorded commit. Attach `baseline.md`, `report.json`,
`samples.csv`, stage logs and SHA256SUMS to the PR, after checking logs for
private machine paths or credentials. Do not merge this as evidence that the
system is production-ready without actual run artefacts and independent review.
