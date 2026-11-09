# Sprint 13 — Performance baseline (single host, test-only signers)

**Measured** at integration candidate commit `83939a938b263ee7e11ac32fbb74ce0f1ecd6162`
(DNA SHA-256 `89c51e48…bbd3f4`, 3 real Holochain 0.7.1 conductors on one Linux
host, 12 logical cores, publicly known TEST signers — not independent operators).
Raw logs and `report.json` are retained outside the repository. Single run; no
repetition across hosts or runs, so **no operating limit is established**.

| Workload | Attempts | Outcome | p50 ms | p95 ms | p99 ms |
| --- | ---: | --- | ---: | ---: | ---: |
| 120 concurrent signed `seal_action` | 120 | **3 succeeded, 117 failed** | 1295 | 1330 | 1335 |
| 33-witness query rejection (post-init) | 64 | 64/64 rejected for expected reason | 305 | 465 | 490 |
| 33-Roughtime-item seal rejection (post-init) | 64 | 64/64 rejected for expected reason | 315 | 470 | 494 |
| Native packet/evidence bound checks | 1536 | 1536 rejected, 0 accepted | n/a | n/a | n/a |

Peak sampled RSS: 1.58 GiB (seal load), 1.43 GiB (adversarial); peak CPU
≈1440% / 1840% of one core. Estimates are 250 ms process-tree samples.

## Findings (not security defects; fail-closed in all cases)

1. **Seal throughput under same-agent concurrency is poor:** 117 of 120 concurrent
   seals failed with `SourceChainError(HeadMoved)` (concurrent writes to one agent
   chain; callers must serialise/retry). This confirms issue #5 (seal throughput)
   remains open; batching (Sprint 15) is the proposed mitigation, not yet wired.
2. **Cold-start burst:** the first run issued 128 concurrent calls to cells that
   had not yet run zome init; all but 3 failed with `InitTimeout` (~30 s). The test
   now warms cells first; cold-start admission behaviour remains an open
   operational risk.
3. Oversized-input rejection is bounded and correct once initialised.

Not measured: real network partitions, live Roughtime, cross-host scale, multi-run
variance. Production release decision remains **NO-GO**.
