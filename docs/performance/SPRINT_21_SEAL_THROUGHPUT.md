# Sprint 21 — Seal throughput and per-author source-chain queue

**Agent K — Concurrency and performance.** GitHub-first design; no merge, deployment or live-performance acceptance yet.

## Observed baseline and goal

Sprint 13 recorded 120 concurrent Holochain seal_action calls: **3 succeeded and 117 failed with SourceChainError(HeadMoved)** on three genuine Holochain 0.7.1 Sweettest conductors (docs/performance/BASELINE.md). A single Holochain author has a linear source chain, so simultaneous appends racing on one head can fail. Sprint 21 targets 120+ concurrent CALLERS, with actual writes **serialized per author**; three independent local author chains can write in parallel. This is not 120 simultaneous writes on the same chain.

A queue can improve success rate at the cost of queue-wait latency. Do not claim an unconditional speedup or publish a production throughput target without local measurements and repetitions.

## Implementation

- integration/load/src/seal_queue.rs: in-process bounded queue (one fair semaphore per author lane), global limit on requests including pending ones, bounded queue wait, conservative HeadMoved-only retry with capped exponential delay and explicit metrics. Full queue and queue timeout never invoke the zome.
- integration/load/tests/queue_policy.rs: deterministic artificial contention (30 jobs across three lanes), cross-lane parallelism, saturation and timeout checks, bounded HeadMoved retries, and negative tests proving unknown errors, malformed evidence, transport problems and ambiguous timeouts are never replayed. This is NOT a real conductor test.
- integration/load/tests/queued_seal_load.rs: three real Holochain 0.7 Sweettest conductors, authenticated test-only anchor targets, 120 to 2,000 concurrently polled client caller futures, real nonce-bound signed seal_action zome writes, unique successful TimeSeal ActionHashes, DHT consistency and at least twelve third-party cross-conductor witness verifications. Any failed seal or duplicate hash fails.
- scripts/load/run_21.py: exact-SHA real-conductor execution and strict sample acceptance. Produces report.json, results.md, samples.csv, command logs, SHA256SUMS outside source. Measures p50/p95/p99 caller/queue/service latency, seals per second, HeadMoved retries and sampled process-tree CPU and memory. Optional unqueued Sprint 13 comparison on the same exact SHA.
- scripts/load/test_run_21.py: offline tests reject missing/replayed samples, duplicate hashes, fake throughput success, wrong retry counts, missing third-party verification and tampered test-DNA provenance. Existing Sprint 13 test remains unchanged.

No coordinator zome, DNA integrity rules, Roughtime signatures, or Unyt logic are changed.

## Exact-commit local runbook

Use a clean, fully fetched SHA in a Holochain 0.7 Holonix-compatible toolchain with Rust, hc, wasm32 target, Python 3.10+ and resource headroom for three local real conductors. Never supply funded keys or production DNA.

First generate the same SHA's throwaway signed test DNA through the existing signed runner:

    export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
    bash scripts/run_signed_quorum.sh

The script prints a new evidence directory containing vtime.dna, dna.yaml and provenance.txt. It must have completed both signed-quorum and smoke stages successfully. All root keys are publicly known insecure test signers.

Then run Sprint 21 (replace the example fixture path with the ACTUAL runner output):

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/load -p 'test_*.py' -v

    python3 scripts/load/run_21.py \
      --expected-sha "$HC_VTIME_EXPECTED_SHA" \
      --dna "../hc-vtime-signed-quorum-<SHA>-<UTC>-<PID>/vtime.dna" \
      --attempts 120 \
      --insecure-test-fixtures \
      --compare-unqueued

Omit --compare-unqueued for the shortest repeat run. For an even larger run use --attempts 256 or 512. Use --out /absolute/new/path/outside/repo to fix output destination; reports are never overwritten. The runner verifies full SHA, clean source, fixture marker, matching packed DNA digest, and passing signed-conductor provenance before executing actual tests.

## Mandatory acceptance gate

A Sprint 21 benchmark may claim **local PASS** only when:

1. All synthetic queue-regression tests and offline Python telemetry regressions pass.
2. The pinned signed test DNA and three genuine Holochain 0.7 conductors run at the same commit; no mocks may satisfy the real-seal gate.
3. At least 100 concurrently admitted client requests, normally 120, complete successfully and produce a matching set of distinct valid ActionHashes. Every task must succeed; zero unexpected errors. Per-author calls serialize while separate agents may overlap.
4. After DHT synchronization, at least twelve successful seals are verified from another conductor using the actual target anchor and seal record. Missing or invalid proof is failure.
5. The report contains the exact Git SHA and DNA SHA-256, workload size, success/failure counts, measured completed seals/second, p50/p95/p99 queue wait, client latency and service time, retry counts, per-author lane distribution, observed CPU/RSS, raw logs and SHA256SUMS.
6. Existing adversarial tests still reject oversized witness/evidence requests.
7. Repeat at least three times on a controlled host; compare unqueued/queued results on the same SHA and record host/build-cache differences. A single run cannot establish an operating SLA.

Machine-readable status PASS requires every stage executed and all queued records verified. No fabricated performance numbers are included in this branch.

## Queue safety, scope and handoff

The queue defaults to capacity 256 and 180 seconds max local wait. The performance runner requests capacity >= task count, permits up to 360 seconds queue wait, and caps capacity at 4096. Three HeadMoved-only retries (20, 40, 80 ms) are permitted. Signature errors, nonce mismatch, invalid proof, timeout, generic conductor errors and ambiguous transport results are terminal. Retrying an ambiguous response might duplicate a successful write, so it is forbidden without a separately verified idempotency/reconciliation protocol.

The queue is currently **a test-side, in-process library**, not a globally durable multi-host production service. The owning app must map actual AgentPubKeys (not merely conductor indices) to shared per-agent queues across all local producers. Cross-process writers can still cause HeadMoved. Production needs operation IDs, durable submission semantics, crash recovery and reconciled outcome checks before claiming exactly-once behavior. Do not paper over faults by allowing invalid signatures, raising accepted evidence budgets or weakening quorum.

For Codex: merge reviewed Sprint 21 code into a local integration candidate, test with Sprint 17 exact-SHA and the above load runner, preserve new measured evidence outside Git, and evaluate production queue wiring as a separately reviewed change. Signed test-only source roots do not establish independent Roughtime operators, real UDP throughput, cross-host partition resilience or deployment safety. Release decision remains NO-GO until all other gates pass.

**This sprint must not merge anything automatically into main.**
