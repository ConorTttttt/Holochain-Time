# Sprint 31 — DHT resource limits and evidence completeness (Agent U)

**Status: implementation candidate only; real 10k-link conductor run and measurements NOT YET EXECUTED. Production release remains NO-GO.** Base: `bae1e5b9380e92cbee511e07fea1681011d4d6d0`. Related: #3 and #4.

## Current-code audit (do not rely on the historical issue description)

- The coordinator `get_verified_time(ActionHash)` is intentionally disabled before DHT activity. A source guard prohibits any `get_links` call in the coordinator. No Holochain 0.7.1 link index pagination has been adopted; local truncation *after* `get_links` is **not** a network budget.
- `verify_time_with_witnesses` retrieves a single supplied target, up to 8 supplied anchor records and up to 32 supplied seal records using `get(..., GetOptions::network())`, and rejects duplicate action hashes *before* record retrieval. It does not enumerate links, cannot claim global completeness, and returns `evidence_complete=false` even when all submitted proofs verify.
- For each eligible non-identical anchor, `must_get_agent_activity(ChainFilter::take(target, count))` proves hash-linked ancestry, with at most 256 actions per host call. This patch additionally caps the **sum** across all such calls at 512 actions, failing the entire request if exceeded.
- Core evidence sets cap readings at 32 per witness; this patch additionally caps the **sum** of readings to cryptographically verify per request at 256. It fails explicitly, never ignores excess evidence.
- `author_chain_flagged` invokes local and network status queries and can return `None` when results are unavailable. The coordinator cannot bound the underlying host transport/warrant response allocation or network latency with these APIs. Do not claim that the 41-record cap or 512-action cap is a bound on DHT transfer bytes or wall time.
- `create_anchor` and `seal_action` write validated DHT links, not link-scanning reads. Oracle RPC and source-chain query paths need their own liveness operational controls. Integrity link validation validates target and author binding and contains no all-links enumeration.

## Enforced application-level verification envelope

| Dimension | Maximum / policy |
| --- | --- |
| Explicit witness hash input | 8 anchors, 32 seals; duplicate or cross-role hashes rejected |
| Direct network record lookups | <= 41 (target + 8 anchors + 32 seals) |
| Single ancestry lookup | <= 256 actions |
| Aggregate ancestry action requests | <= 512; checked before each host call |
| Evidence items in any witness | <= 32 |
| Aggregate witness evidence items | <= 256; checked before cryptographic verification |
| Global DHT links enumerated in verifier | **0**; legacy discovery fails closed |
| Verdict completeness | **Always false** for caller-supplied evidence |
| Host/network transfer bytes and latency | **Not enforceable through these coordinator host APIs**; remaining release blocker |

The response cannot silently drop a supplied proof: exceeding any budget returns an error. It is legitimate for valid proofs to be **rejected for budget**; this is not evidence suppression because no positive verdict is issued. The same input without a relevant proof can still yield a less restrictive conclusion, which is why a supplied-witness clean finding is not proof of network-wide timestamp safety.

## Real-conductor adversarial stress gate

`integration/conductor/tests/dht_spam.rs` creates one older genuine anchor, one newer irrelevant anchor, and a genuine third-party seal using three real signed test Roughtime sources. It then creates **10,240 actual validated DHT links**: 5,120 duplicate links to the newer unrelated anchor, 5,120 duplicate links to the existing valid seal. After DHT convergence, the test checks that the same supplied older anchor and seal yield identical bounds and classification; the legacy scan still rejects, and a 10,001-hash input is not silently truncated. It performs 128 verified reads in 8 batches of 16 simultaneous requests.

The test logs JSON sample request and output response bytes, process RSS/high-water marks on Linux, link-write time, and p50/p95/p99 verifier latency. **JSON sizes are NOT DHT host wire-byte measurements**; process RSS is shared-process, not isolated zome heap; and 16-way concurrency is not a 100+ simultaneous-caller result. A separate packet/host telemetry harness and 100+ simultaneous-client trial are still needed for full #4 acceptance.

Run on an isolated development machine with Holochain 0.7.1 Holonix, wasm32, `hc` and a **clean exact-SHA checkout**:

```bash
HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/run_sprint31_dht_spam.sh
```

The runner builds *feature-gated test WASM* (`vtime/dht-spam-test-only`), synthesizes a disposable DNA using **public insecure signing seeds**, runs baseline signed-quorum/smoke and the ignored 10k-link test, validates one metrics record, and stores SHA-bound logs/artifact hashes outside the repo. The test-only fixture is not included in default or production WASM. Never deploy that fixture DNA.

## Exit criteria / remaining risk

- [x] Inspect current code paths rather than assuming the historical unbounded scan still exists.
- [x] Preserve fail-closed retired global query and no-completeness contract.
- [x] Add aggregate budgets and 10k-link real-conductor test harness.
- [ ] Run native tests, Clippy, rustfmt and both WASM variants against this PR SHA.
- [ ] Execute the real-conductor test and attach its metrics to the PR (actual results, no simulated PASS).
- [ ] Measure true DHT wire response/host allocation and p95 under 100+ simultaneous clients.
- [ ] Review malicious invalid-link validation/transport cost separately from valid index-spam fixture.
- [ ] Independently review residual network status/warrants query liveness and Holochain host-level timeouts/caps.
- [ ] Independent security signoff and explicit production release review.

Until those remaining measurements and residual transport constraints are resolved, **#4 and the production release gate stay open**.
