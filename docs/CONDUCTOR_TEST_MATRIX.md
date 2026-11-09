# Sprint 2 — Holochain conductor acceptance matrix

**Status: design only; not yet run.** Use actual hApp WASM, ≥3 independent agents and test-only configured oracle/Roughtime keys. Confirm HDK/HDI pins, package hApp, and await DHT consistency before cross-agent reads. Save action hashes, logs and evidence for reproducibility.

| Test | Scenario | Expected outcome |
|---|---|---|
| HC-01 | Author's anchor precedes target in same hash-linked chain | Proven lower bound |
| HC-02 | Third party creates a valid seal for target | Proven upper bound regardless of seal author |
| HC-03 | Supplied seal targets another action | Explicit query error |
| HC-04 | Invalid signature or nonce in seal | Integrity rejects; explicit query fails closed |
| HC-05 | Anchor from another author/fork | No accepted lower bound; explicit error |
| HC-06 | Agent-activity proof unavailable or chain warranted | No false claim of valid ancestry; failure/unknown surfaced |
| HC-07 | Duplicate hashes, including cross-role duplication | Reject before record lookups |
| HC-08 | More than 8 anchor or 32 seal hashes | Immediate budget error |
| HC-09 | 10k duplicate/irrelevant links injected into public index | Explicit-witness result unaffected by link enumeration; record legacy failure separately |
| HC-10 | Valid contradiction against action timestamp | Backdated/FutureDated; never `Consistent` |
| HC-11 | One offline oracle and up to f bad responses | Expected quorum behavior, timeout captured |
| HC-12 | Conductor restart, log recovery, source-chain fork | No replay or invalid chain acceptance |
| HC-13 | Concurrent seal requests | Capture signing capacity, quorum success and p50/p95/p99 |
| HC-14 | 10k links and ≥100 concurrent callers | Profile memory, throughput, request sizes, failures and correctness |

**Tests:** Sweettest for multi-agent assertions and validation; Wind-Tunnel `main` for Holochain 0.7 performance data (older tagged Wind-Tunnel releases may target Holochain 0.6). Do not replace real-conductor tests with pure unit tests. Do not use real funds.

**Exit:** each P0 scenario passes against a packaged release candidate, with run logs linked in PR; legacy index risks #3/#4 remain open until safely addressed.
