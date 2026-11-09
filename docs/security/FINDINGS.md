# Sprint 16 — Security findings and reproducible hypotheses

**Assessment status (9 November 2026):** pre-execution review only. No
new exploited vulnerability is confirmed. Severity values below express
*potential impact* and are not CVSS scores. Findings must be updated with
exact-SHA test logs, fuzz crashes or other real evidence before closure.

| ID | Severity | Status | Observation / risk |
| --- | --- | --- | --- |
| S16-01 | Medium (provisional) | Open — resource risk unmeasured | The explicit-witness query limits **count**, but its coordinator comment admits neither individual DHT record size nor fetch latency is bounded by that count. |
| S16-02 | Medium (provisional) | Open — resource risk unmeasured | Up to 32 Roughtime/evidence items can require multiple signature and Merkle checks; sustained valid-looking expensive requests may saturate conductor CPU. Rejection limits reduce but do not establish throughput safety. |
| S16-03 | High impact *if misused* | Documented integration hazard, not a code bug | A caller can mistake `NoContradictionInSuppliedProofs` for global absence of contradictory evidence. The endpoint intentionally reports `evidence_complete=false`. |
| S16-04 | High impact *if deployed* | Existing operational hazard, not a code bug | Deterministic Roughenough fixture keys/seeds are public, not independent external time-source operators. Do not trust them in a production DNA. |
| S16-05 | Unassessed | Open — audit not run | Cargo dependency lockfiles alone do not show known advisory or unsound transitive `unsafe` findings. |
| S16-06 | Informational | Open — coverage pending | Parser mutation tests exist, but fuzz campaigns and integrated witness tests are not yet executed at this PR head. |

## S16-01 — Bounded witness count does not prove bounded network work

**Code reference:** `dnas/vtime/zomes/coordinator/vtime/src/lib.rs`,
`verify_time_with_witnesses` (limits eight anchors and 32 seals). The
function's own documentation notes that the bound does not control end-to-end
latency or size of individual returned records.

**Reproduction plan (test-only, not yet performed):** Build a valid test DNA
and populate target actions plus up to 8 eligible anchors and 32 seals. Repeat
queries at 1/8/32 witness combinations from three agents, measure zome call
latency, DHT timeouts, conductor RSS/CPU and whether unavailable witnesses
fail closed. Compare a single large record to many small records at the same
witness count. Capture exact commit, hardware and input bytes.

**Expected outcome:** bounded count and fail-closed errors, not necessarily
bounded wall time or memory. **Fix gating:** only propose per-record byte/timeout
budgets after host API compatibility review with Sprints 11/12; do not silently
truncate security-relevant proofs.

## S16-02 — Verification work amplification

**Code reference:** `crates/vtime_core/src/evidence.rs`,
`verify_evidence_set`; `roughtime.rs` verification caps (4 KiB request,
16 KiB response; 32 evidence items). Multiple genuine Ed25519 validations
consume CPU even when accepted.

**Reproduction plan:** On the same test machine, compare
`cargo test --workspace --locked -p vtime_core --test security_adversarial`
with Sprint 13's real 120-seal load and adversarial workload. Increase valid
evidence set size to the policy maximum; log CPU percent, memory peaks,
p50/p95/p99, accepted/rejected counts and verifier calls. Check the
per-request admission boundary. Repeat three runs.

**Expected outcome:** oversized inputs rejected without signatures, but no
claimed upper bound on repeated valid work. If saturation is demonstrated,
coordinate admission/rate-limit changes; production shared cryptography is
owned by Sprint 11.

## S16-03 — Explicit proofs cannot establish global completeness

**Code reference:** `AGENTS.md`, `verify_time_with_witnesses` return.
**Reproduce:** run signed-quorum conductor test with a valid supplied
anchor and seal; inspect `evidence_complete` in the accepted result. It is
`false` by design even when the conclusion reports no contradiction.

**Mitigation:** financial consumers must reject treating this as
global-negative evidence. This is a **consumer integration decision**, not
a request to change protocol semantics or revert a safety guard.

## S16-04 — Public deterministic fixture keys

**Code reference:** `integration/conductor/src/fixtures.rs`,
`INSECURE_TEST_SEEDS`. **Reproduce:** call `signed_three` twice with the
same nonce and compare fixture public keys. This proves local test repeatability,
not independent Roughtime sources. **Mitigation:** test-only DNA and
`HC_VTIME_SIGNED_TEST_ONLY=1` sentinel. Require independent authenticated
operators under Sprint 11 before release.

## S16-05 — Third-party dependencies and unsafe code

**Reproduce:**

```bash
python3 scripts/security/inventory.py --expected-sha "$(git rev-parse HEAD)" \
  --out "../security-inventory.json"
cargo audit --file Cargo.lock
cargo audit --file integration/conductor/Cargo.lock
```

The inventory records *locked* package names, exact versions, sources and
checksums from both lockfiles; it scans tracked Rust files for probable
`unsafe` declarations (excluding single-line comments) and
`#![forbid(unsafe_code)]`. It does **not** inspect transitive source, macro
expansion, FFI, Holochain host implementation, WASM output or Rhai code.
`cargo audit` must be installed and allowed to access an up-to-date advisory
database to assess known vulnerabilities; it is **not run** by inventory.py.
Save advisory database revision, command output, any exemptions and reasons.

**Disposition:** never claim “0 vulnerabilities” merely because local
Rust code forbids unsafe or no tool was installed.

## S16-06 — Pending dynamic security evidence

**Reproduce:** follow the standalone `docs/security/README.md` runbook to
execute the deterministic regressions, real-conductor witness matrix and two
libFuzzer targets. Save input corpus hashes, exact Rust/nightly versions,
crash artefacts, replay seeds, executed iterations and elapsed time.

**Disposition:** only a real crash plus independently rerun minimized
reproducer supports a confirmed parser or verifier defect. A clean fuzz run
at fixed time is limited evidence, not a formal security guarantee.

## Coordination / release disposition

Do not edit shared `vtime_core` verification code in this independent branch
without an agreed interface with Sprint 11. Local acceptance requires
Codex to rerun all regressions after branch integration and confirm shared
crypto edits did not alter the protected invariants. The project's production
release decision remains **NO-GO**.

## Execution addendum (consolidation candidate 83939a93…, 9 Nov 2026)

* `security_adversarial` deterministic suite: 4/4 pass. Conductor
  `security_witness`: pass (9 malformed witness fixtures rejected, 1 valid accepted).
* Bounded cargo-fuzz (nightly, libFuzzer, 120 s each, seeded from corpus
  generator): `roughtime_parser` ≈24.4M runs, `roughtime_exchange` ≈5.9M runs,
  **no crashes, timeouts or OOM**. This is a short smoke campaign, not assurance.
* S16-02 partially measured: see `docs/performance/BASELINE.md`; rejection is
  bounded, repeated *valid* work remains unmeasured.
* No confirmed vulnerability. Confirmed *test-suite* defects fixed during
  consolidation: stale Roughtime interop fixture (952-byte request, wrong hashes),
  non-compiling Sprint 11/12 tests, mismatched keyword in Sprint 20 preflight.
* Sprint 12 same-key two-conductor fork test: **INCONCLUSIVE**. The verifier failed
  closed ("target action not found") but did not surface an explicit fork/warrant,
  which that test requires. It stays `#[ignore]`d; fork detection is NOT demonstrated.
