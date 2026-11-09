# Sprint 12 — Holochain 0.7 conductor resilience tests

**Status:** tests and evidence checks implemented; actual Rust build, three-conductor execution, real transport partition, fork/warrant propagation and 256-action load **not yet verified**. Release remains NO-GO.

**Scope:** test-only files under `integration/conductor/` and `scripts/`. No production coordinator or integrity-zome changes. These tests must be retargeted to the final merged release candidate and run again on that exact SHA.

## Two modes

**Baseline** (`bash scripts/run_conductor_resilience.sh`) performs real three-conductor Sweettest calls against an ephemeral DNA with three-of-four authentically signed test-source responses, and verifies:

- An existing Alice anchor and Bob third-party seal remain readable and bounded after Bob's conductor shuts down.
- Alice and Charlie continue writing/verifying during Bob's outage; later Bob restarts using the **same data root and keystore** and catches up with their new actions.
- Nonexistent anchor and seal hashes produce explicit missing-witness errors. A genuine anchor by a *different* author and an anchor written *after* the target cannot lend false ancestry.
- Three live conductors with bootstrapping disabled cannot initially validate remote evidence; after explicit peer-information exchange and gossip convergence, the same proof is verifiable. This is **peer-discovery isolation**, not a guaranteed packet-level network partition once peers know one another.
- All successful witness results retain `evidence_complete: false`. A `None` `author_chain_flagged` is treated as *unknown* by test-only `resilience::assess`, never as a clean chain. An observed fork or timestamp contradiction is not trusted.

**Full fixture** (`bash scripts/run_conductor_resilience.sh --full`) additionally executes two normally ignored tests:

- **Ancestry:** 128 sequential signed anchors on one source chain. Because each anchor creates an entry action plus a link action, the proof path counts are **255 allowed** and **257 rejected**; the coordinator's native unit test additionally checks the exact 256-allowed boundary. The count is computed from Holochain action sequences, not from number of API calls. This deliberately exercises the expensive `must_get_agent_activity` filter with a large real chain. If a later implementation writes a different number of actions per anchor, this test needs adjustment and must NOT be marked green by deleting the assertion.
- **Same-author fork laboratory fixture:** Two isolated conductor databases share one intentionally duplicated **test** agent key. Their first independent source-chain writes create competing branches. A third observer must not report that this known conflict has an automatically trusted clean chain. This requires Holochain 0.7 fork/warrant handling and is subject to real-world Sweettest propagation; do not pretend an unrelated-author anchor demonstrates a same-author fork.

A true **transport-level multi-agent partition**, not just a powered-off node or disabled bootstrapping, requires a supported Iroh relay/transport fault injector (firewall, relay disruption, network namespace or equivalent). It is **not** implemented in this test suite and remains an acceptance blocker. Rejoin from a genuine transport split must demonstrate DHT convergence, warrant/fork handling and no acceptance of missing or conflicting evidence.

## Prerequisites

A clean Git checkout at the reviewed commit, Holochain 0.7 Holonix shell, `cargo`, `rustc`, `hc`, `python3`, `git`, `sha256sum`, and the `wasm32-unknown-unknown` target. The standalone conductor harness must have a pinned `integration/conductor/Cargo.lock`. No production secrets and no real funds.

Use the same publicly known, intentionally insecure Roughenough seeds (51–54) as `integration/conductor/src/fixtures.rs`. The runner builds WASM zomes, generates a disposable test-only DNA manifest from the signed key fixture, packs it and executes actual Sweettest tests across three Holochain conductors. **Four keys do not mean four independent operators**: this demonstrates cryptographic quorum mechanics, not production source independence.

```bash
# Enter a pinned Holochain 0.7 Rust/Holonix environment, then check out the
# intended merged/reviewed release candidate (NOT an old draft branch SHA).
git status --short
git rev-parse HEAD
HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/run_conductor_resilience.sh

# Longer, destructive test-only source-chain fork + ancestry tests.
HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/run_conductor_resilience.sh --full
```

The runner refuses wrong SHAs, dirty trees, missing binaries and an unpinned standalone lockfile. It records the actual Git SHA, both WASM SHA-256 hashes, packed DNA/manifest checksums, test keys, run logs and explicit result status in a report directory **outside** the checkout. A failed Rust test produces a non-zero exit and retains logs; no test is silently skipped except the specifically documented `--full` cases in baseline mode.

## Evidence gate and failure reporting

`scripts/audit_conductor_resilience.py` checks the Rust test result summary and all scenario-specific markers; absent, duplicate, or missing-fork/ancestry logs block the respective mode. Run its own checks with:

```bash
python3 -m unittest discover -s scripts -p 'test_audit_conductor_resilience.py' -v
python3 scripts/audit_conductor_resilience.py --report /path/to/report
python3 scripts/audit_conductor_resilience.py --report /path/to/report --require-full
```

`BASELINE_PASS` only means the real node-offline and peer-discovery tests passed on this recorded SHA. `FULL_FIXTURE_PASS` adds the ancestry and same-author fork lab tests. Both **always** set `release_ready: false`, `physical_network_partition_proven: false`, and `independent_roughtime_operators_proven: false`. A successful Python auditor test, a good GitHub job summary, or a valid Merkle inclusion proof is not proof of runtime resilience.

**Remaining required gates:** actual transport-level 2+1 partition/rejoin and conflicting ancestor/warrant propagation, explicit 256-action conductor acceptance or coordinated native boundary proof plus conductor 255/257 checks, true independent-server signed quorum (#11), full negative-entry validation, source-outage testing, restart under crash (unclean termination), high-load 100+ seals, Unyt test funds, release rollback, independent audit.

Reference: `docs/CONDUCTOR_TEST_MATRIX.md`, `docs/SIGNED_QUORUM_INTEGRATION.md`; Holochain 0.7.1 Sweettest APIs `SweetConductor::shutdown/startup`, `SweetConductorBatch::from_config_rendezvous`, `exchange_peer_info`, and `await_consistency_s`.
