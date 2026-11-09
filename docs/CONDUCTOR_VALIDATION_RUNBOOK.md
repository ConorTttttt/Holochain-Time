# Holochain 0.7 build validation and conductor testing

**Status: harness drafted; no Rust, WASM or conductor test executed in the authoring runtime (Cargo and Holochain CLI absent). Release NO-GO.**

## The two separate gates

1. **Build/format gate:** Check the exact commit SHA, run all Rust unit tests, Clippy, rustfmt and both WASM zomes. Save logs and lockfile/toolchain checksums.
2. **Real-conductor smoke gate:** Run a test-only DNA in 3 actual Holochain 0.7.1 Sweettest conductors. Check distinct agents, DHT gossip consistency, padded Roughtime request, deterministic seal nonce, disabled unsafe legacy query, bounded witness inputs and malformed nonce rejection.
3. **Signed-quorum acceptance gate (NOT included in smoke):** Verify valid independent oracle/Roughtime signatures, 3-source quorum, a third-party seal, valid anchor ancestry, invalid signatures, wrong nonce, unavailable source, restarted chain and load/flood tests. Only the last gate exercises release-critical semantics.

## Exact-commit build commands

Use a clean Git clone of the *actual merged candidate*; do not assume an old PR SHA is the released candidate. Enter the Holochain 0.7 Holonix shell. The workspace pins HDK 0.7.1, HDI 0.8.1.

    git fetch origin
    git switch --detach <FULL_REVIEWED_SHA>
    nix develop 'github:holochain/holonix?ref=main-0.7'
    cargo fmt --all -- --check
    cargo test --workspace --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings
    RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=--import-undefined' cargo build --release --locked --target wasm32-unknown-unknown -p vtime_integrity -p vtime
    HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/verify_local.sh

**Important:** A GitHub Actions workflow whose jobs never started is *not* a Rust test failure and *not* a passing release check. Investigate issue #22 in the repository Actions Settings/billing/runner UI.

## Test-only DNA preparation

The committed sample DNA contains REPLACE_WITH placeholders. It is NOT a working production/test quorum. Use a throwaway worktree to configure **real test-only source public keys** from test keystores and Roughtime servers. Don't commit private keys or real production credentials. The sample quorum is min_sources=3 and max_faulty=1, requiring at least four distinct trusted keys for tolerance of one offline source. Independent public keys are not necessarily independently operated time sources.

After building WASM in that throwaway worktree:

    python3 scripts/check_test_dna_config.py --manifest dnas/vtime/workdir/dna.yaml
    hc dna pack dnas/vtime/workdir

This preflight validates only **key spelling, counts, duplicate keys and the stated quorum promise**. It does NOT establish that keys have signing services, operator independence, or that the packaged DNA actually matches the checked manifest.

## Run actual 3-agent smoke

From a **clean** checkout of the validation branch (after it is merged/rebased onto the intended candidate), point to the packed DNA from the test worktree and the manifest that produced it:

    export HC_VTIME_TEST_DNA=/absolute/path/to/throwaway/dnas/vtime/workdir/vtime.dna
    export HC_VTIME_TEST_MANIFEST=/absolute/path/to/throwaway/dnas/vtime/workdir/dna.yaml
    export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
    bash scripts/run_conductor_smoke.sh

The independent integration/conductor crate keeps heavy host Holochain dependencies away from production WASM workspace. The first run will generate its own Cargo.lock; review and pin this lockfile before treating smoke as a reproducible release check. The script records the test DNA SHA-256, manifest SHA-256, Git SHA, Rust version and test logs. Keep reports outside the repository and review for secrets before posting.

**Do not interpret smoke passing as proof of verified time or financial readiness.** A live signed-quorum harness needs test-only signing sources corresponding to the DNA properties. The source code must be exercised across ≥3 agents after DHT consistency; the Unyt financial transactions require test funds and separate tests.

## Signed-quorum acceptance plan

| Test | Expected observable result |
| --- | --- |
| Three trusted time sources + valid anchor | Verified not-before bound |
| Independent sealer, target on different agent | Verified not-after bound |
| Wrong nonce / forged signature / unrelated anchor | Explicit rejection, not global consistency |
| Caller omits contradictory evidence | evidence_complete remains false |
| One source offline at f=1 | Documented quorum/liveness behaviour |
| Many links under target | No unbounded legacy scan; no confident false verdict |
| Restart oracle | Chain sequence and high-water floor preserved |
| 100+ concurrent seals | p50/p95/p99, capacity, refusals and safe nonce binding |
| Unyt test-funds agreement | Valid execution and invalid proof rejection |

References: Holochain 0.7 Sweettest official APIs, Soushi888 Holochain agent skill/testing.md, project docs/CONDUCTOR_TEST_MATRIX.md, issues #7, #8, #22 and #1. No production funds until P0 acceptance, independent audit and rollback plan.


## Signed, three-source conductor quorum (test-only)

The new parallel validation layer executes real Ed25519 signatures from
four public, deliberately insecure Roughenough test identities across three
actual Holochain conductors. Unlike the smoke suite, it verifies a real
third-party seal and rejects wrong-nonce, duplicate, insufficient, and
mutated Roughtime responses. It never certifies operator independence or
global evidence completeness.

On a clean reviewed SHA with Holochain 0.7 Holonix:

    HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/run_signed_quorum.sh

See docs/SIGNED_QUORUM_INTEGRATION.md for setup, evidence and limitations.
The Rust/conductor test has not run in the authoring environment.
