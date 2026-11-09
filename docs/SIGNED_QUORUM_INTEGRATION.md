# Signed-quorum integration: real RFC 10049 signatures, test identities only

Status: draft and uncompiled; production release NO-GO. This is a second stage
after the three-conductor smoke suite. It does NOT establish independent
time-source operators or financial safety.

Four DIFFERENT fixed, publicly known and INSECURE seed values (51,52,53,54)
are fed to the Roughenough 2.2 KeySource long-term signing backend.
The standard TestContext would reuse seed 42 for every instance, so it
cannot test an independent-source quorum. We therefore use four separate
long-term key sources and real RFC signing, not stubbed Ed25519 validation.

The runner generates a throwaway DNA with four test Roughtime keys,
zero oracle agents, min_sources=3, max_faulty=1, and a unique
DO-NOT-DEPLOY network seed. It uses a temporary detached Git worktree and
does not write keys into the source branch. All private fixture seeds
are already public and can never be trusted for production.

The positive Sweettest requires three Holochain 0.7 conductors and real
integrity/coordinator WASM. Alice submits three genuinely signed Roughtime
readings as an anchor; after DHT consistency, Bob independently seals the
anchor action with three target-nonce-bound readings. After further DHT
consistency, Charlie requests verification of the supplied anchor and seal
hashes. It must return actual lower and upper bounds and
evidence_complete=false. This is positive evidence for supplied proofs
ONLY, never a claim that every contradictory DHT proof was found.

Negative cases retry the exact target with: only two valid sources,
one valid signer answering a different nonce, one repeated signer, and
one mutated signed response. Each must produce the specific three-source
quorum error, not a generic conductor/network failure.

From a clean checkout with Holonix 0.7, hc CLI and the wasm32 target:

    HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)" bash scripts/run_signed_quorum.sh

The script builds both zomes, generates and preflights the temporary DNA,
packs it and runs the Sweettest while recording the exact Git SHA, WASM hashes,
packed DNA checksum, toolchain versions and logs outside the checkout.

Locally observed: the Python fixture generation/preflight suite passed
14 tests and shell syntax passed. Real Cargo build and Holochain conductor
tests DID NOT RUN in the authoring runtime, which lacks Cargo/Holonix.

Remaining P0 acceptance: real independently operated time sources, outage
and partition recovery, fork/warrant handling, link spam, 100+ concurrent
seals, oracle rate limiting, Unyt test-funded flows and security review.
Do not merge a release based solely on this test harness.

References: Soushi888 Holochain 0.7 agent skill, Roughenough server v2.2.0
and the existing CONDUCTOR_TEST_MATRIX. Tracker #39, smoke PR #38.
