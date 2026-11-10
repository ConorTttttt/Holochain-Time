# Sprint 22 — Real fork, warrants and recovery runbook

**Status: code prepared, acceptance not yet run.** The release decision
remains **NO-GO**. Use Holochain 0.7.1 as pinned in the repository and the
existing signed test-only DNA. These tests intentionally exercise a fork in
the **test lab only**; never use a funded, production or deployed DNA.

## 1. Prepare clean reviewed source and signed test DNA

```bash
git fetch origin
git switch --track origin/sprint/22-fork-recovery-2026-11-09
git status --porcelain
SHA="$(git rev-parse HEAD)"
nix develop "github:holochain/holonix?ref=main-0.7"
export HC_VTIME_EXPECTED_SHA="$SHA"
bash scripts/run_signed_quorum.sh
```

The signed-quorum runner builds both WASM zomes, creates a disposable
test manifest using public Roughenough fixture keys and retains a packed
`vtime.dna` in its reported output directory. **Use that actual path.**
`--ack-public-test-keys` acknowledges use of those insecure keys; it is
not technical proof that an arbitrary DNA was configured safely.

## 2. Reproduce logical fork fixtures and normal recovery

```bash
python3 -B -m unittest scripts.test_audit_fork_recovery -v
cargo test --manifest-path integration/conductor/Cargo.toml --locked \
  --lib fork_recovery -- --nocapture

bash scripts/run_fork_recovery.sh \
  --expected-sha "$SHA" \
  --dna "/absolute/signed-test-report/vtime.dna" \
  --ack-public-test-keys
```

The default runner executes a real three-conductor restart with signed
Roughtime evidence, the earlier Sprint 12 resilience test, workspace tests
and Clippy, writing a SHA-pinned report **outside the checkout**. The
auditor returns `BASELINE_ONLY_FORK_NOT_RUN`. This is intentionally not
fork/warrant acceptance.

## 3. Opt-in: actual fork and warrant persistence

Use a disposable Holochain test environment only:

```bash
bash scripts/run_fork_recovery.sh \
  --expected-sha "$SHA" \
  --dna "/absolute/signed-test-report/vtime.dna" \
  --ack-public-test-keys \
  --full --allow-same-key-fork-lab
```

This test installs **the same agent signing identity** on two **separate
conductor databases**. It first copies a genuine signed prefix from the first
genesis source chain into the empty second store with the native restore API, verifying
author, action/entry hashes, signatures, sequence and predecessor links before
import. No private grant entry is reserialized or imported. Separate genesis installations alone have different timestamps and do
not provide a shared predecessor for Holochain fork warrants. Both installed
cells must share the copied genesis head before their first calls initialize
the cells and author signed anchors while isolated. The test asserts the first
post-genesis signed actions have the same sequence and predecessor, archives
only their public signed headers plus the public signed anchors, then connects the two
conductors to a third observer in turn: branch A must integrate before its
conductor stops and the restored fork peer replaces its address. This avoids
duplicate-key address replacement hiding one branch. The alternate rejoins
after the first conductor leaves, refreshing online metadata after the
same-key offline advertisement. No warrant is inserted
by test code. Native tracing and per-store record-delivery/limbo counts are
retained for any warrant failure.

The observer queries Holochain 0.7.1's integration-store
`get_warrants_by_warrantee` API. The test requires **a positive actual
integrated warrant count** (120-second maximum) and checks warrant
`warrantee` binding. It restarts the **same** observer database/keystore
and confirms the warrant still exists. It then checks that the existing
`verify_time_with_witnesses` API does not return a clean status for the
warranted author. Only an explicit warrant/fork/invalid-chain error or
`author_chain_flagged=Some(true)` qualifies; generic unavailable-record,
timeout, `None` and `Some(false)` are *not* success.

A returned `FORK_WARRANT_RESTART_PASS` means **this particular lab
scenario** passed at one commit. It does not prove that every fork reaches
all authorities, that gossip always completes, that warrant query answers
are global, or that an unclean OS process kill is durable.

If the injected fork does not generate a warrant, do not weaken the
assertion or reinterpret a timeout as detection. Preserve the exact
SHA, test-only DNA hash, generated source-chain evidence, DHT logs and
test output. Check Holochain's actual authority arc/network conditions
and coordinate any implementation changes with the runtime owners.

## 4. Required evidence and next security gates

The runner produces `provenance.txt`, `results.tsv`, `audit.json`,
`fork_baseline.log`, optional `fork_injected.log`, all other test logs,
and `SHA256SUMS`. `audit.json` distinguishes baseline-only evidence
from a real integrated-warrant observation. Scrub private paths and
credentials before attaching reports to the PR.

Before Sprint 22 acceptance, Codex must run the same tests on the
**integrated branch SHA**, plus tests for Sprints 11–20. A separate,
controlled unclean conductor process kill (SIGKILL and restore), physical
partition/rejoin and independent-source deployment validation remain
explicitly **not covered** by this PR. Production verifier,
integrity-zome and DNA properties are unchanged.

### Integrated coordinator safeguard

The coordinator checks local status before network status. A locally integrated
warrant or fork always keeps `author_chain_flagged=Some(true)`, including after
restart and when a remote authority returns a partial valid/empty answer. Empty
status and missing observations remain unknown. Two non-flagged observations
are still not proof of global completeness. This changes no integrity schema,
DNA properties, cryptographic verification or financial agreement semantics.
