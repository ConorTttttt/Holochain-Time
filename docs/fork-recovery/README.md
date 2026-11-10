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
conductor databases**, creates different signed anchor actions while
isolated, then connects them to a third observing conductor.

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
`fork-baseline.log`, optional `fork-injected.log`, all other test logs,
and `SHA256SUMS`. `audit.json` distinguishes baseline-only evidence
from a real integrated-warrant observation. Scrub private paths and
credentials before attaching reports to the PR.

Before Sprint 22 acceptance, Codex must run the same tests on the
**integrated branch SHA**, plus tests for Sprints 11–20. A separate,
controlled unclean conductor process kill (SIGKILL and restore), physical
partition/rejoin and independent-source deployment validation remain
explicitly **not covered** by this PR. Production verifier,
integrity-zome and DNA properties are unchanged.
