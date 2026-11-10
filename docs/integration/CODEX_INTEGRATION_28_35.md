# Sprints 28–35 — Local Codex integration preflight

This is a **tooling-only** preflight from `main` at
`bae1e5b9380e92cbee511e07fea1681011d4d6d0`. It does **not** merge PRs,
modify production verification/signing/financial rules, execute privileged
network labs, or authorize production release. Keep
`scripts/make_reviewed_pins_27.py` and `scripts/release_acceptance_27.py`
unchanged as historical evidence.

## Inputs and first checks

The sole authoritative PR mapping is in `scripts/make_reviewed_pins_35.py`:
#67/28, #69/29, #76/30, #68/31, #71/32A, #72/33, #77/34, #74/35.
The snapshot SHA table and pairwise changed-file matrix are in
`docs/integration/sprints28_35_readiness.json`. **Never use its snapshots as
live pins.** Check the current GitHub API response for every PR, confirm its
origin branch and exact main base, and read any review comments that appeared
after this preflight. All eight independent PR tips were found to descend from
the starting `main`, and the snapshot showed zero exact changed-file
collisions; semantic interface and test-infrastructure conflicts remain.

Run in a fresh full clone with authenticated `gh`, `git`, Python >=3.11,
Cargo/rustfmt/Clippy, `wasm32-unknown-unknown`, `hc`, and the 0.7 Holochain
toolchain (for example, the appropriate reviewed Holonix 0.7 shell). Inspect
all `Cargo.lock` graphs and `cargo --version`/`rustc --version`/`hc --version`.
Do not use shallow clones. Existing `main` and sprint PR refs must not move.

```bash
set -euo pipefail
REPO=ConorTttttt/Holochain-Time
BASE=bae1e5b9380e92cbee511e07fea1681011d4d6d0
git clone --no-single-branch "git@github.com:${REPO}.git" holochain-time-codex
cd holochain-time-codex
git fetch origin --prune
test "$(git rev-parse origin/main)" = "$BASE"
for pr in 67 69 76 68 71 72 77 74; do
  gh api "repos/$REPO/pulls/$pr" --jq     '{number: .number, state: .state, head: .head.sha, branch: .head.ref, base: .base.sha}'
done
# Only on an isolated worktree, never on main:
git worktree add -b codex/review-sprints28-35 ../holochain-time-combined "$BASE"
```

Resolve Sprint 29/30 request-ID, signing-state and checkpoint contracts before
wiring anything. The sprint implementations may be reviewed and integrated only
in the disposable **candidate branch** using the *current* fetched PR HEADs,
retaining each tip's ancestry (normal merge commits, not squash/cherry-pick).
For a merge conflict, stop for review; do not silently drop a branch or alter
production cryptographic/financial behavior. Do not point `main` to the
candidate. If an input changes during integration, re-review/rebuild.

## Human-reviewed external scope: no invented provenance

After the candidate is **committed**, clean, and all eight requested tips have
been inspected, discover *every* integration-only commit not reachable through
the starting baseline or any authoritative tip. On the candidate worktree:

```bash
CANDIDATE=$(git rev-parse HEAD)
test -z "$(git status --porcelain --untracked-files=all)"
test "$(git rev-parse --is-shallow-repository)" = false
# Use the eight LIVE reviewed SHA values, NOT the dated snapshot:
git rev-list --reverse "$CANDIDATE" "^$BASE"   "^$SHA_28" "^$SHA_29" "^$SHA_30" "^$SHA_31"   "^$SHA_32A" "^$SHA_33" "^$SHA_34" "^$SHA_35"
```

Use the resulting commit list to review every merge-resolution/glue change
individually. Then create an **external** JSON file, e.g.
`../codex-review/scope.json`, with this shape:

```json
{
  "schema": "hc-vtime/integration-scope-28-35/v1",
  "mode": "complete",
  "included_prs": [67, 69, 76, 68, 71, 72, 77, 74],
  "excluded_prs": [],
  "reviewed_extras": [
    {"sha": "<ACTUAL_40_CHARACTER_INTEGRATION_COMMIT>", "reason": "substantive, human-reviewed conflict resolution and why it is allowed"}
  ],
  "reviewer": "<actual human reviewer identity>",
  "reviewed_at_utc": "<actual YYYY-MM-DDTHH:MM:SSZ>"
}
```

The extras list is illustrative: it must match the **actual** integration-only
commit inventory exactly, including merge commits. No placeholder SHA, reviewer
or timestamp should be submitted. For a reviewed partial candidate, use
`mode: reviewed_partial`, list every excluded PR with a substantive reason in
`excluded_prs`, remove only those PR numbers from `included_prs`, and pass
`--allow-partial`. Every input is still discovered and checked; **partial
candidates can never be declared full development-integration READY**.
External review declarations are provenance records, not cryptographic proof of
independent review.

```bash
EXTERNAL_SCOPE="$(realpath ../codex-review/scope.json)"
EXTERNAL_PINS="$(realpath -m ../codex-review/reviewed-pins-28-35.json)"
EXTERNAL_REPORT="$(realpath -m ../codex-review/acceptance-28-35)"
python3 -B scripts/make_reviewed_pins_35.py \
  --repo "$PWD" --expected-sha "$CANDIDATE" \
  --reviewed-scope "$EXTERNAL_SCOPE" --output "$EXTERNAL_PINS"
python3 -B -m unittest discover -s scripts -p 'test_*35.py' -v
python3 -B scripts/integration_preflight_35.py \
  --repo "$PWD" --expected-sha "$CANDIDATE" \
  --pins "$EXTERNAL_PINS" --report-dir "$EXTERNAL_REPORT"
```

All report, pin, scope and package directories must be new and **outside**
the source checkout. Never rerun into an existing evidence location. Preserve
`report.json`, logs, `SHA256SUMS`, the reviewed scope, and the eight live PR
metadata records. New runner reports are commit-specific; change of HEAD
invalidates prior acceptance.

## What the combined entrypoint runs

It calls Sprint 17's `scripts/integration_validate.py` for source/ancestry,
Python discovery, both Rust formatting checks, root workspace native tests,
root Clippy `-D warnings`, **default-feature** integrity+coordinator WASM,
fresh test-only signed DNA, signed quorum and byte-repacked DNA. The preflight
audits it with Sprint 27's `audited_core`; test-only Sprint 31 spam exports
must not appear in the default WASM. It reuses Sprint 27's negative deployment
config, signed restart, >=100 signed seal load, Sprint 24 journal, Sprint 23
Roughtime offline, Sprint 25 ops offline and Sprint 26 Unyt signed-proof
offline stages.

Additional stages are Sprint 28 offline Python and three native Roughtime
crypto suites; Sprint 29 native runtime, restart, real test-only process-crash
and backup/migration; Sprint 30 SQLite/auth/ambiguous-write test suite;
Sprint 31 root DHT limits and signed security witness tests; Sprint 32A policy
Python and native Unyt harness tests; Sprint 33 offline audit/network-lab
safety tests and signed three-conductor Sweettest recovery; Sprint 34
`scripts/run_sprint34.sh` injected alert/drill audit; Sprint 35
`scripts/audit35/run_local.sh` exact-source bundle re-verification and
`scripts/audit35/supply_chain.py` metadata, cargo-audit and cargo-deny
attempts. Every green command needs actual positive test counts and
supporting logs; missing tools/dependencies are **NOT RUN**, executed failures
are **FAIL**. Missing cargo-audit/cargo-deny cannot silently PASS. GitHub
Actions `failure` with `runner_id=0` and no steps is **NOT RUN,
BEFORE_RUNNER_ASSIGNMENT**, not a Rust test failure.

For a partial reviewed scope, the entrypoint records the scope and leaves
full-consolidation gates NOT RUN. For an explicitly native-only invocation,
WASM/signed DNA and dependent runtime checks remain NOT RUN.

## Privileged, destructive and external gates (never default)

Never run physical partitions, netns administration, process SIGKILL on
deployed conductors, 10k-link feature-enabled spam, same-agent fork labs or
funded Unyt in production or on shared user data. Prepare **disposable
test-only keys, data, network namespaces, standalone conductors, and an
operator-approved kill/rollback plan** first. The Sprint 31 opt-in
`scripts/run_sprint31_dht_spam.sh` builds **feature-enabled test WASM** and
must use a separate isolated test environment; it cannot substitute for the
default WASM gate. The Sprint 33 `scripts/chaos33_netns.py` requires explicit
privileges, three separate isolated processes and a verified signed-app probe:
`rendezvous(false)` is **not** a physical network partition. The inherited
same-key fork/warrant lab can only be requested with both
`--enable-fork-lab --confirm-disposable-test-only`, on appropriate
throwaway test DNA. Running the scripts alone never grants production trust.

External acceptance still requires real live independent Roughtime operator
dossiers and signed 4-to-3 source failure evidence; an independent production
oracle checkpoint with crash/replay; actual deployed admission; native funded
Unyt RAVE plus separately signed recipient Accept and independent peer;
real transport partitions and SIGKILL with positive signed recovery evidence;
authenticated production alerts; reproducible **binary/WASM/DNA/hApp** proof
(not only source tar reproducibility); and independent cryptographic,
financial/economic and supply-chain review. Issue #61 blocks economic policy
approval. Never translate JSON flags or synthetic drills into such proof.

Both the committed preflight snapshot and the generated runtime report keep
`development_integration_ready`, `development_integration_verdict`,
`production_release_ready`, `production_release_verdict`,
`development_blockers` and `release_blockers` separate.
**Production release is always NO-GO in this tooling.**

## Environment and unverified work

This preflight was authored through the GitHub connector without an accessible
private local clone. Its authoring environment has Python 3.13.5 and Git
2.47.3, but no Rust/Cargo, WASM/Holochain binaries or network access to
GitHub from the execution container. Thus these new committed Python modules,
Rust, WASM, signed conductor, source-package and Holochain acceptance
**have not been executed here**. Codex must run the regressions first, fix any
tooling defects on a separate reviewed preflight branch, and then carry out
the exact-commit integration. GitHub Actions has reported failures for the
inspected source PRs, but the inspected run jobs had `runner_id=0` and no
steps, so they are classified NOT RUN before runner assignment.

Do not merge this draft PR or any sprint PR into `main` as part of preflight.
