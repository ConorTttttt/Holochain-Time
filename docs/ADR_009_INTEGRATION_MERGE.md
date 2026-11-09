# ADR 009 — Two-parent integration with explicit downstream-preserving resolution

**Status:** Proposed for review · **Date:** 9 November 2026  
**Holochain reference:** [Soushi888 Holochain 0.7 guidance](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain)  
**Related:** #33, #35, #22, release gate #1.

## Inputs

- Earlier Sprint 3 ancestor: `84756c2eced9cd618572b3bb1ddf40f5923fac72`.
- Latest Sprint 3 reviewed upstream: `97988483e1eeca6ba53c3ce39aa94d3fb847bafd` (includes Sprint 1 and 2 integrations and `cargo fmt`-style changes).
- Sprint 8 parent: `f2cacae8cd61c709af0deb4934de3a8eb76ccff3` (retains Sprints 4–8 and both Sprint 7 verification tools).
- New Sprint 9 commit: two parents (Sprint 8 first, Sprint 3 second), merged tree derived from the Sprint 8 tree with 13 non-conflicting file blobs replaced by their latest Sprint 3 versions.

## Resolution table

**13 upstream files applied verbatim (no intervening Sprint 4–8 edits at their paths):**
- `crates/vtime_core/examples/roughtime_fetch.rs`
- `crates/vtime_core/src/chain.rs`
- `crates/vtime_core/src/hash.rs`
- `crates/vtime_core/src/interval.rs`
- `crates/vtime_core/src/keys.rs`
- `crates/vtime_core/src/malfeasance.rs`
- `crates/vtime_core/src/oracle.rs`
- `crates/vtime_core/src/roughtime.rs`
- `crates/vtime_core/src/statement.rs`
- `crates/vtime_core/src/verdict.rs`
- `crates/vtime_core/tests/roughenough_interop.rs`
- `dnas/vtime/zomes/integrity/vtime_integrity/src/lib.rs`
- `unyt/harness/tests/templates.rs`

**Four overlapping files: choose the later Sprint 8 version; preserve Sprint 4–6 features and reformat during actual Rust validation:**
- `crates/vtime_core/src/evidence.rs`
- `crates/vtime_core/src/lib.rs`
- `crates/vtime_core/tests/evidence_policy.rs`
- `dnas/vtime/zomes/coordinator/vtime/src/lib.rs`

The upstream edits to these four files are formatting, argument layout, trailing commas and import ordering. Choosing the full upstream file would discard later changes such as the Roughtime-first quorum, batch module registration, explicit-witness/disabled legacy query and regression tests. **The four overlap resolutions still require independent review and cargo fmt on the final branch; they are not automatically considered tested.**

## Invariants and follow-up

1. Never interpret two-parent Git history alone as evidence of a working merge. Validate file-by-file and run `cargo test --workspace --locked`, Clippy, rustfmt, WASM, conductor tests and Unyt test-money acceptance.
2. Do not force-push or close historical draft PRs solely because this branch contains a merge commit.
3. Ensure the old `get_verified_time` remains fail-closed and `verify_time_with_witnesses` still has `evidence_complete: false`.
4. Keep the batch oracle primitive **experimental**, not accepted as signed time evidence.
5. Check new GitHub commits and re-run history/provenance audit before changing PRs or `main`.
6. CI remains infrastructure-blocked (#22); code status is **unverified** until a runner actually executes the checks.

**Decision:** merge on a review branch with documented file resolutions, then validate. No production approval.
