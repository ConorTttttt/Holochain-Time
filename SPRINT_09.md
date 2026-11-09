# Sprint 9 — Integration commit and exact-commit release checks

**Kickoff:** 9 November 2026 · **Status:** draft, untested Rust build; release NO-GO  
**Branch:** `sprint/09-integration-candidate-2026-11-09` · **base:** Sprint 8 draft PR #34 · **tracker:** #35  
**Merge parents:** Sprint 8 latest reviewed head `f2cacae8cd61c709af0deb4934de3a8eb76ccff3` and Sprint 3 latest `97988483e1eeca6ba53c3ce39aa94d3fb847bafd`.

## Scope / deliverables

- [x] Verify live GitHub branch graph; Sprint 1→2 and Sprint 2→3 are now forward integrated.
- [x] Identify exactly 17 upstream files changed after the earlier Sprint 3 ancestor. Inspect 13 that were unmodified in later sprints and four overlapping with downstream code.
- [x] Carry forward 13 upstream blob versions byte-for-byte, retaining downstream implementations in four overlapped files. Record all paths and resolution in ADR 009.
- [x] Add a two-parent integration commit on this **new branch**, without overwriting or force-pushing historical PR branches.
- [x] Update Sprint 3's historical test pin to the newer reviewed commit.
- [ ] Run `cargo fmt --all -- --check`, workspace native tests, all-target Clippy and both Holochain 0.7 WASM builds on the final SHA.
- [ ] Review the four retained downstream files against the new upstream formatting and apply `cargo fmt` on a Rust-equipped machine.
- [ ] Verify the newest Sprint 3 commit and Sprint 8 base are both Git ancestors of the integration commit (`git merge-base --is-ancestor`).
- [ ] Review downstream Sprint 4–8 semantic changes, record any conflict resolutions, and validate integration as a coherent release candidate.
- [ ] Holochain conductor ≥3-agent tests #7, Unyt test-funded agreements #8, independent security review #14 and operations gates.
- [ ] Diagnose Actions runner failure #22 and capture exact-SHA CI evidence; this sprint is not complete without executed Rust checks.

## Preconditions / limits

This branch uses **intentional file-level resolution** because the newer upstream Sprint 3 changes are rustfmt-style changes and the four overlapping downstream files also contain security and protocol work from Sprints 4–6. Those downstream files have been preserved pending rustfmt and code review, not silently replaced. Source ancestry alone does not prove all runtime invariants or record correctness. Historical PR #24 may still be listed as divergent because its branch has not been rebased; the integration merge is reviewable on the new candidate branch.

**Do not merge into `main` or start production use on a passing history check alone.**
