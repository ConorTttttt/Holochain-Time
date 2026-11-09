# ADR 008 — Reconcile sprint branches before accepting release test evidence

**Status:** Proposed; integration work underway (Sprint 8).
**Reference:** [Holochain 0.7 design skill](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain)
**Related:** Sprint 8 #33, Sprint 7 PRs #30/#32, runner issue #22, release gate #1.

## Discovery

The sprint PRs were stacked in a series, but Sprint 1 PR #16 received **four further commits** after Sprint 2 PR #19 forked. As observed on 9 November 2026:

| Parent → child | GitHub ancestry comparison |
| --- | --- |
| Sprint 1 HEAD `a4514999...` → Sprint 2 HEAD `92fc8786...` | **diverged** (child ahead by 7, behind by 4) |
| Sprint 2 → 3 → 4 → 5 → 6 → Sprint 7 PR #32 | each child ahead, behind by 0 |

Sprint 1's later commits include Holochain WASM linker settings and extensive `rustfmt` changes across the Rust workspace. Later sprint branches also contain changes to some of those files. Copying Sprint 1's current source wholesale over the Sprint 8 branch would silently discard later implementation work; rebasing automatically and claiming no conflicts would be equally unsafe.

## Decision

1. **Consolidate Sprint 7's complementary tools** on a separate Sprint 8 review branch: PR #30's local harness and PR #32's CI evidence auditor. Preserve both; only Sprint 8 adds its own release-graph guard. Neither original branch is force-pushed, merged or closed during this step.
2. **Pin historical local checks** to exact PR HEAD SHAs and refuse dirty worktrees. Branch HEAD movement is a *new candidate*, not evidence for the previous one. Save actual compile/test logs and hashes.
3. **Block stale ancestry** in `scripts/audit_sprint_stack.py`: query the current PR refs and the GitHub comparison endpoint; a child that is behind or diverged from a parent fails. A successful history check means only that the branches are based correctly — it never means software is safe.
4. **Resolve Sprint 1 divergence on a reviewable integration branch** using an actual Git three-way merge, not manual overwriting, and inspect every conflict. Keep Holochain integrity validation semantics, coordinator changes and Unyt contracts from Sprints 2–7 intact. Record the merge base and any intentionally rejected changes. Review any resulting GitHub PR base changes.
5. **Test the reconciled SHA** with Rust native, Clippy, both WASM zomes and multi-agent conductor tests. Do not use old green checks from Sprint 2 as coverage for a modified HEAD. Check CI runner settings manually; script code cannot repair pre-runner failures.

## Security limits

The local runner and PR ancestry auditor are tooling for *evidence provenance*. They do not verify authenticity of user-supplied offline logs or cryptographic guarantees of runtime protocols. Production release still requires no unresolved P0 correctness findings, full quorum and DoS acceptance, real Holochain conductor tests, real Unyt test-funded contracts, operational readiness and independent security review.

**Release status: NO-GO.**

## Live ancestry update, 9 November 2026

The **initial** 1→2 divergence above is historical, not the latest blocker: another reviewed branch update merged Sprint 1 into Sprint 2, now SHA `a61583afeb46519670d998712f7206552e6deaad`. The latest ancestry API returns `1→2: ahead_by=9, behind_by=0`. Its successor remains stale: `2→3: diverged, ahead_by=5, behind_by=6` (Sprint 3 head `84756c2eced9cd618572b3bb1ddf40f5923fac72`). Continue reconciling **forward one dependency at a time** and run actual tests after each integrated SHA. The audit script queries live PR heads precisely to avoid treating an older statement as current.
