# Sprint 8 — Reconcile test tooling and detect stale sprint ancestry

**Kickoff:** 9 November 2026 (expedited)  
**Branch:** `sprint/08-reconcile-test-stack-2026-11-09`, based on Sprint 7 PR #32  
**Status:** Implementation in draft; Rust and conductor validation not completed  
**Tracker:** #33 · **Runner incident:** #22 · **Release gate:** #1

## What was implemented

- [x] Carry forward exact-SHA GitHub Actions evidence checker from Sprint 7 PR #32.
- [x] Integrate local six-sprint test runner and its operating instructions from sibling Sprint 7 PR #30, preserving the CI auditor rather than overwriting it.
- [x] Pin original Sprint 1–6 branch commits to their reviewed PR HEAD SHAs. If a remote ref moves, refuse to misattribute a result to the old commit.
- [x] Refuse dirty tracked source trees when collecting commit-specific local test evidence.
- [x] Add `scripts/audit_sprint_stack.py` to check PR head/base refs and GitHub commit ancestry; it never merges or approves release.
- [x] Add eight offline unit tests including wrong base, missing PR, missing compare, closed PR, wrong SHA and divergent history.
- [x] Run the eight new offline Python tests in the authoring environment.
- [x] Document the confirmed Sprint 1→Sprint 2 divergence in ADR 008.
- [ ] Obtain Rust, Clippy and WASM results on this exact integrated commit from an assigned GitHub runner or reproducible local environment.
- [ ] Integrate Sprint 1's **four newer** commits into the code used by Sprints 2–7, reviewing formatting conflicts against later protocol changes.
- [ ] Re-run the ancestry audit with zero stale PR ancestry, or use a clearly documented consolidated review branch with explicit approved resolution of every divergence.
- [ ] Run real Holochain conductor tests and Unyt test-funded agreement acceptance; independent security review.
- [ ] Coordinate closing/retargeting sibling Sprint 7 drafts **only after** their changes have been independently reviewed and tested.

## Known evidence at kickoff

GitHub API compare between Sprint 1 HEAD `a4514999e87e92ae5685a5602a4627c3167317b5` and Sprint 2 HEAD `92fc8786972e4fa7ae51f84eb07a48955067ec32` reports **diverged**, ahead by 7 and behind by 4. The later PR heads #21, #24, #26, #28 and #32 are descendants of their respective previous PR heads.

GitHub Actions continues to fail before runner assignment, with no executed Rust or WASM steps (#22). Source-level changes and Python tests are not a substitute for compiler or conductor evidence.

## Local validation

```bash
python3 -m unittest discover -s scripts -p 'test_*.py' -v
bash scripts/test_sprints_local.sh --help
# On an authenticated machine with GitHub CLI:
python3 scripts/audit_sprint_stack.py --repo ConorTttttt/Holochain-Time
# Expect exit status 3 until Sprint 1->2 divergence is resolved.
# For actual Rust tests with a compatible Holochain 0.7 toolchain:
bash scripts/test_sprints_local.sh --current
```

**Merge policy:** Do not merge sprint PRs into `main` or publish a release until actual build, cryptographic, conductor, Unyt, and audit gates are demonstrated on the intended commit. The ancestry script only checks branch graph consistency.

## Mid-sprint ancestry update

Sprint 2 PR #19 advanced to `a61583afeb46519670d998712f7206552e6deaad` by merging current Sprint 1 and formatting its workspace. A fresh GitHub comparison now confirms Sprint 1→2 is **ahead by 9, behind by 0** (resolved). The next dependency, Sprint 2→3, is now **diverged: ahead by 5, behind by 6**. Keep the ancestry audit blocked until the newer Sprint 2 code is reconciled into Sprint 3 and downstream consumers, then retest exact SHAs. Sprint 8's local-test pin for Sprint 2 was updated accordingly.

Sprint 8 run [42608748868](https://github.com/ConorTttttt/Holochain-Time/actions/runs/42608748868) on initial SHA `d7e160984ec50267bcfea2b740fc76bc20bebd0d` failed with no assigned runners and no executed steps in both required jobs; it is not a compiler result. The revised commit also requires new CI evidence.
