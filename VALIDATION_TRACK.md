# Parallel validation track: build checks and real Holochain conductor smoke

**Start:** 9 November 2026. **Issue:** #37. **Branch:** validation/build-and-conductor-smoke-2026-11-09, based on Sprint 9 integration candidate PR #36. Does not change or merge owner's sprint branches.

- [x] Verify source manifests, pinned Holochain versions and API patterns against the Holochain 0.7.1 source and Soushi888 testing reference.
- [x] Implement isolated real-WASM three-conductor Sweettest test harness.
- [x] Implement test DNA key-format + quorum count preflight; six local Python tests passed on the prototype.
- [x] Reject the source manifest with REPLACE_WITH placeholders; confirmed offline.
- [x] Implement a clean-commit, checked-DNA smoke runner with checksummed evidence.
- [x] Document build commands, separate smoke and signed-quorum gates.
- [ ] Run root Rust tests, rustfmt, Clippy and WASM builds on the final merged candidate.
- [ ] Run the Sweettest harness on a machine with Cargo/Holochain 0.7 and a real packed test-only DNA. It has **not been compiled in this environment**.
- [ ] Review and pin the isolated integration crate's newly generated lockfile after its first external build.
- [ ] Implement and execute signed 3-source, third-party, adversarial, restart and 100+ seal tests (P0).
- [ ] Validate Unyt using test funds; close GitHub runner incident #22 only after actual steps execute.

**No release approval, no production funds and no merge to main.** Retarget the independent review branch to whichever actual candidate the user finishes merging; rerun all checks on that exact SHA.
