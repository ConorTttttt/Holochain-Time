# Sprint 7 — Local test recovery and staged PR verification

**Start:** 9 November 2026. **Branch:** sprint/07-local-test-harness-2026-11-09. **Base:** Sprint 6 PR #28. **Issue:** #29. **Status:** implementation draft, no Rust or conductor runtime verification yet.

## Goal

Get a reproducible native, Clippy and WASM test report on each existing sprint branch, without force-pushing, silently merging, or interpreting the results as a production release.

## Checklist

- [x] Confirm source from original uploaded ZIP is already committed on Sprint 1 branch; source ZIP itself need not be uploaded.
- [x] Add isolated per-sprint local test script with exact SHA, toolchain, logs and failure statuses.
- [x] Provide Holochain 0.7 Holonix shell command and safe testing instructions.
- [x] Block packaging with placeholder DNA keys.
- [x] Check script syntax and failure to run when Cargo is unavailable.
- [ ] Run real Rust tests, clippy and WASM on exact branches with a working toolchain.
- [ ] Restore GitHub Actions runner assignment, issue #22.
- [ ] Run real multi-agent Holochain conductor acceptance and Unyt test-funded scenarios.
- [ ] Review and merge PRs in dependency order, with no release approval implied.

**Release gate:** NO-GO until security, availability, conductor, financial and independent-audit gates pass.
