# Sprint 4 — Retire unsafe global evidence scans

**Kickoff:** 9 November 2026 (expedited). **Review target:** 20 November 2026.
**Branch:** `sprint/04-disable-unsafe-index-2026-11-09` stacked on Sprint 3 PR #21.
**Tracking:** #23; master release gate #1; runner incident #22.

## Delivered in draft

- [x] Disable legacy `get_verified_time` before DHT link enumeration.
- [x] Preserve explicit witness verification (8 anchor, 32 seal hash budget).
- [x] Add native no-link-scan guard and legacy fail-closed test.
- [x] Define breaking API migration and proof-completeness semantics in ADR 004.

## Still required

- [ ] Green native tests, Clippy and WASM builds on exact commit.
- [ ] Multi-agent conductor tests for legacy error and witness verification.
- [ ] Investigate GitHub Actions pre-runner failure #22 and restore usable CI.
- [ ] Review client migration, security and incident impact before merge.

## Release safety

No complete bounded DHT discovery protocol is delivered by this sprint.
Keep proof discovery issues #3/#4, conductor #7, oracle throughput #5
and financial execution #8 open. Do not merge as production approval.
