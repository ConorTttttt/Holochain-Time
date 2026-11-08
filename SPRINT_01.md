# Sprint 1 — Source baseline, proof-index correctness, and quorum availability

**Dates:** 9–20 November 2026  
**State:** In progress; **no release approval**  
**Sprint goal:** Bring the full reviewed source into GitHub safely; eliminate misleading partial time-verdicts under noisy proof indexes; check quorum liveness assumptions.

## In-scope GitHub issues

- [ ] #2 Import source working-tree archive via review branch, without embedded Git data or overriding the release plan.
- [ ] #3 Guard against valid anchors/seals being displaced by noisy indexes. A fail-closed mitigation has been applied in the Sprint 1 local source bundle, but must be compiled, reviewed and exercised in conductor tests.
- [ ] #6 Validate quorum availability when sources go offline. A `TimePolicy::check_outage_tolerance` preflight and unit tests are prepared in the bundle.
- [ ] #9 First CI pipeline: native tests, clippy and WASM zome compilation. This workflow cannot go green until #2 is imported.
- [ ] #4 Define a **proof-complete, resource-bounded index**, since an error on overflow is only a temporary correctness mitigation.

## Prepared code (not yet in this GitHub repo)

The latest Sprint 1 download in the ChatGPT conversation contains the 48 original project files plus `SPRINT_01.md`, Rust changes and tests, and CI config. The code adds an explicit `EvidenceIndexIncomplete` error instead of silently skipping links beyond the budget. It also checks `N >= min_sources + unavailable` when an outage tolerance is promised.

**Residual security risk:** Holochain `get_links` still materialises the entire match set before a local cap is checked. A flooded index can still cause service denial or excessive resources. Claiming this mitigates #4 would be incorrect.

## Definition of Done

- Source code imported into a draft PR and reviewed for secrets and provenance.
- Native Rust tests and clippy passing on a pinned clean checkout.
- Both WASM zomes compile; DNA packaging smoke-tested in a conductor.
- Regression test proves no `Consistent` verdict is returned from a truncated evidence set.
- Operator quorum policy tests cover outages; deployment settings documented.
- Explicit design/owner for complete bounded DHT index (#4).

## Evidence and blockers

- GitHub source repo started empty. The source archive must be imported; it is **not** on GitHub as of creating this sprint document.
- The execution environment for the code review has no `cargo`, `rustc`, Holochain conductor or live Unyt node. No automated test has run successfully yet in this sprint.
- No production signing keys or financial integrations should be activated.

## Proposed Sprint 2 (23 November–4 December)

Implement proof-complete bounded evidence discovery (#4), concurrently improve seal throughput/admission control (#5), and add multi-agent integration tests (#7). Scope depends on the Sprint 1 import/build results.

## Links

[Master release tracking issue](../../issues/1) · [Full release plan](../main/RELEASE_PLAN.md)
