# Sprint 36A — inherited dependency vulnerability remediation / technical blocker report

**Agent Z · 10 November 2026 · SECURITY BLOCKED / NO-GO**

| Source | Exact ref |
| --- | --- |
| Current integrated `main` at branch creation | `bae1e5b9380e92cbee511e07fea1681011d4d6d0` |
| Preserved consolidated Sprints 28–35 candidate (PR #80; do not modify) | `3552a815354d9b3b888b7fd237015774f3324a3b` |
| This draft's source branch | `sprint/36a-dependency-security-remediation` |
| Machine-readable 11-advisory matrix | `docs/security/sprint36a_remediation_matrix.json` |
| Reproducible static inventory validator | `scripts/security/sprint36a_validate.py` |
| Synthetic negative regressions | `scripts/security/test_sprint36a_validate.py` |

## Decision

**No Cargo.lock, Cargo.toml, production Rust, cryptography, oracle, settlement, WASM, source-chain, transport, or database logic was modified. No fix is claimed and no risk is accepted.** Do not merge this draft or PR #80 on the strength of this report. Holochain's published 0.7.1 release is the current stable integration line; upgrading to 0.8.0-dev.* would be a pre-release migration. Dependency-specific patched versions are not sufficient evidence of Holochain/Wasmer integration safety.

The standalone conductor and load lockfiles contain **845 packages each**; the root workspace contains **274**. This was established by parsing GitHub's locked sources, not by executing `cargo metadata`. The three lockfiles have Git blob IDs `875bfa8d8ea9686746b99677d864d16ab0126610`, `c210c16e12a55ae6b85d2e345fee93f47033bdfb`, and `efc366ee614e2a7c6b6e98bf6a76c76f74ec9531` respectively, in root/conductor/load order. PR #80's description records that these locks were unchanged from `main`. Its local Codex report stated 37/38 gates passed and both standalone audit scans reported 11 findings. Those earlier tests **are not** test results for Sprint 36A.

As of this advisory review, the 11 original vulnerable-version hits decompose into **1 SQLite + 5 Quinn + 1 ruzstd + 4 ZIP**. Each remains **UNRESOLVED** until a compatible, proven upstream fix or a separately approved and independently reviewed disposition is supplied. The matrix intentionally distinguishes installed dependency presence from runtime reachability.

## Locked dependency paths

All paths below occur in **both** conductor and load. Every arrow is a `Cargo.lock` dependency edge, reconstructed from the locked package records:

- **SQLite:** `hc-vtime-conductor-smoke 0.0.0 → holochain 0.7.1 → holochain_state 0.7.1 → holochain_data 0.7.1 → libsqlite3-sys 0.35.0`. Other immediate parents of `libsqlite3-sys`: `rusqlite 0.37.0`, `sqlx-sqlite 0.9.0`.
- **QUIC:** `hc-vtime-conductor-smoke → holochain 0.7.1 → holochain_p2p 0.7.1 → quinn-proto 0.11.14`. Also introduced by `quinn 0.11.9`. The upstream `holochain_p2p 0.7.1` crate explicitly requires `quinn-proto =0.11.14`.
- **Compression:** `hc-vtime-conductor-smoke → holochain 0.7.1 → wasmer 7.1.0 → wasmer-compiler 7.1.0 → object 0.38.1 → ruzstd 0.8.3`. The published `object 0.38.1` manifest specifies optional `ruzstd 0.8.1` under its **default `compression` feature**. Upgrading `ruzstd` to the incompatible 0.9 line cannot be assumed safe.
- **Archive:** `hc-vtime-conductor-smoke → holochain 0.7.1 → holochain_metrics 0.7.1 → zip 8.6.0`. The same locks also contain a **separate zip 9.5.0 instance**. Its presence does **not** remediate the `zip 8.6.0` metrics path.

The root workspace's locked graph has **none** of the four vulnerable package/version pairs. No finding is direct in the project's manifests.

## Complete original advisory inventory

Severity is a published CVSS label when available, otherwise **not scored**; no unsupported severity is inferred. Detailed platforms, features, code-path preconditions, required approvals and URLs for each ID are in the machine JSON.

| RustSec ID | Version / published fix | Severity | Vulnerable behavior / reachability condition | Disposition |
| --- | --- | --- | --- | --- |
| [2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html) | `libsqlite3-sys 0.35.0` / `>=0.39.0` | MEDIUM | Older **bundled** SQLite can expose process memory if an untrusted local actor controls a DB and mismatched WAL file. System SQLite and SQLCipher need separate library-version/feature analysis. | UNRESOLVED |
| [2026-0185](https://rustsec.org/advisories/RUSTSEC-2026-0185) | `quinn-proto 0.11.14` / `>=0.11.15` | HIGH | Remote out-of-order STREAM fragments exhaust reassembly memory; ordered readers can be affected. | UNRESOLVED |
| [2026-0338](https://rustsec.org/advisories/RUSTSEC-2026-0338.html) | `quinn-proto 0.11.14` / `>=0.11.18` | not scored | Remote zero-length STREAM payloads panic **unordered** reads; ordered-only readers avoid this individual code path but not the other QUIC findings. | UNRESOLVED |
| [2026-0339](https://rustsec.org/advisories/RUSTSEC-2026-0339.html) | `quinn-proto 0.11.14` / `>=0.11.17` | not scored | Repeated already-retired connection IDs bypass retirement queue bound; remote memory exhaustion. | UNRESOLVED |
| [2026-0340](https://rustsec.org/advisories/RUSTSEC-2026-0340.html) | `quinn-proto 0.11.14` / `>=0.11.18` | HIGH | Remote peer parameters can panic ACK_FREQUENCY processing **when send is explicitly enabled**; default is off. | UNRESOLVED |
| [2026-0342](https://rustsec.org/advisories/RUSTSEC-2026-0342.html) | `quinn-proto 0.11.14` / `>=0.11.17` | not scored | Empty DATAGRAM frames bypass byte limits and exhaust memory. Receiving datagrams is enabled by default unless explicitly disabled. | UNRESOLVED |
| [2026-0344](https://rustsec.org/advisories/RUSTSEC-2026-0344.html) | `ruzstd 0.8.3` / `>=0.9.1` | HIGH | Small crafted zstd input forces gigabyte decompression allocation; default `object` compression exposes a decoder but untrusted input flow needs proof. | UNRESOLVED |
| [2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html) | `zip 8.6.0` / `>=9.0.0` | HIGH | Unix ZIP extraction preserves SUID/SGID permission bits; relevant to privileged extraction of untrusted archives. | UNRESOLVED |
| [2026-0368](https://rustsec.org/advisories/RUSTSEC-2026-0368.html) | `zip 8.6.0` / `>=9.0.0` | not scored | Symlink target escapes archive destination on Unix. Advisory description specifically discusses 9.0.0-pre2; **verify the affected source code in 8.6.0 before concluding reachability**. | UNRESOLVED |
| [2026-0369](https://rustsec.org/advisories/RUSTSEC-2026-0369.html) | `zip 8.6.0` / `>=9.0.0` | CRITICAL | ZIP extraction applies Unix permissions through symlink targets outside archive destination. | UNRESOLVED |
| [2026-0429](https://rustsec.org/advisories/RUSTSEC-2026-0429.html) | `zip 8.6.0` / `>=9.0.0` | HIGH | Malicious symlink entry with huge declared ZIP64 size causes infallible allocation and process abort on **Unix and Windows**. | UNRESOLVED |

**Important exclusion checks:** [RUSTSEC-2026-0341](https://rustsec.org/advisories/RUSTSEC-2026-0341.html) explicitly lists `<0.11.15` unaffected, [RUSTSEC-2026-0343](https://rustsec.org/advisories/RUSTSEC-2026-0343.html) lists `<0.11.17` unaffected, and [RUSTSEC-2026-0037](https://rustsec.org/advisories/RUSTSEC-2026-0037.html) was fixed in `0.11.14`. Thus none of these three should be falsely counted against the installed `0.11.14` (the original older `2026-0185` is still affected). Re-run current `cargo audit` because the upstream advisory database may be updated.

## Upstream compatibility decision and technical blockers

1. **Holochain stable line.** On 10 November 2026 upstream lists Holochain **0.7.1** as the latest stable release; the 0.8.0-dev.14 builds are prerelease. The [Holochain changelog](https://github.com/holochain/holochain/blob/develop/crates/holochain/CHANGELOG.md) records substantive breaking host/guest changes and previous database transitions. Holochain's own [5 November update](https://blog.holochain.org/dev-pulse-157-holochain-0-7-1-brings-chain-restore-direct-signal-security/) notes that even the 0.7.0 → 0.7.1 line broke SemVer compatibility. **No broad upgrade is authorized** until the current stable integration line gains a maintained compatible patch or an explicit migration is reviewed.
2. **SQLite.** Investigate `holochain_data`'s direct `libsqlite3-sys` use, `rusqlite 0.37`, and `sqlx-sqlite 0.9` together. The RustSec patch begins at `libsqlite3-sys 0.39` / `rusqlite 0.41`, with changed Rust minimum versions. Determine whether `encryption` builds SQLCipher, a bundled SQLite, or system SQLite per target; document the resolved SQLite C library version and whether less-trusted DB/WAL bytes can be opened. Even where the exploit preconditions appear absent, **absence is not a verified fix**. Preserve database schema, upgrade/downgrade, restart and forensic recovery behavior.
3. **QUIC/Iroh.** Do not replace `holochain_p2p`'s exact `quinn-proto` pin with `[patch]` or a direct constraint. Seek a maintained upstream Holochain networking release with reviewed Quinn updates. Regression needs malformed frames, stream reassembly, connection-ID churn, ACK_FREQUENCY on/off, DATAGRAM accounting, real peer handshake/rejoin, network-partition recovery, transport compatibility, and source-chain/fork correctness. Quinn’s 0.11.17-only advisory is **not** an installed-version finding.
4. **Wasmer/object/ruzstd.** `object 0.38.1` defaults to `compression` and its published constraint is `ruzstd = 0.8.x-compatible`, not 0.9.x. No documented Wasmer-compatible, published update has been compiled/tested here. Evaluate a **maintained upstream** Wasmer/object patch, not an unreviewed local fork. Test malicious zstd object sections as well as normal signed DNA and compiled/WASM-cache handling; RUSTSEC-2026-0344 is a potential denial of service, not stated RCE. A Fedora downstream rebuild is evidence that distributors can backport, **not** evidence of upstream compatibility with Holochain's locked crates.
5. **ZIP/metrics.** `holochain_metrics 0.7.1` requires an older ZIP line; having a second, already-patched ZIP version in the lockfile is not sufficient. Request or evaluate a maintained metrics release with ZIP 9.x. Audit whether any metrics/runtime path **actually extracts** archives supplied by an untrusted party, including privileged CI, backup/import, or host tooling. Track Unix-only permission/symlink paths separately from **cross-platform** ZIP64 allocation. Linux-only test results are never a platform waiver.

Every target-specific or feature-specific exception would need a documented support policy, an independently reproducible `cargo tree -e features -i <crate>` / target check, call-path evidence, and security signoff. Without those, use **UNRESOLVED**; never treat `NOT APPLICABLE — REVIEW REQUIRED` as accepted.

## Holochain 0.8.x migration proposal — future review only

Before considering a new Holochain line, upstream maintainers and project reviewers must evaluate:

- Conductor/admin and websocket APIs, config and feature compatibility; HDK **0.7.1** / HDI **0.8.1**, app-zome message and host/guest serialization bytes, signed DNA/WASM build and production/test separation.
- Wasmer version, compile/cached-module format, runtime sandbox and adversarial Wasm; QUIC/Iroh transport, peer authentication, retries, session compatibility.
- SQLite file layout, state and schema migration with backup, rollback **without** privileged checkpoint rewind; source-chain signing, ancestry, forks, warrants, DHT budgets and multi-conductor replay.
- Signed time evidence and Ed25519/rough delegation/Merkle proof checks; oracle journal/idempotency/restart and fail-closed ambiguous writes; Unyt conservation, challenge, target binding and funded settlement separation.

Deliver an exact-sha two-version compatibility matrix and signed migration decision **before** changing lockfiles. Passing security scans alone is not acceptance.

## Executed evidence vs NOT RUN

**Actually examined in this sprint:** live GitHub PR #80 metadata; all three manifests and lockfiles via the GitHub connector; static lock-package/edge reconstruction; Sprint 35 supply-chain script and audit documentation at the consolidated candidate; upstream RustSec entries and released crate constraints. Static reconstruction proves selected package/version edges **but cannot validate feature resolution or execution**.

**NOT RUN in the current environment:** all three `cargo metadata --locked --offline` commands, three `cargo audit --json --file` commands, `cargo fmt --all -- --check`, `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, conductor acceptance, production-default WASM build, or cargo-deny with Sprint 36B's approved policy. The private repository has not been checked out here and the available container has no `cargo` executable. Synthetic Python regressions are **committed, not claimed executed**. No claim is made about GitHub Actions completing runner assignment.

The Python validator is a **fail-closed static dependency-path consistency aid** only: it rejects missing/changed lockfile bytes, wrong crate versions/paths, omitted original RustSec IDs, false `PATCHED` statuses or a report that claims release readiness. It **cannot** substitute for `cargo audit`, `cargo metadata` (Cargo features), signed runtime tests, licenses or independent review. It generates an exact-sha-labeled JSON report *outside the repository* when Codex supplies `--expected-sha`.

## Sprint 36B SPDX coordination

No dependency or Cargo.lock updates were performed, so **this sprint introduces zero new packages and no new licenses**. This is a change-set finding, **not a full SPDX scan**. Per-package license inventory, project legal governance and `cargo-deny` policy remain **NOT RUN / awaiting Sprint 36B**. No allowlist, deny setting, vulnerability ignore or license override was written. Sprint 36B should consume the JSON inventory and independently record SPDX results for all locked/transitive packages; any future upstream fix may introduce licenses and must trigger license-diff approval.

## Codex integration into preserved PR #80 candidate

1. Preserve PR #80 head `3552a815354d9b3b888b7fd237015774f3324a3b`; record original three lockfile Git blob IDs and all source heads. **Do not merge PR #80 or this PR.**
2. Fetch this branch's **live** head SHA. Review changes against `bae1e5b9380e92cbee511e07fea1681011d4d6d0`: it must consist only of this sprint's new documentation, machine matrix and static checker/tests. Cherry-pick or otherwise integrate the reviewed commit(s) into a new non-release candidate based on PR #80. Do not overwrite newer integrated files or accept stale source hashes.
3. On the **new exact integration commit** `SHA="$(git rev-parse HEAD)"`, run:
   ```sh
   python3 -B -m unittest scripts/security/test_sprint36a_validate.py -v
   python3 -B scripts/security/sprint36a_validate.py --expected-sha "$SHA" \
     --output ../s36a-static-inventory-exact-sha.json
   cargo metadata --locked --offline --format-version 1 > ../s36a-root-metadata.json
   cargo metadata --locked --offline --manifest-path integration/conductor/Cargo.toml --format-version 1 > ../s36a-conductor-metadata.json
   cargo metadata --locked --offline --manifest-path integration/load/Cargo.toml --format-version 1 > ../s36a-load-metadata.json
   cargo audit --json --file Cargo.lock > ../s36a-root-audit.json
   cargo audit --json --file integration/conductor/Cargo.lock > ../s36a-conductor-audit.json
   cargo audit --json --file integration/load/Cargo.lock > ../s36a-load-audit.json
   cargo fmt --all -- --check
   cargo test --workspace --locked
   cargo clippy --workspace --all-targets --locked -- -D warnings
   ```
   Capture **non-zero scan exit codes** even if command output is redirected. For each `cargo audit` save advisory-db revision/fetch date and exact affected versions; reconcile the JSON against the matrix. Run the independent conductor tests and the repository's production-default WASM/Sprint 27 native/dna/hApp suite with known-good toolchain and pinned external witnesses. Do not count ignored tests or zero-step Actions as PASS.
4. Run `cargo-deny` only with the **separately approved** Sprint 36B SPDX policy. Re-run all security invariants, including signing/quorum, Merkle, delegation, oracle journal, ambiguous writes, ancestry/warrants, DHT bounds and native Unyt invariants. Preserve every negative/fail-closed case.
5. Regenerate the **entire** Sprint 35 exact-commit source bundle, audit archive and checksum inventory using the new candidate SHA, then independently verify with a clean full clone. If **any** Cargo.lock changes, previous evidence is invalid and all tests must be rerun, not inherited.
6. Produce a new signed reviewer matrix with per-advisory disposition (PATCHED, NOT APPLICABLE — REVIEW REQUIRED, RISK ACCEPTANCE REQUIRED, UNRESOLVED or NOT VERIFIED) and explicit risk-acceptance approvals if sought. **Unapproved exceptions must leave the supply-chain gate red**. Production remains **NO-GO** until independent release signoff.

## PR #80 compatibility statement

This sprint adds uniquely named security documentation and an optional Python static checker under `docs/security` and `scripts/security`. It does not touch any of PR #80's changed application, integration, WASM, Rust manifest/lock, CI or audit tooling paths; Git does not need to reconcile overlapping feature edits. The previous 37/38 preflight result is **historical evidence only**. This draft neither changes nor fixes the consolidated supply-chain gate; it supplies an auditable blocker inventory for Codex and upstream maintainers.

**Verdict: security vulnerability remediation NOT COMPLETE; `s35_supply_chain` remains FAIL/BLOCKED; production and financial rollout remain NO-GO.**
