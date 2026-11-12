# Sprint 38: release security clearance (Holochain 0.7.1 dependencies and licensing)

**12 November 2026 · `s35_supply_chain` remains FAIL · Development BLOCKED ·
Pilot BLOCKED · Production NO-GO**

Base: PR #83 candidate `18df72cd1fb7e62f85806122628f932333f58b24` (tree
`4b8ef40c`), which is unchanged and preserved. Prepared by automated analysis
(Claude Code) on behalf of the repository owner. **No human, independent or
owner approval is recorded, and none is implied.**

| Document | Content |
| --- | --- |
| [`sprint38_disposition_matrix.json`](sprint38_disposition_matrix.json) | 23 baseline findings and 1 new finding, with Phase G fields and approval status |
| [`SPRINT38_HOLOCHAIN_071_RUNTIME.md`](SPRINT38_HOLOCHAIN_071_RUNTIME.md) | 0.7.1 build provenance and comparison with the 0.7.0 evidence |
| [`SPRINT38_SQLCIPHER_REVIEW.md`](SPRINT38_SQLCIPHER_REVIEW.md) | Compiled SQLCipher/SQLite core, post-3.46.1 CVEs, controls, upstream path |
| [`SPRINT38_PLATFORM_OPTIONS.md`](SPRINT38_PLATFORM_OPTIONS.md) | Linux/macOS-only vs Windows support (owner decision) |
| [`../license38/LICENSE_OWNER_DECISIONS.md`](../license38/LICENSE_OWNER_DECISIONS.md) | Ten license decisions needing owner and legal authorisation |

The Sprint 36A and Sprint 37 matrices are preserved unchanged. The Sprint 37
evaluator still reads the Sprint 37 matrix.

## 1. Findings reproduced against current advisory data

RustSec advisory-db `af7b3ec33460b8e2de8d422e16d628518891a519` was confirmed
equal to upstream HEAD on 2026-11-12. Scanners: cargo-audit 0.22.2,
cargo-deny 0.20.2, cargo 1.99.0.

| Graph | cargo audit | cargo deny | Result |
| --- | --- | --- | --- |
| root | exit 0; 4 unmaintained | exit 5: advisories, licenses | same as Sprint 37 |
| conductor | exit 1; 11 vulnerabilities, 2 unsound, 6 unmaintained | exit 5: advisories, licenses (bans, sources ok) | same |
| load | exit 1; same as conductor | exit 5 | same |

Sprint 37 evaluator on `18df72c`: **BLOCKED** (exit 2), 23 findings, 42
scanner instances matched, 22 blocking, 0 approvals. No advisory was added or
withdrawn since Sprint 37.

## 2. New engineering in this PR

| Control | File | Tests |
| --- | --- | --- |
| Conductor release profile: holochain 0.7.1; QUIC floor noq-proto ≥ 1.4.0, iroh ≥ 1.4.1, kitsune2_transport_iroh ≥ 0.5.3 (lockfile and binary); no `quinn_proto`/`ruzstd`/`zip` symbols and a present symbol table; `HOLOCHAIN_INFLUXIVE_CHILD_SVC` forbidden; target-triple exposure reporting | `scripts/security/conductor_release_profile.py` | 17 |
| Data-root permission audit and restore-set validation (rejects stray `-wal`/`-shm`/`-journal`, symlinks, unlisted and tampered files) | `scripts/security/datastore_guard.py` | 10 |
| Static audit: no locked crate enables QUIC ACK-frequency sending; the noq-proto version must be one that was manually reviewed | `scripts/security/quic_transport_config_audit.py` | 6 |

None of these clears an advisory. They turn the assumptions behind the
proposed dispositions into checks that fail if a future build breaks them.

**No new compatible dependency fix was possible.** Every remaining vulnerable
or unmaintained crate is reached through an exact Holochain 0.7.1 pin or
through `rave_engine` (dev-only). A `[patch]` override of upstream Holochain
is not authorised. The Sprint 37 `rustix` fix remains the only
PATCHED_AND_TESTED finding.

## 3. What changed in the evidence

* **Holochain 0.7.1 gap closed.** The analysis now uses a 0.7.1 conductor
  built from the reviewed graph (sha256 `f88c7de2…9336`). It links 0
  `quinn_proto`, 0 `ruzstd` and 0 `zip` symbols, and uses SQLCipher 4.6.1 /
  SQLite 3.46.1.
* **New finding `HCVT-S38-QUIC-FLOOR`.** The upstream crate's packaged
  lockfile, used by `cargo install --locked`, resolves an older QUIC stack
  than the reviewed lockfile. The release profile now enforces the reviewed
  floor. Details are private (see §5).
* **SQLCipher.** Source diffs confirm that three post-3.46.1 SQLite core fixes
  are absent from the compiled core. Their preconditions (arbitrary SQL)
  appear unavailable under the deployment model. Crafted-database input
  remains the open path. The finding stays **NOT_VERIFIED**.
* **RustSec range gap.** RUSTSEC-2026-0459 lists `libsqlite3-sys >= 0.39.0` as
  patched, but SQLCipher builds need 0.40.0. A scanner would pass an affected
  0.39.x SQLCipher build.
* **zip.** Windows-only, confirmed for 7 target triples. On Windows the only
  caller extracts SHA-256-pinned archives, and only when
  `HOLOCHAIN_INFLUXIVE_CHILD_SVC` is set.

## 4. Disposition summary (24 rows; approvals: none)

| Recommended disposition (not approved) | Findings |
| --- | --- |
| PATCHED_AND_TESTED (done) | RUSTSEC-2026-0486 rustix |
| NOT_APPLICABLE_WITH_APPROVED_EVIDENCE | quinn-proto ×5, ruzstd, HCVT-S37-NOQ-ACKFREQ |
| NOT_APPLICABLE (needs approved Linux/macOS policy) | zip ×4 |
| FORMALLY_ACCEPTED_RESIDUAL_RISK | RUSTSEC-2026-0459 (with implemented controls), lru, memmap2, 7 unmaintained |
| NOT_VERIFIED (must remain) | HCVT-S37-SQLCIPHER-CORE |
| UNRESOLVED (new) | HCVT-S38-QUIC-FLOOR, until the release profile is a mandatory deployment step |

Current status of every row except rustix: **UNRESOLVED or NOT_VERIFIED.**
Approving every recommendation would still not clear the gate:
SQLCIPHER-CORE requires independent review, and the gate policy itself
consumes raw scanner exit codes.

## 5. Confidential disclosure status

`PRIVATE_DISCLOSURE_APPROVAL_PENDING`. A private package covering the
noq-proto items is held **outside** the repository. Nothing has been sent to
n0-computer, Holochain or RustSec. The owner should also note that the
Sprint 37 documents already in this public repository describe
`HCVT-S37-NOQ-ACKFREQ` in technical detail.

## 6. Decisions requested (none taken)

1. Approve or reject each recommended disposition: human approver, role, UTC
   time, exact reviewed commit, scope and evidence.
2. Choose platform Option A or B.
3. Make the release profile and datastore guard mandatory deployment steps
   (this resolves HCVT-S38-QUIC-FLOOR once approved and tested).
4. Authorise private disclosure.
5. Decide whether `s35_supply_chain` may move to a reviewed-disposition
   policy. A proposal is on a separate review branch and is **not active**.
6. License decisions 1–10 (legal review ⚖).
7. Request upstream Holochain 0.7.x changes:
   * drop the unused quinn pins;
   * adopt wasmer ≥ 7.5;
   * adopt zip ≥ 9;
   * adopt kitsune2_transport_iroh ≥ 0.5.3 in the packaged lock;
   * move to libsqlite3-sys ≥ 0.40.0 for SQLCipher.

## 7. Verdicts

| Scope | Verdict | Reason |
| --- | --- | --- |
| Development integration | **DEVELOPMENT_BLOCKED** | `s35_supply_chain` FAIL; no approved policy or exceptions |
| Pilot | **PILOT_BLOCKED** | above, plus no independent review, signer custody or operator acceptance |
| Production | **PRODUCTION_NO_GO** | above, plus financial policy (#61) and live acceptance outstanding |
