# Sprint 37 — supply-chain remediation, executed evidence and upstream blockers

**12 November 2026 · `s35_supply_chain` remains FAIL · production NO-GO**

Machine-readable matrix: [`sprint37_remediation_matrix.json`](sprint37_remediation_matrix.json)
Fail-closed evaluator: [`scripts/security/sprint37_supply_chain_gate.py`](../../scripts/security/sprint37_supply_chain_gate.py)
Historical baseline (preserved): [`sprint36a_remediation_matrix.json`](sprint36a_remediation_matrix.json)

This analysis was produced by automated tooling (Claude Code) on behalf of the
repository owner. **No human, independent or owner approval is recorded.**
Every proposed disposition below is a proposal until a human approval record is
added to the matrix and the evaluator accepts it.

## What was executed

Scanners: cargo-audit 0.22.2, cargo-deny 0.20.2, cargo 1.99.0. RustSec
advisory-db revision `af7b3ec33460b8e2de8d422e16d628518891a519`
(2026-11-12T15:21:59+01:00).

| Command | Root | Conductor | Load |
| --- | --- | --- | --- |
| `cargo metadata --locked` | exit 0, 274 pkgs | exit 0, 845 pkgs | exit 0, 845 pkgs |
| `cargo audit --json --file <lock>` | exit 0 (after rustix fix) | exit 1, 11 vulns | exit 1, 11 vulns |
| `cargo deny --config deny.toml check` | exit 5 | exit 5 | exit 5 |

All 11 inherited vulnerabilities reproduce exactly against the current
advisory database. Sources are clean in every graph (crates.io only).

## Fixed

| Finding | Change | Evidence |
| --- | --- | --- |
| RUSTSEC-2026-0486 `rustix` 1.1.5 (unsound) | `1.1.6` in root `Cargo.lock` (semver patch; dev/test-only via `tempfile`) | Semantic lockfile diff shows only rustix changed; root fmt, 146 tests (0 failed, 0 ignored) and clippy `-D warnings` pass |

## Why the 11 inherited vulnerabilities cannot be patched on Holochain 0.7.1

Cargo's own resolver rejects each upgrade (`cargo update --dry-run --precise`):

| Package | Needed | Blocking requirement |
| --- | --- | --- |
| `quinn-proto` 0.11.14 | ≥0.11.18 | `holochain_p2p 0.7.1`: `quinn-proto = "=0.11.14"`, `quinn = "=0.11.9"` |
| `ruzstd` 0.8.3 | ≥0.9.1 | `holochain 0.7.1`: `wasmer = "=7.1.0"` → `object ^0.38.1` → `ruzstd ^0.8.1` |
| `zip` 8.6.0 | ≥9.0.0 | `holochain_metrics 0.7.1`: `zip ^8.6` |
| `libsqlite3-sys` 0.35.0 | ≥0.39.0 | `holochain_data 0.7.1`: `^0.35`; `sqlx-sqlite 0.9.0` (latest): `<0.38.0` |

No Holochain 0.7.2 exists. 0.8.0-dev.14 is a prerelease, and migrating to it is
not authorised. A `[patch]` override of upstream Holochain crates is not an
acceptable fix.

## Reachability evidence (proposals, not approvals)

* **quinn-proto (5 advisories):** `holochain_p2p` pins it but its source never
  references `quinn` or `quinn_proto`, and no other crate depends on it. The
  live QUIC stack is `iroh 1.4.1 → noq-proto 1.4.0`. The installed, unstripped
  `holochain` binary contains **0 `quinn_proto` symbols** and **2,147
  `noq_proto` symbols**. That binary is 0.7.0, so the check must be repeated on
  the deployed 0.7.1 binary.
* **ruzstd:** `object 0.38.1` calls the decoder only from read-side
  decompression. Its sole dependent, `wasmer-compiler 7.1.0`, uses only
  `object::write`. A sweep of all 843 locked registry crates found no other
  caller, and the inspected binary contains 0 `ruzstd` symbols.
* **zip (4 advisories, including one CRITICAL):** declared only under
  `[target."cfg(windows)".dependencies]`. Cargo confirms it is not compiled for
  either Linux triple or either macOS triple. **Windows conductors remain
  affected**, so the proposal needs an approved Linux/macOS-only platform policy.
* **libsqlite3-sys:** Holochain's `encryption` feature compiles **SQLCipher
  4.6.1 / SQLite 3.46.1**, not the 3.50.2 plain bundle. The advisory needs a
  local attacker who can write both a database and a `-wal` file into the
  conductor data root. Even `libsqlite3-sys 0.39.x` with SQLCipher remains
  affected, so this is proposed as a residual risk with compensating controls
  (data-root permissions, WAL-checkpointed backups, and restores that reject
  stray `-wal` files).

## New findings that the scanners do not report

1. **`HCVT-S37-NOQ-ACKFREQ` (HIGH if enabled).** `noq-proto 1.4.0`, the latest
   release and the live QUIC implementation, still contains the unpatched
   RUSTSEC-2026-0340 `Duration::clamp` code in
   `AckFrequencyState::candidate_max_ack_delay`. A peer-advertised
   `min_ack_delay` can panic the connection driver. The code is reachable only
   when ACK_FREQUENCY sending is enabled. That setting defaults to `None` and is
   not set by iroh 1.4.1, kitsune2 0.5.3 or holochain_p2p 0.7.1. The other
   analogues are fixed or absent in noq: 0185, 0339 and 0342 are fixed, and the
   0338 pattern is absent. **Responsible disclosure to n0-computer needs owner
   approval and should go through their private security channel.**
2. **`HCVT-S37-SQLCIPHER-CORE` (NOT VERIFIED).** RustSec maps
   `libsqlite3-sys 0.35.0` to SQLite 3.50.2. As a result, SQLite C fixes
   released between 3.46.1 and 3.50.2 are not flagged for the SQLCipher build
   that Holochain actually compiles. An independent reviewer must enumerate
   them.
3. **Unsound and unmaintained advisories** that `deny.toml`
   (`unsound`/`unmaintained = "all"`) treats as errors:
   * `lru 0.17.0` is in the Lair key-custody path. Only `get` and `put` are
     called, never `pop`.
   * `memmap2 0.6.2` is pulled in through Wasmer. None of the affected
     functions are called.
   * Seven unmaintained crates, three of them compile-time only.

## Gate result on this candidate

`sprint37_supply_chain_gate.py` returns **BLOCKED** (exit 2) for 23 findings:

* 1 is `PATCHED_AND_TESTED`;
* 21 are `UNRESOLVED`;
* 1 is `NOT_VERIFIED`.

Every one of the 42 graph/finding instances reported by the scanner is matched
to a reviewed row. Hypothetically, approving every proposal would **still not**
clear the gate, because `HCVT-S37-SQLCIPHER-CORE` needs verification first.

## Decisions requested from owners

1. Approve or reject each proposed disposition. Use the matrix approval
   fields: human approver, role, UTC timestamp, exact reviewed commit, scope
   and evidence.
2. Approve a supported-platform policy before using the `zip` disposition.
3. Decide whether `s35_supply_chain` may consume approved matrix dispositions
   instead of raw scanner exit codes. This is a security-policy change. It must
   be approved and validated separately from the current policy, and it has
   **not** been made.
4. Authorise private disclosure of `HCVT-S37-NOQ-ACKFREQ` to n0-computer.
5. Ask Holochain upstream for a 0.7.x release that bumps or removes the unused
   quinn pins, adopts wasmer ≥7.5 and zip ≥9, and moves to a patched SQLCipher.
