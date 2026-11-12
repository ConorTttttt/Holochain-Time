# Sprint 38: Holochain 0.7.1 runtime analysis (replaces the 0.7.0 binary evidence)

Sprint 37 inspected the installed **holochain 0.7.0** executable, while the
repository pins **0.7.1**. This sprint builds 0.7.1 from the reviewed
dependency graph and repeats the analysis. Prepared by automated analysis
(Claude Code); no approval is recorded.

## Build provenance

| Item | Value |
| --- | --- |
| Holochain | 0.7.1 from crates.io (crate sha256 `f4bfdd61…9035`, upstream VCS `c5f5028274c0406cb9d88d0fa48080135137fd75`, `crates/holochain`) |
| Features | crate defaults: `encryption`, `schema`, `wasmer-sys-cranelift` |
| Dependency graph | strict subset (816 packages) of `integration/conductor/Cargo.lock` at `18df72c` (sha256 `fa8b3fe6…e140`); build lock sha256 recorded in the evidence package |
| Toolchain | rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0 |
| Target / profile | x86_64-unknown-linux-gnu, `release` (cargo defaults; holochain declares no profile) |
| Linker | rust-lld (LLD 23.1.1); `RUSTFLAGS` unset |
| Executable | sha256 `f88c7de2762d354a32bc25357a5f709afa5b15a5eea20ffdd4c75b785d219336`, `holochain --version` = `holochain 0.7.1` |

This build is for analysis only. It is not signed, and it shows same-host
reproducibility at most.

## Comparison

| Property | 0.7.0 (installed, Sprint 37) | 0.7.1 (reviewed graph, this sprint) | 0.7.1 via `cargo install --locked` (upstream packaged lock) |
| --- | --- | --- | --- |
| Executable sha256 | `0a6498e7…ce8e` | `f88c7de2…9336` | not built |
| QUIC stack | below the reviewed floor | iroh 1.4.1 / noq-proto 1.4.0 | below the reviewed floor (versions in the private package) |
| Release profile | **VIOLATED** | **SATISFIED** | **VIOLATED** (lockfile check) |
| `quinn_proto` symbols | 0 | **0** | — |
| `ruzstd` symbols | 0 | **0** | — |
| `zip` crate symbols | 0 | **0** | — |
| `noq_proto` symbols | 2,147 | 2,141 | — |
| SQLite core | SQLCipher 4.6.1 / SQLite 3.46.1 | SQLCipher 4.6.1 / SQLite 3.46.1 | same (libsqlite3-sys 0.35.0) |

Symbol counts come from `nm -C --defined-only` and count demangled paths
rooted at the crate. The Sprint 37 matcher also counted `core::iter` zip
adapters and `gzip`; this is fixed and regression-tested.

## Conclusions per advisory family

* **quinn-proto (5):** the Sprint 37 `not_yet_verified` item is now closed on
  0.7.1. Code-level evidence is unchanged: `holochain_p2p` never references
  quinn. The release-profile check now **enforces** zero `quinn_proto`
  symbols and a present symbol table, so a future build that links quinn
  fails instead of silently inheriting the disposition.
* **ruzstd:** `object` 0.38.1 is built with its default `read` +
  `compression` features. Its only dependent, `wasmer-compiler`, uses only
  `object::write`. The decoder is compiled but dropped at link time. Because
  this relies on dead-code elimination, the release profile enforces it.
* **zip (4):** Windows-only. See `SPRINT38_PLATFORM_OPTIONS.md`.
* **noq-proto:**
  * The ACK-frequency finding (`HCVT-S37-NOQ-ACKFREQ`) is re-verified on
    1.4.0 as configuration-gated. A static audit of all 843 locked crates
    enforces that nothing enables it.
  * A new finding, **`HCVT-S38-QUIC-FLOOR`**: the upstream crate's packaged
    lockfile resolves an older QUIC stack than the reviewed one, so conductors
    built that way do not match the reviewed profile. The release profile
    enforces noq-proto ≥ 1.4.0, iroh ≥ 1.4.1 and kitsune2_transport_iroh ≥
    0.5.3. Technical details are held in the private disclosure package
    (`PRIVATE_DISCLOSURE_APPROVAL_PENDING`).
* **SQLCipher:** unchanged between 0.7.0 and 0.7.1. See
  `SPRINT38_SQLCIPHER_REVIEW.md`.

## Limits of this evidence

* Symbol absence supports, but does not prove, non-reachability. The
  dispositions also rely on source and dependency-graph evidence.
* Negative runtime tests against a live 0.7.1 conductor were not run in this
  sprint. The Sprint 33 real-conductor network acceptance (#73) remains
  required on the final SHA.
* Independent-builder reproducibility of the conductor is not demonstrated.
