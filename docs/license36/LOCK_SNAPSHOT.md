# Sprint 36B — Exact-main lockfile identity snapshot

Baseline commit: `bae1e5b9380e92cbee511e07fea1681011d4d6d0`. Source: three tracked `Cargo.lock` files, read through the GitHub repository connector. **This is NOT a verified license metadata inventory.** SPDX and license-file details are not recorded in Cargo.lock; they are explicitly `NOT_PRESENT_IN_LOCKFILE` / `NOT_AVAILABLE_FROM_LOCKFILE`. Do not approve distributions from this CSV.

| Graph | Lockfile | Package entries | Blob SHA |
| --- | --- | ---: | --- |
| root | `Cargo.lock` | 274 | `875bfa8d8ea9686746b99677d864d16ab0126610` |
| conductor | `integration/conductor/Cargo.lock` | 845 | `c210c16e12a55ae6b85d2e345fee93f47033bdfb` |
| load | `integration/load/Cargo.lock` | 845 | `efc366ee614e2a7c6b6e98bf6a76c76f74ec9531` |

Distinct package/version/source/checksum identities across graphs: **876**. Total graph entries: **1964**. All graph package entries have a recorded source or are listed as `LOCAL_PATH`. No Git entries were observed in these three main lockfiles. Source counts: 

- root: {"registry+https://github.com/rust-lang/crates.io-index":269,"LOCAL_PATH":5}
- conductor: {"registry+https://github.com/rust-lang/crates.io-index":843,"LOCAL_PATH":2}
- load: {"registry+https://github.com/rust-lang/crates.io-index":843,"LOCAL_PATH":2}

Run `python3 -B scripts/license36/run.py --expected-sha <SHA> --output-dir <outside-repo>` on the checked-out final candidate to produce the actual `inventory-full.csv` from verified offline `cargo metadata`. Recompute after Sprint 36A, do not reuse this baseline as final licensing evidence.
