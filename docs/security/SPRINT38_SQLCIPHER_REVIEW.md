# Sprint 38: SQLCipher / SQLite security review (HCVT-S37-SQLCIPHER-CORE)

**`HCVT-S37-SQLCIPHER-CORE` remains `NOT_VERIFIED`.** This review narrows the
question and implements compensating controls. It does not complete the
independent review the finding requires. Prepared by automated analysis
(Claude Code); no approval is recorded.

## 1. What is actually compiled

| Item | Value | Evidence |
| --- | --- | --- |
| Rust crate | `libsqlite3-sys` 0.35.0 | conductor `Cargo.lock` |
| Features (unified) | `bundled-sqlcipher-vendored-openssl` (from holochain `encryption`, a default feature), `bundled`, `unlock_notify` | `cargo tree -e features -i libsqlite3-sys` |
| Amalgamation | `libsqlite3-sys-0.35.0/sqlcipher/sqlite3.c`: **SQLCipher 4.6.1, SQLite 3.46.1** | `CIPHER_VERSION_NUMBER`, `SQLITE_VERSION` |
| In the 0.7.1 binary | `SQLITE_SOURCE_ID` `2024-08-13 09:16:08 c9c2ab54…`, which is 3.46.1 | `conductor_release_profile.py --binary` |
| Consumers | `holochain_data` (sqlx-sqlite 0.9.0) **and** `lair_keystore` (rusqlite 0.37.0) | `cargo tree -i libsqlite3-sys` |
| Crypto provider | vendored OpenSSL (`openssl-src` 300.6.1+3.6.3) | conductor `Cargo.lock` |
| Compile flags of note | `SQLITE_ENABLE_FTS3`, `SQLITE_ENABLE_FTS5`, `SQLITE_ENABLE_LOAD_EXTENSION=1`, `SQLITE_HAS_CODEC`, `SQLITE_TEMP_STORE=2` | `libsqlite3-sys` `build.rs` |

The crate also ships a plain SQLite 3.50.2 amalgamation. RustSec maps
`libsqlite3-sys` 0.35.0 to that version, but it is **not** what Holochain
compiles. The Lair keystore database runs on the same 3.46.1 core.

## 2. SQLite core fixes after 3.46.1

Source: <https://www.sqlite.org/cves.html>, retrieved 2026-11-12. CLI-only
issues, extension-only issues not in this build (e.g. zipfile) and non-SQLite
reports are excluded.

| CVE | Fixed in | Class | Present in compiled 3.46.1? | Precondition |
| --- | --- | --- | --- | --- |
| CVE-2025-3277 / CVE-2025-29087 | 3.49.1 | `concat_ws()` integer overflow → heap write | **Yes** (missing `(i64)` cast in `concatFuncCore`) | Attacker-controlled SQL calling `concat_ws` |
| CVE-2025-29088 / CVE-2025-52099 | 3.49.1 | `SQLITE_DBCONFIG_LOOKASIDE` bounds → crash | **Yes** (no `sz`/`cnt` clamp in `setupLookaside`) | Application passes hostile arguments to the C API |
| CVE-2025-6965 | 3.50.2 | aggregate column count overflow → OOB read | **Yes** (no `mxTerm` guard in `findOrCreateAggInfoColumn`) | Attacker-controlled SQL |
| CVE-2025-7709 | 3.50.3 | corrupt FTS5 index → OOB access | Presumed yes (FTS5 compiled; not diffed) | Attacker controls database content using FTS5 |
| CVE-2026-11822 / CVE-2026-11824 | 3.53.2 | FTS5 heap write, DEFENSIVE off | Presumed yes (not diffed) | Arbitrary SQL with FTS5 |
| CVE-2026-119375 (RUSTSEC-2026-0459) | 3.54.0 | DB + `-wal` with mismatched page size → uninitialised page-cache read | Yes (version-based) | Victim opens a DB and sibling `-wal` written by a less-trusted party |

The "Yes" verdicts are source-diff results against the 3.50.2 amalgamation in
the same crate. They show the fix is absent. They do not show exploitability.

## 3. Reachability under the supported deployment model

* **SQL injection surface:** Holochain builds all SQL internally. Zomes call
  host functions (`query`, `get`, …) and cannot submit SQL. No Holochain or
  Lair crate references `concat_ws`, FTS5, `SQLITE_DBCONFIG_LOOKASIDE` or
  `load_extension`. The three SQL-level CVEs need arbitrary SQL, which is not
  available to remote peers or zomes. **Not formally proven:** a reviewer
  should confirm that no conductor admin/app API forwards SQL text.
* **Crafted-database input:** this is the remaining open path, covering
  CVE-2026-119375, the FTS5 corruption CVE, and triggers or views in a crafted
  schema (`trusted_schema=false` limits the functions those can call).
  Routes for an attacker to supply a database:
  1. write access to the conductor data root (local attacker / co-tenant);
  2. a restored backup from an untrusted location;
  3. any import path. **None found** in Holochain 0.7.1 for the conductor
     databases; Lair's store is local only.
* **Encryption:** `holochain_data` applies a per-database key and salt
  (`PRAGMA key`, `cipher_salt`), `cipher_compatibility=4` and
  `cipher_plaintext_header_size=32`. Without the key, an attacker cannot
  forge valid encrypted pages, because SQLCipher checks each page's HMAC.
  **Open question:** the 32-byte database header and the WAL header are
  plaintext, so it is not known whether a page-size mismatch in an
  attacker-edited WAL header triggers CVE-2026-119375 *before* HMAC
  verification rejects the frame. Answering this needs a controlled
  experiment on a disposable SQLCipher 4.6.1 database. That experiment is
  listed for the independent reviewer and was not run here, so that no
  reproduction recipe is published.
* **Encryption is not a fix.** The SQL-level CVEs run after decryption.

## 4. Compensating controls (implemented, tested; not a patch)

`scripts/security/datastore_guard.py` (read-only; 10 regression tests):

* `audit-root`: requires the data root and all contents to be owned by the
  service uid, directories `0700`, files `0600`, no symlinks, no hard links.
  **Filesystem permissions alone are not a complete fix.** They do not help
  against an attacker running as the service user.
* `make-manifest` refuses to record a backup that still has `-wal`, `-shm` or
  `-journal` files (the backup must be checkpointed with writers stopped).
* `verify-restore` refuses restore sets with stray side files, unlisted files,
  hash mismatches, symlinks, unsafe manifest paths, or databases without a
  SQLite header.

Not yet implemented, and needing owner decisions:

* make `audit-root` and `verify-restore` mandatory in the operator runbooks;
* run `PRAGMA cipher_integrity_check` / `PRAGMA integrity_check` on
  restored databases before the conductor opens them (needs the database key
  and therefore Lair integration);
* verify whether Holochain enables `SQLITE_DBCONFIG_DEFENSIVE`.

## 5. Upstream remediation path (actionable report)

| Step | State on 2026-11-12 |
| --- | --- |
| SQLCipher with SQLite ≥ 3.54.0 | `sqlcipher-src` 420.0.0 = SQLCipher 4.20.0 / SQLite 3.54.1 (2026-10-30) |
| `libsqlite3-sys` bundling it | **0.40.0** (2026-11-11). Note: 0.39.x pins `sqlcipher-src` 419.0.6 (SQLite 3.53.4) and is **still affected with `bundled-sqlcipher`**, although RustSec lists `>= 0.39.0` as patched, so a scanner would wrongly pass a 0.39.x SQLCipher build |
| `sqlx-sqlite` accepting it | **Blocked:** sqlx-sqlite 0.9.0 (latest) requires `libsqlite3-sys < 0.38` |
| `holochain_data` | **Blocked:** requires `libsqlite3-sys ^0.35` |
| `rusqlite` (Lair) | rusqlite 0.41 pairs with 0.39.x; a release on 0.40 is needed for SQLCipher builds |

Suggested upstream request: ask Holochain to move `holochain_data` and
`lair_keystore` to `libsqlite3-sys >= 0.40.0` with `bundled-sqlcipher` once
sqlx and rusqlite support it. Also suggest RustSec note in the advisory's
version range that `bundled-sqlcipher` builds need 0.40.0.

## 6. Acceptance

`HCVT-S37-SQLCIPHER-CORE` stays **NOT_VERIFIED** until an independent
reviewer (#14):

1. confirms no conductor interface forwards SQL text;
2. completes the crafted-WAL/HMAC ordering question on a disposable database;
3. checks the FTS5 CVEs against the 3.46.1 source;
4. records a decision in the matrix approval fields.

It must not be marked `NOT_APPLICABLE` or `ACCEPTED` before then.
