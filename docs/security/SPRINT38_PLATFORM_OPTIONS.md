# Sprint 38: supported conductor platforms (owner decision required)

**Status: `PLATFORM_POLICY_APPROVAL_PENDING`.** This document sets out two
options. It does not choose between them. Until the owner approves one,
Windows exposure stays part of the security assessment. The release-profile
checker reports every Windows target as `EXPOSED`.

Prepared by automated analysis (Claude Code) at candidate
`18df72cd1fb7e62f85806122628f932333f58b24`. No approval is recorded.

## Why this decision matters

Four inherited advisories affect `zip` 8.6.0:

* RUSTSEC-2026-0367: SUID/SGID bits preserved;
* RUSTSEC-2026-0368: symlink escape;
* RUSTSEC-2026-0369 (CRITICAL): permissions applied through a symlink;
* RUSTSEC-2026-0429: abort on ZIP64 symlink size.

All four are fixed in zip ≥ 9.0.0. Holochain 0.7.1 cannot use the fix yet,
because `holochain_metrics` 0.7.1 requires `zip ^8.6`.

Evidence (exact-commit, reproducible):

| Target triple | zip 8.6.0 compiled? | Evidence |
| --- | --- | --- |
| x86_64-unknown-linux-gnu | No | `cargo tree --target … -i zip@8.6.0` prints nothing |
| aarch64-unknown-linux-gnu | No | same |
| x86_64-apple-darwin | No | same |
| aarch64-apple-darwin | No | same |
| x86_64-pc-windows-msvc | **Yes** (holochain_metrics) | dependency path recorded |
| aarch64-pc-windows-msvc | **Yes** | same |
| x86_64-pc-windows-gnu | **Yes** | same |

* The 0.7.1 Linux conductor built from the reviewed graph links **0** `zip`
  crate symbols.
* `zip` 9.5.0 (patched) appears only as a **build** dependency of
  `libsodium-sys-stable`.
* On Windows, the only caller is `holochain_metrics`' InfluxDB child-service
  downloader (`extract_zip`). It runs only when `HOLOCHAIN_INFLUXIVE_CHILD_SVC`
  is set (any value). It extracts only archives whose SHA-256 is compiled into
  the binary, and it checks that hash **before** extraction. An attacker would
  therefore need to defeat a SHA-256 pin to supply a malicious archive. This
  is strong mitigating evidence. It is not an approved exception.
* No CI job, packager or build script in this repository performs ZIP
  extraction. A search of `.github/` and `scripts/` for `zipfile`, `unzip` and
  `ZipArchive` finds only this sprint's test fixtures. None of the 14
  workflows targets Windows.

## Option A: Linux/macOS-only conductor deployment

Consequence: the zip advisories become proposed `NOT_APPLICABLE` for every
supported target. Windows operators and developers cannot run a supported
conductor.

Controls to implement **after approval**:

1. **Platform documentation:** a supported-platforms section in `README.md`
   and the operator runbooks listing the four triples above.
2. **Target-triple check:** make `scripts/security/conductor_release_profile.py
   --target <triple>` a required deployment and release step. It already
   fails on Windows triples. After approval, `platform_policy` would read
   `APPROVED (<record>)` instead of `PLATFORM_POLICY_APPROVAL_PENDING`.
3. **CI restriction:** CI builds and tests conductor artefacts only on the
   Linux runners already in use. Any added Windows conductor job must fail
   policy review.
4. **Packaging restriction:** DNA/hApp bundles are platform-neutral WASM and
   are unaffected. Any future conductor binary package must carry its target
   triple and pass the profile check.
5. **Deployment validation:** operators run the profile check against the
   exact conductor binary and environment file, plus
   `datastore_guard.py audit-root` against the data root.
6. **Security review:** any request to support Windows re-opens the four zip
   findings.

## Option B: continue Windows support

Consequence: the four zip findings stay applicable on Windows and cannot be
proposed `NOT_APPLICABLE`. At best they become
`FORMALLY_ACCEPTED_RESIDUAL_RISK` with compensating controls, or are resolved
upstream.

Required work:

1. **Upstream:** a `holochain_metrics` release on `zip >= 9`. zip 9.x changed
   its API; the only call site (`ZipArchive::new` + `extract`) is small.
   Holochain must then publish a 0.7.x release pinning that metrics crate.
2. **Interim control:** forbid `HOLOCHAIN_INFLUXIVE_CHILD_SVC` on Windows
   conductors. The release profile already enforces this on every platform.
3. **Testing:** a Windows CI job building the conductor and running the
   profile and datastore checks. This repository has no Windows runner today.
4. **Residual risk:** the zip code is still linked into Windows conductors, so
   a future Holochain change that adds a new caller would be exposed. A
   symbol-presence check on Windows binaries would need a Windows-capable
   `nm`/`dumpbin` path in the profile tool.

## Decision record (to be completed by the owner)

| Field | Value |
| --- | --- |
| Option chosen | — |
| Approver / role | — |
| Date (UTC) | — |
| Reviewed commit | — |
| Review/expiry date | — |
