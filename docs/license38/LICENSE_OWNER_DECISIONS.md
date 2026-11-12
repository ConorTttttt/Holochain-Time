# Sprint 38: license decisions requiring owner and legal authorisation

**Status: `LICENSE_POLICY_APPROVAL_PENDING`.** Nothing here is a license grant,
an approved exception or legal advice. The draft `NOTICE` in
`docs/license37/proposed/NOTICE.draft` is **not legally effective**. Prepared
by automated analysis (Claude Code). Items marked ⚖ need qualified legal
review before any compliance claim.

## Exact-commit inventory

Regenerated at security-clearance commit
`c2c93152bc180902ba7b3556437b2c890fbe6355`. Rust sources and lockfiles are
identical to candidate `18df72c`; that commit added Python tooling only.

| Scope | Tool | Result |
| --- | --- | --- |
| `vtime_integrity.wasm` (DNA/hApp) | `scripts/license37/artifact_licenses.py` | 111 linked third-party crates |
| `vtime.wasm` (DNA/hApp) | same | 124 linked third-party crates |
| `vtime_core`, `vtime_oracle_state` (native oracle libraries) | same | 30 each |
| Root / conductor / load graphs (incl. build- and test-only) | `scripts/license36/run.py` | 1,964 rows (274 / 845 / 845) |
| Operational Python tooling | import scan of `scripts/`, `integration/` | third-party: `cryptography` 50.0.2 (Apache-2.0 OR BSD-3-Clause), `msgpack` 1.2.4 (Apache-2.0) |

"Linked" means normal dependencies for the artefact's target. Dev, build and
proc-macro subtrees run only on the build host and are excluded. Outputs and
SHA-256 sums are in the external evidence package.

### What each distributed artefact needs reviewed

| Artefact | Items outside the proposed allowlist | Other obligations found |
| --- | --- | --- |
| `vtime_integrity.wasm` | `hdi` 0.8.1 **CAL-1.0** ⚖; `colored` 3.1.1 MPL-2.0; alternatives: `byteorder`, `memchr` (Unlicense OR MIT), `constant_time_eq`, `dunce` (CC0-1.0 OR MIT-0 OR Apache-2.0) | **11 linked crates ship no license text in their crate package**, including `hdi`, `holo_hash`, `holochain_integrity_types`, `holochain_serialized_bytes`, `blake2b_simd`; NOTICE/COPYRIGHT-type files in `rand`, `rand_core`, `rand_chacha`, `rand_xorshift` |
| `vtime.wasm` | as above plus `hdk` 0.7.1 **CAL-1.0** ⚖ | **15** crates without license text, including `hdk`, `hdi`, `holochain_zome_types`, `holochain_wasmer_guest` |
| Native oracle libraries | alternatives only (`byteorder`, `constant_time_eq`) | `blake2b_simd` ships no license text |
| Source package | everything in the repository | **no root `LICENSE`**; manifests declare Apache-2.0; `repository` is a placeholder |
| Conductor (not distributed by this project) | `holochain` CAL-1.0; MPL-2.0 `attohttpc`, `option-ext`, `colored`; vendored C code not visible in Cargo SPDX fields: SQLCipher (Zetetic BSD-style), SQLite (public domain), OpenSSL 3.6 (Apache-2.0), libsodium (ISC) | relevant only if the project ever ships conductor binaries |
| Test-only graphs | root dev graph adds `smartstring` 1.0.1 **MPL-2.0+** (via `rave_engine` → `rhai`, Unyt harness, `publish = false`) | not distributed if the model below is confirmed |

Missing license texts must be taken from the upstream repositories at the
matching tags. They cannot be copied from the crate packages, because the
texts are not there.

## Decisions required

| # | Decision | Owner input needed | Legal ⚖ | Current state |
| --- | --- | --- | --- | --- |
| 1 | Intended project source license | Confirm Apache-2.0 (as declared) or choose another; then add the canonical text as `LICENSE` | ⚖ if not Apache-2.0, or if CAL-1.0 constrains it (see 4) | Not decided; no `LICENSE` file; nothing added |
| 2 | Copyright holder | Legal name(s) and years for `NOTICE` | — | Not named |
| 3 | Distribution model | Confirm the table in `docs/license37/LICENSE_GOVERNANCE.md` §2: source + DNA/hApp distributed; native libraries to operators; conductor **not** distributed; Unyt harness not distributed | — | Unconfirmed |
| 4 | CAL-1.0 compatibility (`hdk`, `hdi` in both zomes) | Must the combined zome be offered under CAL-1.0? Source-provision duties for DNA/hApp distribution? Effect of CAL user-data/key-autonomy terms on the oracle signer and Unyt users? Is there an authoritative Holochain clarification for application zomes? | ⚖ **required** | Open |
| 5 | MPL-2.0 obligations (`colored`, unmodified, in both zomes) | Accept file-level obligations (notice + source availability of MPL files) | ⚖ confirm | Open |
| 6 | Third-party attribution | Approve generating `THIRD_PARTY_LICENSES` per release from the exact-commit inventory, including BSD-3-Clause, Zlib, Unicode-3.0 and Apache NOTICE content, with missing texts sourced upstream | — | Draft generator exists; not approved |
| 7 | Alternative-license elections | Elect for `byteorder`, `memchr` (suggest MIT); `constant_time_eq`, `dunce` (suggest Apache-2.0); `zerocopy`; `aws-lc-sys` (native graphs, full expression) | — | None elected |
| 8 | Required license notices | Approve the content and placement of the root `NOTICE` and of notices shipped inside the DNA/hApp release bundle | ⚖ for CAL notice text | Draft only, not effective |
| 9 | Approved exceptions | Decide whether CAL-1.0 and MPL-2.0 are exceptions to the allowlist (distributed artefacts) and how test-only graphs are treated (Option A/B in the Sprint 37 governance doc §4) | ⚖ for CAL | None approved |
| 10 | Effective policy date | Date from which `deny.toml` license policy and notices apply; review cadence | — | None |

## Hosted-service implications ⚖

Operators run the oracle signer and monitoring as hosted services. CAL-1.0
contains provisions on providing the work's functionality to others and on
user data and keys. Counsel should determine:

* whether running the DNA in a conductor, or offering oracle signing as a
  service, triggers CAL obligations for the operator or the project;
* whether Unyt financial users count as "recipients" under CAL.

## What was deliberately not done

* No `LICENSE`, `NOTICE` or `COPYING` added at the repository root.
* No `deny.toml` allowlist widened.
* No alternative-license election made.
* No claim of compliance.

## Approval record (empty: no approval exists)

| Field | Value |
| --- | --- |
| Decisions 1–10 | — |
| Approver identity and role | — |
| Legal reviewer | — |
| Date (UTC) | — |
| Exact reviewed commit | — |
