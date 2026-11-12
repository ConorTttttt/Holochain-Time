# Sprint 37 — license governance: findings and decisions required

**Status: `LICENSE_POLICY_APPROVAL_PENDING`.** No license policy, exception,
alternative-license election or license grant for this project is approved.
This document was prepared by automated tooling (Claude Code) and **is not
legal advice**. Points marked ⚖ need qualified legal review.

Tooling:
* `scripts/license36/run.py`, the Sprint 36B three-graph inventory with 1,964 rows;
* `scripts/license37/artifact_licenses.py`, which shows what each shipped
  artifact actually links;
* `deny.toml`, the proposed Sprint 36B policy.

Executed with cargo-deny 0.20.2. The installed version accepts the proposed
policy without configuration errors. Every policy failure is a policy
violation, not a CLI problem; this is proven by the strengthened tests in
`scripts/license36/test_policy.py`.

## 1. The project's own license (owner decision)

* Every workspace manifest declares `license = "Apache-2.0"` through
  `[workspace.package]`. The integration test crates (`publish = false`)
  declare no license.
* **The repository contains no `LICENSE`, `NOTICE` or `COPYING` file.** A
  manifest SPDX field alone does not provide the license text that Apache-2.0
  §4(a) expects recipients to receive.
* `repository = "https://example.invalid/hc-vtime"` is a placeholder.
* **Not done, because doing so would be a license grant:** adding the Apache-2.0
  text at the repository root. If the owner confirms Apache-2.0, add the
  canonical text (<https://www.apache.org/licenses/LICENSE-2.0.txt>) as
  `LICENSE` and a project `NOTICE` (see `proposed/NOTICE.draft`). The
  copyright holder must be named by the owner.

## 2. Distribution model, as found in the repository

| Form | Contents | Distributed by this project? |
| --- | --- | --- |
| Source distribution | Repository / Sprint 35 source package | Yes |
| DNA / hApp bundle | `vtime_integrity` and `vtime` WASM zomes (`workdir/happ.yaml`) | Yes |
| Native oracle libraries | `vtime_core` and `vtime_oracle_state`, embedded in operator-hosted services | Intended for operators; confirm |
| Hosted services | Oracle signer and monitoring, run by operators | Operator decision ⚖ |
| Financial integration | Unyt RAVE templates; `unyt_harness` is test-only (`publish = false`) | Templates yes; harness no |
| Holochain conductor | Installed separately by operators | **No.** Used only by the test harnesses |

The owner must confirm this model. Section 3 obligations depend on it.

## 3. Licenses compiled into shipped artifacts

The inventory counts normal dependencies for the artifact's own target. It
excludes dev and build dependencies and proc-macro subtrees, which run on the
build host.

| Artifact | Linked third-party crates | Outside proposed allowlist |
| --- | --- | --- |
| `vtime_integrity.wasm` | ~112 | **`hdi` 0.8.1 — CAL-1.0** ⚖; `colored` 3.1.1 — MPL-2.0 |
| `vtime.wasm` | ~126 | **`hdk` 0.7.1, `hdi` 0.8.1 — CAL-1.0** ⚖; `colored` 3.1.1 — MPL-2.0 |
| `vtime_core` (native) | ~31 | none; only elections between alternatives |
| `vtime_oracle_state` (native) | ~31 | none; only elections between alternatives |

### ⚖ CAL-1.0 (Cryptographic Autonomy License 1.0), `hdk` and `hdi`

The Holochain HDK and HDI are compiled into both zomes, and so into every
distributed DNA or hApp. The crate packages on crates.io contain **no license
text file**; the license is declared only in `Cargo.toml`. Questions for
counsel, which this document does not answer:

1. Does distributing WASM that links `hdk`/`hdi` require the combined zome to
   be offered under CAL-1.0? How does that fit the project's declared
   Apache-2.0?
2. Which source-provision and notice obligations apply to the DNA/hApp, and
   to operators running hosted services?
3. How do CAL-1.0's user-data and key-autonomy provisions apply to the oracle
   signer and to Unyt financial users?
4. Is a Holochain-provided exception or clarification for application zomes
   available, and is it authoritative?

### MPL-2.0, `colored` 3.1.1

`colored` is reached through `holochain_util`. It is a file-level copyleft
dependency and is used unmodified. The likely obligations are a notice plus
availability of the MPL-covered source. **Owner and counsel to confirm.**

### Alternatives needing an explicit election (owner decision)

| Crate(s) | Expression | Suggested election, not made |
| --- | --- | --- |
| `byteorder`, `memchr`; `same-file`, `walkdir` (test graph) | Unlicense OR MIT | MIT |
| `constant_time_eq`, `dunce` | CC0-1.0 OR MIT-0 OR Apache-2.0 | Apache-2.0 |
| `zerocopy` | BSD-2-Clause OR Apache-2.0 OR MIT | Apache-2.0 or MIT |
| `aws-lc-sys` (native graphs) | conjunctive expression with OR sub-terms | Review the full expression |

### Notices that binary distributions (WASM inside DNA) must carry

* **BSD-3-Clause:** `curve25519-dalek` 4.1.3 and `ed25519-dalek` 2.2.0
  (© isis agora lovecruft); `subtle` 2.6.1 (© Isis Agora Lovecruft and
  Henry de Valence). The copyright notice and disclaimer must be reproduced.
* **Zlib:** `foldhash` 0.2.0 (© 2024 Orson Peters).
* **Unicode-3.0:** `unicode-ident` 1.0.27.
* **MIT / Apache-2.0:** permission notices for the crates in the generated
  `THIRD_PARTY_LICENSES` inventory.
* **COPYRIGHT files:** present in `unicode-segmentation` and `unicode-xid`.
  Confirm whether either is linked.

## 4. Licenses outside the allowlist in the conductor/load test graphs only

These graphs are not distributed if section 2 is confirmed:

* `holochain` (CAL-1.0);
* Cranelift, Wasmtime, regalloc2 and target-lexicon (Apache-2.0 WITH LLVM-exception);
* `attohttpc` and `option-ext` (MPL-2.0);
* Unlicense crates;
* `enum-iterator` (0BSD);
* `webpki-roots` (CDLA-Permissive-2.0, root-certificate data);
* `inferno` (CDDL-1.0);
* `libbz2-rs-sys` (bzip2-1.0.6);
* `ppmd-rust` (CC0-1.0 OR MIT-0).

The test crate `hc-vtime-conductor-smoke` has no `license` field, so
`[licenses.private] ignore = false` fails it.

**Policy question (owner):** should the test graphs be held to the same
allowlist as distributed artifacts? Either answer is a policy decision that
must be approved and validated **separately**:

* **Option A:** add the test-only licenses to a test-graph-specific allowlist.
* **Option B:** keep the strict allowlist and accept the failure until approval.

Silently widening the allowlist is not acceptable.

## 5. Approval record (empty: no approval exists)

| Field | Value |
| --- | --- |
| Approved SPDX identifiers | — |
| Elected alternatives | — |
| Approved exceptions | — |
| Required notices accepted | — |
| Source restrictions | — |
| Approver identity and role | — |
| Approval date (UTC) | — |
| Exact reviewed commit | — |
| Legal reviewer, if material | — |

Until this table is completed by the authorised owner, and by counsel where
marked ⚖, the status remains **`LICENSE_POLICY_APPROVAL_PENDING`** and the
cargo-deny license stage stays FAIL.
