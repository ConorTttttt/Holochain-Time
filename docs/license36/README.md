# Sprint 36B — Proposed dependency licensing and source governance

**Status:** `LICENSE_POLICY_APPROVAL_PENDING`. **Production:** `NO-GO`. This is an agent-authored policy proposal, not legal advice, reviewed compliance, release approval, or a vulnerability remediation.

## Scope and verified baseline

- Repository: `ConorTttttt/Holochain-Time`, main `bae1e5b9380e92cbee511e07fea1681011d4d6d0`.
- PR #80 (`3552a815354d9b3b888b7fd237015774f3324a3b`) remains **draft and unmerged**, outside this branch. The documented integration verdict is **37/38 development gates**, `s35_supply_chain` **FAIL**. Sprint 36A owns inherited vulnerabilities.
- Three current lockfiles: root **274**, conductor **845**, load **845** entries (**1,964 graph entries**, with duplicates across graphs). All external locked entries currently use `registry+https://github.com/rust-lang/crates.io-index`; there are no Git-sourced locked entries. The accompanying lockfile-based CSV records every locked identity, version, graph membership, source and checksum; **it does not claim verified SPDX metadata**.
- Root workspace declares `license = "Apache-2.0"`; standalone conductor and load fixtures do not declare a package license. A top-level LICENSE file was not found in the starting main tree. **Owner must verify and supply project source-license and redistribution texts**; do not silently grant additional licenses.
- The repository's existing `scripts/audit35/supply_chain.py` is on PR #80, not main; it runs root `cargo deny --locked check` and audits all three lockfiles. This branch adds all-three-graph scanning rather than weakening that gate.

## Proposed license decisions, NOT approvals

| Class | Proposed technical handling | Human obligation |
| --- | --- | --- |
| Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib | Candidate allowlist ONLY; cargo-deny allows these short IDs when present | Owner/legal review of obligations, actual files, notices and distribution mode. |
| SPDX `AND` of only candidate IDs | Candidate machine-checkable expression | Confirm simultaneous obligations. |
| Any SPDX `OR` expression | Explicit `REVIEW_REQUIRED_ALTERNATIVE_EXPRESSION` in inventory, even if cargo-deny can choose an allowed option | Identify selected lawful option and required attribution; independent signoff. |
| Other licenses, `WITH` exceptions, nonstandard `LicenseRef-`, unrecognised identifiers | Not on allowlist; error or flag | Narrow, exact version-specific exception only after documented review. |
| Missing license metadata, ambiguous/corrupt license files or invalid SPDX | Unknown or failed; no inference from crate name | Inspect authoritative package license files; hash-pin cargo-deny clarification if justified. |
| GPL/AGPL/LGPL/MPL/EPL/CDDL/BSL/SSPL or other obligations | **Requires additional review**, not automatically declared illegal | Determine compatibility, linkage/distribution and copyleft/reciprocity case-by-case. |
| Known incompatible dependency confirmed by counsel | Prohibit once decision recorded | Identify legal basis and applicable distribution. |
| Licenses not yet evaluated by owner | **Not yet approved** | Owner/legal/security approval required regardless of passing machine checks. |

This proposal deliberately does **not** add every license found to an allowlist. The current effective compliance outcome is `NOT_YET_APPROVED` even if a technical scan later succeeds. Exceptions and clarifications are **empty** until evidence and external approval exist. `licenses.private.ignore = false` checks local harnesses too.

## Source-origin policy

Only default crates.io registry is proposed as an acceptable external source. Exact package checksums must be present in each `Cargo.lock`. No Git source, nonstandard registry, `[patch]` / `[replace]`, or external path dependency has blanket approval. `cargo-deny` separately rejects unknown Git and registry sources. `source_policy.py` also checks committed manifests and local package IDs. Any new registry, Git URL, local crate, vendored source or generated build source must be independently reviewed and explicitly documented before policy relaxation.

This repository has tracked generated artifacts, including Python bytecode per Sprint 35's audit briefing. **Provenance and removal remain separate release-hygiene work**: nothing is deleted in 36B without review. Review all third-party source/binary, build-script, target-specific and vendored packages for license-file preservation. Existing paths inside the repository are not automatic redistribution approvals.

## Reproducing inventory and enforcement on an exact commit

Run on a clean, full clone at the **actual 36B integrated candidate SHA** (not PR #80's old SHA). Required: Python 3.11+, Git, matching Rust toolchain, offline cached crate metadata, cargo-deny, cargo-audit, advisory database. From repository root:

```sh
SHA="$(git rev-parse --verify HEAD)"
python3 -B -m unittest discover -s scripts/license36 -p 'test_*.py' -v
python3 -B scripts/license36/run.py --expected-sha "$SHA" \
  --output-dir ../s36b-licenses-evidence
```

The runner refuses dirty or mismatched repositories, keeps evidence outside Git and writes `inventory-full.csv`, `report.json`, logs and checksums. It attempts **all three** locked offline `cargo metadata --all-features`, all three `cargo deny --locked check`, and all three `cargo audit --json --file <lockfile>` commands. A command only passes if actually executed with exit code 0; missing binaries, metadata, failed source restrictions, or unreviewed dependencies are never reported PASS. Review the SPDX field, declared files, observed license/NOTICE files, graph, feature/target qualifiers, and direct/transitive fields in `inventory-full.csv`. The inventory includes **metadata-declared** license strings, not verified legal grant analysis. Each row keeps attribution status `REVIEW_REQUIRED_BEFORE_DISTRIBUTION`.

The locked CSV committed here is **lock-only provisional evidence**: its `spdx_expression` is `NOT_PRESENT_IN_LOCKFILE`, not an invented license. Full metadata is unavailable in this GitHub connector environment. The actual `cargo-deny`, `cargo-audit`, metadata and runtime regressions are **NOT RUN in this sprint's chat environment**, and any results from other candidate SHAs must not be transferred.

`source_policy.py` intentionally checks exact-package source identities but does **not** substitute for cryptographic verification of downloaded crate bytes against lockfile hashes. Offline cache integrity, registry index, vendored source, build scripts, external releases, and notices remain reviewer responsibilities.

## Source / binary / DNA / hApp distribution checklist

1. **Development integration:** run complete locked metadata and policy scans on all graphs; inspect `UNKNOWN`, OR, `WITH`, exceptions, target-specific crates, dev/build dependencies; separately run all vulnerability/advisory checks. No category may hide another's FAIL.
2. **Reproducible package:** verify actual exact SHA, lockfile bytes/checksums, source origins, vendor/archive provenance, bundled third-party license/NOTICE files and full cargo-deny version/config. Recompute after Sprint 36A changes.
3. **Source distribution:** preserve copyright, license texts and applicable source/NOTICE files; confirm reciprocal source obligations with counsel before distribution.
4. **Binary, WASM, DNA and hApp distribution:** identify shipped static/dynamic code, generated artifacts and included transitive components per target/feature; supply attribution and notices; obtain qualified review of distribution-specific obligations.
5. **External signoff:** project owner accepts distribution model and proposed policy; qualified legal reviewer resolves ambiguities and scope; independent security reviewer validates supply-chain provenance and vulnerability remediation. Record names, dates, exact SHA, evidence and exceptions outside agent-generated PASS flags.
6. **Release:** run complete Sprint 28–35 development gates, Rust/Clippy/WASM and Sprint 35 source package independently; retain security FAIL and `NO-GO` until vulnerabilities, licensing approval, audit and all other production gates are actually closed.

## Sprint 36A handoff and integration instructions

Sprint 36A should review proposed identifiers above, any `UNKNOWN` / OR / unlisted licenses, notice obligations and strict crates.io-only source restriction **before selecting upgrades**. Any patch registry or Git fork must be explicitly reviewed and pinned; do not relax `allow-git` to make an upgrade pass. Codex should merge this draft into a **new temporary integration branch**, preserve PR #80, integrate 36A, regenerate full inventory, rerun policy and all three security scans, check exact SHA / clean source / source bundle / WASM / Rust / Clippy, and preserve separate development vs production verdicts. An agent cannot approve its own policy.

**Outstanding: `LICENSE_POLICY_APPROVAL_PENDING`; dependency vulnerabilities unresolved on starting graphs; `s35_supply_chain` remains FAIL; `PRODUCTION_RELEASE=NO-GO`.**
