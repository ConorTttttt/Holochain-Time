# Exact-commit provenance, dependency review and no-paid-runner reproduction

**Separate four claims:** (A) committed source reproduced, (B) dependencies and supply chain independently reviewed, (C) native/WASM/DNA/hApp/Unyt artifacts actually built and tested, (D) security/economic approval. Sprint 35 enables **A** and a lockfile inventory feeding **B**; the other claims remain independent and unproven.

## 1. Build a deterministic tracked-source package

Run on a clean, full (non-shallow) checkout of the reviewer-approved candidate SHA, with Python 3.11+ and Git. Use no production signing secrets:

```sh
SHA="$(git rev-parse --verify HEAD)"
git status --porcelain --untracked-files=all  # prints nothing
python3 -B -m unittest discover -s scripts/audit35 -p 'test_*.py' -v
python3 -B scripts/audit35/package.py \
  --expected-sha "$SHA" --output-dir ../s35-audit-source-first
python3 -B scripts/audit35/verify.py \
  --expected-sha "$SHA" --bundle ../s35-audit-source-first

# Repeat from second clean independent clone of SAME SHA.
python3 -B scripts/audit35/package.py \
  --expected-sha "$SHA" --output-dir ../s35-audit-source-second
sha256sum ../s35-audit-source-first/source.tar.gz \
          ../s35-audit-source-second/source.tar.gz
```

Output directories must be new and outside Git. Each has **only** `source.tar.gz`, `dependencies.json`, `provenance.json`, `SHA256SUMS`. The archive is `git archive --format=tar <exact SHA>` wrapped in gzip with mtime=0 and no host filename; untracked build artifacts cannot enter it. `verify.py` independently regenerates that archive, recomputes checksums, inspects the embedded Cargo locks and their package metadata, and rejects fabricated production-approval flags. This is not an authenticated release signature: the human auditor must authenticate the Git remote/commit and reviewer-approved ref separately.

The creation timestamp in `provenance.json` differs between runs. Only the tracked **source archive** and normalized dependency inventory are intended to be byte-identical for the same Git/Python implementation. Pin Git/Python versions and investigate cross-tool differences; do not claim all output bytes or generated WASM are deterministic merely because source tarballs match.

## 2. Rust dependencies, SBOM and security scans

`dependencies.json` inventories **all three committed** lockfiles: root workspace `Cargo.lock`, standalone `integration/conductor/Cargo.lock`, and standalone `integration/load/Cargo.lock`. It records exact lockfile SHA, package name/version/source and recorded Cargo checksum. The standalone fuzz project lacks a committed `fuzz/Cargo.lock` on this baseline; pin it before claiming a complete build dependency graph. This inventory is **not** CycloneDX/SPDX validation, vulnerability scanning, license review or proof of RustSec database freshness.

Execute on an isolated approved host and save actual commands, return codes, tool versions, advisory DB date/revision, logs and digests outside Git:

```sh
cargo metadata --locked --format-version 1 > /secure/audit/root-metadata.json
cargo metadata --locked --manifest-path integration/conductor/Cargo.toml --format-version 1 \
  > /secure/audit/conductor-metadata.json
cargo metadata --locked --manifest-path integration/load/Cargo.toml --format-version 1 \
  > /secure/audit/load-metadata.json
cargo audit --version
cargo audit --json > /secure/audit/cargo-audit-workspace.json
cargo deny --version
cargo deny check > /secure/audit/cargo-deny-workspace.log
```

Run equivalent scanner checks for each standalone lockfile **only using syntax supported by the installed scanner version**; record coverage. Include `cargo tree`, upstream source/checksum verification, native Unyt and Holochain application dependencies, fuzz dependencies, license review, unsafe/FI interfaces, and GitHub Actions ref/action provenance. A missing scanner or stale advisory database means **NOT RUN/UNVERIFIED**, not “no vulnerabilities”. `scripts/security/inventory.py` is a pre-existing source-level unsafe marker heuristic, not an external dependency audit.

## 3. Reproduce real runtime artifacts separately

Sprint 27 is the authoritative single-commit integration runner. After reviewing branch tip ancestry and generating external `hc-vtime/integration-pins/v1` pins:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/release_acceptance_27.py \
  --expected-sha "$SHA" \
  --pins /secure/reviewed-integration-pins.json \
  --report-dir /secure/s35-executed-sprint27-evidence
```

Consult `docs/SPRINT_27_RELEASE_ACCEPTANCE.md` for full test matrix and optional destructive fork-lab restrictions. A green **development** result is still **production NO-GO**. Production DNA must be built only after `scripts/deployment_preflight.py` and `scripts/pack_release_dna.py` approve exact external manifest, policy, WASM digests and key provenance; direct `hc dna pack` bypasses this protection. Rebuild in two independently maintained compatible environments and compare **actual** WASM, DNA and hApp SHA-256, toolchain versions and raw logs. If bytes differ, document non-reproducibility; neither SOURCE_DATE_EPOCH nor `source.tar.gz` alone proves binary reproducibility.

Save per-stage SHA, exact command, exit code, start/stop timestamps, machine/toolchain, executed test count, artifact digest, raw log hash and classification. Missing data, synthetic logs, wrong SHA, unassigned Actions runners and unperformed native RAVE/Accept are **NOT RUN**, never PASS.

## 4. Alternatives to paid GitHub-hosted Actions

**Local/Codex Linux host:** `bash scripts/audit35/run_local.sh "$SHA" ../new-s35-bundle` verifies the source bundle and its negative tests without a hosted runner. Then execute Sprint 27 separately for Rust/WASM/conductor evidence.

**Self-hosted Actions:** manually dispatch `.github/workflows/sprint35-self-hosted-audit.yml` on a dedicated disposable Linux runner labelled `hc-vtime-audit`. The workflow intentionally does not receive production keys and checks only source packaging. Never accept unreviewed PR code on a long-lived self-hosted runner with signing keys or sensitive access; protect the dispatch privilege and verify the checked-out commit.

**Independent reviewer machine:** repeat source and *actual* runtime artifact builds using the same full SHA, toolchain and externally approved key policy; compare hashes and sign findings separately.

Issue #22 tracks GitHub Actions jobs rejected before runner assignment. The original administrative cause is not established; do not attribute those jobs to compiler failures or mark their tests executed.

## 5. Audit handoff

Supply the authenticated full Git SHA and independently pinned branch tips; protected source bundle with SHA256SUMS; standalone verification logs; lockfile and **fresh** advisory/license reports; Rust/WASM/DNA/hApp provenance; real operator root and signer identity records; actual Unyt RAVE and separate recipient Accept; threat/invariant dossiers; open findings; and named independent reviewer approval.

**Release status remains NO-GO.** A reproducible Git-tracked source snapshot is necessary review input, not an attestation of build, deployed financial finality or operational security.
