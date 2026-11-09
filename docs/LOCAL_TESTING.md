# Local Holochain 0.7 verification — Sprints 1–6

**Status:** Scripts prepared and shell-checked; no successful local Rust or conductor run has been executed in the ChatGPT environment (Cargo, Rust and Holochain tools are not installed). No release approval is implied.

## Source: already on GitHub

The project ZIP was imported as project files on Sprint 1 PR #16 and later combined through Sprint 6 PR #28. GitHub main still contains only RELEASE_PLAN.md. You do not need to upload the original ZIP. Clone your **private** repository using your authenticated GitHub account:

```bash
git clone https://github.com/ConorTttttt/Holochain-Time.git
cd Holochain-Time
git fetch origin
git switch --track origin/sprint/08-reconcile-test-stack-2026-11-09
```

On Windows, run these commands in Ubuntu on WSL2. Linux/macOS users can use their normal terminal. For a source-only ZIP, use the branch selector on GitHub's Sprint 6 branch and select Code → Download ZIP; to test all branch commits you need the Git clone.

## Toolchain

Use Nix with flakes enabled and the official Holochain 0.7 environment:

```bash
nix develop "github:holochain/holonix?ref=main-0.7"
```

Official setup reference: https://developer.holochain.org/get-started/install-advanced/ . The repository locks HDK 0.7.1 and HDI 0.8.1. Record actual Rust, hc and conductor versions for reproducibility. System Rust can run native checks, but the WASM target and Holochain 0.7 CLI are also needed. With rustup, install rustfmt, clippy and wasm32-unknown-unknown.

## Test locally in dependency order

Run the first cumulative check:

```bash
bash scripts/test_sprints_local.sh --current --native-only
bash scripts/test_sprints_local.sh --current
```

Then verify each original PR head in a detached Git worktree without altering your working checkout:

```bash
bash scripts/test_sprints_local.sh --sprint 1
bash scripts/test_sprints_local.sh --sprint 2
bash scripts/test_sprints_local.sh --sprint 3
bash scripts/test_sprints_local.sh --sprint 4
bash scripts/test_sprints_local.sh --sprint 5
bash scripts/test_sprints_local.sh --sprint 6
# Or run all in order:
bash scripts/test_sprints_local.sh --all
```

Each run logs its **exact SHA** and environment, runs Cargo formatting, full workspace tests, all-target Clippy, a focused regression test, and both WASM builds, with separate PASS/FAIL logs in test-reports/local-*/results.tsv. A nonzero result means at least one executed check failed. No automatic merges or deployments occur.

| Sprint | Focused check | Required follow-up NOT covered by local unit tests |
| --- | --- | --- |
| 1 | Evidence/quorum tests | Review import; real conductor quorum and recovery |
| 2 | Coordinator and explicit witness checks | Three-agent Sweettest: third-party seals, forks, missing proofs |
| 3 | Roughenough interoperability | Real network and fuzz/DoS measurements |
| 4 | Coordinator legacy-lookup guard | Demonstrate no DHT scan in real conductor; consumer migration |
| 5 | Evidence policy | Three truly independent Roughtime sources and 100+ seals |
| 6 | Merkle batch primitive | v3 signing, admission control, independent cryptographic audit |

## DNA packaging: explicit safety gate

The repository intentionally contains REPLACE_WITH placeholder public keys in dnas/vtime/workdir/dna.yaml. Do not deploy or publish a DNA using them. After a reviewed TEST-only configuration with valid public keys, use a local copy of the manifest and:

```bash
bash scripts/test_sprints_local.sh --current --pack
```

The script pins the original sprint branch heads to the reviewed SHA values and refuses tracked working-tree edits; it blocks if remote sprint heads have moved. A successful run does not repair the GitHub Actions runner issue or demonstrate that the sprint PR ancestry is current. The script refuses packing if placeholder keys remain. Packing is not a conductor integration test. The real-conductor acceptance plan is docs/CONDUCTOR_TEST_MATRIX.md; it has not yet been executed. Run a genuine ≥3-agent Sweettest suite, DHT partition/restart tests, 10k-link floods and 100+ concurrent seal load. Run test-funded Unyt transaction tests separately. Do not use real money.

## Send back the results

After starting with Sprint 1, share test-reports/local-*/results.tsv, environment.txt and any failing .log files, after removing local paths, tokens or sensitive data. We'll fix failures at their earliest sprint, rerun and proceed in PR dependency order (#16, #19, #21, #24, #26, #28). GitHub Actions runner incident #22 remains open. Wider release is NO-GO.
