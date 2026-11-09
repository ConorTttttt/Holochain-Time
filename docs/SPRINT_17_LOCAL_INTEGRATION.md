# Sprint 17 — Codex local integration and exact-commit evidence

**Scope:** Build GitHub-hosted validation tooling; do not merge sprint branches or promote main. All validation described here runs later from Codex on a local, already-consolidated checkout. **Release decision remains NO-GO** without separate external, Holochain and Unyt acceptance.

## One command

After Codex has **reviewed and integrated** the desired sprint branches into a local candidate (not main), and fetched all review refs, run from the clean candidate checkout:

```sh
git fetch origin --prune
git rev-parse HEAD  # record the FULL 40-character tested candidate SHA
# Copy integration/reviewed_pins.example.json outside the repo and replace
# every placeholder with the reviewed candidate SHA, original main SHA, and
# EXACT FULL remote tips for every selected and integrated sprint.
python3 scripts/integration_validate.py \
  --expected-sha "$(git rev-parse HEAD)" \
  --pins ../reviewed-integration-pins.json \
  --ci-run-id <OPTIONAL_EXACT_SHA_GITHUB_ACTIONS_RUN_ID>
```

If no GitHub run ID is known, **omit** the final argument entirely; CI is then `NOT RUN`, not PASS. The tool works without `gh` when no CI audit is requested. `--repo` points at another local candidate clone; `--report-dir` names an **unused directory outside the repo**. By default it makes a unique sibling `hc-vtime-integration-*/` directory. The entry point does not call git merge, rebase, push, checkout, update-ref or edit main.

**Mandatory:** `--expected-sha` is a full, exact 40-character commit hash, not a moving branch. `--pins` must be reviewed, copied **outside** the source worktree, and contain `schema`, `candidate_sha`, `base` and at least one `branches` entry. Each branch must have a stable `branch` name and full `sha` for the exact remote `origin/<branch>` tip. It validates that the local tracking ref **still matches** the pinned tip and that the exact parent SHA is included in the candidate's Git history. It also checks the pinned `origin/main` ancestry. If Codex chooses an alternative implementation of Sprint 14A, it should list only the reviewed one and document why; it must not claim to have integrated both independently unless both tips are actually ancestors. Add Sprint 16 if completed and selected. Omit excluded branches only after explicit integration review.

**A shallow checkout or dirty tracked/untracked worktree fails** the source gate. The tool never fetches, merges, rebases or updates branches. Stale local `origin/*` refs require an intentional `git fetch` followed by re-review and re-pinning, not silently accepting moved tips.

## Required local gates

| Gate | What the tool performs |
| --- | --- |
| `source` | exact `HEAD`, complete commit SHA, clean worktree/index, Cargo.lock fingerprint, non-shallow history |
| `ancestry` | pinned origin main + every reviewed sprint remote tip must match and be ancestors of tested candidate |
| `python_tests` | `python3 -m unittest discover -s scripts -p 'test_*.py' -v` |
| `workspace_format` | workspace `cargo fmt --all -- --check` |
| `conductor_format` | standalone conductor `cargo fmt ... --check` |
| `native_tests` | locked Rust workspace tests (including Unyt harness if in candidate) |
| `clippy` | all-target locked `cargo clippy ... -D warnings` |
| `wasm` | compile HDK 0.7 integrity + coordinator WASM with configured getrandom/link flags |
| `signed_conductor` | existing `run_signed_quorum.sh` rebuilds fresh WASMs, generates 4 insecure **test-only** Roughtime public keys, packs throwaway DNA, runs signed three-source + three-conductor smoke tests, preserves logs |
| `fresh_dna` | regenerated manifest from exact source + the recorded public keys and random seed; **second independent `hc dna pack`** in another temporary detached worktree; bytes must match first signed-runner bundle |

All of the above are required for a **local** PASS. `--native-only` is available for early debugging and marks WASM, conductor and DNA `NOT RUN`, so overall cannot be PASS. Missing tools, preflight failure, explicitly skipped tests, and non-executed workflows are never counted as passing. Executed failures are `FAIL`; missing/skipped gates are `NOT RUN`. Exit codes: **0** all required local gates PASS; **1** at least one FAIL; **2** no failures but one or more NOT RUN. The `overall` field and every check use exactly `PASS`/`FAIL`/`NOT RUN`.

The runner uses the existing Signed Quorum code without replacing the test keys with real keys. It produces **only test-fixture evidence**, never proof of genuinely independent external Roughtime operators. It never deploys the test DNA or spends Unyt funds.

## Evidence layout and verification

Each run gets a brand-new evidence directory **outside** the repository, for example:

```text
hc-vtime-integration-<unique>/
  report.json                 machine-readable exact SHA + every gate result
  report.md                   human-readable local integration report
  SHA256SUMS                  SHA-256 of every recorded file except itself
  python_tests.log / workspace_format.log / native_tests.log / ...
  signed/
    provenance.txt            SHA, toolchains, lock and WASM fingerprints
    dna.yaml                  fresh test-only manifest
    keys-public.json          public test-only keys only
    vtime.dna                 first freshly packed test bundle
    signed-quorum.log         signed Roughtime three-agent Sweettest
    conductor-smoke.log       three-agent smoke
    SHA256SUMS
  fresh-dna/
    repack.log                second pack command log
    fresh-vtime.dna           second independently packed test bundle
    dna-comparison.json       both SHA-256 values, byte comparison, result
  ci-audit.json               only when an exact-SHA audit is available
```

Every log has an execution result and SHA-256 recorded in `report.json` when its command was attempted; `SHA256SUMS` includes all non-symlink files and is computed after final `report.json`/`report.md` creation. **Do not modify a report directory** after validation. The manifest is an integrity checksum, not a signature, and independent reviewers must verify it:

```sh
cd ../hc-vtime-integration-<unique>
sha256sum -c SHA256SUMS
python3 -m json.tool report.json >/dev/null
```

Evidence hashes must be coupled to the exact tested SHA, not merely names of sprint branches. Compare `signed/provenance.txt`, `fresh-dna/dna-comparison.json`, SHA256SUMS, and the candidate's actual Git ancestry. Avoid sharing logs containing local private paths or secrets until reviewed; no wallet credentials are requested by these tools.

## GitHub Actions billing / runner failure handling

The existing `scripts/audit_ci.py` classifies GitHub workflow metadata. Optional `--ci-run-id N` audits **only** the supplied exact expected commit using authenticated local `gh` CLI. `--ci-run-json` and `--ci-jobs-json` may instead provide *offline metadata fixtures*, but those cannot by themselves prove the GitHub run is authentic.

| `audit_ci.py` state | Sprint 17 CI result | Meaning |
| --- | --- | --- |
| `passed` | PASS | Both jobs and required steps executed successfully on exact SHA |
| `before_runner` | NOT RUN | Jobs fail with no runner and zero steps. Common with workflow policy/billing issues; specific cause needs administrator verification |
| `pending`, `incomplete` | NOT RUN | Insufficient CI execution evidence |
| `executed_failure` | FAIL | Actual required command failed on runner |
| `sha_mismatch` | FAIL | CI belongs to a different commit and cannot certify this one |

A missing run ID or unavailable `gh` yields `NOT RUN`. **Do not classify zero-step Actions failures as Rust/compiler errors or infer a billing cause without GitHub administration evidence.** The optional CI audit is reported separately from the mandatory local gates: a successful, independently reviewed local run can be labelled **local PASS / CI NOT RUN**, but **never hosted CI PASS**. Changes to repository Actions billing/settings remain a separate administrator action.

## Operational constraints

- The DNA comparison uses a temporary detached Git worktree and removes only the temporary worktree it created. It never changes remote branch refs or merges into `main`.
- The signed runner is allowed to accept `HC_VTIME_SIGNED_REPORT_DIR` solely to collate logs in the top-level report. The path must be new and outside the checkout.
- A missing Rust/Holonix 0.7 / `hc` / WASM toolchain produces `NOT RUN` for affected checks; executing another gate with a different SHA is forbidden.
- The `report.json` value `release_ready` is **always false**. The tool does not certify Sprint 11 real independent Roughtime, Sprint 12 partition/outage acceptance, Sprint 13 real resource ceilings, Sprint 14B funded payments, Sprint 15 runtime security, Sprint 16 audit, global evidence completeness or independent security review. List these as separate integration acceptance gates.
- Template signer keys in the test bundle are publicly known and **not** for production. No hosted GitHub agent should receive private keys or funded Unyt credentials.

## Agent G handoff to Codex

1. Review/merge chosen sprint branches into a **local candidate branch**, resolving overlapping verification interfaces and any competing Sprint 14A implementations. Do not promote main yet.
2. Fetch `origin` and pin every reviewed branch tip + the original main base in an **external** JSON file. Ensure all tips really occur in the candidate ancestry.
3. Run the one command on the **final integrated candidate SHA**. Fix errors and repeat from a new clean commit; do not overwrite existing evidence.
4. Review and archive `report.json`, `report.md`, logs, `SHA256SUMS`, signed conductor provenance, and independent DNA comparison. Attach a sanitized report and exact SHA to the promotion review.
5. Only after all separate release gates and independent review, decide promotion by the existing GitHub PR process. **Sprint 17 itself must never merge into main automatically.**

## Sprint 17 acceptance

- [ ] Code review and offline unittest/shell syntax checks on exact Sprint 17 branch commit.
- [ ] Codex runs with a reviewed pin manifest on a clean consolidated candidate.
- [ ] Output contains complete and accurate PASS/FAIL/NOT RUN results, hashes and exact commit.
- [ ] Fresh signed test DNA byte-matches an independent rebuild.
- [ ] Local ancestor validation rejects stale/missing/unmerged branch tips.
- [ ] Zero-step GitHub workflow is accurately labelled NOT RUN, with admin follow-up.
- [ ] Source merge/push/production deploy and funded testnet actions remain out of scope.
