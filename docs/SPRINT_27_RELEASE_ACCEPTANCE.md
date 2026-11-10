# Sprint 27 — Combined release acceptance and evidence

**Agent Q — Integration/release engineering | Priority: CRITICAL | Status: GitHub-first implementation.**

**Release verdict: NO-GO regardless of local results.** This runner reports what actually executed and identifies remaining operator/security/economic dependencies. It never merges, deploys, edits signing keys, creates testnet funds, or approves a production release.

## Review of existing tools (10 November 2026)

Do **not** replace proven Sprint 17 checks with ad-hoc simulations. `scripts/integration_validate.py` already enforces one full commit SHA, a clean non-shallow Git clone, independently reviewed branch pins, Cargo.lock provenance, Python suites, root and independent conductor rustfmt, locked Rust tests, all-target Clippy, both HDK/HDI 0.7 WASMs, **actual signed test-only three-conductor quorum**, and a byte-for-byte second DNA repack. Sprint 27 runs and verifies that report, including native logs, exact commit, provenance, signed test DNA and WASM magic bytes/hashes.

Additional isolated runners currently exist on **separate, unmerged sprint branches**; they may only be counted if their code is present **in the tested candidate commit**:

| Requirement | Existing implementation | Sprint 27 policy |
| --- | --- | --- |
| Exact commit and reviewed ancestry | Sprint 17 `scripts/integration_validate.py` | FAIL on dirty/mismatched HEAD, missing pins NOT RUN |
| Root Rust, fmt, Clippy and WASM | Sprint 17 | Import the actual stage exit/log+SHA. Recheck both WASM artifacts |
| Fresh DNA | Sprint 17 `scripts/repack_test_dna.py` | Require two byte-identical packed bundles on the exact SHA |
| Real signed quorum | Sprint 17 `scripts/run_signed_quorum.sh` | Require signed-quorum and smoke exit zero, provenance, native logs, fixture DNA |
| Configuration safety | Sprint 20 `scripts/deployment_preflight.py` | Execute adversarial Python suite AND prove tracked invalid production example returns BLOCKED |
| Conductor restart/rejoin | Sprint 12 `integration/conductor/tests/resilience.rs` | Actual native Holochain test invocation; require named executed successes |
| Fork/warrant | Sprint 22 `scripts/run_fork_recovery.sh` | Run **full** opt-in same-agent fork lab; require positive actual warrant and audit `FORK_WARRANT_RESTART_PASS`. A baseline run is NOT a warrant pass |
| 100+ successful seals | Sprint 21 `scripts/load/run_21.py` | 120 default concurrent caller attempts; require >=100 distinct successful action hashes and >=12 third-party verifications, raw CSV, full native report |
| Durable native oracle journal | Sprint 24 `scripts/oracle_state/run.sh` | Require actual process-kill/restart/signing replay tests and `LOCAL_PERSISTENCE_REGRESSION_PASS` on same commit |
| Oracle runtime restart/replay | Sprint 24 *not yet integrated with live oracle key service* | Always NOT RUN pending real runtime antirollback and crash/replay integration |
| Funded Unyt outcomes | Sprint 26 candidates #62/#63 and Sprint 14A | Always NOT RUN pending authorized *native* funded agreement execution, distinct recipient Accept and independent review |

**Important:** Sprint 21/22/23/24/25/26 branches are under independent development/review. Sprint 27 does not merge them. Until selected and consolidated, missing runners are `NOT_IN_CANDIDATE`; they are not evidence of broken code, and their earlier branch-local tests cannot be reattributed to a new SHA. Likewise, Sprint 17's deterministic fixture keys are **publicly known and insecure**; their passing quorum demonstrates cryptographic integration on disposable conductors, NOT independently operated external Roughtime infrastructure.

## One combined command: exact final integration candidate

After local Codex independently reviews, selects and integrates required branches in a single clean checkout, fetches and pins their *exact* tip SHAs:

```bash
git fetch origin --prune
git rev-parse HEAD                     # full 40-character reviewed candidate commit
git status --porcelain --untracked-files=all
# Consolidate and commit all seven authoritative PR tips, then pin live GitHub HEADs:
python3 -B scripts/make_reviewed_pins_27.py \
  --expected-sha "$(git rev-parse HEAD)" \
  --output ../reviewed-integration-pins.json

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/release_acceptance_27.py \
  --expected-sha "$(git rev-parse HEAD)" \
  --pins ../reviewed-integration-pins.json \
  --report-dir ../sprint27-evidence-unique \
  --attempts 120
```

**`--enable-fork-lab` is an explicit acknowledgement for the Sprint 22 same-agent test-only fork experiment.** Never run it on production conductors, real oracle keys, or public DNA. Without the flag, fork/warrant is `NOT RUN/OPERATOR_OPT_IN_REQUIRED`. If Sprint 22 is not integrated, it is `NOT RUN/NOT_IN_CANDIDATE` regardless of flag.

`--ci-run-id <run>` optionally asks Sprint 17's GitHub auditor to inspect exact-commit Actions metadata. Jobs with **zero executed steps / before runner assignment** are `NOT RUN / CI_BEFORE_RUNNER`; they are not a compiler or test failure. Missing `gh`, unavailable CI, and incomplete/pending jobs are also NOT RUN. A locally executed failure is `FAIL / EXECUTED_FAILURE`. Never infer test success from a green GitHub check status without executed steps verified on exact SHA.

`--unyt-evidence /secure/local/evidence-index.json` can associate a local file SHA-256 with the report, but **cannot** authenticate its contents or mark funded transfers PASS. Native Unyt validation and independent review must be recorded separately; no private keys, seed phrases, keystores or funded API tokens belong in a checked-in or CI job.

The pinned manifest must have Sprint 17's `hc-vtime/integration-pins/v1` schema and contain the candidate SHA, reviewed baseline main SHA, and exact `origin/<branch>` tip SHAs. A moving branch name is not an acceptance identity. Missing `--pins` prevents Sprint 17 core execution; it is `NOT RUN/MISSING_REVIEWED_PINS`, **not** PASS.

### Reproducibility and output

A new directory **outside Git** is required. The runner refuses overwrites, sets output dir to mode 0700, never invokes shell with untrusted text, and does not edit main or start production installations. It produces:

```text
sprint27-evidence-unique/
  report.json                   exact-SHA, source provenance, every gate status and blocker
  report.md                     readable PASS/FAIL/NOT RUN table and blocker reasons
  SHA256SUMS                    every bundled evidence file except itself
  sprint17_entrypoint.log
  sprint17/
    report.json, report.md, SHA256SUMS
    native_tests.log, clippy.log, wasm.log, signed_conductor.log, fresh_dna.log, ...
    signed/                      signed fixture + original packaged vtime.dna
    fresh-dna/                   independently repacked byte-equal DNA
  config_tests.log
  config_invalid_example.log
  restart_recovery.log
  fork_warrant.log              available only if Sprint 22 script present and opted in
  concurrent_seals.log          available only if Sprint 21 script present
  throughput/                   raw per-attempt CSV and signed-fixture report
  oracle_journal.log            available only if Sprint 24 script present
  roughtime_offline.log         Sprint 23 offline Python/Rust/compile-only
  monitoring_offline.log        Sprint 25 privacy/ops Python suites
  unyt_offline.log              Sprint 26 offline signed-proof/audit runner
```

Sprint 22/24/26 specialized scripts additionally create their own **new sibling evidence directories**; the combined report records their full paths plus cryptographic hashes after validating their internal `SHA256SUMS`, exact-SHA provenance and specialized auditor output. Preserve those referenced sibling bundles alongside the Sprint 27 directory. **A self-reported JSON PASS never substitutes for original signed Holochain records or separate peer validation.**

The machine report uses schema `hc-vtime/sprint27-combined-acceptance/v1`. Each gate has exactly one:
- `PASS`: actually executed and independently checkable by logs/artifact hashes, or proven exact source ancestry.
- `FAIL`: code/test error after execution, timeout, corrupted/missing claimed evidence, unsafe config accidentally accepted, or an invalid provenance assertion.
- `NOT RUN`: missing tool, missing branch integration, no signed fixture, missing reviewed pin, unavailable infrastructure, explicit unsafe-test opt-out or missing authorized financial environment.

The `classification` field further distinguishes `PROVENANCE_FAILURE`, `EXECUTED_FAILURE`, `EXECUTED_TIMEOUT`, `INVALID_EVIDENCE`, `MISSING_TOOL`, `NOT_IN_CANDIDATE`, `OPERATOR_OPT_IN_REQUIRED`, `CI_BEFORE_RUNNER`, `PROTOCOL_INTEGRATION_PENDING` and `EXTERNAL_FINANCIAL_ACCEPTANCE_PENDING`.

The legacy `overall` remains `INCOMPLETE` when external gates are NOT RUN, even if the separate development verdict is READY. Exit codes now follow `development_integration_verdict`: `0` READY, `1` FAILED, `2` INCOMPLETE. `production_release_verdict` is always `NO-GO`. **`release_ready=false` and `financial_release_allowed=false` in every generated report, always.**

Reviewers should independently re-run `sha256sum -c SHA256SUMS` and the nested Sprint 17/Sprint 21/22/24 checksums; independently inspect signed raw source-chain evidence and negative-case balances where financial correctness is at stake.

## Exact-SHA automated offline adversarial tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s scripts -p 'test_release_acceptance_27.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
```

The Sprint 27 tests exercise fabricated PASS records, missing core logs, fake DNA repacks, missing executed restart tests, baseline-only forks, fewer than 100 seals, wrong commit throughput, orphan journal proof, mutated checksum reports, and unsafe configuration acceptance. Tests use **mock input**, not real conductor, ledger, or CI execution. Rust/WASM/signed quorum remain run by the unified acceptance entrypoint on Codex's integrated machine.

## Release blocker tracking and closure criteria

`report.json.release_blockers[]` enumerates every non-PASS gate, links to parent GitHub issues, classifies CI separately, and appends the required independent security/economic signoff. It never hides the outstanding issues simply because native Cargo passes.

| Blocker | Why it stays open |
| --- | --- |
| #22 | Actions jobs failing before runner assignment yield no CI test evidence |
| #5 | At least 100 successful real simultaneous caller seals required; Sprint 13 had high source-chain contention |
| #7 | Full conductor restart, real fork/warrant, partition/rejoin and independent witness security |
| Sprint 21/22/24 branches | Integration into ONE tested exact final SHA and native reports not established by separate PR existence |
| Sprint 23 | Real independent Roughtime operator/control and fresh signed packets not proven by test-only keys |
| #61, Sprint 26 | Financial target/replay/expiry contract not closed; no authorized funded Unyt RAVEs/recipient Accepts |
| #1 | Independent security/economic review and release authorization outstanding |

**Approval order:** consolidate/review candidate → execute entire suite on a clean exact SHA → verify checksum inventories → independently review original native conductor and Unyt evidence → resolve protocol/economic blockers → separately authorize a release. Neither this sprint nor any green local test can skip the last gates.


## Sprint 27 Codex handoff: authoritative branches and two verdicts

The 10 November 2026 original main baseline is **cd0fae92929c9c56fc5e6b099ef2ad09ac70c2ad**. Required candidate ancestors, pinned to their *latest live GitHub PR HEADs* at manifest-generation time, are:

| PR | Sprint | Authoritative source branch | 10 Nov observed HEAD (snapshot, re-fetch) |
| --- | --- | --- | --- |
| #56 | 22 | sprint/22-fork-recovery-2026-11-09 | 678216023796b70d4439f0468c9b9e4d0a8388be |
| #57 | 21 | sprint/21-seal-throughput-queue-2026-11-09 | d51065bc5994f19102a4bf887bfc132d5603a96f |
| #58 | 23 | sprint/23-independent-roughtime-acceptance-2026-11-10 | 78fd8447cc744bf6f78ca25e116724e91d0024a0 |
| #59 | 24 | sprint/24-oracle-persistence-restart-2026-11-10 | 6a3a9dc80ab64720670f095fe130c12ca78a9a19 |
| #64 | 25 | sprint/25-operations-monitoring-2026-11-10 | b230375c64715366d853e4dba7784eb4f543f06f |
| #63 | 26 | sprint/26-unyt-financial-integration-2026-11-10 | ffad4ce70e2c15d3c4143b751e85647b19bf4533 |
| #65 | 27 | sprint/27-combined-acceptance-2026-11-10 | MOVING; fetch live PR HEAD |

Alternative PR **#60** supplied monitoring review fixes reconciled into #64; **#62** was the closed alternative reconciled into #63; **#50** is the earlier Sprint 14A financial alternative. Record them as review dispositions, **not mandatory ancestors**. The new pin helper writes review_disposition metadata separately and refuses to include these three as mandatory sprint ancestors.

**Toolchain:** a clean, full (non-shallow) Git clone; authenticated GitHub CLI (gh) for fresh PR metadata; Git, Bash, Python 3, Rust cargo/rustc/rustfmt/clippy, rustup wasm32-unknown-unknown target, GNU sha256sum, uname, Holochain 0.7.1-compatible hc and conductor test environment, and the Python msgpack + cryptography dependencies expected by Sprint 26. The source pins HDK =0.7.1, HDI =0.8.1 and Cargo.lock; do not invent a Rust compiler version, record what actually executes. The standalone conductor has an independent Cargo workspace. Linux/Holonix-like tooling and sufficient RAM/disk are recommended.

**Order:** (1) integrate selected PR heads and commit one candidate on a non-main branch; (2) refresh origin refs and run the live-PR-head pin generator; (3) run Sprint 17 exact source, ancestry, Python, formatting, locked Rust, Clippy, WASM, signed-quorum and independent fresh DNA checks; (4) run Sprint 20 invalid-production configuration rejection; (5) run the Sprint 23, Sprint 25 and Sprint 26 offline scripts, recording their own executed suites; (6) run three-conductor restart, Sprint 21 concurrent seals and Sprint 24 persistence journal serially; (7) optionally run the destructive Sprint 22 same-agent fork lab ONLY with explicit opt-in; (8) inspect all checksum inventories and external release blockers. Sprint 21's internal simultaneous caller test is deliberately concurrent; the expensive runner invocations are serial.

**Reproducible candidate command** (the manifest is written outside the checkout):

~~~bash
git fetch origin --prune
git status --porcelain --untracked-files=all   # MUST be empty
FULL_SHA="$(git rev-parse HEAD)"
python3 -B scripts/make_reviewed_pins_27.py \
  --expected-sha "$FULL_SHA" \
  --output ../reviewed-integration-pins.json
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/release_acceptance_27.py \
  --expected-sha "$FULL_SHA" \
  --pins ../reviewed-integration-pins.json \
  --attempts 120 \
  --report-dir ../sprint27-final-evidence-unique
# ONLY on disposable test DNA: append --enable-fork-lab if authorized.
(cd ../sprint27-final-evidence-unique && sha256sum -c SHA256SUMS)
~~~

**Manifest example** (deliberately invalid placeholder SHA fields; helper must populate real current HEADs):

~~~json
{
  "schema": "hc-vtime/integration-pins/v1",
  "candidate_sha": "FULL_FINAL_40_HEX_COMMIT_SHA",
  "base": {"branch": "main", "sha": "cd0fae92929c9c56fc5e6b099ef2ad09ac70c2ad"},
  "branches": [
    {"branch": "sprint/22-fork-recovery-2026-11-09", "sha": "LIVE_56_SHA"},
    {"branch": "sprint/21-seal-throughput-queue-2026-11-09", "sha": "LIVE_57_SHA"},
    {"branch": "sprint/23-independent-roughtime-acceptance-2026-11-10", "sha": "LIVE_58_SHA"},
    {"branch": "sprint/24-oracle-persistence-restart-2026-11-10", "sha": "LIVE_59_SHA"},
    {"branch": "sprint/25-operations-monitoring-2026-11-10", "sha": "LIVE_64_SHA"},
    {"branch": "sprint/26-unyt-financial-integration-2026-11-10", "sha": "LIVE_63_SHA"},
    {"branch": "sprint/27-combined-acceptance-2026-11-10", "sha": "LIVE_65_SHA"}
  ],
  "review_disposition": [
    {"pr": 60, "disposition": "reviewed into #64, not mandatory"},
    {"pr": 62, "disposition": "alternate financial review, not mandatory"},
    {"pr": 50, "disposition": "earlier financial alternative, not mandatory"}
  ]
}
~~~

The manifest helper fetches live pull metadata for each PR via authenticated GitHub API, refreshes origin tracking, rejects remote tip/PR HEAD mismatches, and requires every selected tip (and original main baseline) to be a true ancestor of the final candidate commit. It exits **3** on invalid or stale provenance and **0** only after writing a reviewed external mode-0600 manifest. Sprint 17 independently verifies that the origin tracking refs still equal those pins and all are ancestors. If a PR moves, re-fetch, re-review, re-consolidate, recommit, recreate the manifest and rerun.

### Development integration versus production release

The machine report now has **development_integration_ready** (boolean), **development_integration_verdict** (READY / FAILED / INCOMPLETE), **development_blockers**, **production_release_ready** (always false), **production_release_verdict** (always NO-GO), **release_blockers**, and **external_acceptance**.

Development readiness requires executed PASS (or actual source/ancestry proof) for precisely these **17** applicable gates: source, reviewed_ancestry, python_tests, rust_format, conductor_format, rust_tests, clippy, wasm, signed_quorum, fresh_dna, config_negative, restart_recovery, concurrent_seals, oracle_journal, roughtime_offline, monitoring_offline, unyt_offline. Any required local FAILURE means FAILED; missing or unexecuted means INCOMPLETE. A failed *executed* opt-in fork lab also blocks development; an opt-out does not claim real warrant acceptance. Optional CI evidence remains separately classified.

Offline Sprint 23 success is only signed-time policy/crypto/compile evidence, not live independent-source or one-source-outage acceptance. Offline Sprint 25 success is only probe/monitor/privacy testing, not authenticated live telemetry, operator compromise detection or incident drill acceptance. Offline Sprint 26 checks executed negative signed-proof tests and audit stage exit codes, not actual funded Unyt alliance settlement. No JSON attestation can establish a native RAVE plus separate recipient Accept and independent peer check. External acceptance requires human-reviewed signed independent-source captures, real oracle runtime restart/replay with external anti-rollback, approved production configuration, funded native network acceptance and independent security/economic signoff.

The existing aggregate **overall** remains INCOMPLETE if release-only gates are NOT RUN, even when **development_integration_ready=true**. Both release_ready and financial_release_allowed remain false. This is intentional, not a failed local development verdict.

**Sprint 27 process exit codes:** 0 = development READY; 1 = failed required local test / invalid evidence / executed failed opt-in fork; 2 = incomplete applicable development gates. A failed final evidence write also exits 1. **Production verdict: NO-GO in all cases.**

**Resource policy:** Run Sprint 17 once, then specialized scripts sequentially. Reuse normal Cargo build objects only when exact same checkout, input fingerprints, flags and profile make them identical. Cargo's incremental caching is not evidence a test executed. Do not optimize away distinct Sprint 23/26 scripted tests, independent second DNA repack, or real conductor tests. Do not transfer a prior commit's PASS. This runner does not run funded network activity, deploy an oracle or create signed production credentials.

**Execution limitation:** PR-hosted code changes here have not run Rust, WASM or actual Holochain conductors. Only the final local Codex checkout can provide exact-commit development acceptance. No production-ready declaration or GitHub Actions green claim is permitted without actual executed evidence.
