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
# Create a reviewed pins JSON outside checkout per docs/SPRINT_17_LOCAL_INTEGRATION.md.

PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/release_acceptance_27.py \
  --expected-sha "$(git rev-parse HEAD)" \
  --pins ../reviewed-integration-pins.json \
  --report-dir ../sprint27-evidence-unique \
  --attempts 120 \
  --enable-fork-lab
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
```

Sprint 22/24 specialized scripts additionally create their own **new sibling evidence directories**; the combined report records their full paths plus cryptographic hashes after validating their internal `SHA256SUMS`, exact-SHA provenance and specialized auditor output. Preserve those referenced sibling bundles alongside the Sprint 27 directory. **A self-reported JSON PASS never substitutes for original signed Holochain records or separate peer validation.**

The machine report uses schema `hc-vtime/sprint27-combined-acceptance/v1`. Each gate has exactly one:
- `PASS`: actually executed and independently checkable by logs/artifact hashes, or proven exact source ancestry.
- `FAIL`: code/test error after execution, timeout, corrupted/missing claimed evidence, unsafe config accidentally accepted, or an invalid provenance assertion.
- `NOT RUN`: missing tool, missing branch integration, no signed fixture, missing reviewed pin, unavailable infrastructure, explicit unsafe-test opt-out or missing authorized financial environment.

The `classification` field further distinguishes `PROVENANCE_FAILURE`, `EXECUTED_FAILURE`, `EXECUTED_TIMEOUT`, `INVALID_EVIDENCE`, `MISSING_TOOL`, `NOT_IN_CANDIDATE`, `OPERATOR_OPT_IN_REQUIRED`, `CI_BEFORE_RUNNER`, `PROTOCOL_INTEGRATION_PENDING` and `EXTERNAL_FINANCIAL_ACCEPTANCE_PENDING`.

Top-level verdicts: `FAIL` if any FAIL; `INCOMPLETE` if no FAIL but any NOT RUN; `LOCAL_TESTS_COMPLETE_NO_RELEASE_APPROVAL` only if every listed local gate PASS (not achievable while oracle runtime and funded Unyt remain not done). Exit codes are 1, 2, and 0 respectively. **`release_ready=false` and `financial_release_allowed=false` in every generated report, always.**

Reviewers should independently re-run `sha256sum -c SHA256SUMS` and the nested Sprint 17/Sprint 21/22/24 checksums; independently inspect signed raw source-chain evidence and negative-case balances where financial correctness is at stake.

## Exact-SHA automated offline adversarial tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest scripts.test_release_acceptance_27 -v
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
