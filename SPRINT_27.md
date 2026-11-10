# Sprint 27 — Combined release evidence and validation

**Agent Q | Priority CRITICAL | 10 November 2026**
**Status: implementation prepared; exact-commit integrated acceptance NOT RUN. Production NO-GO.**

## Delivered

- `scripts/release_acceptance_27.py` — one-command exact-SHA orchestration of existing Sprint 17 release validation plus configuration rejection, real signed-conductor restart/rejoin, opt-in real warrant/fork test, >=100 successful concurrent seal acceptance, native oracle journal recovery, and explicit pending runtime/Unyt gates.
- `scripts/test_release_acceptance_27.py` — adversarial mock-based report and evidence classification tests, including forged PASS records, mismatched SHA, no real warrant, insufficient real seals, incomplete DNA, missing recipient-independent evidence, and tampered checksum manifests.
- `docs/SPRINT_27_RELEASE_ACCEPTANCE.md` — operator runbook, machine report contract, exact-commit provenance, artifact layout, safety and exception classification.

## Two-stage local Codex command (only after reviewed consolidation)

```sh
python3 -B scripts/make_reviewed_pins_27.py \
  --expected-sha "$(git rev-parse HEAD)" \
  --output ../reviewed-integration-pins.json
python3 -B scripts/release_acceptance_27.py \
  --expected-sha "$(git rev-parse HEAD)" \
  --pins ../reviewed-integration-pins.json \
  --attempts 120 \
  --report-dir ../sprint27-final-evidence-unique
```

The pin helper fetches current GitHub HEADs for authoritative PRs #56/#57/#58/#59/#64/#63/#65, checks stale remote tracking refs and every tip in the exact candidate ancestry. It records PR #60/#62/#50 as superseded or alternatives, not mandatory ancestors. The destructive same-agent fork lab is opt-in only: add --enable-fork-lab on disposable test DNA. This must be executed by Codex on ONE clean integration candidate with a compatible Holochain 0.7 toolchain, working Cargo/WASM/hc and true signed test-only conductor fixture. `--enable-fork-lab` permits **only** disposable same-key test DNA experiments; do not run against production or mainnet.

The generated `report.json` and `SHA256SUMS` are tied to the exact reviewed Git commit, with native stage logs and artifact digests. `PASS` requires executed evidence; `FAIL` means a real failure, timeout or invalid evidence; `NOT RUN` means no execution, missing tool, missing integrated runner, or deferred/unsafe external gate. GitHub Actions failing before any runner step is `NOT RUN`, not failed application code.

## Development integration vs production release

The report now contains development_integration_ready, development_integration_verdict (READY/FAILED/INCOMPLETE), development_blockers, production_release_ready (always false), production_release_verdict (NO-GO), release_blockers, external_acceptance and tool_versions. Required development gates: exact clean source, all seven branch pins, Sprint 17 Python/Rust/fmt/Clippy/WASM/signed-quorum/fresh DNA, negative production config, restart/rejoin, >=100 signed successful seals, native journal recovery, and dedicated offline Sprint 23/25/26. A real required local failure blocks readiness; an unexecuted PASS is rejected. The overall aggregate may remain INCOMPLETE because funded Unyt and deployed runtime are release-only, even while development is READY.

Sprint 23: bash scripts/roughtime/check_23.sh; Sprint 25: bash scripts/ops/check_25.sh; Sprint 26: bash scripts/unyt/run_sprint26.sh --expected-sha FULL_SHA. Execute serially on the same candidate. Rust artifacts may be cached by Cargo on identical source/flags; never recycle test results between commits. Production independent Roughtime, external anti-rollback, approved production configuration, real fork/warrant, authenticated live metrics, funded RAVE + separate Accept and security/economic review remain release blockers.

Exit codes for the combined runner: 0 development READY, 1 development FAILED, 2 development INCOMPLETE. Pin helper exits 3 on stale, wrong or missing authoritative ancestry. No merge or production promotion.

## Unverified or blocked as of this draft

| Gate | State | Why |
| --- | --- | --- |
| Sprint 27 unit tests | NOT RUN | GitHub-writing agent cannot execute checkout; expanded mock regressions committed, must execute on Codex |
| Full Rust fmt/test/clippy | NOT RUN | Exact combined final candidate not locally tested |
| WASM and fresh DNA | NOT RUN | Actual Holonix toolchain and final commit run required |
| Signed quorum | NOT RUN | Must rerun on final SHA (earlier Sprint 17 results not transferable) |
| Restart/rejoin | NOT RUN | Final candidate needs actual three-conductor run |
| Fork/warrant | NOT RUN | Sprint 22 on separate draft; opt-in, real positive DHT warrant required |
| >=100 concurrent seals | NOT RUN | Sprint 21 on separate draft; do not use old 3/120 Sprint 13 baseline as pass |
| Native journal crash/replay | NOT RUN | Sprint 24 on separate draft; native tests not deployed runtime |
| Sprint 23 Roughtime offline | NOT RUN | Requires exact integrated candidate and executed standalone offline suite |
| Sprint 25 monitoring offline | NOT RUN | Requires exact integrated candidate and executed privacy/ops suites |
| Sprint 26 Unyt offline | NOT RUN | Requires exact integrated candidate and signed-proof/native audit tests |
| Actual oracle signer restart and replay | NOT RUN | Durable journal/runtime adapter not integrated or independently verified |
| Production config safety | NOT RUN | Negative tests and documented production example rejection must execute |
| Unyt funded agreement | NOT RUN | Authorized native RAVE, distinct recipient Accept and peer state needed |
| Independent review | NOT RUN | Security, economic and production decisions remain separate |

GitHub Actions runner incident #22 is infrastructure, not source validation. Protocol blocker #61 includes target-bound Unyt proof, one-use replay policy and release agreement expiry. Master release gate #1 remains NO-GO.

**Do not merge or present a green Python/mock report as Holochain conductor acceptance, funded Unyt settlement or production readiness.**
