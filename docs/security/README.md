# Sprint 16 — Reproducible security hardening

**Scope:** test-only additions on an independent GitHub branch. No production
cryptographic, integrity-zome or coordinator changes are made here.
**Evidence state:** Rust, fuzz, conductor and dependency-advisory commands
have not been executed by this GitHub agent.

## Files and controls

| Directory | Purpose |
| --- | --- |
| `crates/vtime_core/tests/security_adversarial.rs` | Real deterministic oracle/Roughtime signatures; mutation, replay, duplicate-source, cross-DNA, packet/framing/oversized-set regressions. |
| `integration/security/fixtures/witness_cases.json` | Versioned ten-case malformed/valid witness matrix with expected error messages. |
| `integration/conductor/tests/security_witness.rs` | Run the witness matrix through 3 actual Holochain 0.7.1 conductors and signed test-only DNA. |
| `fuzz/fuzz_targets/roughtime_parser.rs` | libFuzzer: untrusted packet framing, RFC message header, tag/offset parser. |
| `fuzz/fuzz_targets/roughtime_exchange.rs` | libFuzzer: arbitrary request/response split plus verified well-formed request, actual signature-verification path. |
| `scripts/security/make_fuzz_corpus.py` | Deterministic small seed corpus with size/header boundaries; no fake signatures. |
| `scripts/security/inventory.py` | Exact lockfile dependency inventory and source-level unsafe marker heuristic; **not** an advisory scan. |
| `scripts/security/run.sh` | Exact SHA, clean checkout, test-only, fail-closed local runner. Writes logs and checksums outside repository. |
| `docs/security/FINDINGS.md` | Severity, reproduction plan, known unknowns and dependency/Sprint 11 coordination. |

## Local prerequisites

Use a clean, exact-SHA checkout of the Sprint 16 PR. Follow `AGENTS.md`
and the lockfile's Holochain **0.7.1** interface contract; install Python
3.11+, Git, Rust/rustfmt/Clippy and WASM toolchain. For conductor tests the
recommended environment is:

```bash
nix develop "github:holochain/holonix?ref=main-0.7"
git rev-parse HEAD
git status --porcelain
```

For fuzzing install a supported Rust **nightly** and `cargo-fuzz`. The
standalone `fuzz/Cargo.toml` has a separate Cargo dependency graph;
`fuzz/Cargo.lock` is generated locally and ignored by Git. Record its
checksum and tool versions. This means fuzz builds are not yet locked across
machines; pin the resolved fuzz dependencies once validated, separately from
the production workspace.

## Deterministic regressions and inventory

```bash
SHA="$(git rev-parse HEAD)"
python3 -m unittest discover -s scripts/security -p 'test_*.py' -v
cargo fmt --all -- --check
cargo test --workspace --locked -p vtime_core --test security_adversarial -- --nocapture
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 scripts/security/inventory.py \
  --expected-sha "$SHA" --out "../security-inventory-${SHA:0:12}.json"
```

The `security_adversarial` test uses deterministic test keys only and
exercises 64 oracle signature byte mutations, every non-frame Roughtime
response byte mutation, two replay classes, duplicate-source checks, foreign
DNA binding, 33-item budget and pre-crypto packet rejection.

## Real conductor witness matrix

First run the existing trusted **test-fixture creation** path. It builds
WASM, generates a manifest with public test-only keys, packs a disposable
`vtime.dna`, and records its output directory:

```bash
export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
bash scripts/run_signed_quorum.sh

# Replace with the *actual* output directory printed by that script.
export HC_VTIME_TEST_DNA="/absolute/signed-run-report/vtime.dna"
export HC_VTIME_SIGNED_TEST_ONLY=1
cargo test --manifest-path integration/conductor/Cargo.toml --locked \
  --test security_witness -- --nocapture
```

Do not supply production, publicly deployed, funded or previously trusted DNA
keys. All ten fixtures must execute: **one** accepted control, **nine**
specific rejection reasons. Generic failures, runner startup errors,
unavailable dependencies or timeouts do not count as successful rejection.

## Roughtime libFuzzer runs

Generate deterministic initial seeds **outside** the repository:

```bash
python3 scripts/security/make_fuzz_corpus.py --out "../hc-vtime-fuzz-corpus-$SHA"
cargo +nightly fuzz list
cargo +nightly fuzz run roughtime_parser "../hc-vtime-fuzz-corpus-$SHA/roughtime_parser" -- \
  -max_total_time=120 -max_len=65536
cargo +nightly fuzz run roughtime_exchange "../hc-vtime-fuzz-corpus-$SHA/roughtime_exchange" -- \
  -max_total_time=120 -max_len=65536
```

Keep crash artefacts and newly discovered corpus inputs outside the repo, and
record SHA-256, CLI nightly/libFuzzer versions and seed. A sanitizer/fuzz
failure must be minimized and reproduced in a deterministic Rust regression.
A two-minute run is a *starting exercise*, not proof of absence of bugs.
Signed evidence is separately validated by deterministic tests.

## Combined full runner and evidence

After building a genuine **test-only** signed DNA, run the combined suite:

```bash
SHA="$(git rev-parse HEAD)"
bash scripts/security/run.sh \
  --dna "/absolute/signed-run-report/vtime.dna" \
  --expected-sha "$SHA" --fuzz-seconds 120
```

This executes offline Python tests, formatting, native security tests,
workspace Rust tests, Clippy, the signed conductor witness matrix, dependency
inventory, corpus generation, and both fuzz targets. Each step logs a distinct
exit status. The runner does not silently convert an unavailable tool,
wrong expected rejection, timeout, compiler error, or missing conductor DNA
to a PASS. Report directory and `SHA256SUMS` are outside the source checkout.
Inspect generated logs for host-specific paths/tokens before sharing.

The combined runner does not create the test DNA itself; that is a separate
cryptographic trust boundary. A complete acceptance record also requires
packaged WASM checks, `cargo audit` with an up-to-date advisory DB, the
integrated Sprint 11+12+13+15 branches tested by Codex, and a human review of
any confirmed findings. Do not claim independent external time sources or
production approval from local signatures.

**No release approval:** Sprint 16 remains draft pending integrated local
acceptance, external source proof and security review.
