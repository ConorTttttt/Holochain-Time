# Sprint 18 — Evidence interoperability and compatibility

**Current status:** protocol-level fixtures and regression harness prepared
on GitHub; Rust/Clippy/WASM/conductor acceptance evidence remains pending.

## Deliverables

- `integration/interop/wire.rs`: **proposed** v1 typed, byte-preserving
  MessagePack envelope. Compiled and exercised by
  `crates/vtime_core/tests/evidence_interop.rs`; not linked into production
  coordinator/integrity code or adopted as a deployed API.
- `integration/interop/fixtures/v1_oracle.json`: canonical, Python-signed
  oracle envelope, SHA-256 of envelope and existing v2 signing bytes.
- `integration/interop/fixtures/roughtime_rfc_v1.json`: valid RFC 10049
  request/response plus seven deterministic invalid-case recipes.
- `scripts/interop/generate_vectors.py`: independently regenerates canonical
  fixtures using Python `msgpack` + Ed25519 from `cryptography`.
- `scripts/interop/verify_vectors.py`: independent Python-side signed oracle
  and RFC Roughtime fixture checker, including negative cases.
- `crates/vtime_core/tests/evidence_interop.rs`: direct-core vs versioned
  envelope verdict equivalence (signed oracle, RFC Roughtime, mixed policy),
  13 real Roughenough reference-server Merkle exchanges, unsupported versions,
  unknown fields, byte tampering, replay and truncated/malformed binary input.
- `scripts/interop/run.sh`: exact-SHA test evidence with failures and
  checksums, outside the repository.

Read [SPEC_V1.md](SPEC_V1.md) before considering adoption. Unknown fields
are rejected, not treated as a flexible extension point. No current
Holochain DNA entry type or signing rules are changed.

## Quick native test and independent Python checks

Use a clean checkout at the exact PR SHA. Holochain 0.7.1 dependencies are
pinned in `Cargo.lock`. Python fixture regeneration requires these **test
dependencies**, not production dependencies (a temporary venv is recommended):

```bash
python3 -m venv /tmp/hc-vtime-interop-venv
. /tmp/hc-vtime-interop-venv/bin/activate
python3 -m pip install 'msgpack==1.1.2' 'cryptography==46.0.4'
python3 scripts/interop/generate_vectors.py --check
python3 scripts/interop/verify_vectors.py

cargo test --locked -p vtime_core --test evidence_interop -- --nocapture
cargo test --locked -p vtime_core --test roughenough_interop -- --nocapture
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

These commands must be run on the exact integrated SHA. A Python PASS is
not evidence the Rust verifier or real conductor passed.

## Repeated, source-pinned acceptance

To create a **test-only**, signed DNA (public fixture keys; never deploy):

```bash
export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
bash scripts/run_signed_quorum.sh
```

The existing runner prints its report directory and retains `vtime.dna`.
Use that actual path for full interoperability acceptance:

```bash
SHA="$(git rev-parse HEAD)"
bash scripts/interop/run.sh --expected-sha "$SHA" \
  --signed-dna "/actual/test-only-report/vtime.dna"
```

When a test-only DNA is unavailable, the runner can produce **partial**
native evidence, explicitly labelled as missing host acceptance:

```bash
bash scripts/interop/run.sh --expected-sha "$(git rev-parse HEAD)" --core-only
```

The runner verifies exact SHA and clean checkout, logs Python vector
regeneration, Python verification, Rust formatting, native interop and
Roughenough suites, whole workspace tests/Clippy, and optionally the
existing signed three-agent conductor suite. Logs, `results.tsv`,
`provenance.txt` and `SHA256SUMS` are written **outside the checkout**.
A nonzero stage does not disappear from the summary; the runner exits nonzero
if any step fails.

Replaying a committed signed fixture does not make its source independent.
Reference Roughenough local responses and Python-generated signatures are
compatibility probes, not real multi-operator production acceptance.

## Acceptance decision and integration

Sprint 18 is accepted only after a reviewed exact-SHA run has passed the
canonical cross-language vector check, Rust native suite, reference
Roughenough tests, full regression suite, and actual signed conductor
validation. Codex must rerun after Sprints 11/12/13/15/16 integration,
review relevant changed crypto interfaces, and ensure the envelope **never**
alters signed bytes, proof binding or unknown-version rejection.

Production activation of the envelope is **not included in this sprint**:
that needs an API/ADR, DNA/storage compatibility review, and coordination
with Sprint 11. Release remains **NO-GO** pending independent-source and
wider acceptance.
