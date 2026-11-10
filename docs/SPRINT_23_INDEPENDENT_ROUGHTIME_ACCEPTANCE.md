# Sprint 23 — Independent Roughtime acceptance

**Agent M · Critical release gate · 10 November 2026**

**Status:** GitHub implementation and regression tests prepared. There are NO accepted three-independent-operator live receipts or real Holochain acceptance test logs in this branch. Separate public-key test signers demonstrate protocol cryptography; they do NOT establish independent real-world operators.

## Security scope and source ownership

RFC 10049 Roughtime authenticates an operator's long-term Ed25519 key, signed delegation, signed SREP, nonce and Merkle inclusion path. Sprint 11 already implemented these checks and a real UDP client in crates/vtime_core/examples/roughtime_independent.rs. Sprint 23 builds on this implementation: **no changes to production integrity validation, signature algorithms, consensus, or minimum quorum.** The existing native client now emits a structured HC_RT_VERIFIED record showing the authenticated source intervals for subsequent, independent auditing.

The pinned public candidate registry lives at config/roughtime-independent-sources.json. The companion, intentionally **not approved** operator infrastructure dossier lives at config/sprint23-operator-dossier.example.json. The dossier enumerates owner assertions, endpoint, public key source of record, protocol compatibility and potential common hosting/control/upstream dependencies.

Cloudflare's registered legacy draft11 endpoint is currently incompatible with the RFC10049/draft15 verifier; do not count it unless the service produces a verifiable supported response and the dossier is updated. The other four entries are protocol-compatible *candidates*, not four proven live responders or genuinely independent administrators. No fallback to unsigned NTP, public test keys or untrusted Holochain oracle witnesses is allowed.

**Three different public keys, hostnames, IP addresses and operator labels do not prove three administratively independent signing authorities.** Independent reviewers must directly authenticate each root and verify administrative control, hosting/shared infrastructure, upstream time sources, supported protocol, currently reachable endpoints and root rotation/revocation procedures. The automated outputs always state operator_independence_proven=false, even if dossier review checkboxes are populated.

The configured quorum is immutable in the Sprint 23 helper: min_sources=3; max_faulty=1; max_unavailable=1. At least **four eligible independently reviewed signing roots** are required to allow one outage and still acquire three real signed responses. Another outage or a protocol-incompatible service means the quorum cannot be obtained and the run must fail; there is never an automatic downgrade to two.

## GitHub deliverables

| Item | Implementation |
| --- | --- |
| Configurable real UDP Roughtime client | Existing Sprint 11 native client, orchestrated by scripts/roughtime/accept.py |
| Authenticated key registry + operator dossier | Sprint 11 source registry plus config/sprint23-operator-dossier.example.json |
| Signed capture and offline verification | accept.py capture/verify; original request and response frames, native authentication, SHA-256 evidence |
| Signature/delegation/nonce/Merkle verification | Existing Rust vtime_core verifier; no Python cryptography imitation |
| Three-source and one-outage tests | Native test crate and opt-in real Sweettest; outage operator skipped without changing trusted keys |
| Wrong DNA/target and forged packet tests | crates/vtime_core/tests/roughtime_acceptance.rs and integration/conductor/tests/live_roughtime.rs |
| Duplicate operator/root rejection | Registry/dossier binding, native independent-source policy and conductor assertions |
| Reproducible reports | Full commit, registry/dossier/DNA/receipt digests, archived raw bytes, failure logs, SHA256SUMS |
| Replay/freshness policy | Offline cryptographic re-verification permissible; optional local SQLite one-time consumption claims (not a global replay guarantee) |

## Step 1 — Offline validation

From a clean, exact-commit checkout with Rust/Holochain-compatible toolchain:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/roughtime -p 'test_*.py' -v
    cargo test -p vtime_core --test roughtime_acceptance --locked
    cargo test -p vtime_core --test independent_sources --locked
    cargo test -p vtime_core --test roughenough_interop --locked
    cargo fmt --all -- --check

Alternatively run: bash scripts/roughtime/check_23.sh

This exercises genuine **synthetic** Roughenough Ed25519 packets with deterministic public test seeds. It is not evidence of external operator independence or a live Holochain result. A zero-step GitHub Actions failure is NOT RUN, not a Rust failure.

## Step 2 — Pin operator identities and probe external UDP

Set the exact commit and a truly **out-of-band reviewed** registry fingerprint. A digest calculated from the same local mutable registry without independent review is not an authenticated trust anchor.

    export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
    export RT_REGISTRY="config/roughtime-independent-sources.json"
    export RT_DOSSIER="config/sprint23-operator-dossier.example.json"
    export PINNED_RT_REGISTRY_SHA256="<out-of-band approved 64-hex SHA-256>"

    python3 scripts/roughtime/accept.py audit \
      --registry "$RT_REGISTRY" \
      --dossier "$RT_DOSSIER" \
      --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256"

For a **real** target action, provide the raw 39-byte DNA hash and 39-byte target ActionHash as exactly 78 lowercase hexadecimal characters. These are NOT the displayed Holochain base64url hashes; extract the authoritative get_raw_39() bytes. The live conductor harness in step 3 performs this extraction itself.

    python3 scripts/roughtime/accept.py capture \
      --registry "$RT_REGISTRY" \
      --dossier "$RT_DOSSIER" \
      --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256" \
      --expected-sha "$HC_VTIME_EXPECTED_SHA" \
      --dna-hex "<78 lowercase hex DNA bytes>" \
      --target-hex "<78 lowercase hex target bytes>" \
      --report-dir "../sprint23-capture-unique"

This invokes the real Rust UDP client, captures every operator's attempted response and any errors, then runs the **same native strict verifier on the stored signed wire bytes** using the original pinned registry. It preserves source packet bytes, attempt outcomes, native verified time intervals, exact commit and SHA256SUMS. A status like CRYPTO_PASS_REVIEW_PENDING means **cryptographically verified from configured candidates, not independent acceptance**.

To simulate one unavailable compatible service, add:

    --outage-operator tanner-ryan

The runner marks that operator unreachable but leaves every trusted signing key and the required three-source quorum unchanged. If only two genuine signatures remain, acceptance fails.

Read-only independent offline verification (safe to repeat) uses:

    python3 scripts/roughtime/accept.py verify \
      --registry "$RT_REGISTRY" \
      --dossier "$RT_DOSSIER" \
      --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256" \
      --expected-sha "$HC_VTIME_EXPECTED_SHA" \
      --dna-hex "<78 lowercase hex DNA bytes>" \
      --target-hex "<78 lowercase hex target bytes>" \
      --receipt "../sprint23-capture-unique/receipt.json" \
      --report-dir "../sprint23-verify-unique"

The negative tests must reject a wrong target, wrong DNA, wrong signer key, forged signature/delegation packet, malformed/truncated frame, duplicate signer/operator, unsupported version and fewer than three signed sources.

## Step 3 — Codex runs real external signed proof through the conductor

**Never use Sprint 10's publicly known signer DNA for this test.** The real harness refuses the fixture sentinel. Build a new **isolated** reviewed DNA that trusts exactly the authenticated public operator keys (no oracle fallback), with a new network seed, max_faulty=1, min_sources=3, and bounded Roughtime radius. The Sprint 11 template at dnas/vtime/workdir/dna-independent-sources.example.yaml is a candidate only; replace incompatible/unreviewed sources with reviewed roots before packing. Changing keys/seed changes the DNA hash. Validate with Sprint 20 deployment preflight where applicable and record all hashes.

The intended local acceptance runner is:

    python3 scripts/roughtime/run_conductor.py \
      --expected-sha "$(git rev-parse HEAD)" \
      --dna "/outside/repo/reviewed-operators/vtime.dna" \
      --registry config/roughtime-independent-sources.json \
      --dossier "/outside/repo/approved-operator-dossier.json" \
      --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256" \
      --report-dir "../sprint23-live-conductor-unique"

This test, ignored by default in Cargo, starts THREE genuine Holochain 0.7.1 Sweettest conductors. Alice creates an anchored real target using a fresh OS-random nonce and real UDP Roughtime signatures. Bob obtains a new signed source quorum bound to the actual DNA/target seal nonce and writes a real TimeSeal. Charlie verifies time bounds from the explicit signed target/TimeSeal witnesses. The test then makes conductor calls that reject forged packet data, a duplicate signer, a correctly signed response attached to a different real target, and a two-source quorum; wrong DNA/target nonce is rejected by the native cryptographic core. The source of each signed packet is recorded. The very signed receipt used by the conductor is extracted from the test stdout and independently replayed through vtime_core; a mismatch blocks the report.

Run a separate approved source-outage scenario with:

    --outage-operator tanner-ryan

The operator_id must be present and eligible in the dossier. The test must still collect three good signed responses. Two remaining operators are never accepted. An actual network outage could leave fewer than three and must fail loudly.

With the checked-in PENDING dossier, exploratory runs may use --allow-candidates, but they still return a **nonaccepted** status and cannot be counted as independent three-operator acceptance.

The directory includes report.json, conductor stdout/stderr, complete raw signed conductor receipt, native verification output and SHA256SUMS. Verify after collecting:

    cd "../sprint23-live-conductor-unique"
    sha256sum -c SHA256SUMS

Even successful live cryptography and two populated reviewer fields alone do not machine-prove real-world administrative independence; the separate signed human evidence must be reviewed.

## Step 4 — Explicit same-target replay and idempotency decision

**Decision:** the seal nonce is deterministic for the exact same DNA and target action. Therefore the signed response remains cryptographically valid and repeatable for **that same target**, and historical TimeSeals must remain independently verifiable. A fresh verifier may replay the same signed packet without violating the Roughtime signature or nonce scheme. Rejected: signed evidence reused for another DNA or target.

**Prohibited operational behavior:** interpreting a historical same-target receipt as a *new* Roughtime measurement, or processing it again to trigger a financial settlement or unique business operation. This is an application-level state problem, not something an Ed25519 signature alone can solve.

**Implemented local guard:** accept.py consume verifies cryptography, optionally checks source time intervals against a separately trusted local UTC clock (max age default 600 seconds and future allowance 90 seconds), and atomically claims a receipt SHA-256 and logical operation ID in a local SQLite ledger. Unique indexes on (DNA, target, receipt) and (DNA, target, operation ID) reject repeats from concurrent local callers. It never modifies production DNA consensus.

    python3 scripts/roughtime/accept.py consume \
      --registry "$RT_REGISTRY" \
      --dossier "$RT_DOSSIER" \
      --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256" \
      --expected-sha "$HC_VTIME_EXPECTED_SHA" \
      --dna-hex "<actual DNA raw 78 hex>" \
      --target-hex "<actual target raw 78 hex>" \
      --receipt "../sprint23-capture-unique/receipt.json" \
      --operation-id "business-operation-001" \
      --ledger "../private-operator-state/roughtime-claims.sqlite" \
      --report-dir "../sprint23-consumption-unique"

**Known limitations / release consequence:**
- The local clock screen is NOT cryptographic freshness if the host time can be manipulated.
- The SQLite ledger is ONE-HOST local idempotency. It neither prevents a second host from replaying the same signed bytes nor changes on-chain acceptance.
- A crash after claiming the ledger but before a Holochain write can leave a claimed operation without a published seal; reconciliation is needed before production use.
- Global exactly-once settlement and network-wide same-target consumption need a separately reviewed, durable consensus/idempotency mechanism with a Holochain entry or equivalent authenticated state. If system-wide prevention is a release requirement, **this remains NO-GO**, despite a passing local ledger.

## Mandatory acceptance checklist (all pending until evidenced)

- [ ] At least four *genuinely* independently controlled and currently eligible real roots verified by two human reviewers, with published key provenance and no common administrator/upstream failures.
- [ ] Fresh real signed external responses from at least three of those roots (not fixture signers), authenticated by strict native Ed25519/delegation/Merkle/nonce verification.
- [ ] Real Holochain 0.7 three-conductor anchor/seal/peer verification on exact reviewed DNA and Git SHA; preserve the raw signed receipt and independently replay it.
- [ ] A one-operator outage scenario still yields three valid signed responses; two remaining responses are rejected without any quorum downgrade.
- [ ] Forged, malformed, duplicate, wrong-DNA, wrong-target and unsupported-version negative tests pass in native and conductor gates.
- [ ] Same-target historical proof reuse and local-vs-global idempotency scope formally accepted; no ungrounded freshness or exactly-once claim.
- [ ] SHA256SUMS, registry/dossier/receipt/DNA hashes, actor ownership records and current supported endpoints independently reviewed.
- [ ] Sprint 17 integrated exact-commit validation, Sprint 20 deployment preflight and final release/security review completed.

**Until those conditions are satisfied, release gate #1 remains NO-GO. Sprint 23 must not merge automatically into main or deploy production DNA.**
