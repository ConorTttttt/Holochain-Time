# Sprint 28 — Independent Roughtime source readiness (Agent R)

**As-of:** 10 November 2026  
**Baseline:** `bae1e5b9380e92cbee511e07fea1681011d4d6d0` (integrated development main)  
**Status:** OFFLINE TOOLING PROPOSED; external UDP signature captures NOT RUN; operator independence NOT APPROVED; production **NO-GO**.

Sprint 11 implemented the cryptographic verifier, Sprint 23 implemented signed UDP capture, offline replay and three-conductor acceptance, and Sprint 25 implemented a read-only production monitoring probe. **Sprint 28 extends those controls; it must not replace the Rust verifier or change integrity/DNA/quorum or financial code.**

## Current reviewed *candidates*, not approved trust anchors

Canonical exact keys and UDP endpoints are in `config/roughtime-independent-sources.json`, paired by byte-identical root keys to `config/sprint23-operator-dossier.example.json`. The two JSON documents must be independently fingerprinted/approved before live use; neither is an authority merely because it is in Git.

| Operator ID | Published service and key source | Client compatibility | Shared-infrastructure, administration and time-source risks | Disposition |
| --- | --- | --- | --- | --- |
| `cloudflare` | Cloudflare-Roughtime-2, `roughtime.cloudflare.com:2003`; [operator root key](https://developers.cloudflare.com/time-services/roughtime/usage/) | **EXCLUDE**: service currently advertises older IETF draft08/draft11, whereas local Rust request allows RFC 10049/draft15. Protocol probe must validate before changing this status. | Anycast Cloudflare network; beta root may rotate; published hostname/key do not prove operational reliability. | Not eligible for current signed quorum. |
| `int08h` | `roughtime.int08h.com:2002`; [ecosystem and DNS provenance](https://github.com/cloudflare/roughtime/blob/master/ecosystem.md) | Draft15/RFC protocol candidate, **live probe pending**. | Cloudflare ecosystem describes DigitalOcean NYC hosting, with upstream NTP from Google, Amazon and NIST. External operator administrative/key-control audit still needed. | Compatible candidate only. |
| `roughtime-se` | `roughtime.se:2002`; [operator site](https://roughtime.se/) | Compatible candidate, **live probe pending**. | Ecosystem documents STUPI AB hosting in Stockholm and stratum-1 atomic-clock inputs; independent signing-key governance not verified. | Compatible candidate only. |
| `tanner-ryan` | `time.txryan.com:5319`; [operator key and RFC 10049 endpoint](https://time.txryan.com/) | RFC 10049 candidate, **live probe pending**. | Operator describes OVH / AS16276 hosting in Canada, stratum-2 NTP and GNSS/metrology upstreams including NIST/NRC. Shared upstreams and revocation need direct review. | Compatible candidate only. |
| `sturdy-statistics` | `roughtime.sturdystatistics.com:2002`; [operator key and revision](https://roughtime.sturdystatistics.com/) | IETF draft15 candidate, **live probe pending**. | Hosting/provider, upstream time source, operational ownership and SLA have not been independently documented. | Compatible candidate only. |

**Key review requirement:** the published Ed25519 public keys are authenticated as *publicly advertised candidate roots* via operator sites/ecosystem, **not cryptographically attested as belonging to independent operators**. Record two distinct human reviewers, out-of-band key verification, hosting/AS/cloud region, root key custody/rotation, time inputs, shared DNS/network/admin/control-plane dependencies, and signed observed response digests in an **external approved** dossier. Do not silently promote the checked-in example dossier.

The retired Cloudflare `:2002` key and Google's old sandbox endpoint are not valid fallback servers; the ecosystem marks these former services inactive/deprecated. Protocol compatibility must be rechecked using actual signed packets whenever the published implementation changes.

## Offline gates (GitHub / Codex)

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/roughtime -p 'test_*.py' -v
cargo test -p vtime_core --locked --test roughtime_acceptance
cargo test -p vtime_core --locked --test independent_sources
cargo test -p vtime_core --locked --test roughenough_interop
cargo fmt --all -- --check
```

These are **synthetic/offline tests** for malformed packets, wrong nonce and target, forged signature/delegation, bad Merkle proof, replay and duplicate roots, insufficient 3-of-4 quorum, and evaluator fail-closed logic. They do **not** establish currently reachable services, operator independence or a real Holochain result. The CI workflow never makes live UDP probes or checks in evidence packets. A workflow with no assigned runner is **NOT RUN**, not a passed test.

## Safe audited source registry

```bash
export RT_REGISTRY=config/roughtime-independent-sources.json
export RT_DOSSIER=config/sprint23-operator-dossier.example.json
# These hashes MUST be confirmed through a separately approved channel;
# calculating them from editable files alone does not authenticate the roots.
export PINNED_RT_REGISTRY_SHA256='<externally reviewed lowercase 64-hex>'
export PINNED_RT_DOSSIER_SHA256='<externally reviewed lowercase 64-hex>'
python3 scripts/roughtime/readiness_28.py audit \
  --registry "$RT_REGISTRY" --dossier "$RT_DOSSIER" \
  --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256" \
  --expected-dossier-sha256 "$PINNED_RT_DOSSIER_SHA256"
```

The audit requires unique 32-byte canonical Ed25519 roots, stable operator IDs, consistent published endpoints and exact dossier-to-registry binding. It does not open a UDP socket or confer operator approval.

## Opt-in real UDP capture + one-source-outage simulation

Run on a clean, pinned **exact commit** with approved external keys, open outbound UDP, Rust/Cargo and a trusted local clock. Use the *raw* 39-byte Holochain DNA and target ActionHash bytes (78 lowercase hex each); displayed base64url Holochain identifiers are **not** valid CLI inputs. Evidence directories must be new and **outside** the repository.

```bash
export HC_VTIME_EXPECTED_SHA="$(git rev-parse HEAD)"
python3 scripts/roughtime/readiness_28.py survey \
  --registry "$RT_REGISTRY" --dossier "$RT_DOSSIER" \
  --expected-registry-sha256 "$PINNED_RT_REGISTRY_SHA256" \
  --expected-dossier-sha256 "$PINNED_RT_DOSSIER_SHA256" \
  --expected-sha "$HC_VTIME_EXPECTED_SHA" \
  --dna-hex '<actual raw DNA bytes, 78 hex>' \
  --target-hex '<actual raw ActionHash bytes, 78 hex>' \
  --outage-operator tanner-ryan \
  --report-dir ../sprint28-source-survey-unique
(cd ../sprint28-source-survey-unique && sha256sum -c SHA256SUMS)
```

The runner first captures from all configured sources using the existing `roughtime_independent` Rust client. It then re-verifies raw signed frames with the **original** trust roots, requires **four distinct compatible native-verified signatures** before source loss and checks source intervals only against local wall clock (**advisory, not cryptographic freshness**). Next it replaces exactly one selected compatible source UDP endpoint with `127.0.0.1:9` (leaving its root key and the 3-source quorum unchanged), re-captures via UDP, re-verifies against the original registry and requires three other authenticated signing roots. The outage run must not count the simulated-offline operator; verified operator IDs must be a subset of the first run.

The evidence bundle retains full original and outage capture registries, raw signed packet receipts, attempts/stderr, native replay logs, digests, interval summaries, the exact source SHA and SHA256SUMS. A run with fewer than four compatible responders, stale relative to the local clock, a network outage or a bad signature is **BLOCKED/FAIL** rather than silently reduced to a two-source policy. Successful cryptography yields `CRYPTO_PASS_HUMAN_REVIEW_PENDING` or `CRYPTO_PASS_REVIEW_ASSERTIONS_ONLY`, **never production ready**.

For a fuller outage matrix, repeat the real survey independently for `int08h`, `roughtime-se`, `tanner-ryan` and `sturdy-statistics` with distinct directories, exact-SHA attestations, and separately preserved SHA256SUMS. One simulated outage is **not** evidence of a physically failed operator or a durable availability SLA. Using the same target means a deterministic seal nonce can authenticate old responses for that same target; neither the fresh UDP request nor the local-clock check proves server-issued freshness against a replaying adversary.

To independently verify a captured three-source receipt, use Sprint 23 `accept.py verify` on the precise saved `baseline.receipt.json` or `outage.receipt.json` and keep the cryptographic results. Do not treat JSON self-claims as proof: only a successful execution of the Rust verifier may authorize the signed-root counts.

## Remaining release gates — all unproven

1. **Operator provenance:** two independent reviewers verify 4+ genuinely separate administrators, key custody, upstream clock diversity, failure domains, revocations, rotations, contact/incident escalation and approve an out-of-band dossier. Public branding, distinct hostname/IP/key and GitHub PR alone are not proof.
2. **Live availability:** at least four individually eligible independent roots actually respond with acceptable signed packets, and three distinct operators remain signed after each eligible source outage (or approved representative failure) on the exact pinned checkout.
3. **Runtime acceptance:** Sprint 23 `run_conductor.py` uses a freshly packed operator-specific DNA, three real Holochain 0.7 conductors, target-bound seal nonce and third-party verification, actual signed receipts, negative tamper cases, and external replay verification. Fixture-signers or shared local keys do not count.
4. **Replay/idempotency:** changed DNA/target, malformed/truncated response, altered SREP/CERT/signature/Merkle, duplicate key/operator and 2-of-3 attempts fail. Same-target historical verification remains allowed; unique financial action consumption is *not* guaranteed network-wide by the local Sprint 23 SQLite ledger.
5. **Integration release gate:** exact-commit Rust/Clippy/WASM/packaging, Sprint 27 combined acceptance and production release blockers, security review, funded Unyt and deployed oracle runtime acceptance all remain separately required.

**Never merge this sprint as a statement of external source availability or production readiness.**

Integration validation note: the committed pending operator dossier still labels two sources `unknown-probe-required`. Sprint 28 deliberately rejects that dossier for four-source readiness; resolve compatibility with independently verified data before a live survey. The offline positive pinning test uses an explicitly synthetic candidate dossier and never upgrades the committed dossier or operator approval flags.
