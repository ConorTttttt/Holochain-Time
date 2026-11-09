# Sprint 11 — independent external Roughtime evidence

**State (9 November 2026): implementation candidate; NOT acceptance evidence.**
Do not mark the three-operator cryptographic quorum complete without a live
receipt verified from three truly independent operators. Do not drop quorum
from three to two to work around connectivity or protocol incompatibility.

## Trust roots and operator review

Pinned source-of-record: [Cloudflare Roughtime ecosystem list](https://github.com/cloudflare/roughtime/blob/master/ecosystem.json);
[operator descriptions](https://github.com/cloudflare/roughtime/blob/master/ecosystem.md);
[Cloudflare's directly published key](https://developers.cloudflare.com/time-services/roughtime/usage/).
The reviewed *candidate* JSON is in
`config/roughtime-independent-sources.json`. Keys are copied from published
registry entries, not discovered over unauthenticated UDP at verification time.

| Candidate operator | Endpoint | Key authentication/provenance | Independence assessment |
| --- | --- | --- | --- |
| Cloudflare | roughtime.cloudflare.com:2003 | Key independently published in Cloudflare docs, registry | Separate public operator, global anycast. Beta root rotation possible. |
| int08h | roughtime.int08h.com:2002 | Registry, operator website / DNS TXT | Independently operated by roughenough author, hosted on DigitalOcean; time upstream includes Google/Amazon/NIST. |
| roughtime.se | roughtime.se:2002 | Registry, operator website / DNS TXT | Stratum-1 service hosted by STUPI AB in Stockholm; verify who actually controls the root key. |
| Tanner Ryan | time.txryan.com:2002 | Registry, operator website / DNS TXT | Independently presented service; confirm operator identity and key ownership. |

Four differently named providers are **not** by themselves four proven
independent trust domains. Human reviewer must establish administrative/key
control, shared upstream dependencies, cross-hosting, and current operability
before production trust. A DNS hostname, an IP address, a different signer
key, or a JSON `operator` label does not prove independence. Registry labels
are *locally reviewed assertions* and MUST NOT be accepted from remote callers.

Inactive services including Chainpoint and Google Sandbox must not count.
The independent-source helper uses the existing canonical Ed25519 / delegated
key / signed SREP / nonce / Merkle verification. It rejects duplicate keys,
duplicate reviewed operator identities (case-insensitive), missing/untrusted
key mappings, invalid signatures, and fewer than three sources. This extra
client-side gate does **not** change on-chain DNA trust semantics: on-chain
integrity can authenticate distinct public keys, not real-world operator
control. Independently vet every key before pinning it in a DNA.

## How to collect and replay evidence

A machine with Rust, access to remote UDP ports 2002 and 2003, and stable
network time for operational comparison is required.

Generate the real target-specific nonce from **authoritative 39-byte raw**
DNA and action hashes. Do not confuse Holochain's `uhC...` string encoding
with their raw 39-byte forms. The Holochain coordinator's
`seal_nonce_for(target)` may be used as an independent cross-check.

```sh
cargo test -p vtime_core --test independent_sources --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings

# Replace with the real 78-hex-character raw hashes for a genuine seal.
DNA_HEX="<78 hex chars for 39-byte DNA hash>"
TARGET_HEX="<78 hex chars for 39-byte target ActionHash>"
cargo run -p vtime_core --example roughtime_independent --locked -- \
  --live config/roughtime-independent-sources.json "$DNA_HEX" "$TARGET_HEX" \
  > sprint11-receipt.json

# Replay uses the same trusted registry plus externally supplied DNA/target,
# recomputes the required nonce, and fully verifies all stored packet bytes.
cargo run -p vtime_core --example roughtime_independent --locked -- \
  --verify config/roughtime-independent-sources.json \
  sprint11-receipt.json "$DNA_HEX" "$TARGET_HEX"
sha256sum sprint11-receipt.json
```

The live runner connects to UDP sources individually, checks each full
cryptographic response immediately, and records the failure reason for any
unavailable/invalid source. It emits JSON containing attempt diagnostics and
raw signed evidence *even if the quorum fails*. It accepts only if at least
three valid sources remain. One outage may be tolerated with four valid
operator mappings; two outages must fail. Invalid answers are discarded from
the attempted acquisition (and logged); **invalid answers supplied in a
quorum set are never filtered** by
`verify_independent_roughtime_quorum`.

For reproducible external evidence run the manual GitHub Actions workflow
`.github/workflows/sprint11-live-roughtime.yml` on the exact tested commit.
It uses PUBLIC synthetic DNA/target hash bytes for protocol verification
only (not a real conductor seal). The artifact records the source packet
bytes, attempts, commit SHA, collection timestamp, and receipt SHA-256. A
passing job establishes that >=3 independently *configured* operators
returned signed responses, NOT that their administrative control was audited.
A failing or absent workflow run is **not** live acceptance evidence.

To test a real conductor seal, promote reviewed keys into a **new DNA**
using `dnas/vtime/workdir/dna-independent-sources.example.yaml` as a
template, pack/install it, then seal a real action with the same nonce and
signed receipts. This example is Roughtime-only; there is no oracle fallback
to accidentally satisfy a three-source acceptance claim. Altering DNA
properties changes the DNA hash, so do not overwrite an existing production
DNA or treat this sample as a safe migration.

## Replay and freshness: what is and is not proven

- **Rejected:** evidence with wrong DNA, wrong action target, mismatched
  challenge nonce, tampered request/response bytes, duplicate signer/claimed
  operator, an unreviewed key, or missing/invalid signatures.
- **Not cryptographically rejected by this protocol:** reusing a genuinely
  signed response for the **exact same DNA and exact same target**. The seal
  nonce is deterministic and Roughtime verifies the server answered that
  nonce, not that this is its first use or that a trusted wall clock recently
  observed it. Anchors that accept any nonce also make no freshness promise:
  old genuine time only supplies an old sound lower bound. True session
  anti-replay would need a fresh challenge carried through consensus or a
  stateful, authenticated consumption record. Do not claim this requirement
  is complete from a successful packet replay check for *other* targets.

## Release acceptance checklist (no silent downgrade)

1. Four pins cross-checked directly with their operators, review signed off
   with identity/provenance and no shared administrative key control.
2. Live workflow or equivalent captures >=3 signed responses in one run,
   independently verifies certificates and Merkle inclusion, and preserves
   source/operator mapping, request/response bytes, timestamp and SHA-256.
3. All negative native tests pass: tamper, unknown key, duplicate key and
   operator, two-source outage, wrong DNA/target, wrong challenge.
4. Wrong-target and wrong-DNA replays fail. Same-target freshness limitation
   explicitly accepted by a security reviewer or resolved with protocol
   changes; without this the full replay criterion remains open.
5. Test new DNA in an actual Holochain 0.7 conductor against collected live
   signed evidence. Run native and WASM builds on exact commit, and establish
   no unjustified oracle substitution.
6. An outage that leaves two independent valid sources fails loudly rather
   than auto-adjusting `min_sources`; if the required three live sources
   cannot be obtained, remain **NO-GO**.

The previous Sprint 10 local signed-quorum tests are useful integration
fixtures, but four local test signing keys on one machine cannot establish
independent external operators.
