# hc-vtime: verifiable time for Holochain

Holochain timestamps are whatever the author wrote. hc-vtime adds time **bounds that every peer
can verify**, built from Roughtime servers (RFC 10049) and Holochain oracle agents, tolerant of up
to `f` lying sources, with Unyt Smart Agreements that spend on verified time and bond oracles
against lying. See [DESIGN.md](DESIGN.md) for the research basis, proofs and threat model, and
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the security review and what was hardened.

## What you get

| Piece | Path | What it does |
| --- | --- | --- |
| `vtime_core` | `crates/vtime_core` | `no_std` library: Roughtime verification, oracle statements, fault-tolerant bounds, seal nonces, chain propagation, malfeasance proofs |
| `vtime_integrity` | `dnas/vtime/zomes/integrity/vtime_integrity` | `TimeAnchor` (not before), `TimeSeal` (not after), private `OracleLog`; validation through the host's Ed25519 verifier |
| `vtime` | `dnas/vtime/zomes/coordinator/vtime` | oracle service, anchoring, sealing, explicit-witness verification, Unyt export |
| DNA and hApp manifests | `dnas/vtime/workdir/dna.yaml`, `workdir/happ.yaml` | trusted keys, fault bound and tolerances as DNA properties |
| `verified_time_release` | `unyt/verified_time_release` | Unyt template: tranches unlock on m-of-n oracle-proven time |
| `time_oracle_bond` | `unyt/time_oracle_bond` | Unyt template: an oracle's bond, slashed by its own contradictory signatures |
| `unyt_harness` | `unyt/harness` | runs both templates through `rave_engine` 0.15.0 |
| `roughtime_fetch` | `crates/vtime_core/examples` | UDP client that fetches and pre-verifies one Roughtime reading |

## Build and test

```bash
cargo test --workspace        # 62 tests: core, Roughtime interop, evidence policy, Unyt templates
cargo clippy --workspace --all-targets -- -D warnings

# Zomes (needs the wasm target, e.g. inside a holonix 0.7 shell)
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p vtime_integrity -p vtime
hc dna pack dnas/vtime/workdir && hc app pack workdir
```

Before packing, replace the placeholder Roughtime keys and oracle agent keys in `dna.yaml`.
Those values are part of the DNA hash.

## Using it in a hApp

**As a zome pair.** Add both zomes to your DNA. Then:

1. *Anchor.* The client fetches a few Roughtime readings with any fresh nonce and calls
   `create_anchor({ roughtime })`. The zome adds statements from every reachable oracle. Everything
   the agent writes afterwards is provably not before the anchor's bound.
2. *Seal.* For an action that must be shown to exist by a time, the client calls
   `seal_nonce_for(action)`, fetches Roughtime readings with that nonce (`build_roughtime_request`
   gives the exact packet), and calls `seal_action({ target, roughtime })`.
3. *Check.* Call `verify_time_with_witnesses({ target, anchors, seals })` with
   one or more **known action hashes** for relevant anchors or third-party
   seals. The coordinator verifies their signatures, nonce and ancestry.
   `evidence_complete` is **always false**. A clean
   `NoContradictionInSuppliedProofs` conclusion is not global consistency
   and is not proof of publication before a deadline.

**Breaking pre-release API change (Sprint 4):** The legacy
`get_verified_time(action)` now returns a clear migration error **without
making any DHT index queries**. Its old unbounded `get_links` scan was
unsafe under link flooding and could not prove completeness. Do not retry
the old endpoint. See [ADR 004](docs/ADR_004_LEGACY_DHT_QUERY_RETIREMENT.md).
Only known submitted evidence can be checked until a complete, resource-
bounded discovery mechanism exists. Issues #3/#4 and conductor #7 stay open.
**As a library.** Your own integrity zome can embed `Vec<TimeEvidence>` in its entries and call
`vtime_core::evidence::anchor_lower_bound` or `seal_upper_bound` with
`vtime_integrity::HostVerifier` and a policy whose `oracle_dna` is your DNA hash. A seal proves an
action's *content* existed by a time, not that it was published then or that the author prepared
no alternatives. So a rule like "a bid is invalid unless sealed before the close" is only safe with
commit–reveal: one published, sealed commitment per bidder, revealed after the close. See DESIGN.md
§3.1.

**With Unyt.** Park the output of `unyt_time_proof()` as the `time_proof` input of
`verified_time_release`, and list your DNA hash in its `oracle_dnas`. Oracles post
`time_oracle_bond` agreements; anyone holding one self-contradicting statement, or two that
contradict each other, can check them with `check_oracle_statements` and then claim.

## Running an oracle

An oracle is an ordinary conductor whose agent key is listed in `oracles`. Keep its clock
disciplined well inside `oracle_radius_ms` (for example chrony with NTS, or a Roughtime client).
DNA configuration must provide at least `min_sources + max_faulty` distinct
trusted providers for availability with up to `max_faulty` unavailable sources,
in addition to the usual fault-soundness requirement.

The coordinator refuses to sign anything below its chain's floor, so a clock that jumps backwards
stops the oracle rather than incriminating it. It answers at most once per second
(`MIN_STATEMENT_SPACING_US` in the coordinator; changing it does not change the DNA hash).

Two operating rules keep an honest oracle unslashable:

- One key may serve several networks (each statement names its DNA), but never run **two cells of
  the same DNA** with one key. Holochain treats that as a chain fork, and the two statement chains
  would be equivocation.
- Never restore an oracle's agent key without its source chain. The private statement log is not
  on the DHT, and the coordinator refuses to sign if the latest log entry is unreadable.

Under sustained abuse an operator can revoke the unrestricted `attest_time` /
`latest_attestation` grant and issue assigned grants instead.

## Status

Tested natively and security-reviewed (see SECURITY_REVIEW.md). Zome WASM builds and conductor
tests were not run here because the WASM target could not be installed. See DESIGN.md section 5
for exactly what was and was not verified.
