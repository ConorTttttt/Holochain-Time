# Sprint 26 — Financial acceptance results (initial)

**Status:** GitHub implementation of offline preparation, strict v2 proof
preflight and normalized evidence reconciliation. **NOT ACCEPTED.**
No Unyt wallet credentials, transactions, funded accounts, TestNet
RAVE records, signed recipient Accept or independent peer checks were
read or produced by this GitHub-writing agent.

| Required acceptance | Existing offline coverage | Actual testnet state |
| --- | --- | --- |
| Agreement deployment | SHA-pinned Sprint 14A plan and operator-approved local deploy wrapper | **NOT DEPLOYED** |
| Verified-time evidence submission | Canonical v2 Ed25519 preflight + `stage-proof` Rhai payload | **NOT SUBMITTED** |
| Valid release payout 100/100/100 | Existing rave_engine 0.15.0 tests plus preflight and event audit | **NOT EXECUTED** |
| Forged proof rejection | Genuine v2 mutation tests, offline mock Rhai | **NOT EXECUTED** |
| Wrong DNA rejection | Canonical DNA allowlist check and offline Rhai case | **NOT EXECUTED** |
| Wrong target rejection | **BLOCKED:** current oracle nonce not agreement-bound | **UNSUPPORTED** |
| Replayed proof rejection | **BLOCKED:** release may safely reuse old valid lower bound; agreement input consumption must be specified | **UNSUPPORTED** |
| Expired agreement | **BLOCKED:** no agreed expiry semantics in Rhai | **UNSUPPORTED** |
| Valid refund | Signed refund witness quorum preflight and 14A bond fixture | **NOT EXECUTED** |
| Valid challenge | Bond malfeasance proof preflight, in-window native behavior still needs contract | **UNSUPPORTED** |
| Invalid slashing rejection | Signed pair/honest and forged proof tests | **NOT EXECUTED** |
| Bond slashing 50/450 | Existing engine tests + signed malfeasance preflight | **NOT EXECUTED** |
| Financial transition verification | Off-chain conservation, unique consumed sources, RAVE chain and Accept artifact requirements | **NO NATIVE TRANSACTION EVIDENCE** |
| Transaction/execution evidence | Sample normalized schema; native raw/peer files and hashes required | **NONE COLLECTED** |
| Independent review | Runbook and critical protocol-gap record only | **NOT COMPLETE** |

`PR #50`'s alternative receipt/journal schema is not
accepted as native Unyt proof without source mapping. All producer
claims must be checked against real action/entry records, peer
validation, signer and the installed app build.

The checkouts' GitHub Actions may fail before an assigned runner is
present. Never confuse zero-step job failure with executed Rust
validation. Keep PR in **Draft**, and release **NO-GO**, even if
the offline suite later passes.
