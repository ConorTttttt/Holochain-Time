# Operator key generation, custody, rotation and revocation

**Status:** review-ready **procedure**, not executed provisioning. This document contains **no private key material** and does not authorize production operations. Pair with `docs/SPRINT_20_RELEASE_CONFIGURATION.md`, `scripts/deployment_preflight.py`, `docs/oracle-persistence/RECOVERY_MIGRATION.md` and `docs/operations/INCIDENT_RESPONSE.md`.

## Identity classes — never confuse or reuse

| Identity | Purpose | Rotation impact |
| --- | --- | --- |
| Holochain agent Ed25519 key | Authenticates source chain, signed v2 oracle statements and possible v3 host signer | New agent/chain; do not reinitialize old journal or claim old seq; may require new DNA/properties/trust set |
| Roughtime root Ed25519 key | Authenticates delegated time-server keys and signed Roughtime evidence | Update independently authenticated root allowlist and production DNA; historical receipts retain original trust context |
| Roughtime delegated key | Short-lived operational signing, signed under root policy | Must validate certificate/delegation period; changing it alone should not silently alter root identity |
| Unyt account/agent key | Owns parked spend sources, RAVE execution and recipient Accept | Review ownership, outstanding allocations, agreement rules and balance reconciliation |
| Release approval/signing identity | Attests exact Git SHA, artifacts and reviewer approvals | Independent from oracle and financial keys; revoke/report compromise with external audit log |
| External antirollback checkpoint principal | Owns monotonic latest checkpoint per DNA/oracle | Must not share rollback domain or automatically adopt a restored old signer disk |

No one key should simultaneously serve as test signing root, production oracle signer, checkpoint administrator, and release approver. The existing deterministic fixtures in `deployment/known_insecure_keys.json` and test scripts are intentionally **public**, suitable for disposable local labs **only**.

## New-key provisioning ceremony — production proposal

1. **Change authorization:** Open a reviewed GitHub issue with purpose, DNA/network, identity class, custody owner, expected trust/quorum policy, rotation triggers, and no secrets. Obtain two independent human approvals (operations + security). For Unyt, add an economic owner.
2. **Generate inside reviewed signer/custody system:** Prefer a non-exportable HSM or established managed secure key store/Lair configured with OS and Holochain version compatibility. Use provider-supported **cryptographically secure Ed25519 key generation**; do not invent or run an unreviewed provider CLI command, copy dev seeds, use deterministic derivation, or output private key bytes to a terminal/log. Record device model/version, protected key handle/label, allowed signing domain, owner and recovery policy *outside Git*.
3. **Verify public material independently:** Export **only** public key/fingerprint; recompute canonical 39-byte Holochain agent key with checksum if relevant, independently verify root provenance directly with operator, confirm correct DNA and signer policy. Record artifact digest and key provenance URL in controlled approval files.
4. **Demonstrate signing policy:** Prove the key-service refuses arbitrary message domains, wrong DNA, wrong oracle ID, duplicate request IDs and expired credentials. Exercise two-person HSM operator/role permission separation, credential renewal and audit-log retention. Sprint 29's `OracleSigner` interface is a boundary proposal, **not** evidence the real signer enforces these constraints.
5. **Check operator independence:** Validate that distinct Roughtime/operator IDs actually use separately administered roots, infrastructure and escalation chains, not only different strings. Sprint 20 production policy requires enough independent sources for outage tolerance; compare to the actual quorum threshold before approval.
6. **Stage without publishing:** Prepare a new DNA configuration in external access-controlled staging. Run `scripts/deployment_preflight.py` with exact manifest and policy digests, independently reviewed source roots and approval records, and later `scripts/pack_release_dna.py` with reviewed WASM hashes. No direct unguarded `hc dna pack` for production; no staging keys in a public or previously funded DNA.
7. **Fresh genesis:** Before any v3 signer first launch, create its journal **once** only under independently verified *new identity* authorization, bind its initial checkpoint to the trusted external monotonic store, then test restart. Missing old state is **not** permission to use bootstrap again.
8. **Acceptance:** Test real conductor quorum and HSM crash/restart/rollback; verify live authorized time source, source-chain ancestry, native Roughtime captures, downstream Unyt compatibility and actual key handle with two reviewers. Log hashes and signatures, not secrets.

## Rotation and retirement

**Routine:** announce new root/agent identities, preserve old signed evidence for read-only historical verification, build a reviewed *new* DNA/network configuration when immutable integrity properties/trusted keys change, stage separate route/chain endpoints, dual-verify with independently pinned old/new trust **without treating proofs as interchangeable**, complete consumer migration, then revoke/retire old signing capability. Existing immutable Unyt agreements have fixed signer/DNA rules: make an explicitly reviewed replacement agreement and reconcile parked sources and pending RAVE/Accept; never mutate agreement history.

**Compromise/emergency:** (a) freeze admission, funding, and all involved HSM/client privileges; (b) preserve original journals, checkpoints, action receipts, key audit trails and immutable backups with custody records; (c) quarantine all uncertain signed operations, do not retry after SIGNING; (d) publish witnessed revocation to the correct trust domain and independently notify downstream verifiers/operators; (e) provision an entirely new identity/DNA/agreement under two-person review; (f) independently verify no same-key dual signer or stale checkpoint writer remains before resumption. For fund-bearing agreements, obtain an approved finance response; do not assert an irreversible RAVE/Accept can be undone by restoring an app backup.

**Lost HSM/key, journal or checkpoint:** no automatic reset. A trusted newest journal+remote checkpoint and correct key are preconditions for continuing the same v3 identity. If proof is unavailable, **retire** that identity and document expected liveness/funding impact rather than re-sign a supposedly fresh genesis.

## Evidence the auditor must see

A redacted public-key and owner inventory; hardware/provisioner version; identity/DNA fingerprints; independent operator root key provenance; two authorizations; HSM permission tests and key-rotation dry run; safely recorded source-chain and Roughtime signatures; exact source/WASM/DNA hashes; external monotonic checkpoint and rollback refusal; downstream Unyt agreement sign-off; incident drill logs. No private keys, mnemonic phrases, API tokens, key backups or production credentials in GitHub PR comments, CI artifacts, audit tarball or plain chat.

**Unresolved integration:** real non-exportable HSM/Lair signer and independently controlled checkpoint backend (#70) and actual funded recipient Accept (#61) are release blockers, not matters of documentation completion.
