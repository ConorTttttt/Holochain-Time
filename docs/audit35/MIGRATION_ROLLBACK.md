# Migration, rollback and disaster-recovery release plan

**Applies only after approval of a concrete candidate and operator topology.** This is a prospective playbook, not an executed drill. A “rollback” can revert application code/traffic when compatible; it cannot safely erase a signed source chain, reverse a consumed Unyt spend or reset a monotonic oracle sequence.

## Change inventory required for every release

Record old and proposed: Git commit SHA, cargo/toolchain/container digests, integrity/coordinator WASM SHA-256, packed DNA/hApp hash, original/new DNA hash and network seed, Roughtime operators/root keys, oracle agent/HSM key, signing statement version, verification policy, Unyt agreement code/rules SHA and instances, active account/recipient, latest independently authenticated oracle checkpoint, externally held backups, pending RAVEs and recipient Accept states. Refuse cutover if any mapping is missing.

## Protocol compatibility matrix

| Transition | Safe action | Prohibited shortcut |
| --- | --- | --- |
| Coordinator-only code with unchanged integrity DNA and signed schema | Test exact new WASM against existing DNA via real conductors, with read/write backward compatibility proof | Implicitly trust old proof indexes after altered discovery logic |
| Integrity type, DNA properties, trusted Roughtime sources or network seed change | Pack/install **new DNA** using externally approved manifest/policy, explicitly migrate consumers and revalidate proof trust | Reuse old DNA hash or silently replace cryptographic policy under an old identity |
| v2 oracle statement to v3 batch signature | Preserve v2 verification for historical evidence and deployed Unyt; introduce versioned v3 identity, bindings and clients after reviewed upgrade | Interpret v2 nonce/seq/prev/floor as v3 batch root or continue old signer key after re-bootstrap |
| Sprint 24 native journal to Sprint 29 v3 runtime | Authenticate full history and external latest checkpoint, bind historical request identities under reviewed migration or provision a fresh v3 key | Auto-migrate untagged requests, retry ambiguous SIGNING, reset file after corruption |
| Unyt agreement rules/target/expiry/challenge upgrade | Version agreement instance and source policy, reconcile parked funds, old RAVEs, distinct Accept and unspent balances | Edit immutable prior RAVE outcomes or claim a proof in an unbound replacement instance |
| External checkpoint store replacement | Signed+reviewed monotonic handoff, sealed latest head/high-water and stale-writer fencing across domains | Copy a local checkpoint file to same rollback volume and claim protection |
| App/host rollback after key compromise | Revoke key, freeze signing, preserve evidence and install vetted fresh identity | Restart previously compromised key from old backup |

## Phased release drill (no real funds or production keys)

1. **Baseline freeze:** choose a named full Git commit, reviewed PR ancestry pins and immutable original backup. Capture reports from `scripts/release_acceptance_27.py`; the output intentionally declares production NO-GO. Do not infer branch ancestry from a moving tag.
2. **Build/reproduce:** in two isolated checkouts with the same toolchain/lockfiles, run locked workspace Rust, Clippy, both WASM zomes and `hc dna pack` through reviewed preflight. Capture source/WASM/DNA/hApp SHA256SUMS and logs. Any byte difference requires investigation; `SOURCE_DATE_EPOCH` alone does not establish Holochain toolchain determinism.
3. **Network rehearsal:** 3+ disposable Holochain agents, source fork/warrant and unavailable witness scenarios, DHT spam/partition/rejoin, Roughtime operator outages and 100+ concurrent seals. Test preexisting clients on new DNA, and old clients reading old verified evidence.
4. **Signer fault rehearsal:** stop/kill the actual HSM-connected sidecar at PREPARE, inside SIGNING, after COMMIT and during remote checkpoint CAS; restore onto clean host, prove no key duplicate or conflicting signature, recover only exact committed replay and reject an authentic but stale backup. Keep SIGNING uncertainty quarantined pending reviewed receipts.
5. **Financial rehearsal:** in an *authorized isolated test alliance*, exercise release tranches, refund/challenge and slash, wrong target, duplicate proof vs double-spent source, expiry, rejected RAVE, recipient Accept and lost-reply recovery. Capture both sides' signed raw native records and independently reconcile spent sources. Do not treat mock CSV/JSON as payment completion.
6. **Cutover review:** security, economic, operations and release owners independently inspect evidence; record sign-off, unresolved exceptions and release strategy before enabling any external access. Start with time-limited, rate-limited pilot and defined rollback windows.

## Runtime rollback decision tree

**Before any new chain write / agreement execution:** stop deployments; return traffic to last independently verified compatible build and configuration, preserving the exact same DNA and signing keys where allowed. Record reason and hashes.

**After new Holochain actions but before funds:** stop new writes; preserve already-published signed actions, warrants, source-chain evidence and DHT state. Validate whether old coordinator understands new entries before code rollback. If integrity/DNA changed, maintain the **new DNA as a separate network**; roll clients to the old one only with explicit data/replay compatibility and user disclosure.

**After ambiguous SIGNING:** do not roll signer key or journal backwards. Stop key service; reconcile signature/nonce/sequence against independent HSM receipts and newest trusted checkpoint. If unresolved, permanently retire key and migrate after operator review (#70).

**After native Unyt RAVE or recipient Accept:** do not imply reverse execution by restoring a snapshot. Freeze future transactions and use only approved protocol-supported new compensating agreements/transfers after reconciliation and legal/economic authorization. Maintain unaltered native actions as evidence and report potential loss.

**On storage corruption/host compromise:** restore only from reviewed off-host immutable backup and the **freshest independently authenticated checkpoint**. Never silently drop incomplete record tails; a signature might have escaped. Keep forensic copy with chain-of-custody.

## Acceptance and exit

For each rehearsal store: exact commit, source archive digest, toolchain versions, before/after DNA and WASM hashes, logs with start/end and exit codes, HSM/checkpoint action receipts, Holochain actions and warrants, Unyt raw RAVEs+Accepts, pass/fail classification, machine-readable incident record and independent reviewers. A runner failure before assignment is **NOT RUN**. Any unresolved Critical/High audit finding or funded Unyt/antirollback uncertainty keeps **production NO-GO**.

Related: `docs/oracle-persistence/RECOVERY_MIGRATION.md`, `docs/operations/INCIDENT_RESPONSE.md`, `docs/SPRINT_20_RELEASE_CONFIGURATION.md`, `docs/SPRINT_27_RELEASE_ACCEPTANCE.md`, `docs/unyt/SPRINT26_RUNBOOK.md` and master issue #1.
