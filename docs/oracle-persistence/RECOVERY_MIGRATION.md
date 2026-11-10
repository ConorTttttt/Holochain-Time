# Sprint 24 — Oracle recovery, backup and migration

**Operational policy: fail closed on any uncertainty about signed history.**
These are test-proven **candidate procedures**, not deployed production
automation. Two independent copies of one old journal do not make a trusted
freshness checkpoint. Use reviewed Lair/HSM keys only outside test mode.

## Controlled shutdown and restart

1. Quiesce the oracle admission queue. Stop issuing new batch signatures.
2. Let the in-flight durable signing operation reach COMMIT; if it cannot,
   record its last on-disk phase. Do not call sign again after SIGNING.
3. Stop the signer process and confirm it has exited. Normal shutdown
   removes the exclusive `.lock`.
4. Confirm the journal and external current monotonic checkpoint refer to
   the correct DNA, oracle key and radius. Record path hash and last seq.
5. Reopen using `Journal::open_checked(path,dna,oracle,max_radius,
   &externally_authenticated_checkpoint,verifier)`, which re-verifies
   all signed history and refuses rollback before returning.
6. Compare the latest receipt, including signed statement bytes and
   signature; only then admit the next queued request.

**Never** call `bootstrap_new` on an old identity to bypass missing state.

## Actual process death (SIGKILL)

The deterministic `process_crash.rs` tests kill disposable native
subprocesses at the three fsynced boundaries, then assert:

- **After PREPARE, before SIGNING:** signed callback was not entered;
  `PreparedNotSigned` is safe to execute once after restart.
- **After the signer executed but before COMMIT:** the recovered journal is
  `SigningMayHaveOccurred`; all additional signing fails until outside
  reconciliation. A stale lock is also deliberately blocking.
- **After COMMIT but before caller acknowledgment:** original signature can
  be retrieved with `committed_retry(exact_statement)` without a second
  signer call or new sequence number.

After process death a stale `journal.lock` is expected. Human/operator
runbook: verify on the host and in the supervisor that no process or
second host is using that identity, stop auto-restarts, freeze permissions,
copy the journal and lock for forensics, then remove the stale lock and
fsync its directory. **Never auto-expire a live lock by elapsed time.**

## Backup and complete state loss

Backup only `Clean` state using `backup_clean(new_backup_path)`; it
refuses pending states and overwrites. Copy the journal to a separate
failure domain, with restrictive permissions. Persist the returned
`Checkpoint` in an independently authenticated **monotonic** system and
record DNA, oracle key, radius and original file hash.

For restoration, stop all signer instances and prove identity ownership.
Restore to a staging file outside the live journal path; fsync the staging
file and containing directory. Verify the entire signature chain through
the normal `Journal::open` path on a staging identity, then compare the
checkpoint with the **latest external** checkpoint. Only an exact match
allows promotion to the live identity, followed by another full
`open_checked` read before admitting new work. Do not overwrite a live
journal or bypass externally recorded newer sequence/floor.

If state is missing and the latest backup/checkpoint cannot be authenticated,
**fail closed and retire/quarantine the signer identity** until reviewed
restoration is possible. A freshly generated genesis for the same key/DNA
would permit replay and is unacceptable.

## Partial journal / filesystem corruption

Stop all callers and snapshot raw failed bytes before touching them.
`open` refuses partial records, wrong length, checksum mismatch, unknown
format version, wrong DNA/key/radius and invalid Ed25519 history. Do not
truncate an incomplete COMMIT automatically: the signature may already
have escaped to an external party. Repair from an authenticated complete
backup and external monotonic checkpoint or quarantine the identity.
A local filesystem's successful fsync is only as strong as its storage
implementation. NFS, network shares and multi-host writers are **not
validated**; require a single-writer durable local volume.

## Incomplete signing intent: reconciliation

`SigningMayHaveOccurred` represents an **uncertain signature**, not
necessarily an unsigned operation. Resolving it requires proof from a
trusted idempotent signing service or externally audited signature receipt
matching **exactly** the pinned unsigned statement and sequence. Sprint 24
does *not* implement receipt import because a cryptographically valid
signature alone cannot prove no second conflicting signature was issued.
Until a reviewed recovery mechanism is implemented, this identity remains
blocked for further signing. Key rotation with independent policy/DNA
review may be necessary.

## Migration from existing runtime or v2 records

The v2 oracle signed-statement format is domain-separated from the
proposed v3 signed-batch format. Do not reinterpret a v2 `seq`, `prev`,
`floor` or signature as a v3 batch commitment. Options require an ADR:

- **Fresh v3 identity (preferred)**: formally register a new signing key
  and DNA/policy with all verifiers; prove the old key retired, then
  `bootstrap_new` once. Preserve old v2 evidence/verification compatibility
  separately. A key rotation might require a controlled DNA upgrade.
- **Existing v3 history import**: stop the current signer, acquire all
  original signed v3 commitments from genesis through the last **externally
  anchored** head, prove every signature and prev/floor chain, replay them
  with `accept_verified` into a staging journal and fsync. Compare an
  external monotonic checkpoint and seek sign-off from Sprint 15/21
  owners. Any unknown history, duplicate seq or source-chain fork blocks.

An in-memory queue from Sprint 21 cannot recover an uncertain signing
result. Holochain `HeadMoved` is a source-chain appending race, *not*
permission to repeat a signing callback after a crash.

## Acceptance evidence and limitations

Run `bash scripts/oracle_state/run.sh --expected-sha <exact_sha>`
on a clean Unix host. Preserve the report's `audit.json`,
`provenance.txt`, stage logs and `SHA256SUMS`. Before production
acceptance additionally run true host/keystore integration, external
monotonic checkpoint rollback exercises, same-identity multi-process
admission, power-loss/storage fault injection, and integrated Sprint 15/21
orchestrator tests. None is certified by the native test suite alone.
