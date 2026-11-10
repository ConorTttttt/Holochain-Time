# Sprint 24 — Acceptance evidence ledger

**Current state:** GitHub code available, no executed Rust/Holochain
regression evidence on the exact candidate commit yet.

| Scenario | Native test | Evidence |
| --- | --- | --- |
| Normal restart preserves trusted sequence, prev and floor | `restart_safety::normal_restart_preserves_verified_chain_seq_and_highwater` | NOT RUN |
| Crash before signing — safe prepared retry | `process_crash::actual_process_kill_before_signer_fence_allows_retry` | NOT RUN |
| Crash after signer invocation — quarantine/no second signature | `process_crash::actual_process_kill_after_signer_call_blocks_second_signature` | NOT RUN |
| Commit durable but reply lost — reissue exact signature only | `process_crash::actual_process_kill_after_durable_commit_returns_original_receipt` | NOT RUN |
| Replay old signature/duplicate sequence | `restart_safety::stateful_verifier_denies_duplicate_signed_seq_and_conflicting_histories` | NOT RUN |
| Wrong previous commitment and lower high-water | Same as above | NOT RUN |
| Missing state or changed identity/policy | `restart_safety::corruption_partial_append_policy_change_and_missing_state_fail_closed` | NOT RUN |
| Corrupted/truncated journal fails closed | `restart_safety::truncated_tail_is_not_silently_ignored_or_replayed` | NOT RUN |
| Concurrent opener blocked | `restart_safety::same_identity_cannot_be_opened_by_two_writers_at_once` | NOT RUN |
| Backup/valid restore | `backup_migration::safe_backup_matches_exact_externally_recorded_checkpoint_and_resumes` | NOT RUN |
| Older backup vs external later checkpoint | `backup_migration::rolling_back_a_valid_backup_fails_against_newer_checkpoint` | NOT RUN |
| Signing in-flight cannot be backed up | `backup_migration::backup_is_blocked_while_a_signed_commit_may_be_in_flight` | NOT RUN |
| Real native Lair/HSM signing integration | Not included in branch | NOT IMPLEMENTED |
| Monotonic external checkpoint transport and authorization | Caller-supplied checkpoint API only | NOT IMPLEMENTED |
| Signed batch integrated with conductor and queue | Sprints 15/21 coordination | NOT IMPLEMENTED |
| Real power-loss recovery across host reboot | Requires separate fault injection | NOT RUN |

**Release decision: NO-GO.** Do not conflate isolated Rust tests
with full runtime signing, backup independence, external antirollback,
or completeness of signed oracle source-chain history.
