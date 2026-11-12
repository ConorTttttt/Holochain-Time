# PROPOSED: reviewed-disposition policy for `s35_supply_chain` (inactive)

**Status: proposal on review branch `proposal/s35-reviewed-disposition-policy`.
Not approved, not activated and not wired into any gate.** The current
`s35_supply_chain` gate keeps failing whenever a scanner command fails. This
is unchanged.

Changing what the gate consumes is a security-policy change. Only the project
owner can approve it, and it must then be validated separately. Prepared by
automated analysis (Claude Code).

## What the proposal would do

`scripts/security/proposed_disposition_gate.py` builds on the Sprint 37
evaluator. It could clear only if **all** of the following hold:

1. A **human activation record**
   (`hc-vtime/disposition-policy-activation/v1`) is bound to the SHA-256 of
   the policy file and to the exact evaluated commit, and has not expired.
   With no record, the result is `PROPOSED_INACTIVE` / `BLOCKED`.
2. Scanner evidence exists for root, conductor and load: `cargo audit --json`
   plus `cargo deny check advisories|licenses|bans|sources` exit codes and
   scanner versions. A missing scanner gives INVALID.
3. Every scanner finding has a matrix row. A newly introduced advisory gives
   INVALID.
4. Every non-patched row carries a human approval that:
   * names the exact evaluated commit;
   * has `expires_at_utc` in the future and `approved_at_utc` not in the
     future;
   * has a `scope` matching finding, package, version and approved status;
   * has a scope `graphs` list covering every graph where the scanner
     reports the finding.
5. `licenses`, `bans` and `sources` exit codes are 0. **They are never waived.**

Each evaluation appends a SHA-256 hash-chained entry to an append-only
history file outside the checkout. Before appending, the evaluator verifies
the chain and refuses a history that has been altered or truncated. Results
keep the raw exit codes and artifact hashes, and list `patched_and_tested`,
`not_applicable_approved` and `accepted_residual_risk` separately.

## Tests

`scripts/security/test_proposed_disposition_gate.py` covers 15 cases:

* inactive by default;
* missing, expired, future-dated, wrong-commit and mismatched approvals;
* findings outside the approved graph scope;
* new vulnerabilities;
* missing scanners;
* non-waivable license failures;
* preservation of raw results;
* residual-risk vs patched separation;
* activation binding;
* a tamper-evident history.

## To adopt (owner)

1. Review and approve this policy text and evaluator.
2. Record the activation (human, role, policy SHA-256, commit, expiry).
3. In a separate, reviewed change, wire it into
   `scripts/integration_preflight_35.py` and validate that change.
4. Add per-finding approvals to the matrix.

None of these steps has been taken.
