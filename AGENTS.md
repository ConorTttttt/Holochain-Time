# Repository coding instructions — hc-vtime

## Holochain version contract
This project is on **HDK =0.7.1 / HDI =0.8.1 / holochain_integrity_types 0.7.1** according to the committed Cargo.lock. Before changing a zome, confirm the lockfile and target/toolchain versions. Do not silently apply APIs from 0.6 or later unstable Holochain lines.

Design reference: https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain (architecture, patterns, ReviewZome, data modelling and Sweettest; read source version before using examples). Reference material is guidance, not a substitute for compiling against pinned crates.

## Holochain invariants
- **Integrity zome** owns entry/link definitions and deterministic validation. No clock, randomness, mutable local state or nondeterministic DHT reads. Use supported must_get_* dependency operations only.
- **Coordinator zome** owns remote oracle calls, record discovery, source-chain inspection, data assembly and query APIs.
- Explicit proof hashes must not be trusted until entry type, target/author binding, cryptographic evidence and relevant source-chain ancestry are verified.
- Shared DHT indexes and get_links results can be incomplete, spammed or expensive. Never truncate a security-relevant set and then claim global completeness or a globally clean timestamp.
- The new verify_time_with_witnesses endpoint returns only a finding about **caller-supplied evidence**; evidence_complete is false. A financial app must not mistake NoContradictionInSuppliedProofs for proof that no contradictory evidence exists.
- Fail closed on unavailable dependencies for any proof the caller supplied. Bound record requests, payloads and concurrency.
- Keep the v1→v2 statement/financial-agreement compatibility policy explicit, and do not alter DNA integrity configuration without a migration plan.

## Validation gates
- cargo test --workspace --locked
- cargo clippy --workspace --all-targets --locked -- -D warnings
- WASM zome builds with getrandom_backend="custom" and the correct Holochain host imports (Rust 1.96+ changed default WASM linker behavior).
- Real packaged hApp tests in a multi-agent conductor before release. See docs/CONDUCTOR_TEST_MATRIX.md.
- Independent security/economic review and test-funded Unyt acceptance before real funds.

Current release decision: **NO-GO**. Review the master gate in issue #1 and the sprint checklists; do not merge draft sprint PRs as a release approval.
