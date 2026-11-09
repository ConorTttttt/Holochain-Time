# Parallel signed-quorum integration track

Based on validation smoke PR #38. Separate from the owner's merges.
Status: implementation review, not yet compiled or run.

- [x] Four actual distinct test-only Roughtime signing keys, not repeated fixed TestContext identity.
- [x] Real RFC 10049 request/response fixture generator using Roughenough 2.2.
- [x] Disposable manifest generator: four trusted Roughtime keys, no oracle fallback, 3-of-4 with f=1.
- [x] Three Sweettest conductors: Alice anchors, Bob seals, Charlie verifies after DHT propagation.
- [x] Negative cases: two-source quorum, wrong nonce, duplicate signer, tampered packet.
- [x] Exact-commit build/pack/run shell entrypoint with separate evidence logs.
- [x] 14 local offline Python tests and shell syntax validation.
- [ ] Native Rust compilation, zome WASM build and real conductor execution. Cargo unavailable here.
- [ ] Review and pin generated standalone integration Cargo.lock.
- [ ] Production source independence, outages/partitions, load, Unyt and audit still pending.

All fixtures use well-known insecure seeds and must NEVER be deployed.
Wider release: NO-GO.
