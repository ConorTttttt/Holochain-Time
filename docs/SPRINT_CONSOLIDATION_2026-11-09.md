# Development baseline consolidation — 9 November 2026

Starting remote main: `ea2814a87b06b440fbd25c873cdbb6dc87105517`.
Candidate branch: `integration/consolidate-completed-sprints`.
This is development consolidation. The production release decision remains NO-GO.
Exact final commit, toolchains, test counts, DNA hash, artifact checksums and logs
are recorded in external validation evidence and the integration pull request.

## Branch integration matrix

No listed branch head was an ancestor of starting main. Test status below refers
to coverage required on the combined final candidate, not inherited green tests.
All complete branches are merged normally; cumulative ancestors need no separate
merge. The original branch tips and PRs are preserved.

| Branch (prefix omitted where indicated) | Already in starting main? | New work | Test status / gate | Security risk | Action |
|---|---|---|---|---|---|
| integration/main-promotion-2026-11-09 @ a625a90 | No | Cumulative 1–9 and smoke | Full local suite + fresh DNA | Security-critical baseline | Normal merge |
| sprint/01-foundation-evidence-2026-11-09 @ a451499 | No | Core, zomes, Unyt prototype | Native evidence regressions | Crypto/financial | Included through cumulative ancestry |
| sprint/02-proof-witness-api-2026-11-09 @ a61583a | No | Explicit witnesses | Native + conductor witnesses | Incomplete discovery must stay explicit | Included; hardened witness identity and ancestry |
| sprint/03-roughtime-packet-budgets-2026-11-09 @ 9798848 | No | Bounded packet parsing | Interop and mutation tests | Untrusted packet inputs | Included through cumulative ancestry |
| sprint/04-disable-unsafe-index-2026-11-09 @ 9fad694 | No | Disable global scans | Native + conductor rejection | Unbounded DHT scans | Included through cumulative ancestry |
| sprint/05-roughtime-first-quorum-2026-11-09 @ b7a1abf | No | Verified Roughtime fast path | Quorum regressions + signed conductor | Signature, nonce and source counting | Included through cumulative ancestry |
| sprint/06-oracle-batch-commitments-2026-11-09 @ ce638be | No | Bounded Merkle primitive | Native boundary/replay tests | Primitive is not signed batch acceptance | Included; runtime batching deferred |
| sprint/07-ci-provenance-2026-11-09 @ 62bf4e5 | No | Exact-SHA evidence | Python + verifier script | False CI claims | Included; hosted CI remains unavailable |
| sprint/07-local-test-harness-2026-11-09 @ b45b682 | No | Original local runner | Existing unit/command checks | Stale refs must block | Normal ancestry merge; preserve Sprint 8 improvements |
| sprint/08-reconcile-test-stack-2026-11-09 @ f2cacae | No | Stack audit and combined tooling | Python + candidate ancestry | Historical stack can differ from final candidate | Included through cumulative ancestry |
| sprint/09-integration-candidate-2026-11-09 @ ca107d4 | No | Reconcile current sprint heads | Candidate ancestry | Older security fixes must survive | Included through cumulative ancestry |
| validation/build-and-conductor-smoke-2026-11-09 @ 9647edb | No | Original smoke infrastructure | Separate real smoke gate | Smoke is not signed acceptance | Included through signed-test merge |
| validation/conductor-integration-local @ 78000bf | No | Locked local smoke harness | Standalone locked build + smoke | Bundle provenance | Included through main-promotion merge |
| validation/signed-roughtime-quorum-2026-11-09 @ 2f77b9f | No | Distinct signed test keys, disposable DNA | Signed conductor gate + Python | Public insecure test seeds | Normal merge; test-only isolation retained |
| local sprint/10-signed-quorum-acceptance-2026-11-09 @ 78000bf | No | No commits beyond local smoke | Same smoke harness | Branch name overstates content | Already included; signed work comes from validation branch |

Discovery found 13 open draft PRs (#16, #19, #21, #24, #26, #28, #30,
#32, #34, #36, #38, #40, #41) and no merged PRs. Their draft status is
historical development state, not release approval. No sprint branches or
PRs are deleted or silently rewritten by consolidation.

## Security review and necessary integration fixes

Reviewed coordinator, integrity, Roughtime parser, evidence policy, signature
verifiers, oracle state and batch primitive. Delegation and response signatures
remain required; sealed readings remain bound to DNA and target through their
nonce. Duplicate sources cannot satisfy quorum, and one key cannot count in
both oracle and Roughtime roles. Invalid supplied witnesses fail closed.
Legacy global evidence queries remain disabled. Witness conclusions retain
`evidence_complete=false` and never claim global consistency. Oracle fallback
is limited to recent signed readings for lower bounds; seals require their own
nonce. Batch membership alone never authenticates a timestamp. No settlement
activation or deployment keys are introduced.

Two coordinator issues were fixed during review: unbounded ancestry length and
witness decoding without checking its declared app entry type. ADR 010 records
the 256-action cap and exact entry identity checks. Regression coverage includes
real descendant ancestry and a TimeSeal misrepresented as a TimeAnchor. The
integrity configuration is unchanged, so these fixes require no DNA migration.

The signed runner uses locked dependencies, builds fresh zomes, packages a
unique test DNA, preserves the manifest/bundle, and records independent smoke
and signed-quorum logs. Its known public test keys are never installed in the
tracked source manifest. The standalone harness lockfile adds Roughenough and
its dependencies, resolving compatible locally cached versions; the production
workspace lockfile is unchanged.

The first signed-conductor run exposed a harness serialization defect:
MessagePack byte-valued Holochain hashes cannot decode into JSON Value. Typed
witness responses now validate the real wire output, and negative scenarios
require the specific expected guest error. A decode or unrelated conductor
failure cannot satisfy a rejection test. The runner executes smoke separately
even if signed acceptance fails and returns a failure if either gate fails.

This review is an integration review by the implementing assistant, not an
independent security audit. Remaining resource risks include per-record payload
and network latency, operator-configured oracle lists, long local oracle-log
recovery, and chain health responses. No global completeness guarantee follows.

## Validation and limitations

Final promotion requires clean exact-SHA formatting, all native and Python
tests, Clippy with denied warnings, both WASM zomes, standalone conductor build,
a freshly packed DNA, three-agent smoke and the signed-quorum scenario. External
provenance and SHA256SUMS are authoritative for the actual executed results.
The installed CLI may be 0.7.0 while the locked Sweettest conductor library is
0.7.1; record both rather than reporting a single ambiguous Holochain version.

GitHub-hosted workflows are not evidence of success when billing prevents their
jobs from starting. No payment, protection downgrade or administrative bypass
is part of this integration. The branch endpoint reports main unprotected;
protection/rules detail endpoints returned HTTP 403 for this private repository.
Normal PR merge must still be permitted by GitHub at promotion time.

## Deferred release work and next sprint

Sprint 1–9 implementation is incorporated; original acceptance checklists retain
release work beyond their code. Sprint 10 now has test-only signed-quorum
coverage, not independent-source acceptance or production readiness. Sprint 6
runtime signed batch transport/acceptance remains a prototype follow-up.

Next sprint: independent-source and resilience acceptance.

1. Pin authentic independently operated Roughtime keys and collect verifiable
   real request/response exchanges. Prove source identity and operator separation;
   accept a three-source quorum and reject unknown, duplicate, replayed,
   wrong-network and forged evidence.
2. Exercise one unavailable source at f=1, network partition/rejoin, conductor
   and oracle restart, fork/warrant handling, and missing witnesses. Preserve
   refusal on unavailable required dependencies and record recovered floors.
3. Run 100+ concurrent seals and adversarial witness/payload load with p50/p95/p99,
   memory and request budgets. Verify recent anchors work and over-budget
   ancestry fails explicitly without unbounded fetching.
4. Execute Unyt agreements with test funds, validating intended payouts and all
   rejection paths; complete independent security/economic review before funds.
5. Restore executable CI or obtain explicit approval for an independently
   reviewed local-evidence alternative. Never relabel unexecuted workflows PASS.

Acceptance requires reproducible exact-commit logs, artifact hashes, separate
smoke versus signed/resilience results, and reviewer sign-off on release gates.
