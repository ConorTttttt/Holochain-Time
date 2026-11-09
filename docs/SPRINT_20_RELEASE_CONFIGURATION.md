# Sprint 20 — Holochain Time deployment configuration safety

**Status: GitHub-first release tooling. No main merge, production deployment, live signing credentials, independently verified operator reviews, or production release authorization.**

## Boundaries and fail-closed requirements

Holochain Time's actual validation policy is part of the DNA integrity properties in `dnas/vtime/workdir/dna.yaml` (`VtimeProperties` in the integrity zome). Key rotation, source changes, `min_sources`/`max_faulty`, radii or network seed changes produce a NEW DNA hash and require migration. Sprint 20 does **not** change the DNA schema, source consensus, or the production verification interfaces owned by Sprint 11.

Two Python 3 standard-library commands are introduced:

- `scripts/deployment_preflight.py` validates the **exact bytes** of a prepared DNA YAML, the separately reviewed deployment policy and (for production) the **separate human approval**. Production requires external SHA-256 pins for both the manifest and policy. It never installs or packs a DNA.
- `scripts/pack_release_dna.py` invokes the same preflight **before** running `hc dna pack`; only when approved does it stage the reviewed manifest and two pinned WASM binaries in a disposable directory. It produces a bundle, SHA-256 file and provenance without installing/deploying it. Production also requires independently reviewed WASM digests and exact local Git SHA.

**Direct `hc dna pack` and direct conductor installation bypass these guards.** The release process MUST only accept artifacts emitted by the guarded packer and independently verify the attached hashes, source commit and approval. This repository cannot prevent an operator with filesystem/cluster access from bypassing the wrapper, and it does not claim runtime enforcement in the Holochain engine.

## Production preflight and guarded packaging

1. Use the templates in `deployment/environments/production.dna.example.yaml`, `production.policy.example.json`, and `production.approval.example.json` as **non-runnable examples only**. Copy them to an **external, access-controlled staging folder** (never check in real approvals or any secret). Review every supported field against `deployment/policy.schema.json` and `deployment/approval.schema.json`.
2. Replace placeholders with long-term Roughtime root keys **directly authenticated with operators**, credible HTTPS key provenance, stable operator identifiers, root key ownership evidence, shared-hosting/upstream dependency review and tested compatible protocol (`rfc10049` or `draft15`). Sprint 11's candidate `config/roughtime-independent-sources.json` may help identify providers **after the branches are integrated**; it is NOT pre-approved. Cloudflare's documented draft11 endpoint must not be counted while unsupported. Never substitute public Roughenough fixture signer keys.
3. Set a new sufficiently random and environment-unique DNA network seed. Do not point an unreviewed staging build at production DNA, clone a release network seed, or reduce `min_sources` below 3. Baseline requires `max_faulty=1`, `min_sources=3`, **at least 4 distinct source keys** to tolerate one offline source, and at least 3 Roughtime roots. If `max_faulty` increases, preflight requires `min_sources >= 2*f+1` and at least `min_sources+f` source identities. The count alone is NOT evidence of their independent administration.
4. Produce native signed Roughtime request/response captures (including protocol, delegated signature, nonce/Merkle verification), collect SHA-256 of those artifacts for each actual operator and get **two human reviewers** to inspect who controls every signing key, shared providers/upstreams, reachable supported endpoints and fresh signed receipts. Complete `production.approval.json`, setting `approval_status` to `approved` and recording evidence hashes **only after actual review**. These fields are untrusted human assertions, not cryptographically authenticated attestations.
5. Pin SHA-256 of the final immutable DNA YAML and deployment policy outside both files. Generate independently verified WASM hashes and full tested Git commit SHA. A SHA over a file computed inside that same file is not an independent trust anchor.

Sample commands (paths and expected SHA placeholders MUST be replaced before any real run):

```sh
sha256sum /secure/release/dna.yaml /secure/release/policy.json
sha256sum target/wasm32-unknown-unknown/release/vtime_integrity.wasm \
  target/wasm32-unknown-unknown/release/vtime.wasm
git rev-parse HEAD
python3 scripts/deployment_preflight.py \
  --environment production \
  --manifest /secure/release/dna.yaml \
  --policy /secure/release/policy.json \
  --approval /secure/release/approval.json \
  --expected-manifest-sha256 '<reviewed DNA manifest SHA-256>' \
  --expected-policy-sha256 '<reviewed policy SHA-256>' \
  --output /secure/evidence/preflight-unique.json
```

A nonzero exit or `status=BLOCKED` means **DO NOT PACK, INSTALL OR START** the configuration. Preflight output contains `operator_independence_proven=false` and `safe_to_install_proven=false` even when all static checks pass. Never use `--allow-development-test-keys` on production/staging; the library also refuses to apply that bypass to a production manifest.

Guarded packaging (still **not deployment**):

```sh
python3 scripts/pack_release_dna.py \
  --environment production \
  --manifest /secure/release/dna.yaml \
  --policy /secure/release/policy.json \
  --approval /secure/release/approval.json \
  --expected-manifest-sha256 '<reviewed manifest SHA-256>' \
  --expected-policy-sha256 '<reviewed policy SHA-256>' \
  --expected-integrity-wasm-sha256 '<reviewed integrity WASM SHA-256>' \
  --expected-coordinator-wasm-sha256 '<reviewed coordinator WASM SHA-256>' \
  --expected-commit-sha '<full reviewed Git commit SHA>' \
  --output-dir /secure/evidence/new-release-package
cd /secure/evidence/new-release-package
sha256sum -c SHA256SUMS
```

The output bundle MUST be installed only after an authorized operator independently validates the source commit and fresh DNA identity, 3-source live signed quorum, Roughtime root-key operator control, quorum outage behavior, environmental networking and conductor compatibility. The guarded packer never calls `hc app install`, `hc app enable`, `holochain`, Unyt or a remote API.

## Environment templates and test identities

| Environment | Checked-in examples | Gate |
| --- | --- | --- |
| `production` | `production.dna.example.yaml`, `production.policy.example.json`, `production.approval.example.json` | All key pins and approvals are unresolved; **blocked** until distinct reviewed operators, two reviewers, pinned manifest/policy/WASMs and exact commit are provided |
| `staging` | `staging.dna.example.yaml`, `staging.policy.example.json` | External signing identities, supported protocol and distinct operator mapping required; staging cannot use known insecure identities. Separate approval optional; no production acceptance implied |
| `development` | `development.dna.example.yaml`, `development.policy.example.json` | Examples use publicly known repeated-seed identities solely for local testing. Requires explicit `--allow-development-test-keys` and `--environment development` to bypass the denylist. **NEVER DEPLOY THIS DNA TO A PUBLIC NETWORK.** |

The catalog `deployment/known_insecure_keys.json` explicitly rejects known publicly exposed Ed25519 seed-derived keys, including 51–54 (local signed-quorum fixture material), the zero seed, and deterministic fixture keys used by the Unyt harness. It also rejects a zero or repeated-byte raw key and cross-role duplicate raw signing keys. This denylist is **not exhaustive**: a key *not* in the list is not necessarily secure; account ownership, provenance and management must be audited separately.

The preflight rejects placeholder identity strings, malformed/canonically misencoded Ed25519 public keys (including Holochain agent checksum), unknown YAML features/duplicate settings, unknown JSON fields/duplicate keys, duplicate operator IDs or casefolded labels, repeated UDP endpoints, unsupported draft11 protocols, private/loopback endpoints outside development, unknown source trust roots, insufficient fault/outage margin and missing review records. Operator labels are advisory: one organization can control many keys/domains under different labels. Even a PASS cannot prove organizational independence or successful live signed responses.

## Configuration migration and rollback

**Never silently edit an installed DNA and claim an in-place key rotation.** DNA integrity properties are part of the DNA hash. Changes require a new network identity.

1. Inventory the current deployed DNA hash, signed-seal verification coverage, old operator keys and accepted evidence. Export a read-only copy of the old manifest and lock each artifact by SHA-256.
2. Independently review the new operator registry, key provenance, protocol compatibility, and outage thresholds in Sprint 11. Prepare a new production policy with explicit **new network seed**, do not reuse the original DNA hash, and record both old and proposed DNA hashes.
3. Build new WASMs at a reviewed exact Git commit; run Sprint 17 local validation plus native/conductor and adversarial acceptance; run the Sprint 20 preflight and guarded DNA pack on the final **unchanged** release manifest. Archive report, SHA256SUMS and reviewer references.
4. Stage the new DNA as a separate Holochain cell and migrate application client references, role assignments, witness collection and oracle statement chains deliberately. Never assume proof/nonce from old DNA can be replayed under the new DNA; verify DNA and target binding again. Record any new genesis and chain continuity plan.
5. Roll out with a monitored overlap window. Old evidence must remain verifiable under its original DNA key policy; do not rewrite the history or label old signer keys as new roots. Observe actual operator response rates, conductor health and ≥3-source quorum with one source offline.
6. On failed acceptance, stop new writes/installations for the new DNA and route clients back to the separately preserved old cell **only after revalidating its own release policy and key safety**. A prior unsafe configuration is not a safe rollback target. Do not downgrade `min_sources` as a workaround.

## Offline negative tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts \
  -p 'test_deployment_preflight.py' -v
# Expected FAIL CLOSED for the checked-in production examples:
python3 scripts/deployment_preflight.py \
  --environment production \
  --manifest deployment/environments/production.dna.example.yaml \
  --policy deployment/environments/production.policy.example.json
```

Before promotion, Codex must run the complete Python suite and existing Rust/WASM/conductor suites on the combined exact SHA. The GitHub Actions runner-not-assigned issue remains an infrastructure blocker rather than evidence that code passed/failed. Do not use production wallet keys or funded Unyt credentials in GitHub, CI or this preflight.

## Integration interfaces / acceptance

Sprint 11 owns actual Roughtime packet verification and operator trust policy; Sprint 20 only cross-checks offline configuration and human provenance. If Sprint 11 changes DNA properties, the parser/schema/examples here must be updated **together**, and the final candidate must compile/re-run with the new DNA hash. Coordinate through PR review rather than modifying shared Rust crypto code in this sprint.

- [ ] All static negative tests pass at exact final SHA with logs.
- [ ] Production examples remain blocked; no test identity or unknown key reaches guarded pack.
- [ ] Reviewed production config, human approval, exact source/WASM pins and manifest hashes are reproducible on the integrated commit.
- [ ] At least three truly independent and live authenticated Roughtime operators validated **outside this tool**, with no quorum reduction.
- [ ] Every production release stage requires preflight and guarded pack; installation pipeline verifies corresponding hashes and real signed Roughtime evidence.
- [ ] A separate security/release reviewer signs off; the tool never claims operator independence or deployment readiness by counting keys.
