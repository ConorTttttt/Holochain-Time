//! Sprint 23: real external Roughtime + real Holochain 0.7 conductor acceptance.
#![allow(clippy::too_many_lines)]
//!
//! Deliberately #[ignore]: normal CI must NOT claim a genuine independent
//! external-operator test passed when live UDP services/approved DNA are absent.
//! Requires operator-reviewed DNA with actual source keys in DNA integrity,
//! HC_VTIME_LIVE_ROUGHTIME=1, and an explicit local operator registry.
//! The protocol authenticates keys and packets, not legal/administrative
//! independence: human infrastructure/key-control review is separately needed.

use hc_vtime_conductor_smoke::fixtures::test_public_keys;
use holochain::prelude::*;
use holochain::sweettest::*;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;
use vtime_core::evidence::{
    check_independent_roughtime_sources, verify_independent_roughtime_quorum,
    IndependentRoughtimeSource, RoughtimeEvidence, TimePolicy,
};
use vtime_core::hash::to_hex;
use vtime_core::keys::roughtime_key_from_b64;
use vtime_core::roughtime::{
    build_request, verify_response, MAX_RESPONSE_PACKET_SIZE, VERSION_DRAFT, VERSION_RFC,
};
use vtime_core::seal::seal_nonce;
use vtime_core::DalekVerifier;

const MIN_SOURCES: usize = 3;
const MAX_SOURCES: usize = 32;

#[derive(Deserialize)]
struct Registry {
    schema: String,
    sources: Vec<Remote>,
}

#[derive(Deserialize)]
struct Remote {
    name: String,
    operator: String,
    address: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct WitnessResult {
    target: ActionHash,
    not_before_us: Option<i64>,
    not_after_us: Option<i64>,
    evidence_complete: bool,
}

fn ensure_env() {
    assert_eq!(
        std::env::var("HC_VTIME_LIVE_ROUGHTIME").as_deref(),
        Ok("1"),
        "explicit live UDP test sentinel required"
    );
    assert!(
        std::env::var("HC_VTIME_SIGNED_TEST_ONLY").is_err(),
        "the public deterministic-signature fixture flag must NOT be present"
    );
}

fn entropy() -> [u8; 32] {
    let mut value = [0u8; 32];
    // Holonix is Linux. Actual externally acquired anchor nonces must not
    // be fixed public fixture values.
    std::fs::File::open("/dev/urandom")
        .expect("secure OS entropy unavailable; do not use a static anchor nonce")
        .read_exact(&mut value)
        .expect("cannot read secure OS nonce");
    value
}

fn load_registry(path: &Path) -> (Registry, Vec<IndependentRoughtimeSource>, TimePolicy) {
    let registry: Registry =
        serde_json::from_slice(&fs::read(path).expect("registry missing"))
            .expect("invalid registry JSON");
    assert_eq!(registry.schema, "hc-vtime/independent-roughtime/v1");
    assert!(
        (4..=MAX_SOURCES).contains(&registry.sources.len()),
        "need >=4 distinct candidate roots to test one source outage"
    );
    let sources: Vec<_> = registry
        .sources
        .iter()
        .map(|s| IndependentRoughtimeSource {
            operator: s.operator.clone(),
            public_key: roughtime_key_from_b64(&s.public_key)
                .expect("malformed trusted public root"),
        })
        .collect();
    let registered: Vec<_> = sources.iter().map(|source| source.public_key).collect();
    assert_eq!(
        registered.iter().collect::<HashSet<_>>().len(),
        registered.len(),
        "duplicate Roughtime root in source registry"
    );
    for pubkey in test_public_keys() {
        assert!(!registered.contains(&pubkey), "insecure known test signing root trusted");
    }
    let policy = TimePolicy {
        roughtime_servers: registered,
        oracles: Vec::new(),
        max_faulty: 1,
        min_sources: MIN_SOURCES as u32,
        max_radius_us: 10_000_000,
        oracle_dna: None,
    };
    check_independent_roughtime_sources(&sources, &policy)
        .expect("duplicate operator, unknown key or unsupported quorum");
    (registry, sources, policy)
}

fn query_real(address: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let addrs = address
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve UDP endpoint: {e}"))?;
    let mut last = "no usable UDP address".to_string();
    for addr in addrs {
        let reply = (|| -> Result<Vec<u8>, String> {
            let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
            sock.set_read_timeout(Some(Duration::from_secs(3)))
                .map_err(|e| e.to_string())?;
            sock.set_write_timeout(Some(Duration::from_secs(3)))
                .map_err(|e| e.to_string())?;
            sock.connect(addr).map_err(|e| e.to_string())?;
            sock.send_all(request).map_err(|e| e.to_string())?;
            let mut buffer = [0u8; MAX_RESPONSE_PACKET_SIZE + 1];
            let size = sock.recv(&mut buffer).map_err(|e| e.to_string())?;
            if size > MAX_RESPONSE_PACKET_SIZE {
                return Err("oversized UDP response rejected".into());
            }
            Ok(buffer[..size].to_vec())
        })();
        match reply {
            Ok(bytes) => return Ok(bytes),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn acquire(
    registry: &Registry,
    sources: &[IndependentRoughtimeSource],
    policy: &TimePolicy,
    nonce: [u8; 32],
    outage_operator: Option<&str>,
) -> (Vec<RoughtimeEvidence>, Vec<serde_json::Value>) {
    let mut accepted = Vec::new();
    let mut attempts = Vec::new();
    for (remote, source) in registry.sources.iter().zip(sources.iter()) {
        let disabled = outage_operator.is_some_and(|x| {
            x.eq_ignore_ascii_case(&remote.operator) || x.eq_ignore_ascii_case(&remote.name)
        });
        if disabled {
            attempts.push(json!({
                "name": remote.name, "operator": remote.operator,
                "outcome": "operator deliberately disabled for one-outage test"
            }));
            continue;
        }
        let request = build_request(
            &nonce, &[VERSION_RFC, VERSION_DRAFT], Some(&source.public_key),
        );
        let result = query_real(&remote.address, &request).and_then(|response| {
            verify_response(
                &source.public_key, &request, &response, &DalekVerifier,
            )
            .map_err(|error| format!("invalid Roughtime signature/cert/packet: {error}"))?;
            Ok(RoughtimeEvidence {
                server_public_key: source.public_key.to_vec(),
                request,
                response,
            })
        });
        match result {
            Ok(item) => {
                attempts.push(json!({
                    "name": remote.name, "operator": remote.operator, "outcome": "verified"
                }));
                accepted.push(item);
            }
            Err(error) => {
                attempts.push(json!({
                    "name": remote.name, "operator": remote.operator,
                    "outcome": format!("unavailable-or-invalid: {error}")
                }));
            }
        }
    }
    // Every included reading MUST already have passed full cryptographic
    // verification. Do not silently filter invalid data from a quorum.
    verify_independent_roughtime_quorum(
        &accepted, sources, policy, &DalekVerifier, &nonce,
    )
    .expect("fewer than 3 independent configured verified roots or forged packet");
    (accepted, attempts)
}

fn reject_seal(
    conductors: &SweetConductorBatch,
    cell: &SweetCell,
    conductor_index: usize,
    target: ActionHash,
    proof: Vec<RoughtimeEvidence>,
    reason: &str,
) -> impl std::future::Future<Output = ()> + '_ {
    async move {
        let result: Result<ActionHash, _> = conductors[conductor_index]
            .call_fallible(
                &cell.zome("vtime"),
                "seal_action",
                json!({"target": target, "roughtime": proof}),
            )
            .await;
        let err = format!("{:?}", result.expect_err("forged/invalid seal ACCEPTED"));
        assert!(
            err.contains("need 3 distinct trusted sources"),
            "{reason}: wanted authenticated quorum rejection; got {err}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires external Roughtime UDP and operator-reviewed DNA; execute only from Sprint 23 local runbook"]
async fn real_external_three_operator_quorum_and_negative_conductor_checks() {
    ensure_env();
    let dna_path = std::env::var("HC_VTIME_LIVE_DNA")
        .expect("HC_VTIME_LIVE_DNA must point to newly packed, reviewed-operator DNA");
    let config_path = std::env::var("HC_VTIME_LIVE_OPERATOR_REGISTRY")
        .expect("HC_VTIME_LIVE_OPERATOR_REGISTRY is required");
    let outage = std::env::var("HC_VTIME_LIVE_OUTAGE_OPERATOR").ok();
    let (registry, sources, policy) = load_registry(Path::new(&config_path));
    if let Some(name) = outage.as_deref() {
        assert!(registry.sources.iter().any(|s| {
            s.name.eq_ignore_ascii_case(name) || s.operator.eq_ignore_ascii_case(name)
        }), "unknown configured outage operator");
    }

    let dna = SweetDnaFile::from_bundle(Path::new(&dna_path))
        .await
        .expect("new independent-source DNA bundle not readable");
    let dna_raw = dna.dna_hash().get_raw_39().to_vec();
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors
        .setup_app("vtime-real-roughtime-acceptance", &[dna])
        .await
        .expect("real conductor install must succeed")
        .cells_flattened();
    assert_eq!(cells.len(), 3);
    assert_eq!(
        cells.iter().map(|cell| cell.agent_pubkey().clone()).collect::<HashSet<_>>().len(),
        3, "three distinct Holochain agents required"
    );
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("real conductors did not synchronize");

    // Anchor on Alice's actual chain using a fresh OS-random nonce. If the
    // deployed DNA trusted registry differs, validation refuses the evidence.
    let anchor_nonce = entropy();
    let (anchor_proof, _) = acquire(
        &registry, &sources, &policy, anchor_nonce, outage.as_deref(),
    );
    let target: ActionHash = conductors[0]
        .call(
            &cells[0].zome("vtime"),
            "create_anchor",
            json!({"roughtime": anchor_proof}),
        )
        .await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("genuinely signed target did not synchronize");

    let nonce = seal_nonce(&dna_raw, target.get_raw_39());
    let (signed, attempts) = acquire(
        &registry, &sources, &policy, nonce, outage.as_deref(),
    );
    assert!(signed.len() >= MIN_SOURCES);
    let seal: ActionHash = conductors[1]
        .call(
            &cells[1].zome("vtime"),
            "seal_action",
            json!({"target": target.clone(), "roughtime": signed.clone()}),
        )
        .await;
    assert_ne!(target, seal, "seal must be a distinct action");
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("signed third-party seal did not synchronize");

    let verified: WitnessResult = conductors[2]
        .call(
            &cells[2].zome("vtime"),
            "verify_time_with_witnesses",
            json!({"target": target.clone(),
                   "anchors": [target.clone()],
                   "seals": [seal.clone()]}),
        )
        .await;
    assert_eq!(verified.target, target);
    assert!(verified.not_before_us.is_some(), "missing authenticated anchor lower bound");
    assert!(verified.not_after_us.is_some(), "missing authenticated seal upper bound");
    assert!(verified.not_before_us <= verified.not_after_us);
    assert!(!verified.evidence_complete, "explicit witnesses are not global DHT enumeration");

    // The actual fully signed bytes used by the *real* Holochain conductor
    // are emitted for independent offline vtime_core replay (exact DNA and
    // target hashes). The Python runner captures this JSON in an evidence file.
    println!("HC_RT_RECEIPT {}", json!({
        "schema": "hc-vtime/roughtime-receipt/v1",
        "dna_hex": to_hex(&dna_raw),
        "target_hex": to_hex(target.get_raw_39()),
        "nonce_hex": to_hex(&nonce),
        "attempts": attempts,
        "evidence": signed.clone()
    }));
    println!("HC_RT_CONDUCTOR {}", json!({
        "schema": "hc-vtime/live-conductor-acceptance/v1",
        "dna_hex": to_hex(&dna_raw),
        "target_hex": to_hex(target.get_raw_39()),
        "seal_action": seal.to_string(),
        "verified_by_peer": true,
        "signed_roots": signed.len(),
        "requested_outage": outage,
        "operator_independence_proven": false,
        "replay_same_target_prevented_on_chain": false
    }));

    // Signed but wrongly bound to a *different* real target must fail.
    let wrong_target: ActionHash = conductors[0]
        .call(
            &cells[0].zome("vtime"),
            "create_anchor",
            json!({"roughtime": acquire(&registry, &sources, &policy,
                                       entropy(), outage.as_deref()).0}),
        )
        .await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("second target not synchronized");
    reject_seal(
        &conductors, &cells[2], 2, wrong_target, signed.clone(), "wrong target replay",
    )
    .await;

    // Two still-genuine signed responses cannot satisfy the three-source
    // acceptance policy: never downgrade min_sources in an outage.
    reject_seal(
        &conductors, &cells[2], 2, target.clone(), signed[..2].to_vec(),
        "one extra source unavailable leaves only two",
    )
    .await;

    let mut forged = signed.clone();
    let last = forged[2].response.len();
    assert!(last > 20);
    forged[2].response[last - 8] ^= 0x40;
    reject_seal(
        &conductors, &cells[2], 2, target.clone(), forged, "tampered signature/packet",
    )
    .await;

    let mut duplicate = signed.clone();
    duplicate[2] = signed[0].clone();
    reject_seal(
        &conductors, &cells[2], 2, target.clone(), duplicate, "duplicate operator key",
    )
    .await;

    // Wrong-DNA rebind must fail cryptographically before any Holochain call.
    let different_dna = [0xA1; 39];
    let nonce_from_wrong_dna = seal_nonce(&different_dna, target.get_raw_39());
    assert!(verify_independent_roughtime_quorum(
        &signed, &sources, &policy, &DalekVerifier, &nonce_from_wrong_dna,
    ).is_err(), "wrong DNA nonce accepted");
    let nonce_from_other_target = seal_nonce(&dna_raw, &[0xA2; 39]);
    assert!(verify_independent_roughtime_quorum(
        &signed, &sources, &policy, &DalekVerifier, &nonce_from_other_target,
    ).is_err(), "wrong target nonce accepted");

    // Same-DNA, same-target cryptographic evidence remains repeatable. This
    // is intentional and MUST NOT be misreported as fresh or globally consumed.
    assert!(verify_independent_roughtime_quorum(
        &signed, &sources, &policy, &DalekVerifier, &nonce,
    ).is_ok(), "correct same-target signature must remain valid");

    println!("HC_RT_NEGATIVE {}", json!({
        "schema": "hc-vtime/live-roughtime-negative-tests/v1",
        "wrong_target_rejected": true,
        "wrong_dna_nonce_rejected": true,
        "two_source_quorum_rejected": true,
        "forged_packet_rejected": true,
        "duplicate_key_rejected": true,
        "same_target_crypto_reuse_permitted": true
    }));
}
