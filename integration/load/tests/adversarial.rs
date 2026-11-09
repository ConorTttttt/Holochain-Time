//! Adversarial rejection under load against actual zome boundaries.
use futures::future::join_all;
use hc_vtime_conductor_smoke::fixtures::signed_three;
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::json;
use std::path::Path;
use std::time::Instant;
use vtime_core::error::Error;
use vtime_core::evidence::{verify_evidence_set, TimeEvidence, TimePolicy};
use vtime_core::roughtime::{
    build_request, verify_response, MAX_REQUEST_PACKET_SIZE, MAX_RESPONSE_PACKET_SIZE, VERSION_RFC,
};
use vtime_core::verifier::Ed25519Verifier;

struct NoCrypto;
impl Ed25519Verifier for NoCrypto {
    fn verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> vtime_core::Result<bool> {
        panic!("oversized packet reached expensive signature verification")
    }
}

#[test]
fn native_packet_and_evidence_bounds_under_repeated_attack() {
    let verifier = NoCrypto;
    let request = build_request(&[3; 32], &[VERSION_RFC], None);
    let bad_request = vec![0x51; MAX_REQUEST_PACKET_SIZE + 1];
    let bad_response = vec![0x52; MAX_RESPONSE_PACKET_SIZE + 1];
    assert!(request.len() <= MAX_REQUEST_PACKET_SIZE);
    let policy = TimePolicy {
        roughtime_servers: vec![[1; 32], [2; 32], [3; 32]],
        oracles: vec![],
        max_faulty: 1,
        min_sources: 3,
        max_radius_us: 10_000_000,
        oracle_dna: None,
    };
    let dummy = TimeEvidence::Roughtime(vtime_core::evidence::RoughtimeEvidence {
        server_public_key: vec![1; 32],
        request: request.clone(),
        response: bad_response.clone(),
    });
    let oversized = vec![dummy; 33];
    let start = Instant::now();
    for _ in 0..512 {
        assert!(matches!(
            verify_response(&[1; 32], &bad_request, &request, &verifier),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            verify_response(&[1; 32], &request, &bad_response, &verifier),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            verify_evidence_set(&oversized, &policy, &verifier, None),
            Err(Error::Malformed(_))
        ));
    }
    println!(
        "HC_ADVERSARIAL {}",
        json!({
            "kind": "native_bounded_rejection",
            "iterations": 512, "checks_per_iteration": 3,
            "total_rejected": 1536, "unexpected_accepted": 0,
            "wall_ms": start.elapsed().as_secs_f64() * 1000.0,
            "request_max_bytes": MAX_REQUEST_PACKET_SIZE,
            "response_max_bytes": MAX_RESPONSE_PACKET_SIZE,
            "evidence_item_max": 32
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn oversized_witnesses_and_evidence_fail_closed_under_load() {
    assert_eq!(
        std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(),
        Ok("1"),
        "test-only key sentinel required"
    );
    let file = std::env::var("HC_VTIME_TEST_DNA").expect("test DNA required");
    assert!(Path::new(&file).is_file());
    let dna = SweetDnaFile::from_bundle(Path::new(&file))
        .await
        .expect("invalid test DNA");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors
        .setup_app("vtime-adversarial-load", &[dna])
        .await
        .expect("conductor installation failed")
        .cells_flattened();
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("conductor consistency failed");

    let target = ActionHash::from_raw_32(vec![0x51; 32]);
    let mut oversized_readings = signed_three([0xAB; 32], 1_800_000_000);
    while oversized_readings.len() < 33 {
        oversized_readings.push(oversized_readings[0].clone());
    }
    let jobs = (0..128).map(|attempt| {
        let ix = attempt % 3;
        let conductor = &conductors[ix];
        let zome = cells[ix].zome("vtime");
        let target = target.clone();
        let readings = oversized_readings.clone();
        async move {
            let kind = if attempt % 2 == 0 {
                "oversized_witnesses"
            } else {
                "oversized_roughtime_items"
            };
            let start = Instant::now();
            let result: Result<serde_json::Value, _> = if attempt % 2 == 0 {
                conductor
                    .call_fallible(
                        &zome,
                        "verify_time_with_witnesses",
                        json!({"target": target.clone(), "anchors": [],
                        "seals": vec![target; 33]}),
                    )
                    .await
            } else {
                conductor
                    .call_fallible(
                        &zome,
                        "seal_action",
                        json!({"target": target, "roughtime": readings}),
                    )
                    .await
            };
            let error = result.err().map(|e| format!("{e:?}"));
            let expected = if attempt % 2 == 0 {
                "33 records exceed safe limit 32"
            } else {
                "too many Roughtime readings for a seal"
            };
            let safe_rejection = error.as_ref().is_some_and(|s| s.contains(expected));
            json!({
                "attempt": attempt, "kind": kind, "conductor": ix,
                "ok": safe_rejection, "latency_ms": start.elapsed().as_secs_f64() * 1000.0,
                "error": error.as_ref().map(|s| s.chars().take(600).collect::<String>()),
                "unexpected_accepted_or_wrong_failure": !safe_rejection
            })
        }
    });
    let samples = join_all(jobs).await;
    for sample in &samples {
        println!("HC_LOAD_SAMPLE {}", sample);
    }
    let unsafe_count = samples.iter().filter(|s| s["ok"] != true).count();
    println!(
        "HC_ADVERSARIAL {}",
        json!({
            "kind": "conductor_bounded_rejection", "attempts": samples.len(),
            "correct_rejections": samples.len() - unsafe_count,
            "incorrect_or_unexpected": unsafe_count
        })
    );
    assert_eq!(samples.len(), 128);
    assert_eq!(
        unsafe_count, 0,
        "adversarial request was not rejected for the expected reason"
    );
}
