//! Sprint 21: >=100 simultaneously submitted tasks, with per-agent queues,
//! writing actual signed TimeSeal entries and links on three real conductors.
//! This is a local one-host test with public fixture signers, NOT live UDP.
#[path = "../src/seal_queue.rs"]
mod seal_queue;

use futures::future::join_all;
use hc_vtime_conductor_smoke::fixtures::{signed_three, INSECURE_TEST_SEEDS};
use holochain::prelude::*;
use holochain::sweettest::*;
use seal_queue::{is_holochain_head_moved, QueueConfig, SealQueue};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

#[derive(Deserialize)]
struct VerifiedTime {
    target: ActionHash,
    not_before_us: Option<i64>,
    not_after_us: Option<i64>,
    evidence_complete: bool,
}

fn epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn requested(name: &str, default: usize, min: usize, max: usize) -> usize {
    let value = std::env::var(name)
        .ok()
        .map(|s| s.parse::<usize>().expect("invalid numeric load setting"))
        .unwrap_or(default);
    assert!((min..=max).contains(&value), "{name} must be in {min}..={max}");
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn queued_concurrent_seal_load() {
    assert_eq!(
        std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(),
        Ok("1"),
        "only public, insecure fixture signing keys are allowed"
    );
    let attempts = requested("HC_VTIME_LOAD_ATTEMPTS", 120, 100, 2000);
    let capacity = requested("HC_VTIME_SEAL_QUEUE_CAPACITY", attempts, attempts, 4096);
    let wait_ms = requested("HC_VTIME_SEAL_MAX_WAIT_MS", 360_000, 1, 600_000);
    let config = QueueConfig {
        capacity,
        max_wait: Duration::from_millis(wait_ms as u64),
        ..QueueConfig::default()
    };
    let queue = SealQueue::new(3, config).expect("invalid queue config");
    let file = std::env::var("HC_VTIME_TEST_DNA").expect("fresh signed fixture DNA required");
    assert!(Path::new(&file).is_file(), "packed fixture DNA missing");
    let dna = SweetDnaFile::from_bundle(Path::new(&file))
        .await
        .expect("invalid signed test DNA bundle");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors
        .setup_app("vtime-queued-seal-load", &[dna])
        .await
        .expect("three real conductors failed to start")
        .cells_flattened();
    assert_eq!(cells.len(), 3);
    assert_eq!(
        cells.iter().map(|cell| cell.agent_pubkey().clone()).collect::<HashSet<_>>().len(),
        3,
        "each queue lane must represent a different author AgentPubKey"
    );
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("three conductors did not synchronize after installation");

    // Warm all cells sequentially and create persisted, signed target anchors
    // before admitting the burst. First-use zome init is not conflated with
    // source-chain contention. Use the exact target ActionHashes as nonces.
    let mut targets = Vec::with_capacity(3);
    for i in 0..3 {
        let target: ActionHash = conductors[i]
            .call(
                &cells[i].zome("vtime"),
                "create_anchor",
                json!({
                    "roughtime": signed_three(
                        [INSECURE_TEST_SEEDS[i]; 32], epoch_seconds()
                    )
                }),
            )
            .await;
        targets.push(target);
    }
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("signed anchor targets did not synchronize");

    let fixtures: Vec<_> = targets
        .iter()
        .map(|target| {
            let nonce = seal_nonce(cells[0].dna_hash().get_raw_39(), target.get_raw_39());
            signed_three(nonce, epoch_seconds())
        })
        .collect();
    let zomes: Vec<_> = cells.iter().map(|cell| cell.zome("vtime")).collect();
    let launch = Instant::now();
    // join_all polls all caller futures in one burst. The queue is the only
    // admission throttle. It does not mock any conductor API.
    let jobs = (0..attempts).map(|attempt| {
        let conductor_index = attempt % 3;
        let conductor = &conductors[conductor_index];
        let zome = &zomes[conductor_index];
        let target = targets[conductor_index].clone();
        let proof = fixtures[conductor_index].clone();
        let q = queue.clone();
        async move {
            let request = Instant::now();
            let result = q
                .submit(
                    conductor_index,
                    || {
                        let target = target.clone();
                        let proof = proof.clone();
                        async move {
                            let result: Result<ActionHash, _> = conductor
                                .call_fallible(
                                    zome,
                                    "seal_action",
                                    json!({"target": target, "roughtime": proof}),
                                )
                                .await;
                            result.map_err(|error| format!("{error:?}"))
                        }
                    },
                    |diagnostic| is_holochain_head_moved(diagnostic),
                )
                .await;
            let metrics = result.metrics;
            let (ok, hash, error, error_code) = match result.result {
                Ok(hash) => (true, Some(hash), None, None),
                Err(error) => (
                    false,
                    None,
                    Some(format!("{error:?}").chars().take(700).collect::<String>()),
                    Some(error.code()),
                ),
            };
            let hash_text = hash.as_ref().map(ToString::to_string);
            let sample = json!({
                "attempt": attempt,
                "kind": "queued_seal_action",
                "conductor": conductor_index,
                "ok": ok,
                "latency_ms": request.elapsed().as_secs_f64() * 1000.0,
                "queue_wait_ms": metrics.queue_wait_ms,
                "service_ms": metrics.service_ms,
                "queue_depth_at_admission": metrics.queue_depth_at_admission,
                "admitted": metrics.admitted,
                "write_attempts": metrics.attempts,
                "head_moved_retries": metrics.head_moved_retries,
                "action_hash": hash_text,
                "error": error,
                "error_code": error_code,
            });
            (sample, hash)
        }
    });
    let completed = join_all(jobs).await;
    let completion_wall_ms = launch.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(completed.len(), attempts, "not all queued calls returned");
    let samples: Vec<_> = completed.iter().map(|(sample, _)| sample.clone()).collect();
    for sample in &samples {
        println!("HC_LOAD_SAMPLE {}", sample);
    }
    let successful: Vec<_> = samples.iter().filter(|s| s["ok"] == true).collect();
    let hashes: HashSet<_> = successful
        .iter()
        .filter_map(|sample| sample["action_hash"].as_str())
        .collect();
    let errors: Vec<_> = samples.iter()
        .filter(|sample| sample["ok"] != true)
        .map(|sample| sample["error_code"].as_str().unwrap_or("unknown"))
        .collect();
    let retries: u64 = samples.iter()
        .map(|sample| sample["head_moved_retries"].as_u64().unwrap_or(0))
        .sum();

    // A returned ActionHash alone is not enough. Wait for DHT consistency and
    // read a deterministic sample of genuine receipts from third-party cells.
    let mut verified_receipts = 0;
    if successful.len() == attempts {
        await_consistency([&cells[0], &cells[1], &cells[2]])
            .await
            .expect("seals did not achieve conductor DHT consistency");
        let stride = (attempts / 12).max(1);
        for index in (0..attempts).step_by(stride) {
            let lane = index % 3;
            let reader = (lane + 1) % 3;
            let seal = completed[index].1.clone().expect("successful seal must have typed hash");
            let proof: Result<VerifiedTime, _> = conductors[reader]
                .call_fallible(
                    &cells[reader].zome("vtime"),
                    "verify_time_with_witnesses",
                    json!({
                        "target": targets[lane].clone(),
                        "anchors": [targets[lane].clone()],
                        "seals": [seal],
                    }),
                )
                .await;
            let verified = proof.expect("third-party verification rejected queued seal");
            assert_eq!(verified.target, targets[lane], "wrong target in verified seal");
            assert!(verified.not_before_us.is_some());
            assert!(verified.not_after_us.is_some());
            assert!(!verified.evidence_complete, "bounded supplied proofs cannot claim full DHT enumeration");
            verified_receipts += 1;
        }
    }

    println!(
        "HC_LOAD_META {}",
        json!({
            "kind": "queued_seal_action",
            "requested": attempts,
            "successful": successful.len(),
            "failed": attempts - successful.len(),
            "unique_success_action_hashes": hashes.len(),
            "head_moved_retries": retries,
            "failure_codes": errors,
            "queue_capacity": queue.capacity(),
            "queue_policy": "one in-process writer per AgentPubKey source chain",
            "max_wait_ms": wait_ms,
            "conductor_count": 3,
            "third_party_verified_receipts": verified_receipts,
            "completion_wall_ms": completion_wall_ms,
            "successful_seals_per_second": if completion_wall_ms > 0.0 {
                successful.len() as f64 * 1000.0 / completion_wall_ms
            } else { 0.0 },
            "fixture": "same-host publicly known test signers; not independent operators",
            "external_roughtime_network": false,
            "production_independence_proven": false,
        })
    );
    assert!(attempts >= 100);
    assert_eq!(successful.len(), attempts, "queued real seal failures remain; review HC_LOAD_SAMPLE");
    assert_eq!(hashes.len(), attempts, "duplicate or missing successful seal actions");
    assert!(verified_receipts >= 12, "too few genuine third-party verifications");
}
