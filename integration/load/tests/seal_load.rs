//! Real 3-conductor, >=100 overlapping seal_action calls.
//! Do not treat same-host fixture signers as independent Roughtime operators.
use futures::future::join_all;
use hc_vtime_conductor_smoke::fixtures::{signed_three, INSECURE_TEST_SEEDS};
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::json;
use std::collections::HashSet;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

fn epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_seal_load() {
    assert_eq!(std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(), Ok("1"),
        "test-only key sentinel required");
    let attempts: usize = std::env::var("HC_VTIME_LOAD_ATTEMPTS")
        .unwrap_or_else(|_| "120".into()).parse().expect("invalid attempts");
    assert!((100..=2000).contains(&attempts), "attempts must be 100..=2000");

    let file = std::env::var("HC_VTIME_TEST_DNA").expect("packed test-only DNA is required");
    assert!(Path::new(&file).is_file(), "packed test DNA not found");
    let dna = SweetDnaFile::from_bundle(Path::new(&file))
        .await.expect("failed to open test-only DNA");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors.setup_app("vtime-load", &[dna])
        .await.expect("three conductor setup failed").cells_flattened();
    assert_eq!(cells.len(), 3);
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await.expect("initial peer consistency failed");

    // Create three genuine signed targets; never synthesize a target that does
    // not exist on the DHT, as that would measure failure handling instead.
    let mut targets = Vec::new();
    for i in 0..3 {
        let anchor: ActionHash = conductors[i].call(
            &cells[i].zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([INSECURE_TEST_SEEDS[i]; 32], epoch_seconds())}),
        ).await;
        targets.push(anchor);
    }
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await.expect("anchor consistency failed");

    // One valid, nonce-bound triple per target is reused; concurrency measures
    // conductor admission, validation, source-chain write and link costs,
    // *not* live Roughtime network throughput or operator independence.
    let signed: Vec<_> = targets.iter().map(|target| {
        let nonce = seal_nonce(cells[0].dna_hash().get_raw_39(), target.get_raw_39());
        signed_three(nonce, epoch_seconds())
    }).collect();
    let launched = Instant::now();
    let calls = (0..attempts).map(|attempt| {
        let conductor_index = attempt % 3;
        let conductor = &conductors[conductor_index];
        let zome = cells[conductor_index].zome("vtime");
        let target = targets[conductor_index].clone();
        let evidence = signed[conductor_index].clone();
        async move {
            let started = Instant::now();
            let outcome: Result<ActionHash, _> = conductor.call_fallible(
                &zome, "seal_action",
                json!({"target": target, "roughtime": evidence}),
            ).await;
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            let (ok, hash, error) = match outcome {
                Ok(hash) => (true, Some(hash.to_string()), None),
                Err(err) => (false, None, Some(format!("{err:?}").chars().take(600).collect::<String>())),
            };
            json!({
                "attempt": attempt, "kind": "seal_action",
                "conductor": conductor_index, "ok": ok,
                "latency_ms": elapsed, "action_hash": hash, "error": error
            })
        }
    });
    let samples = join_all(calls).await;
    let wall_ms = launched.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(samples.len(), attempts, "some scheduled calls were not observed");
    let successes: Vec<_> = samples.iter().filter(|s| s["ok"] == true).collect();
    let hashes: HashSet<_> = successes.iter()
        .filter_map(|s| s["action_hash"].as_str()).collect();
    for sample in &samples {
        println!("HC_LOAD_SAMPLE {}", sample);
    }
    println!("HC_LOAD_META {}", json!({
        "kind": "seal_action", "attempted": attempts,
        "success": successes.len(), "failed": attempts - successes.len(),
        "unique_success_action_hashes": hashes.len(),
        "wall_ms": wall_ms, "conductor_count": 3,
        "fixture": "same-host publicly known test seeds",
        "external_roughtime_network": false
    }));
    assert_eq!(hashes.len(), successes.len(), "duplicate successful seal action hash");
    assert!(!successes.is_empty(), "all conductor seal attempts failed");
}
