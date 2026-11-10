//! Sprint 31: real-conductor adversarial DHT link-spam acceptance.
//! This expensive test requires an opt-in, disposable, test-key DNA built with
//! vtime/dht-spam-test-only. Never run it on a production network or funded app.
use hc_vtime_conductor_smoke::fixtures::signed_three;
use holochain::prelude::*;
use holochain::sweettest::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

const BATCHES: usize = 80;
const LINKS_PER_BATCH: u16 = 64;
const CONCURRENT_READERS: usize = 16;
const READ_BATCHES: usize = 8;

#[derive(Debug, Deserialize, Serialize)]
struct WitnessOutput {
    not_before_us: Option<i64>,
    not_after_us: Option<i64>,
    conclusion: WitnessConclusion,
    evidence_complete: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
enum WitnessConclusion {
    Backdated { by_us: i64 },
    FutureDated { by_us: i64 },
    NoContradictionInSuppliedProofs,
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn resident_kib(field: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix(field)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

async fn verify(
    conductor: &SweetConductor,
    cell: &SweetCell,
    target: &ActionHash,
    seal: &ActionHash,
) -> WitnessOutput {
    conductor
        .call(
            &cell.zome("vtime"),
            "verify_time_with_witnesses",
            json!({"target": target, "anchors": [target], "seals": [seal]}),
        )
        .await
}

async fn timed_verify(
    conductor: &SweetConductor,
    cell: &SweetCell,
    target: &ActionHash,
    seal: &ActionHash,
) -> (WitnessOutput, u64) {
    let start = Instant::now();
    let result = verify(conductor, cell, target, seal).await;
    (result, u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX))
}

fn percentile(samples: &[u64], percentile: usize) -> u64 {
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let index = ((ordered.len() - 1) * percentile) / 100;
    ordered[index]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "costly >=10k real DHT writes; run only via Sprint 31 test-only runner"]
async fn spammed_link_indexes_do_not_change_explicit_witnesses() {
    assert_eq!(
        std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(),
        Ok("1"),
        "public test signing identities must be explicitly authorized"
    );
    assert_eq!(
        std::env::var("HC_VTIME_DHT_SPAM_TEST_ONLY").as_deref(),
        Ok("1"),
        "DHT flood requires dedicated test-only sentinel"
    );
    let path = std::env::var("HC_VTIME_TEST_DNA").expect("packed test-only DNA required");
    assert!(Path::new(&path).is_file(), "test-only DNA is unavailable");
    let dna = SweetDnaFile::from_bundle(Path::new(&path))
        .await
        .expect("bad packed test DNA");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors
        .setup_app("vtime-sprint31-dht-spam", &[dna])
        .await
        .expect("conductor setup failed")
        .cells_flattened();
    conductors.exchange_peer_info().await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("initial DHT consistency failed");

    let target: ActionHash = conductors[0]
        .call(
            &cells[0].zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([0xA1; 32], epoch())}),
        )
        .await;
    let irrelevant_newer_anchor: ActionHash = conductors[0]
        .call(
            &cells[0].zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([0xA2; 32], epoch())}),
        )
        .await;
    let nonce = seal_nonce(cells[0].dna_hash().get_raw_39(), target.get_raw_39());
    let seal: ActionHash = conductors[1]
        .call(
            &cells[1].zome("vtime"),
            "seal_action",
            json!({"target": target, "roughtime": signed_three(nonce, epoch())}),
        )
        .await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("valid signed proofs did not replicate");

    let baseline = verify(&conductors[2], &cells[2], &target, &seal).await;
    assert!(baseline.not_before_us.is_some());
    assert!(baseline.not_after_us.is_some());
    assert!(!baseline.evidence_complete);

    let request_bytes = serde_json::to_vec(&json!({
        "target": target, "anchors": [target], "seals": [seal]
    }))
    .unwrap()
    .len();
    let rss_before = resident_kib("VmRSS:");
    let hwm_before = resident_kib("VmHWM:");
    let started = Instant::now();

    // Alice can legitimately index her own later anchor. Many duplicate
    // *newer* links must not displace the older valid target anchor.
    // Bob can legitimately index his one third-party seal repeatedly.
    // Both index types are actual validated DHT links, not in-memory mocks.
    let mut newer_anchor_links = 0usize;
    let mut duplicate_seal_links = 0usize;
    for _ in 0..BATCHES {
        let written: u16 = conductors[0]
            .call(
                &cells[0].zome("vtime"),
                "test_only_spam_anchor_links",
                json!({"anchor": irrelevant_newer_anchor, "count": LINKS_PER_BATCH}),
            )
            .await;
        assert_eq!(written, LINKS_PER_BATCH);
        newer_anchor_links += usize::from(written);

        let written: u16 = conductors[1]
            .call(
                &cells[1].zome("vtime"),
                "test_only_spam_seal_links",
                json!({"target": target, "seal": seal, "count": LINKS_PER_BATCH}),
            )
            .await;
        assert_eq!(written, LINKS_PER_BATCH);
        duplicate_seal_links += usize::from(written);
    }
    assert!(newer_anchor_links + duplicate_seal_links >= 10_000);
    let spam_write_ms = started.elapsed().as_millis();
    await_consistency_s(600, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("DHT link flood did not converge");

    let post = verify(&conductors[2], &cells[2], &target, &seal).await;
    assert_eq!(baseline.not_before_us, post.not_before_us);
    assert_eq!(baseline.not_after_us, post.not_after_us);
    assert_eq!(baseline.conclusion, post.conclusion);
    assert!(!post.evidence_complete);

    // Silent truncation is not allowed: an over-budget supplied witness set
    // must fail even when every repeated hash refers to a valid signed seal.
    let oversized: Result<WitnessOutput, _> = conductors[2]
        .call_fallible(
            &cells[2].zome("vtime"),
            "verify_time_with_witnesses",
            json!({"target": target, "anchors": [], "seals": vec![seal.clone(); 10_001]}),
        )
        .await;
    assert!(
        format!("{:?}", oversized.expect_err("10k witnesses were silently truncated"))
            .contains("10001 records exceed safe limit 32")
    );
    let legacy: Result<serde_json::Value, _> = conductors[2]
        .call_fallible(&cells[2].zome("vtime"), "get_verified_time", target.clone())
        .await;
    assert!(
        format!("{:?}", legacy.expect_err("legacy global scan was re-enabled"))
            .contains("get_verified_time is disabled")
    );

    let mut elapsed = Vec::new();
    let mut max_response_bytes = 0usize;
    // 128 actual requests in 8 batches of 16 simultaneous readers.
    for _ in 0..READ_BATCHES {
        let (
            a, b, c, d, e, f, g, h,
            i, j, k, l, m, n, o, p
        ) = tokio::join!(
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
            timed_verify(&conductors[2], &cells[2], &target, &seal),
        );
        for (result, us) in [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] {
            assert_eq!(result.not_before_us, baseline.not_before_us);
            assert_eq!(result.not_after_us, baseline.not_after_us);
            assert_eq!(result.conclusion, baseline.conclusion);
            assert!(!result.evidence_complete);
            max_response_bytes = max_response_bytes.max(serde_json::to_vec(&result).unwrap().len());
            elapsed.push(us);
        }
    }
    assert_eq!(elapsed.len(), CONCURRENT_READERS * READ_BATCHES);
    println!(
        "HC_SPRINT31_DHT_SPAM {}",
        json!({
            "schema": "hc-vtime/sprint31-dht-spam/v1",
            "actual_conductor": true,
            "test_only_fixture": true,
            "validated_newer_anchor_links": newer_anchor_links,
            "validated_duplicate_seal_links": duplicate_seal_links,
            "links_inserted": newer_anchor_links + duplicate_seal_links,
            "concurrent_readers_per_batch": CONCURRENT_READERS,
            "verified_requests": elapsed.len(),
            "all_valid_proofs_preserved": true,
            "over_budget_rejected": true,
            "legacy_global_query_rejected": true,
            "evidence_complete": false,
            "request_json_bytes": request_bytes,
            "max_response_json_bytes": max_response_bytes,
            "host_dht_wire_bytes_measured": false,
            "rss_before_kib": rss_before,
            "rss_after_kib": resident_kib("VmRSS:"),
            "hwm_before_kib": hwm_before,
            "hwm_after_kib": resident_kib("VmHWM:"),
            "spam_write_ms": spam_write_ms.to_string(),
            "latency_p50_us": percentile(&elapsed, 50),
            "latency_p95_us": percentile(&elapsed, 95),
            "latency_p99_us": percentile(&elapsed, 99),
            "signed_sources_independent_operators": false,
            "production_release_ready": false
        })
    );
    hc_vtime_conductor_smoke::shutdown_batch(conductors).await;
}
