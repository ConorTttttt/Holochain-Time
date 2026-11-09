//! Three-agent Holochain Sweettest with real Roughenough RFC 10049 signatures.
//! Public test keys on one machine do NOT imply independent operators.
use hc_vtime_conductor_smoke::fixtures::{
    signed_roughtime, signed_three, test_public_keys, INSECURE_TEST_SEEDS,
};
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn assert_quorum_denied(result: Result<Value, impl std::fmt::Debug>, scenario: &str) {
    let err = result.expect_err("expected explicit quorum rejection");
    let message = format!("{err:?}");
    assert!(
        message.contains("need 3 distinct trusted sources"),
        "{scenario}: wrong error, might be a conductor failure: {message}"
    );
}

#[test]
fn test_server_signing_keys_are_distinct() {
    let keys = test_public_keys();
    assert_eq!(keys.len(), 4);
    assert_eq!(keys.iter().copied().collect::<HashSet<_>>().len(), 4);
    let readings = signed_three([0x99; 32], now_epoch());
    assert_eq!(readings.len(), 3);
    for (r, key) in readings.iter().zip(keys.iter()) {
        assert_eq!(r.server_public_key.as_slice(), key);
        assert_eq!(r.request.len(), 1024);
        assert!(!r.response.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_source_anchor_third_party_seal_and_adversarial_rejection() {
    assert!(
        matches!(
            std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(),
            Ok("1")
        ),
        "requires explicit test-only sentinel"
    );
    let file = std::env::var("HC_VTIME_TEST_DNA").expect("requires a freshly packed test-only DNA");
    assert!(Path::new(&file).is_file());
    let dna = SweetDnaFile::from_bundle(Path::new(&file))
        .await
        .expect("test-only DNA bundle invalid");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors
        .setup_app("vtime-signed-quorum", &[dna])
        .await
        .expect("three-conductor install failed")
        .cells_flattened();
    assert_eq!(cells.len(), 3);
    assert_eq!(
        cells
            .iter()
            .map(|x| x.agent_pubkey().clone())
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .unwrap();

    // Alice anchors using three independently signed responses and no oracles.
    let at = now_epoch();
    let anchors: Vec<_> = INSECURE_TEST_SEEDS[..3]
        .iter()
        .map(|seed| signed_roughtime(*seed, [*seed; 32], at))
        .collect();
    let target: ActionHash = conductors[0]
        .call(
            &cells[0].zome("vtime"),
            "create_anchor",
            json!({"roughtime": anchors}),
        )
        .await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .unwrap();

    // Bob creates a real third-party seal for Alice's target hash.
    let nonce = seal_nonce(cells[0].dna_hash().get_raw_39(), target.get_raw_39());
    let signed = signed_three(nonce, now_epoch());
    let seal: ActionHash = conductors[1]
        .call(
            &cells[1].zome("vtime"),
            "seal_action",
            json!({"target": target.clone(), "roughtime": signed.clone()}),
        )
        .await;
    assert_ne!(target, seal);
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .unwrap();

    // Charlie verifies explicit proof hashes from two other source chains.
    let verified: Value = conductors[2]
        .call(
            &cells[2].zome("vtime"),
            "verify_time_with_witnesses",
            json!({"target": target.clone(), "anchors": [target.clone()], "seals": [seal]}),
        )
        .await;
    assert_eq!(verified["evidence_complete"], json!(false));
    assert!(
        verified["not_before_us"].is_number(),
        "missing signed lower bound: {verified}"
    );
    assert!(
        verified["not_after_us"].is_number(),
        "missing signed upper bound: {verified}"
    );

    let insufficient: Result<Value, _> = conductors[2]
        .call_fallible(
            &cells[2].zome("vtime"),
            "seal_action",
            json!({"target": target.clone(), "roughtime": signed[..2].to_vec()}),
        )
        .await;
    assert_quorum_denied(insufficient, "two sources");

    let mut wrong = signed.clone();
    wrong[2] = signed_roughtime(INSECURE_TEST_SEEDS[2], [0xAB; 32], now_epoch());
    let replay: Result<Value, _> = conductors[2]
        .call_fallible(
            &cells[2].zome("vtime"),
            "seal_action",
            json!({"target": target.clone(), "roughtime": wrong}),
        )
        .await;
    assert_quorum_denied(replay, "different action nonce");

    let mut duplicate = signed.clone();
    duplicate[2] = signed[0].clone();
    let repeated: Result<Value, _> = conductors[2]
        .call_fallible(
            &cells[2].zome("vtime"),
            "seal_action",
            json!({"target": target.clone(), "roughtime": duplicate}),
        )
        .await;
    assert_quorum_denied(repeated, "duplicate signer");

    let mut tampered = signed;
    let n = tampered[2].response.len();
    assert!(n > 20);
    tampered[2].response[n - 8] ^= 1;
    let forged: Result<Value, _> = conductors[2]
        .call_fallible(
            &cells[2].zome("vtime"),
            "seal_action",
            json!({"target": target, "roughtime": tampered}),
        )
        .await;
    assert_quorum_denied(forged, "altered signed packet");
}
