//! Real 3-agent Holochain 0.7.1 smoke test. Not signed-quorum acceptance.
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::json;
use std::path::Path;

#[tokio::test(flavor = "multi_thread")]
async fn three_agent_real_wasm_smoke() {
    let file = std::env::var("HC_VTIME_TEST_DNA")
        .expect("HC_VTIME_TEST_DNA is required; do not silently skip tests");
    assert!(Path::new(&file).is_file(), "test DNA bundle not found");
    let dna = SweetDnaFile::from_bundle(Path::new(&file))
        .await
        .expect("cannot open packed test DNA");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let apps = conductors
        .setup_app("vtime-smoke", &[dna])
        .await
        .expect("three-conductor DNA install failed");
    let cells = apps.cells_flattened();
    assert_eq!(cells.len(), 3);
    assert_ne!(cells[0].agent_pubkey(), cells[1].agent_pubkey());
    assert_ne!(cells[1].agent_pubkey(), cells[2].agent_pubkey());
    assert_eq!(cells[0].dna_hash(), cells[1].dna_hash());
    assert_eq!(cells[1].dna_hash(), cells[2].dna_hash());
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .unwrap();

    // All three actual coordinator zomes must generate the same padded packet.
    let input = json!({"nonce_hex": "00".repeat(32), "server_public_key_b64": null});
    let mut first: Option<Vec<u8>> = None;
    for (index, cell) in cells.iter().enumerate() {
        let packet: Vec<u8> = conductors[index]
            .call(
                &cell.zome("vtime"),
                "build_roughtime_request",
                input.clone(),
            )
            .await;
        assert_eq!(packet.len(), 1024);
        if let Some(ref earlier) = first {
            assert_eq!(&packet, earlier);
        }
        first = Some(packet);
    }

    let target_a = ActionHash::from_raw_32(vec![0x44; 32]);
    let target_b = ActionHash::from_raw_32(vec![0x45; 32]);
    let a: String = conductors[0]
        .call(&cells[0].zome("vtime"), "seal_nonce_for", target_a.clone())
        .await;
    let a_peer: String = conductors[1]
        .call(&cells[1].zome("vtime"), "seal_nonce_for", target_a.clone())
        .await;
    let b: String = conductors[2]
        .call(&cells[2].zome("vtime"), "seal_nonce_for", target_b)
        .await;
    assert_eq!(a.len(), 64);
    assert_eq!(a, a_peer);
    assert_ne!(a, b);

    // The unsafe global index endpoint must remain disabled.
    let legacy: Result<serde_json::Value, _> = conductors[0]
        .call_fallible(
            &cells[0].zome("vtime"),
            "get_verified_time",
            target_a.clone(),
        )
        .await;
    assert!(
        format!("{:?}", legacy.expect_err("legacy query was re-enabled"))
            .contains("get_verified_time is disabled")
    );

    // Input limits are enforced before fetching any witness records.
    let oversized = json!({"target": target_a.clone(), "anchors": [],
                           "seals": vec![target_a; 33]});
    let result: Result<serde_json::Value, _> = conductors[2]
        .call_fallible(
            &cells[2].zome("vtime"),
            "verify_time_with_witnesses",
            oversized,
        )
        .await;
    assert!(format!(
        "{:?}",
        result.expect_err("over-budget witness request accepted")
    )
    .contains("33 records exceed safe limit 32"));

    let malformed = json!({"nonce_hex": "f", "server_public_key_b64": null});
    let rejected: Result<Vec<u8>, _> = conductors[1]
        .call_fallible(
            &cells[1].zome("vtime"),
            "build_roughtime_request",
            malformed,
        )
        .await;
    assert!(format!(
        "{:?}",
        rejected.expect_err("malformed Roughtime nonce accepted")
    )
    .contains("hex string has odd length"));
}
