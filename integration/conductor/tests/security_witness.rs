//! Sprint 16: deliberate malformed explicit-witness inputs against real DNA.
//! Requires the existing test-only signed DNA; do not use funded credentials.
use hc_vtime_conductor_smoke::fixtures::signed_three;
use holochain::prelude::*;
use holochain::sweettest::*;
use serde::Deserialize;
use serde_json::json;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Deserialize)]
struct WitnessOutput {
    target: ActionHash,
    evidence_complete: bool,
}

#[derive(Debug, Deserialize)]
struct WitnessFixtures {
    schema: String,
    cases: Vec<WitnessCase>,
}
#[derive(Debug, Deserialize)]
struct WitnessCase {
    id: String,
    target: String,
    anchors: Vec<String>,
    seals: Vec<String>,
    expected_error: Option<String>,
}

fn resolve(
    hash_name: &str,
    alice: &ActionHash,
    charlie: &ActionHash,
    bob_seal: &ActionHash,
) -> ActionHash {
    match hash_name {
        "alice" => alice.clone(),
        "charlie" => charlie.clone(),
        "bob_seal" => bob_seal.clone(),
        other => panic!("unknown fixture hash alias: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_witness_fixtures_fail_closed() {
    assert_eq!(
        std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(),
        Ok("1"),
        "HC_VTIME_SIGNED_TEST_ONLY=1 required to use public test signing seeds"
    );
    let test_dna = std::env::var("HC_VTIME_TEST_DNA").expect("requires packed test-only DNA path");
    assert!(Path::new(&test_dna).is_file(), "packed test DNA is missing");
    let cases: WitnessFixtures =
        serde_json::from_str(include_str!("../../security/fixtures/witness_cases.json"))
            .expect("committed fixture JSON must parse");
    assert_eq!(cases.schema, "hc-vtime-sprint16-witness-v1");
    assert_eq!(cases.cases.len(), 10, "unexpected witness fixture count");

    let dna = SweetDnaFile::from_bundle(Path::new(&test_dna))
        .await
        .expect("bad test DNA bundle");
    let mut conductors = SweetConductorBatch::standard(3).await;
    let cells = conductors
        .setup_app("vtime-witness-hardening", &[dna])
        .await
        .expect("setup failed")
        .cells_flattened();
    assert_eq!(cells.len(), 3);
    conductors.exchange_peer_info().await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("initial consistency failed");

    let alice: ActionHash = conductors[0]
        .call(
            &cells[0].zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([0x41; 32], epoch())}),
        )
        .await;
    let charlie: ActionHash = conductors[2]
        .call(
            &cells[2].zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([0x43; 32], epoch())}),
        )
        .await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("anchor consistency failed");

    let nonce = seal_nonce(cells[0].dna_hash().get_raw_39(), alice.get_raw_39());
    let bob_seal: ActionHash = conductors[1]
        .call(
            &cells[1].zome("vtime"),
            "seal_action",
            json!({"target": alice.clone(), "roughtime": signed_three(nonce, epoch())}),
        )
        .await;
    await_consistency([&cells[0], &cells[1], &cells[2]])
        .await
        .expect("seal consistency failed");

    let mut rejected = 0;
    let mut accepted = 0;
    for case in cases.cases {
        let input = json!({
            "target": resolve(&case.target, &alice, &charlie, &bob_seal),
            "anchors": case.anchors.iter()
                .map(|h| resolve(h, &alice, &charlie, &bob_seal)).collect::<Vec<_>>(),
            "seals": case.seals.iter()
                .map(|h| resolve(h, &alice, &charlie, &bob_seal)).collect::<Vec<_>>(),
        });
        let result: Result<WitnessOutput, _> = conductors[1]
            .call_fallible(&cells[1].zome("vtime"), "verify_time_with_witnesses", input)
            .await;
        match case.expected_error {
            Some(needle) => {
                let err = result.expect_err(&format!("{} was unexpectedly accepted", case.id));
                let message = format!("{err:?}");
                assert!(
                    message.contains(&needle),
                    "{} rejected for wrong reason (expected {needle:?}): {message}",
                    case.id
                );
                rejected += 1;
            }
            None => {
                let output = result
                    .unwrap_or_else(|e| panic!("{} valid fixture was rejected: {e:?}", case.id));
                assert!(
                    !output.evidence_complete,
                    "caller-supplied witnesses cannot prove completeness"
                );
                assert_eq!(output.target, alice);
                accepted += 1;
            }
        }
    }
    assert_eq!(rejected, 9);
    assert_eq!(accepted, 1);
    println!(
        "HC_SECURITY_WITNESSES {}",
        json!({
            "valid": accepted, "correct_rejections": rejected,
            "test_signers_independent_operators": false,
            "actual_conductor": true
        })
    );
}
