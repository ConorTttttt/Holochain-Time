//! Sprint 33: recovery across delayed DHT gossip and deliberately missing
//! witnesses. This is real three-conductor Holochain 0.7.1 Sweettest, but the
//! initial isolation is DISCOVERY isolation, not a transport partition.
//! The separate Linux network-namespace lab tests kernel-enforced partitions.
use hc_vtime_conductor_smoke::fixtures::signed_three;
use hc_vtime_conductor_smoke::resilience::{assess, RecoveryAssessment, WitnessResult};
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::json;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

fn test_only_dna() -> String {
    assert_eq!(std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(), Ok("1"));
    let path = std::env::var("HC_VTIME_TEST_DNA").expect("test-only DNA path required");
    assert!(Path::new(&path).is_file(), "test DNA file missing");
    path
}
fn epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
fn pass(label: &str) {
    println!("CHAOS33_CASE={label}:PASS");
}
async fn anchor(conductor: &SweetConductor, cell: &SweetCell, tag: u8) -> ActionHash {
    conductor
        .call(
            &cell.zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([tag; 32], epoch())}),
        )
        .await
}
async fn seal(conductor: &SweetConductor, cell: &SweetCell, target: &ActionHash) -> ActionHash {
    let nonce = seal_nonce(cell.dna_hash().get_raw_39(), target.get_raw_39());
    conductor
        .call(
            &cell.zome("vtime"),
            "seal_action",
            json!({"target": target, "roughtime": signed_three(nonce, epoch())}),
        )
        .await
}
async fn witness(
    conductor: &SweetConductor,
    cell: &SweetCell,
    target: &ActionHash,
    anchors: Vec<ActionHash>,
    seals: Vec<ActionHash>,
) -> Result<WitnessResult, String> {
    let result: Result<WitnessResult, _> = conductor
        .call_fallible(
            &cell.zome("vtime"),
            "verify_time_with_witnesses",
            json!({"target": target, "anchors": anchors, "seals": seals}),
        )
        .await;
    result.map_err(|error| format!("{error:?}"))
}
fn require_failure(result: Result<WitnessResult, String>, expected: &str) {
    let reason = result.expect_err("invalid or unavailable witness became trusted");
    assert!(
        reason.contains(expected),
        "unavailable/invalid witness must fail explicitly; expected {expected:?}, got {reason}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delayed_dht_rejoin_retains_ancestry_and_rejects_false_witnesses() {
    let dna = SweetDnaFile::from_bundle(Path::new(&test_only_dna()))
        .await
        .expect("test DNA cannot be opened");
    // Holochain rendezvous with bootstrap disabled deliberately prevents
    // automatic discovery. THIS DOES NOT BLOCK ALREADY CONNECTED TRANSPORT.
    let mut conductors = SweetConductorBatch::from_config_rendezvous(
        3,
        SweetConductorConfig::rendezvous(false),
    )
    .await;
    let mut cells = conductors
        .setup_app("sprint33-delayed-gossip", &[dna])
        .await
        .expect("cannot install test-only DNA")
        .cells_flattened();
    let first = anchor(&conductors[0], &cells[0], 0xC1).await;
    let descendant = anchor(&conductors[0], &cells[0], 0xC2).await;
    let foreign = anchor(&conductors[1], &cells[1], 0xC3).await;

    // Remote signed evidence was authored before the observer learned peers.
    // It must never silently turn into an empty-but-"consistent" verdict.
    let unavailable =
        witness(&conductors[2], &cells[2], &first, vec![first.clone()], vec![]).await;
    assert!(
        unavailable.is_err(),
        "undiscovered remote signed action was unexpectedly accepted: {unavailable:?}"
    );
    pass("discovery_isolation_unknown_witness_rejected");

    conductors.exchange_peer_info().await;
    await_consistency_s(120, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("delayed DHT gossip did not converge");
    let sealed = seal(&conductors[1], &cells[1], &descendant).await;
    await_consistency_s(120, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("third-party seal did not replicate");

    let before = witness(
        &conductors[2],
        &cells[2],
        &descendant,
        vec![first.clone()],
        vec![sealed.clone()],
    )
    .await
    .expect("rejoined observer cannot verify real signed ancestor and third-party seal");
    assert!(before.not_before_us.is_some() && before.not_after_us.is_some());
    assert!(!before.evidence_complete);
    assert_ne!(assess(&before), RecoveryAssessment::UntrustedConflict);
    pass("delayed_gossip_signed_bounds_available");

    // Full recovery must NEVER treat a later anchor as an earlier ancestor,
    // nor use a different author's anchor to fabricate a lower time bound.
    require_failure(
        witness(
            &conductors[2],
            &cells[2],
            &first,
            vec![descendant.clone()],
            vec![],
        )
        .await,
        "not an eligible action by the target author",
    );
    require_failure(
        witness(&conductors[2], &cells[2], &descendant, vec![foreign], vec![]).await,
        "not an eligible action by the target author",
    );
    require_failure(
        witness(
            &conductors[2],
            &cells[2],
            &descendant,
            vec![first.clone()],
            vec![ActionHash::from_raw_32(vec![0xE5; 32])],
        )
        .await,
        "supplied seal action is unavailable",
    );
    pass("false_ancestry_and_missing_seal_rejected");

    // Restart the identical persistent SweetConductor (not a new database).
    let cell_id = cells[2].cell_id().clone();
    conductors[2].shutdown().await;
    let offline = anchor(&conductors[0], &cells[0], 0xC4).await;
    await_consistency_s(120, [&cells[0], &cells[1]])
        .await
        .expect("live peers failed to replicate while observer was offline");
    conductors[2].startup().await;
    cells[2] = conductors[2]
        .get_sweet_cell(cell_id)
        .expect("restart did not preserve the original observer cell");
    conductors.exchange_peer_info().await;
    await_consistency_s(120, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("observer failed to recover missed DHT writes");
    let after = witness(
        &conductors[2],
        &cells[2],
        &descendant,
        vec![first.clone()],
        vec![sealed],
    )
    .await
    .expect("signed bounds missing after restart");
    assert_eq!(after.not_before_us, before.not_before_us);
    assert_eq!(after.not_after_us, before.not_after_us);
    assert_eq!(after.conclusion, before.conclusion);
    assert!(!after.evidence_complete);
    let recovered = witness(
        &conductors[2],
        &cells[2],
        &offline,
        vec![offline.clone()],
        vec![],
    )
    .await
    .expect("missed signed evidence was not recovered");
    assert!(recovered.not_before_us.is_some());
    assert!(!recovered.evidence_complete);
    require_failure(
        witness(&conductors[2], &cells[2], &first, vec![offline], vec![]).await,
        "not an eligible action by the target author",
    );
    pass("restart_rejoin_never_trusts_conflicting_ancestry");

    println!(
        "CHAOS33_CONDUCTOR_REPORT {}",
        json!({
            "schema": "hc-vtime/sprint33-conductor/v1",
            "real_conductor": true,
            "transport_partition_proven": false,
            "unclean_sigkill_proven": false,
            "database_corruption_recovery_proven": false,
            "delayed_discovery_rejoin": true,
            "signed_bounds_preserved": true,
            "invalid_ancestry_rejected": true,
            "missing_witness_rejected": true,
            "evidence_complete": false,
            "release_approved": false
        })
    );
    hc_vtime_conductor_smoke::shutdown_batch(conductors).await;
}

#[test]
fn absence_of_author_health_never_becomes_clean_recovery() {
    use hc_vtime_conductor_smoke::resilience::{WitnessConclusion, WitnessResult};
    let result = WitnessResult {
        target: ActionHash::from_raw_32(vec![0x33; 32]),
        not_before_us: Some(100),
        not_after_us: Some(200),
        author_chain_flagged: None,
        evidence_complete: false,
        conclusion: WitnessConclusion::NoContradictionInSuppliedProofs,
    };
    assert_eq!(assess(&result), RecoveryAssessment::UntrustedUnknownAncestry);
    pass("unknown_author_health_not_trusted");
}
