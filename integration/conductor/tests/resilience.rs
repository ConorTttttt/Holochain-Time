//! Sprint 12: Holochain 0.7 real-conductor durability and failure scenarios.
//!
//! Uses four *different*, publicly known Roughenough test signers. Signature
//! verification is real; these signers are NOT independent real-world operators.
//! A transport-level partition or authentic same-author fork needs special
//! fault injection; each scenario is scoped honestly in the report.
use hc_vtime_conductor_smoke::fixtures::signed_three;
use hc_vtime_conductor_smoke::resilience::{assess, RecoveryAssessment, WitnessResult};
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::json;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

fn test_dna_path() -> String {
    assert_eq!(std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(), Ok("1"),
               "refusing to run against a non-test DNA");
    let path = std::env::var("HC_VTIME_TEST_DNA").expect("HC_VTIME_TEST_DNA is mandatory");
    assert!(Path::new(&path).is_file(), "test-only DNA bundle is missing");
    path
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

async fn setup(bootstrap: bool) -> (SweetConductorBatch, Vec<SweetCell>) {
    let path = test_dna_path();
    let dna = SweetDnaFile::from_bundle(Path::new(&path)).await.expect("invalid test DNA");
    let mut conductors = SweetConductorBatch::from_config_rendezvous(
        3,
        SweetConductorConfig::rendezvous(bootstrap),
    ).await;
    let cells = conductors.setup_app("vtime-resilience", &[dna]).await
        .expect("could not start three Holochain agents").cells_flattened();
    assert_eq!(cells.len(), 3);
    assert_eq!(cells[0].dna_hash(), cells[2].dna_hash());
    assert_ne!(cells[0].agent_pubkey(), cells[1].agent_pubkey());
    assert_ne!(cells[1].agent_pubkey(), cells[2].agent_pubkey());
    (conductors, cells)
}

async fn anchor(conductor: &SweetConductor, cell: &SweetCell) -> ActionHash {
    conductor.call(
        &cell.zome("vtime"),
        "create_anchor",
        json!({"roughtime": signed_three([0x63; 32], now_epoch())}),
    ).await
}

async fn seal(conductor: &SweetConductor, cell: &SweetCell, target: &ActionHash) -> ActionHash {
    let nonce = seal_nonce(cell.dna_hash().get_raw_39(), target.get_raw_39());
    conductor.call(
        &cell.zome("vtime"),
        "seal_action",
        json!({"target": target, "roughtime": signed_three(nonce, now_epoch())}),
    ).await
}

async fn witness(
    conductor: &SweetConductor, cell: &SweetCell, target: &ActionHash,
    anchors: Vec<ActionHash>, seals: Vec<ActionHash>,
) -> Result<WitnessResult, String> {
    let result: Result<WitnessResult, _> = conductor.call_fallible(
        &cell.zome("vtime"), "verify_time_with_witnesses",
        json!({"target": target, "anchors": anchors, "seals": seals}),
    ).await;
    result.map_err(|err| format!("{err:?}"))
}

fn marker(name: &str) {
    println!("RESILIENCE_CASE={name}:PASS");
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_restart_recovers_signed_proofs_and_missing_witnesses_fail_closed() {
    let (mut conductors, mut cells) = setup(true).await;
    conductors.exchange_peer_info().await;
    let target = anchor(&conductors[0], &cells[0]).await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]]).await.unwrap();
    let seal_hash = seal(&conductors[1], &cells[1], &target).await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]]).await.unwrap();
    let original = witness(&conductors[2], &cells[2], &target,
                           vec![target.clone()], vec![seal_hash.clone()]).await
        .expect("a fully replicated genuine proof should verify before restart");
    assert!(original.not_before_us.is_some());
    assert!(original.not_after_us.is_some());
    assert!(!original.evidence_complete, "never claim globally complete evidence");
    assert_ne!(assess(&original), RecoveryAssessment::UntrustedConflict);
    marker("durable_before_restart");

    // Bob is *actually stopped*: this is a real node outage, not a fake error
    // injected into the verifier. Alice/Charlie must retain replicated proof.
    let bob_id = cells[1].cell_id().clone();
    conductors[1].shutdown().await;
    let still_there = witness(&conductors[2], &cells[2], &target,
                              vec![target.clone()], vec![seal_hash.clone()]).await
        .expect("replicated signed proof disappeared while Bob was offline");
    assert_eq!(still_there.not_before_us, original.not_before_us);
    assert_eq!(still_there.not_after_us, original.not_after_us);
    assert!(!still_there.evidence_complete);
    marker("offline_conductor");

    // While Bob is offline, Alice authors fresh evidence. Charlie can see it.
    let during_outage = anchor(&conductors[0], &cells[0]).await;
    await_consistency_s(90, [&cells[0], &cells[2]]).await.unwrap();
    let recovered_elsewhere = witness(&conductors[2], &cells[2], &during_outage,
                                      vec![during_outage.clone()], vec![]).await
        .expect("fresh evidence was not verifiable on surviving peers");
    assert!(recovered_elsewhere.not_before_us.is_some());
    marker("survivors_continue");

    let fake = ActionHash::from_raw_32(vec![0xD7; 32]);
    let missing_seal = witness(&conductors[2], &cells[2], &target,
                               vec![target.clone()], vec![fake.clone()]).await
        .expect_err("missing seal was unexpectedly trusted");
    assert!(missing_seal.contains("supplied seal action is unavailable"),
            "wrong failure type: {missing_seal}");
    let missing_anchor = witness(&conductors[2], &cells[2], &target,
                                 vec![fake], vec![]).await
        .expect_err("missing anchor was unexpectedly trusted");
    assert!(missing_anchor.contains("supplied anchor action is unavailable"),
            "wrong failure type: {missing_anchor}");
    marker("missing_witness_rejected");

    // A real anchor by another author cannot lend Alice a false lower bound.
    let charlie_anchor = anchor(&conductors[2], &cells[2]).await;
    await_consistency_s(90, [&cells[0], &cells[2]]).await.unwrap();
    let conflict = witness(&conductors[2], &cells[2], &target,
                           vec![charlie_anchor], vec![]).await
        .expect_err("an anchor from a different author was accepted");
    assert!(conflict.contains("not an eligible action by the target author"),
            "unexpected conflicting ancestry error: {conflict}");
    // A later anchor from the same author also cannot be applied backwards.
    let future_anchor = witness(&conductors[2], &cells[2], &target,
                                vec![during_outage.clone()], vec![]).await
        .expect_err("later anchor was used for an earlier target");
    assert!(future_anchor.contains("not an eligible action by the target author"),
            "unexpected reverse-ancestry error: {future_anchor}");
    marker("conflicting_ancestry_rejected");

    // Restart the same durable conductor/keystore; do not create a fresh cell.
    conductors[1].startup().await;
    cells[1] = conductors[1].get_sweet_cell(bob_id).expect("Bob's cell was not restored");
    conductors.exchange_peer_info().await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]]).await
        .expect("three agents failed to resynchronize after restart");
    let after = witness(&conductors[1], &cells[1], &target,
                        vec![target.clone()], vec![seal_hash]).await
        .expect("restored conductor cannot verify durable signed proof");
    assert_eq!(after.not_before_us, original.not_before_us);
    assert_eq!(after.not_after_us, original.not_after_us);
    assert!(!after.evidence_complete);
    let caught_up = witness(&conductors[1], &cells[1], &during_outage,
                            vec![during_outage], vec![]).await
        .expect("restored conductor did not acquire proof written while offline");
    assert!(caught_up.not_before_us.is_some());
    assert!(!caught_up.evidence_complete);
    marker("restart_rejoin_and_durable_proofs");
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_bootstrap_isolation_then_manual_peer_rejoin() {
    // Isolates peer discovery in three *live* conductors. This is NOT a
    // transport-level partition once peer addresses are known; a complete
    // partition test still requires an Iroh relay/transport fault injector.
    let (mut conductors, cells) = setup(false).await;
    let target = anchor(&conductors[0], &cells[0]).await;
    let unavailable = witness(&conductors[2], &cells[2], &target,
                               vec![target.clone()], vec![]).await;
    assert!(unavailable.is_err(),
            "isolated peer unexpectedly accepted a remote proof: {unavailable:?}");
    marker("no_bootstrap_missing_proof");
    conductors.exchange_peer_info().await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]]).await
        .expect("DHT did not converge after peer discovery was restored");
    let after = witness(&conductors[2], &cells[2], &target,
                        vec![target], vec![]).await
        .expect("known proof not verifiable after peers rejoined");
    assert!(after.not_before_us.is_some());
    assert!(!after.evidence_complete);
    marker("peer_discovery_rejoin");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "expensive 128-write ancestry boundary; run with --ignored in resilience full suite"]
async fn ancestry_256_action_budget_enforced_in_conductor() {
    let (mut conductors, cells) = setup(true).await;
    conductors.exchange_peer_info().await;
    let first = anchor(&conductors[0], &cells[0]).await;
    let mut near = None;
    let mut over = None;
    // Each create_anchor writes a TimeAnchor action *and* an index link:
    // 127 calls after first => sequence distance 254, path count 255.
    // 128 calls after first => sequence distance 256, path count 257.
    // Coordinator native unit tests additionally check exactly 256 permitted.
    for number in 1..=128 {
        let next = anchor(&conductors[0], &cells[0]).await;
        if number == 127 { near = Some(next.clone()); }
        if number == 128 { over = Some(next); }
    }
    await_consistency_s(180, [&cells[0], &cells[1], &cells[2]]).await.unwrap();
    let near = near.unwrap();
    let under = witness(&conductors[2], &cells[2], &near,
                        vec![first.clone()], vec![]).await
        .expect("ancestry below the action budget was rejected");
    assert!(under.not_before_us.is_some());
    assert!(!under.evidence_complete);
    marker("ancestry_255_actions_pass");
    let over = over.unwrap();
    let denied = witness(&conductors[2], &cells[2], &over,
                         vec![first], vec![]).await
        .expect_err("ancestry above the 256-action cap was accepted");
    assert!(denied.contains("anchor ancestry exceeds the bounded action budget"),
            "unexpected action-budget failure: {denied}");
    marker("ancestry_257_actions_rejected");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "same-key two-conductor fork injection is destructive; run explicitly on a disposable DNA only"]
async fn same_agent_two_conductor_fork_does_not_become_trusted() {
    let path = test_dna_path();
    let dna = SweetDnaFile::from_bundle(Path::new(&path)).await.unwrap();
    let rendezvous = SweetLocalRendezvous::new().await;
    let config = SweetConductorConfig::rendezvous(false);
    let mut primary = SweetConductor::from_config_rendezvous(config.clone(), rendezvous.clone()).await;
    let agent = SweetAgents::one(primary.keystore()).await;
    // Controlled lab: *same* signing key on *separate* source-chain databases.
    // This is prohibited for real oracles and only used to construct a fork.
    let mut fork = SweetConductor::create_with_defaults(
        config.clone(), Some(primary.keystore()), Some(rendezvous.clone()),
    ).await;
    let mut observer = SweetConductor::from_config_rendezvous(config, rendezvous).await;
    let first_cell = primary.setup_app_for_agent("fork-main", agent.clone(), &[dna.clone()]).await
        .expect("first fork installation failed").into_cells().remove(0);
    let second_cell = fork.setup_app_for_agent("fork-secondary", agent, &[dna.clone()]).await
        .expect("second fork installation failed").into_cells().remove(0);
    let observed_cell = observer.setup_app("fork-observer", &[dna]).await
        .expect("observer installation failed").into_cells().remove(0);
    let original = anchor(&primary, &first_cell).await;
    let contradictory = anchor(&fork, &second_cell).await;
    assert_ne!(original, contradictory, "two isolated source chains did not diverge");
    for _ in 0..10 {
        if SweetConductor::exchange_peer_info([&primary, &fork, &observer]).await { break; }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    // The eventual verifier may fail the call entirely, or surface an
    // explicit fork/warrant. `Some(false)` is unacceptable for known conflict.
    let result = witness(&observer, &observed_cell, &original,
                         vec![original.clone()], vec![]).await;
    match result {
        Err(error) => {
            // A generic timeout/missing-peer error is *not* proof that the
            // fork was detected. Only an explicit fork/invalid-chain/warrant
            // refusal counts as evidence for this acceptance scenario.
            let explanation = error.to_ascii_lowercase();
            assert!(
                explanation.contains("fork")
                    || explanation.contains("warrant")
                    || explanation.contains("invalid chain")
                    || explanation.contains("invalid action"),
                "fork recovery is inconclusive (not an accepted rejection): {error}"
            );
        }
        Ok(value) => assert_eq!(
            value.author_chain_flagged,
            Some(true),
            "known same-agent fork was not explicitly flagged (false/unknown)"
        ),
    }
    marker("same_author_fork_untrusted");
}
