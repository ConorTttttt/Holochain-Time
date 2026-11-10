//! Sprint 22: actual Holochain 0.7.1 restart and fork/warrant acceptance.
//! Requires test-only DNA with publicly known Roughenough fixtures.
//!
//! The ignored fork scenario deliberately reuses an agent signing key in
//! separate source-chain databases. NEVER run against a real/production DNA.
use hc_vtime_conductor_smoke::fixtures::signed_three;
use hc_vtime_conductor_smoke::fork_recovery::{classify, ActivityHealth, Decision, ForkFixture};
use hc_vtime_conductor_smoke::resilience::{assess, RecoveryAssessment, WitnessResult};
use holochain::prelude::*;
use holochain::sweettest::*;
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vtime_core::seal::seal_nonce;

fn test_dna() -> String {
    assert_eq!(
        std::env::var("HC_VTIME_SIGNED_TEST_ONLY").as_deref(),
        Ok("1"),
        "public test-fixture signer sentinel is required"
    );
    let path = std::env::var("HC_VTIME_TEST_DNA").expect("test-only DNA path required");
    assert!(Path::new(&path).is_file(), "test-only DNA is absent");
    path
}
fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn marker(case: &str) {
    println!("FORK_RECOVERY_CASE={case}:PASS");
}
async fn anchor(conductor: &SweetConductor, cell: &SweetCell, id: u8) -> ActionHash {
    conductor
        .call(
            &cell.zome("vtime"),
            "create_anchor",
            json!({"roughtime": signed_three([id; 32], epoch())}),
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
    let value: Result<WitnessResult, _> = conductor
        .call_fallible(
            &cell.zome("vtime"),
            "verify_time_with_witnesses",
            json!({"target": target, "anchors": anchors, "seals": seals}),
        )
        .await;
    value.map_err(|error| format!("{error:?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn real_three_conductor_restart_preserves_signed_witnesses_without_false_clearance() {
    let dna = SweetDnaFile::from_bundle(Path::new(&test_dna()))
        .await
        .expect("invalid signed test-only DNA");
    let mut peers = SweetConductorBatch::standard(3).await;
    let mut cells = peers
        .setup_app("s22-restart", &[dna])
        .await
        .expect("failed to install signed test DNA")
        .cells_flattened();
    peers.exchange_peer_info().await;
    let original = anchor(&peers[0], &cells[0], 0x22).await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("target did not replicate");
    let witness_seal = seal(&peers[1], &cells[1], &original).await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("seal did not replicate");

    let before = witness(
        &peers[2],
        &cells[2],
        &original,
        vec![original.clone()],
        vec![witness_seal.clone()],
    )
    .await
    .expect("valid signed witness failed before restart");
    assert!(before.not_before_us.is_some() && before.not_after_us.is_some());
    assert!(!before.evidence_complete);
    assert_ne!(assess(&before), RecoveryAssessment::UntrustedConflict);
    marker("signed_witness_before_restart");

    // Restart with the same persistent source chain, keystore and DNA.
    let id = cells[2].cell_id().clone();
    peers[2].shutdown().await;
    let during = anchor(&peers[0], &cells[0], 0x23).await;
    await_consistency_s(90, [&cells[0], &cells[1]])
        .await
        .expect("survivors did not replicate while observer was stopped");
    peers[2].startup().await;
    cells[2] = peers[2]
        .get_sweet_cell(id)
        .expect("restarted conductor lost its original cell");
    peers.exchange_peer_info().await;
    await_consistency_s(90, [&cells[0], &cells[1], &cells[2]])
        .await
        .expect("restarted conductor never rejoined");

    let after = witness(
        &peers[2],
        &cells[2],
        &original,
        vec![original.clone()],
        vec![witness_seal],
    )
    .await
    .expect("restarted conductor lost signed witness verification");
    assert_eq!(after.not_before_us, before.not_before_us);
    assert_eq!(after.not_after_us, before.not_after_us);
    assert!(!after.evidence_complete);
    assert_ne!(assess(&after), RecoveryAssessment::UntrustedConflict);
    let recovered = witness(&peers[2], &cells[2], &during, vec![during.clone()], vec![])
        .await
        .expect("restarted conductor did not obtain missed signed anchor");
    assert!(recovered.not_before_us.is_some());
    assert!(!recovered.evidence_complete);
    marker("restart_rejoin_preserves_signed_bounds");

    // An unknown proof after restart is never silently transformed into a
    // clean, empty witness result.
    let fake = ActionHash::from_raw_32(vec![0xEA; 32]);
    let denied = witness(
        &peers[2],
        &cells[2],
        &original,
        vec![original.clone()],
        vec![fake],
    )
    .await
    .expect_err("missing seal became acceptable after restart");
    assert!(
        denied.contains("supplied seal action is unavailable"),
        "wrong missing-witness failure after restart: {denied}"
    );
    marker("missing_witness_still_rejected_after_restart");
}

/// Deliberately disruptive laboratory fork injection. Only real integrated
/// warrant records count as warrant detection, NOT arbitrary zome errors.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "opt-in: two source chains with the same test-only agent key; requires real warrant convergence"]
async fn real_same_agent_fork_issues_and_persists_warrant_across_observer_restart() {
    let dna = SweetDnaFile::from_bundle(Path::new(&test_dna()))
        .await
        .expect("invalid test DNA");
    let rendezvous = SweetLocalRendezvous::new().await;
    let config = SweetConductorConfig::rendezvous(false);
    let mut main = SweetConductor::from_config_rendezvous(config.clone(), rendezvous.clone()).await;
    let agent = SweetAgents::one(main.keystore()).await;
    // Distinct conductor database, intentionally same keystore.
    let mut alternate = SweetConductor::create_with_defaults(
        config.clone(),
        Some(main.keystore()),
        Some(rendezvous.clone()),
    )
    .await;
    let mut observer = SweetConductor::from_config_rendezvous(config, rendezvous).await;
    let first = main
        .setup_app_for_agent("s22-main", agent.clone(), std::slice::from_ref(&dna))
        .await
        .expect("main source-chain install failed")
        .into_cells()
        .remove(0);
    let second = alternate
        .setup_app_for_agent("s22-fork", agent.clone(), std::slice::from_ref(&dna))
        .await
        .expect("alternate source-chain install failed")
        .into_cells()
        .remove(0);
    let observer_cell = observer
        .setup_app("s22-observer", &[dna])
        .await
        .expect("observer install failed")
        .into_cells()
        .remove(0);
    assert_eq!(first.agent_pubkey(), second.agent_pubkey());
    assert_ne!(first.agent_pubkey(), observer_cell.agent_pubkey());
    let dna_hash = first.dna_hash().clone();
    let observed_cell_id = observer_cell.cell_id().clone();

    // No peer exchange until both branches have actually authored their own
    // signed time actions. A different hash alone is not a verified fork;
    // authority-issued warrant evidence is required below.
    let a = anchor(&main, &first, 0x41).await;
    let b = anchor(&alternate, &second, 0x42).await;
    assert_ne!(a, b, "same-key isolated chains did not diverge");
    marker("isolated_same_agent_branches_created");

    // exchange_peer_info returns a unique-agent count heuristic; with three
    // conductors but deliberately only TWO different agent keys, its boolean
    // can be false even when signed peer metadata was exchanged. Do not use
    // that boolean as an assertion in a duplicate-key fork test.
    SweetConductor::exchange_peer_info([&main, &alternate, &observer]).await;
    observer
        .wait_for_peer_visible(
            vec![agent.clone()],
            Some(observed_cell_id.clone()),
            Duration::from_secs(30),
        )
        .await
        .expect("observer never learned the forked agent's peer info");

    let started = Instant::now();
    let mut warrant_count = 0usize;
    while started.elapsed() < Duration::from_secs(120) {
        let db = observer
            .get_dht_store(&dna_hash)
            .expect("observer DHT store unavailable");
        let rows = db
            .as_read()
            .get_warrants_by_warrantee(agent.clone())
            .await
            .expect("warrant database query failed");
        assert!(rows.iter().all(|row| row.data().warrantee == agent));
        warrant_count = rows.len();
        if warrant_count > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        warrant_count > 0,
        "NO real integrated warrant after 120s: fork detection is INCONCLUSIVE/FAIL, not PASS"
    );
    println!("FORK_RECOVERY_WARRANT_COUNT={warrant_count}");
    marker("integrated_warrant_against_forked_agent");

    // A warrant is enough to block a purportedly clean verdict, even when
    // activity status may be unavailable or a record is only locally cached.
    let decision = classify(&ForkFixture {
        id: "observed-real-warrant".into(),
        dna: dna_hash.to_string(),
        author: agent.to_string(),
        activity_health: ActivityHealth::Unavailable,
        warrants_observed: Some(warrant_count as u32),
        actions: vec![],
        expected: Decision::RejectConflict,
    });
    assert_eq!(decision, Decision::RejectConflict);
    marker("warrant_blocks_clean_classification");

    observer.shutdown().await;
    observer.startup().await;
    let restored = observer
        .get_sweet_cell(observed_cell_id)
        .expect("observer lost its original DNA/keystore after restart");
    assert_eq!(restored.dna_hash(), &dna_hash);
    let persisted = observer
        .get_dht_store(&dna_hash)
        .unwrap()
        .as_read()
        .get_warrants_by_warrantee(agent.clone())
        .await
        .expect("persisted warrant database unreadable");
    assert!(
        persisted.iter().any(|row| row.data().warrantee == agent),
        "integrated warrant vanished across observer restart"
    );
    marker("warrant_survives_observer_restart");

    // Existing production witness endpoint must never announce a *clean*
    // same-author result after a provably integrated warrant. If it rejects
    // because the record was invalid, this must be a concrete integrity
    // rejection, not a generic timeout or missing peer.
    let observed = witness(&observer, &restored, &a, vec![a.clone()], vec![]).await;
    match observed {
        Ok(value) => {
            assert_eq!(
                value.author_chain_flagged,
                Some(true),
                "warranted agent was misreported as unflagged or unknown"
            );
            assert!(!value.evidence_complete);
        }
        Err(error) => {
            let reason = error.to_ascii_lowercase();
            assert!(
                reason.contains("warrant")
                    || reason.contains("fork")
                    || reason.contains("invalid action")
                    || reason.contains("invalid chain"),
                "generic error is not proof of refusal due to warrant: {error}"
            );
        }
    }
    marker("warranted_author_not_cleared_after_restart");
}
