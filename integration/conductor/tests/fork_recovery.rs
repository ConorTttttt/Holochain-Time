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
use vtime_core::{DalekVerifier, Ed25519Verifier};

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
    hc_vtime_conductor_smoke::shutdown_batch(peers).await;
}

/// Deliberately disruptive laboratory fork injection. Only real integrated
/// warrant records count as warrant detection, NOT arbitrary zome errors.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "opt-in: two source chains with the same test-only agent key; requires real warrant convergence"]
async fn real_same_agent_fork_issues_and_persists_warrant_across_observer_restart() {
    holochain_trace::test_run();
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
    // Clone a genuine accepted prefix BEFORE installing the second cell.
    // Independent genesis timestamps produce disjoint chains, not a fork
    // with a shared predecessor. No synthetic action or warrant is inserted.
    let records = main
        .get_dht_store(first.dna_hash())
        .unwrap()
        .as_read()
        .source_chain_records(&agent, true, false)
        .await
        .unwrap();
    // Clone only genesis. Private CapGrant entries contain HashSet fields in
    // Holochain 0.7.1 and need not reserialize to the original entry bytes.
    // Never weaken the copied-entry hash check to import such a record.
    assert_eq!(records.len(), 3, "expected an uninitialized genesis prefix");
    let mut previous = None;
    for (seq, record) in records.iter().enumerate() {
        let action = record.action();
        assert_eq!(action.author(), &agent);
        assert_eq!(action.action_seq(), seq as u32);
        assert_eq!(action.prev_action(), previous.as_ref());
        assert_eq!(&ActionHash::with_data_sync(action), record.action_address());
        let signing_bytes = ExternIO::encode(action).unwrap();
        assert!(
            DalekVerifier
                .verify(
                    agent.get_raw_32().try_into().unwrap(),
                    signing_bytes.as_bytes(),
                    record.signature().as_ref().try_into().unwrap(),
                )
                .unwrap(),
            "copied prefix signature is invalid"
        );
        if let Some(hash) = action.entry_hash() {
            let entry = record.entry().as_option().expect("copied entry missing");
            assert_eq!(&EntryHash::with_data_sync(entry), hash);
        }
        previous = Some(record.action_address().clone());
    }
    let common_head = previous.expect("signed prefix is empty");
    let second_store = alternate.get_dht_store(first.dna_hash()).unwrap();
    assert!(
        second_store
            .as_read()
            .source_chain_records(&agent, true, false)
            .await
            .unwrap()
            .is_empty(),
        "fork clone store must be empty"
    );
    second_store
        .write_restored_chain(&agent, records)
        .await
        .unwrap();
    drop(second_store);
    let second = alternate
        .setup_app_for_agent("s22-fork", agent.clone(), std::slice::from_ref(&dna))
        .await
        .expect("alternate source-chain install failed")
        .into_cells()
        .remove(0);
    for conductor in [&main, &alternate] {
        let head = conductor
            .get_agent_source_chain(&agent, first.dna_hash())
            .await
            .chain_head_nonempty()
            .unwrap();
        assert_eq!(head.action, common_head, "cloned source-chain heads differ");
    }
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
    let left = main
        .get_dht_store(&dna_hash)
        .unwrap()
        .as_read()
        .retrieve_record(&a, Some(&agent))
        .await
        .unwrap()
        .unwrap();
    let right = alternate
        .get_dht_store(&dna_hash)
        .unwrap()
        .as_read()
        .retrieve_record(&b, Some(&agent))
        .await
        .unwrap()
        .unwrap();
    // The first call initializes each cell independently: the first signed
    // post-genesis actions (private grants) are the actual fork pair. Their
    // signed headers are public; never archive private capability payloads.
    let left_chain = main
        .get_dht_store(&dna_hash)
        .unwrap()
        .as_read()
        .source_chain_records(&agent, false, true)
        .await
        .unwrap();
    let right_chain = alternate
        .get_dht_store(&dna_hash)
        .unwrap()
        .as_read()
        .source_chain_records(&agent, false, true)
        .await
        .unwrap();
    let left_fork = &left_chain[3];
    let right_fork = &right_chain[3];
    assert_eq!(left_fork.action().prev_action(), Some(&common_head));
    assert_eq!(right_fork.action().prev_action(), Some(&common_head));
    assert_eq!(
        left_fork.action().action_seq(),
        right_fork.action().action_seq()
    );
    assert_ne!(left_fork.action_address(), right_fork.action_address());
    println!(
        "FORK_RECOVERY_SIGNED_RECORDS={}",
        serde_json::to_string(&[left_fork.signed_action(), right_fork.signed_action()]).unwrap()
    );
    println!(
        "FORK_RECOVERY_SIGNED_ANCHORS={}",
        serde_json::to_string(&[left, right]).unwrap()
    );
    marker("isolated_same_agent_branches_created");

    // A network directory identifies an agent by one current address.
    // Observe branch A first, then replace its live peer with the restored
    // fork database. Concurrent duplicate-key peers may overwrite routing
    // entries before the observer ever receives both signed histories.
    assert!(SweetConductor::exchange_peer_info([&main, &observer]).await);
    await_consistency_s(90, [&first, &observer_cell])
        .await
        .expect("observer did not integrate the first signed branch");
    assert!(observer
        .get_dht_store(&dna_hash)
        .unwrap()
        .as_read()
        .retrieve_record(&a, None)
        .await
        .unwrap()
        .is_some());
    main.shutdown().await;
    // Leaving publishes newer offline agent metadata for this SAME key.
    // Rejoin the alternate after that leave so its online address is fresh;
    // exchanging the alternate's older online record would be ignored.
    alternate.shutdown().await;
    alternate.startup().await;
    assert!(SweetConductor::exchange_peer_info([&alternate, &observer]).await);
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
    for (label, conductor) in [("alternate", &alternate), ("observer", &observer)] {
        let store = conductor.get_dht_store(&dna_hash).unwrap();
        let left_seen = store
            .as_read()
            .retrieve_record(&a, None)
            .await
            .unwrap()
            .is_some();
        let right_seen = store
            .as_read()
            .retrieve_record(&b, None)
            .await
            .unwrap()
            .is_some();
        println!(
            "FORK_RECOVERY_DELIVERY={label}:left={left_seen}:right={right_seen}:limbo={:?}",
            store.limbo_state_counts().await.unwrap()
        );
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
    alternate.shutdown().await;
    observer.shutdown().await;
    marker("warranted_author_not_cleared_after_restart");
}
