//! Sprint 38 Lair signer + authenticated checkpoint regressions, run against a
//! real Lair IPC keystore server (in-process, unix socket, passphrase
//! authenticated). Test-only keys; checkpoint service is a TEST DOUBLE.
mod common;

use std::fs;
use std::time::Duration;

use common::*;
use vtime_core::signed_batch::{BatchStatementV3, BATCH_SIGNING_BYTES_LEN};
use vtime_core::{DalekVerifier, Ed25519Verifier};
use vtime_lair_signer::{
    FailureClass, LairOracleSigner, SharedLairSigner, SignerError, SignerIdentity,
};
use vtime_oracle_state::runtime::{BatchSignRequest, OracleSigner, RuntimeError};
use vtime_oracle_state::StoreError;

fn request(id: u8, seed: u8) -> BatchSignRequest {
    BatchSignRequest {
        request_id: [id; 32],
        nonces: nonces(seed, 3),
    }
}

fn statement_bytes(dna: [u8; 39], oracle: [u8; 32], seq: u64) -> Vec<u8> {
    let (merkle_root, nonce_count) =
        vtime_core::signed_batch::prepare_batch_root(&dna, &nonces(1, 2)).unwrap();
    let interval = vtime_core::interval::TimeInterval::from_midpoint(T0, 250_000).unwrap();
    BatchStatementV3 {
        dna,
        oracle,
        merkle_root,
        nonce_count,
        earliest_us: interval.earliest_us,
        latest_us: interval.latest_us,
        seq,
        prev_signature: (seq > 0).then_some([1u8; 64]),
        floor_us: (seq > 0).then_some(T0 - 1_000_000),
    }
    .signing_bytes()
    .unwrap()
}

#[test]
fn signs_through_lair_commits_journal_and_advances_external_checkpoint() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-a");
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    let mut runtime = lane.open(signer.clone()).unwrap();

    let signed = runtime.sign(request(1, 10)).unwrap();
    let bytes = signed.statement.signing_bytes().unwrap();
    let sig: [u8; 64] = signed.signature.as_slice().try_into().unwrap();
    assert!(DalekVerifier.verify(&lane.oracle, &bytes, &sig).unwrap());
    assert_eq!(signed.statement.seq, 0);
    assert_eq!(lane.service.version(lane.dna, lane.oracle), 1);
    let status = signer.status();
    assert_eq!((status.keystore_requests, status.successes), (1, 1));
    assert!(status.identity_bound && status.last_failure.is_none());

    let second = runtime.sign(request(2, 20)).unwrap();
    assert_eq!(second.statement.seq, 1);
    assert_eq!(second.statement.prev_signature, Some(sig));
    assert_eq!(lane.service.version(lane.dna, lane.oracle), 2);
}

#[test]
fn duplicate_request_returns_original_signature_without_new_lair_call() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-dup");
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    let mut runtime = lane.open(signer.clone()).unwrap();
    let first = runtime.sign(request(1, 10)).unwrap();
    let again = runtime.sign(request(1, 10)).unwrap();
    assert_eq!(first, again);
    assert_eq!(signer.status().keystore_requests, 1);
    assert!(matches!(
        runtime.sign(request(1, 99)),
        Err(RuntimeError::ConflictingRequest)
    ));
    assert_eq!(signer.status().keystore_requests, 1);
}

#[test]
fn invalid_request_rejected_before_any_lair_call() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-invalid");
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    let mut runtime = lane.open(signer.clone()).unwrap();
    let duplicate_nonces = BatchSignRequest {
        request_id: [3; 32],
        nonces: vec![[5; 32]; 2],
    };
    assert!(runtime.sign(duplicate_nonces).is_err());
    let empty = BatchSignRequest {
        request_id: [4; 32],
        nonces: vec![],
    };
    assert!(runtime.sign(empty).is_err());
    assert_eq!(signer.status().keystore_requests, 0);
}

#[test]
fn adapter_refuses_arbitrary_wrong_dna_wrong_oracle_and_replayed_sequence() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-guard");
    let mut signer = lair.signer(lane.identity());

    let reject = |r: Result<[u8; 64], String>| {
        let e = r.unwrap_err();
        assert!(e.starts_with("REJECTED_BEFORE_KEYSTORE"), "{e}");
    };
    reject(signer.sign_once(b"arbitrary bytes the oracle must never sign"));
    reject(signer.sign_once(&vec![0u8; BATCH_SIGNING_BYTES_LEN]));
    reject(signer.sign_once(&statement_bytes(dna(8), lane.oracle, 0)));
    reject(signer.sign_once(&statement_bytes(lane.dna, [1u8; 32], 0)));
    assert_eq!(signer.status().keystore_requests, 0);
    assert_eq!(
        signer.status().last_failure,
        Some(FailureClass::RejectedBeforeKeystore)
    );
    assert!(FailureClass::RejectedBeforeKeystore.proves_no_signature());

    let ok = statement_bytes(lane.dna, lane.oracle, 5);
    let sig = signer.sign_once(&ok).unwrap();
    assert!(DalekVerifier.verify(&lane.oracle, &ok, &sig).unwrap());
    // Same or lower sequence again in this process: refused before Lair.
    reject(signer.sign_once(&ok));
    reject(signer.sign_once(&statement_bytes(lane.dna, lane.oracle, 4)));
    assert_eq!(signer.status().keystore_requests, 1);
}

#[test]
fn identity_binding_rejects_key_mismatch_exportable_unknown_tag_and_wrong_passphrase() {
    let lair = LairHarness::start();
    let a = lair.new_seed("oracle-a", false);
    let b = lair.new_seed("oracle-b", false);
    lair.new_seed("exportable", true);
    let connect = |tag: &str, oracle: [u8; 32], pass: &str| {
        LairOracleSigner::connect(
            lair.url.clone(),
            passphrase(pass),
            SignerIdentity {
                dna: dna(7),
                oracle,
                lair_tag: tag.into(),
            },
            TIMEOUT,
        )
        .map(|_| ())
    };
    let good = "test-only-lair-passphrase";
    assert_eq!(connect("oracle-a", a, good), Ok(()));
    assert_eq!(
        connect("oracle-a", b, good),
        Err(SignerError::KeyMismatch {
            expected: b,
            actual: a
        })
    );
    assert_eq!(
        connect("exportable", a, good),
        Err(SignerError::ExportableKey)
    );
    assert!(matches!(
        connect("missing", a, good),
        Err(SignerError::UnknownTag(_))
    ));
    assert!(matches!(
        connect("oracle-a", a, "wrong passphrase"),
        Err(SignerError::Connect(_))
    ));
}

#[test]
fn runtime_refuses_signer_for_another_oracle() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-lane");
    let other = lair.new_seed("oracle-other", false);
    let signer = SharedLairSigner::new(lair.signer(SignerIdentity {
        dna: lane.dna,
        oracle: other,
        lair_tag: "oracle-other".into(),
    }));
    assert!(matches!(
        lane.open(signer),
        Err(RuntimeError::WrongSignerKey)
    ));
}

#[test]
fn ambiguous_lair_outcome_quarantines_and_restart_never_resigns() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-amb");
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    let mut runtime = lane.open(signer.clone()).unwrap();
    runtime.sign(request(1, 10)).unwrap();

    signer.set_request_timeout(Duration::from_millis(300));
    lair.stall(Duration::from_millis(1500));
    let err = runtime.sign(request(2, 20)).unwrap_err();
    assert!(
        err.to_string().contains("AMBIGUOUS") || matches!(err, RuntimeError::Journal(_)),
        "{err}"
    );
    let status = signer.status();
    assert_eq!(status.last_failure, Some(FailureClass::Ambiguous));
    assert!(!FailureClass::Ambiguous.proves_no_signature());
    assert!(matches!(
        runtime.sign(request(3, 30)),
        Err(RuntimeError::Quarantined)
    ));
    assert_eq!(
        lane.service.version(lane.dna, lane.oracle),
        1,
        "no checkpoint for ambiguous op"
    );
    drop(runtime);

    // "Process restart": fresh Lair session and runtime over the same journal.
    // The journal records that the signer may have been invoked, so the lane
    // refuses to open at all until an operator reconciles or retires it.
    let fresh = SharedLairSigner::new(lair.signer(lane.identity()));
    assert!(matches!(
        lane.open(fresh.clone()),
        Err(RuntimeError::Journal(StoreError::AmbiguousSigning))
    ));
    assert_eq!(
        fresh.status().keystore_requests,
        0,
        "restart must not re-sign"
    );
}

#[test]
fn restart_after_success_continues_sequence_and_replays_from_journal() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-restart");
    let first = {
        let mut runtime = lane
            .open(SharedLairSigner::new(lair.signer(lane.identity())))
            .unwrap();
        runtime.sign(request(1, 10)).unwrap()
    };
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    let mut runtime = lane.open(signer.clone()).unwrap();
    assert_eq!(runtime.sign(request(1, 10)).unwrap(), first);
    assert_eq!(signer.status().keystore_requests, 0);
    let next = runtime.sign(request(2, 20)).unwrap();
    assert_eq!(next.statement.seq, 1);
    assert_eq!(
        next.statement.prev_signature.map(|s| s.to_vec()),
        Some(first.signature.clone())
    );
}

#[test]
fn journal_backup_rollback_is_rejected_by_external_checkpoint() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-rollback");
    let backup = lane.dir.path().join("journal.backup");
    fs::copy(&lane.journal, &backup).unwrap();
    {
        let mut runtime = lane
            .open(SharedLairSigner::new(lair.signer(lane.identity())))
            .unwrap();
        runtime.sign(request(1, 10)).unwrap();
    }
    fs::copy(&backup, &lane.journal).unwrap();
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    assert!(lane.open(signer.clone()).is_err(), "stale journal accepted");
    assert_eq!(signer.status().keystore_requests, 0);
}

#[test]
fn replayed_forged_and_regressed_checkpoints_are_rejected() {
    use vtime_oracle_state::runtime::CheckpointAnchor;
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-anchor");
    {
        let mut runtime = lane
            .open(SharedLairSigner::new(lair.signer(lane.identity())))
            .unwrap();
        runtime.sign(request(1, 10)).unwrap();
    }
    // Replay of an old, genuinely signed reply (first reply ever: version 0).
    lane.service.mode.set(ServiceMode::ReplayOldReply);
    let mut anchor = lane.anchor();
    let e = anchor
        .load_authenticated(&lane.dna, &lane.oracle)
        .unwrap_err();
    assert!(e.contains("not bound to this request"), "{e}");
    assert!(lane
        .open(SharedLairSigner::new(lair.signer(lane.identity())))
        .is_err());

    // Reply signed by a key other than the pinned service key.
    lane.service.mode.set(ServiceMode::ForgeKey);
    let e = lane
        .anchor()
        .load_authenticated(&lane.dna, &lane.oracle)
        .unwrap_err();
    assert!(e.contains("signature invalid"), "{e}");

    // Freshly signed but regressed version within one process.
    lane.service.mode.set(ServiceMode::Honest);
    let mut anchor = lane.anchor();
    anchor.load_authenticated(&lane.dna, &lane.oracle).unwrap();
    let genesis = lane.service.replies.borrow()[0].record.checkpoint.clone();
    lane.service
        .state
        .borrow_mut()
        .insert((lane.dna, lane.oracle), (0, genesis));
    let e = anchor
        .load_authenticated(&lane.dna, &lane.oracle)
        .unwrap_err();
    assert!(e.contains("stale checkpoint"), "{e}");
}

#[test]
fn checkpoint_write_failure_withholds_signature_and_blocks_restart() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-cas");
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    let mut runtime = lane.open(signer.clone()).unwrap();
    lane.service.mode.set(ServiceMode::FailWrites);
    assert!(matches!(
        runtime.sign(request(1, 10)),
        Err(RuntimeError::Anchor(_))
    ));
    assert!(matches!(
        runtime.sign(request(2, 20)),
        Err(RuntimeError::Quarantined)
    ));
    drop(runtime);
    lane.service.mode.set(ServiceMode::Honest);
    // Local COMMIT exists but the anchor never advanced: refuse to open.
    assert!(lane
        .open(SharedLairSigner::new(lair.signer(lane.identity())))
        .is_err());
}

#[test]
fn health_and_rotation_planning() {
    let lair = LairHarness::start();
    let lane = Lane::new(&lair, "oracle-rot");
    lair.new_seed("oracle-next", false);
    lair.new_seed("oracle-next-exportable", true);
    let signer = SharedLairSigner::new(lair.signer(lane.identity()));
    assert_eq!(signer.health_check(), Ok(()));
    assert_eq!(signer.status().last_health_ok, Some(true));
    let plan = signer.plan_rotation("oracle-next".into()).unwrap();
    assert_eq!(plan.retiring_oracle, lane.oracle);
    assert_ne!(plan.next_oracle, lane.oracle);
    assert!(!plan.required_steps.is_empty());
    assert_eq!(
        signer.plan_rotation("oracle-rot".into()),
        Err(SignerError::RotationToSameKey)
    );
    assert_eq!(
        signer.plan_rotation("oracle-next-exportable".into()),
        Err(SignerError::ExportableKey)
    );
}
