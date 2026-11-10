//! Disposable crash helper for actual OS-level kill tests.
//! Test-only deterministic private key; NEVER for production oracle use.
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64};
use vtime_core::signed_batch::{prepare_batch_root, BatchStatementV3};
use vtime_core::DalekVerifier;
use vtime_oracle_state::Journal;

const TIME_US: i64 = 1_792_000_000_000_000;
const MAX_RADIUS: i64 = 10_000_000;

fn park(label: &str) -> ! {
    println!("{label}");
    io::stdout().flush().expect("flush crash-test marker");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("expected crash-test mode");
    let path = args.next().expect("expected journal path");
    assert!(args.next().is_none(), "unexpected argument");
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let dna = dna_hash_from_b64(&dna_hash_to_b64(&[1u8; 32])).unwrap();
    let key = signing.verifying_key().to_bytes();
    let mut journal = Journal::open(Path::new(&path), dna, key, MAX_RADIUS, &DalekVerifier)
        .expect("child failed to open existing journal");
    let (root, count) = prepare_batch_root(&dna, &[[0xAA; 32], [0xAB; 32]]).unwrap();
    let statement = BatchStatementV3 {
        dna,
        oracle: key,
        merkle_root: root,
        nonce_count: count,
        earliest_us: TIME_US,
        latest_us: TIME_US + 1_000_000,
        seq: 0,
        prev_signature: None,
        floor_us: None,
    };
    journal.prepare(statement).expect("failed durable prepare");
    match mode.as_str() {
        "before_signer" => park("READY_PREPARED"),
        "inside_signer" => {
            journal
                .sign_prepared(
                    |msg| {
                        let _issued = signing.sign(msg).to_bytes();
                        // Signal only AFTER the signer has executed, BEFORE any
                        // signed output can be persisted or returned to the caller.
                        park("READY_SIGNING")
                    },
                    &DalekVerifier,
                )
                .unwrap();
        }
        "after_commit" => {
            let signed = journal
                .sign_prepared(|msg| Ok(signing.sign(msg).to_bytes()), &DalekVerifier)
                .unwrap();
            assert_eq!(signed.statement.seq, 0);
            park("READY_COMMITTED");
        }
        _ => panic!("invalid crash-test mode"),
    }
}
