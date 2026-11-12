//! Real separate-process Lair keystore (`lair-keystore` 0.7.1 binary) with a
//! persisted SQLite store in a disposable temporary root. Exercises SIGKILL of
//! the keystore during operation, restart, and authentication failure.
//!
//! Skips (and says so) when the binary is missing or not version 0.7.1, unless
//! `HC_VTIME_REQUIRE_LAIR_PROCESS=1`, which turns a skip into a failure. Only
//! the child processes this test starts are ever signalled.
mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use lair_keystore_api::dependencies::url::Url;
use lair_keystore_api::ipc_keystore_connect;
use lair_keystore_api::prelude::PwHashLimits;
use vtime_lair_signer::{FailureClass, LairOracleSigner, SharedLairSigner, SignerError};
use vtime_oracle_state::runtime::{BatchSignRequest, RuntimeError};
use vtime_oracle_state::StoreError;

const PASS: &str = "test-only-process-lair-passphrase";

fn lair_binary() -> Option<PathBuf> {
    let bin = std::env::var_os("LAIR_KEYSTORE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("lair-keystore"));
    let out = Command::new(&bin).arg("--version").output().ok()?;
    let version = String::from_utf8_lossy(&out.stdout);
    version.trim().ends_with("0.7.1").then_some(bin)
}

/// Kills (SIGKILL) and reaps the keystore child on drop.
struct LairProcess {
    child: Child,
}

impl LairProcess {
    fn start(bin: &Path, root: &Path) -> (Self, Url) {
        let mut child = Command::new(bin)
            .arg("--lair-root")
            .arg(root)
            .args(["server", "--piped"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(PASS.as_bytes())
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut ready = false;
        for line in BufReader::new(stdout).lines() {
            if line.unwrap().contains("# lair-keystore running #") {
                ready = true;
                break;
            }
        }
        assert!(ready, "lair-keystore server did not report readiness");
        let url = Command::new(bin)
            .arg("--lair-root")
            .arg(root)
            .arg("url")
            .output()
            .unwrap();
        let url = Url::parse(String::from_utf8(url.stdout).unwrap().trim()).unwrap();
        (Self { child }, url)
    }

    fn sigkill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for LairProcess {
    fn drop(&mut self) {
        self.sigkill();
    }
}

fn init(bin: &Path, root: &Path) {
    let mut child = Command::new(bin)
        .arg("--lair-root")
        .arg(root)
        .args(["init", "--piped"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(PASS.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "lair-keystore init failed");
}

fn new_seed(url: &Url, tag: &str) -> [u8; 32] {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let url = url.clone();
    let tag: Arc<str> = tag.into();
    rt.block_on(async move {
        let client = ipc_keystore_connect(url, passphrase(PASS)).await.unwrap();
        let info = PwHashLimits::Minimum
            .with_exec(|| client.new_seed(tag, None, false))
            .await
            .unwrap();
        *info.ed25519_pub_key
    })
}

fn request(id: u8) -> BatchSignRequest {
    BatchSignRequest {
        request_id: [id; 32],
        nonces: nonces(id, 2),
    }
}

#[test]
fn separate_lair_process_sigkill_restart_and_authentication() {
    let Some(bin) = lair_binary() else {
        if std::env::var("HC_VTIME_REQUIRE_LAIR_PROCESS").as_deref() == Ok("1") {
            panic!("lair-keystore 0.7.1 binary required but not found");
        }
        eprintln!("SKIPPED: lair-keystore 0.7.1 binary not found (set LAIR_KEYSTORE_BIN)");
        return;
    };
    let root = tempfile::TempDir::with_prefix("hc-vtime-lair-process").unwrap();
    init(&bin, root.path());
    let (mut server, url) = LairProcess::start(&bin, root.path());
    let oracle = new_seed(&url, "oracle-process");
    let lane = Lane::with_key(oracle, "oracle-process");

    // Unauthorized access: wrong keystore passphrase.
    assert!(matches!(
        LairOracleSigner::connect(url.clone(), passphrase("wrong"), lane.identity(), TIMEOUT),
        Err(SignerError::Connect(_))
    ));

    let signer = SharedLairSigner::new(
        LairOracleSigner::connect(url.clone(), passphrase(PASS), lane.identity(), TIMEOUT).unwrap(),
    );
    let mut runtime = lane.open(signer.clone()).unwrap();
    let first = runtime.sign(request(1)).unwrap();
    assert_eq!(first.statement.seq, 0);

    // Keystore process crash while the oracle lane is live.
    server.sigkill();
    signer.set_request_timeout(Duration::from_secs(5));
    assert!(runtime.sign(request(2)).is_err());
    let status = signer.status();
    assert!(matches!(
        status.last_failure,
        Some(FailureClass::KeystoreError | FailureClass::Ambiguous)
    ));
    assert!(matches!(
        runtime.sign(request(3)),
        Err(RuntimeError::Quarantined)
    ));
    drop(runtime);

    // Keystore restart from its persisted store: the key survives, but the
    // oracle lane stays closed because the failed call is ambiguous.
    let (_server2, url2) = LairProcess::start(&bin, root.path());
    let fresh = SharedLairSigner::new(
        LairOracleSigner::connect(url2, passphrase(PASS), lane.identity(), TIMEOUT).unwrap(),
    );
    assert_eq!(fresh.health_check(), Ok(()));
    assert!(matches!(
        lane.open(fresh.clone()),
        Err(RuntimeError::Journal(StoreError::AmbiguousSigning))
    ));
    assert_eq!(fresh.status().keystore_requests, 0);
}

#[test]
fn separate_lair_process_restart_between_successful_signatures() {
    let Some(bin) = lair_binary() else {
        eprintln!("SKIPPED: lair-keystore 0.7.1 binary not found");
        return;
    };
    let root = tempfile::TempDir::with_prefix("hc-vtime-lair-process").unwrap();
    init(&bin, root.path());
    let (mut server, url) = LairProcess::start(&bin, root.path());
    let oracle = new_seed(&url, "oracle-restart");
    let lane = Lane::with_key(oracle, "oracle-restart");
    let first = {
        let signer = SharedLairSigner::new(
            LairOracleSigner::connect(url, passphrase(PASS), lane.identity(), TIMEOUT).unwrap(),
        );
        let mut runtime = lane.open(signer).unwrap();
        runtime.sign(request(1)).unwrap()
    };
    // Idle keystore restart (no request in flight): signing continues safely.
    server.sigkill();
    let (_server2, url2) = LairProcess::start(&bin, root.path());
    let signer = SharedLairSigner::new(
        LairOracleSigner::connect(url2, passphrase(PASS), lane.identity(), TIMEOUT).unwrap(),
    );
    let mut runtime = lane.open(signer.clone()).unwrap();
    let second = runtime.sign(request(2)).unwrap();
    assert_eq!(second.statement.seq, 1);
    assert_eq!(
        second.statement.prev_signature.map(|s| s.to_vec()),
        Some(first.signature)
    );
    assert_eq!(signer.status().keystore_requests, 1);
}
