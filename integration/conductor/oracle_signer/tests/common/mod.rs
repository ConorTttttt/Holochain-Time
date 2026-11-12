//! Shared test harness. Test-only identities and a checkpoint service TEST
//! DOUBLE. Nothing here is production key custody or external anti-rollback.
#![allow(dead_code)]
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use lair_keystore_api::dependencies::{sodoken, url::Url};
use lair_keystore_api::ipc_keystore::IpcKeystoreServer;
use lair_keystore_api::prelude::{LairServerConfigInner, PwHashLimits, SharedLockedArray};
use lair_keystore_api::{ipc_keystore_connect, LairClient};
use vtime_core::keys::{dna_hash_from_b64, dna_hash_to_b64};
use vtime_core::DalekVerifier;
use vtime_lair_signer::{
    record_signing_bytes, AuthenticatedCheckpointAnchor, CheckpointRecord, CheckpointTransport,
    LairOracleSigner, SharedLairSigner, SignedCheckpointReply, SignerIdentity,
};
use vtime_oracle_state::runtime::{OracleClock, OracleRuntime, RuntimeError, RuntimePolicy};
use vtime_oracle_state::{BootstrapAuthorization, Checkpoint, Journal};

pub const MAX_RADIUS: i64 = 10_000_000;
pub const T0: i64 = 1_792_000_000_000_000;
pub const TIMEOUT: Duration = Duration::from_secs(20);

pub fn passphrase(text: &str) -> SharedLockedArray {
    Arc::new(Mutex::new(sodoken::LockedArray::from(
        text.as_bytes().to_vec(),
    )))
}

pub fn dna(byte: u8) -> [u8; 39] {
    dna_hash_from_b64(&dna_hash_to_b64(&[byte; 32])).unwrap()
}

/// Real Lair IPC keystore server (unix socket, passphrase-authenticated) in a
/// private temporary root. In-memory store; one server per test.
pub struct LairHarness {
    pub rt: tokio::runtime::Runtime,
    _server: IpcKeystoreServer,
    pub url: Url,
    pub passphrase: SharedLockedArray,
    admin: LairClient,
    _dir: tempfile::TempDir,
}

impl LairHarness {
    pub fn start() -> Self {
        let dir = tempfile::TempDir::with_prefix("hc-vtime-lair-test").unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let pass = passphrase("test-only-lair-passphrase");
        let root = dir.path().to_owned();
        let (server, url, admin) = rt.block_on({
            let pass = pass.clone();
            async move {
                let config = Arc::new(
                    PwHashLimits::Minimum
                        .with_exec(|| LairServerConfigInner::new(&root, pass.clone()))
                        .await
                        .unwrap(),
                );
                let server = IpcKeystoreServer::new(
                    config,
                    lair_keystore_api::mem_store::create_mem_store_factory(),
                    pass.clone(),
                )
                .await
                .unwrap();
                let url = server.get_config().connection_url.clone();
                let admin = ipc_keystore_connect(url.clone(), pass).await.unwrap();
                (server, url, admin)
            }
        });
        Self {
            rt,
            _server: server,
            url,
            passphrase: pass,
            admin,
            _dir: dir,
        }
    }

    /// Block every server worker thread for `d`, so in-flight requests are
    /// received but not answered until later (a genuinely ambiguous outcome).
    pub fn stall(&self, d: Duration) {
        for _ in 0..4 {
            self.rt.spawn(async move { std::thread::sleep(d) });
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    /// Create a seed and return its Ed25519 public key.
    pub fn new_seed(&self, tag: &str, exportable: bool) -> [u8; 32] {
        let info = self
            .rt
            .block_on(
                PwHashLimits::Minimum
                    .with_exec(|| self.admin.new_seed(tag.into(), None, exportable)),
            )
            .unwrap();
        *info.ed25519_pub_key
    }

    pub fn signer(&self, identity: SignerIdentity) -> LairOracleSigner {
        LairOracleSigner::connect(self.url.clone(), self.passphrase.clone(), identity, TIMEOUT)
            .unwrap()
    }
}

/// Per-(DNA, oracle) version and latest checkpoint held by the test service.
pub type LaneStates = HashMap<([u8; 39], [u8; 32]), (u64, Checkpoint)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceMode {
    Honest,
    /// Return the first reply ever produced (old challenge, old version).
    ReplayOldReply,
    /// Sign with a key other than the pinned one.
    ForgeKey,
    /// Refuse every compare-and-swap.
    FailWrites,
}

/// In-memory checkpoint service TEST DOUBLE. Shares state across clones so
/// tests can simulate restarts, rollbacks and misbehaviour.
#[derive(Clone)]
pub struct TestCheckpointService {
    key: Rc<SigningKey>,
    forged: Rc<SigningKey>,
    pub state: Rc<RefCell<LaneStates>>,
    pub replies: Rc<RefCell<Vec<SignedCheckpointReply>>>,
    pub mode: Rc<Cell<ServiceMode>>,
}

impl TestCheckpointService {
    pub fn new() -> Self {
        Self {
            key: Rc::new(SigningKey::from_bytes(&[9u8; 32])),
            forged: Rc::new(SigningKey::from_bytes(&[10u8; 32])),
            state: Rc::default(),
            replies: Rc::default(),
            mode: Rc::new(Cell::new(ServiceMode::Honest)),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn genesis(&self, dna: [u8; 39], oracle: [u8; 32], checkpoint: Checkpoint) {
        self.state
            .borrow_mut()
            .insert((dna, oracle), (0, checkpoint));
    }

    pub fn version(&self, dna: [u8; 39], oracle: [u8; 32]) -> u64 {
        self.state.borrow()[&(dna, oracle)].0
    }

    fn sign(&self, record: CheckpointRecord, challenge: [u8; 32]) -> SignedCheckpointReply {
        let key = if self.mode.get() == ServiceMode::ForgeKey {
            &self.forged
        } else {
            &self.key
        };
        let signature = key
            .sign(&record_signing_bytes(&record, &challenge))
            .to_bytes();
        let reply = SignedCheckpointReply {
            record,
            challenge,
            signature,
        };
        self.replies.borrow_mut().push(reply.clone());
        reply
    }

    fn replay(&self) -> Option<SignedCheckpointReply> {
        (self.mode.get() == ServiceMode::ReplayOldReply)
            .then(|| self.replies.borrow().first().cloned())
            .flatten()
    }
}

impl CheckpointTransport for TestCheckpointService {
    fn read_latest(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        challenge: [u8; 32],
    ) -> Result<SignedCheckpointReply, String> {
        if let Some(old) = self.replay() {
            return Ok(old);
        }
        let (version, checkpoint) = self
            .state
            .borrow()
            .get(&(*dna, *oracle))
            .cloned()
            .ok_or("unknown lane")?;
        Ok(self.sign(
            CheckpointRecord {
                dna: *dna,
                oracle: *oracle,
                version,
                checkpoint,
            },
            challenge,
        ))
    }

    fn compare_and_swap(
        &mut self,
        dna: &[u8; 39],
        oracle: &[u8; 32],
        expected_version: u64,
        expected: &Checkpoint,
        next: &Checkpoint,
        challenge: [u8; 32],
    ) -> Result<SignedCheckpointReply, String> {
        if self.mode.get() == ServiceMode::FailWrites {
            return Err("simulated checkpoint service write failure".into());
        }
        let mut state = self.state.borrow_mut();
        let entry = state.get_mut(&(*dna, *oracle)).ok_or("unknown lane")?;
        if entry.0 != expected_version || &entry.1 != expected {
            return Err("compare-and-swap conflict".into());
        }
        *entry = (expected_version + 1, next.clone());
        let record = CheckpointRecord {
            dna: *dna,
            oracle: *oracle,
            version: entry.0,
            checkpoint: next.clone(),
        };
        drop(state);
        Ok(self.sign(record, challenge))
    }
}

#[derive(Clone)]
pub struct TestClock(pub Rc<Cell<i64>>);
impl OracleClock for TestClock {
    fn now_us(&mut self) -> Result<i64, String> {
        let now = self.0.get();
        self.0.set(now + 1_000_000);
        Ok(now)
    }
}

pub type Anchor = AuthenticatedCheckpointAnchor<TestCheckpointService>;
pub type Runtime = OracleRuntime<SharedLairSigner, Anchor, TestClock>;

/// One oracle lane: Lair key, bootstrapped journal, service genesis.
pub struct Lane {
    pub dir: tempfile::TempDir,
    pub journal: PathBuf,
    pub dna: [u8; 39],
    pub oracle: [u8; 32],
    pub tag: &'static str,
    pub service: TestCheckpointService,
    pub clock: TestClock,
}

impl Lane {
    pub fn new(lair: &LairHarness, tag: &'static str) -> Self {
        let oracle = lair.new_seed(tag, false);
        Self::with_key(oracle, tag)
    }

    pub fn with_key(oracle: [u8; 32], tag: &'static str) -> Self {
        let dir = tempfile::TempDir::with_prefix("hc-vtime-oracle-lane").unwrap();
        let journal = dir.path().join("oracle.journal");
        let dna = dna(7);
        let mut j = Journal::bootstrap_new(
            &journal,
            dna,
            oracle,
            MAX_RADIUS,
            BootstrapAuthorization::VerifiedNewIdentity,
        )
        .unwrap();
        let genesis = j.checkpoint().unwrap();
        drop(j);
        let service = TestCheckpointService::new();
        service.genesis(dna, oracle, genesis);
        Self {
            dir,
            journal,
            dna,
            oracle,
            tag,
            service,
            clock: TestClock(Rc::new(Cell::new(T0))),
        }
    }

    pub fn identity(&self) -> SignerIdentity {
        SignerIdentity {
            dna: self.dna,
            oracle: self.oracle,
            lair_tag: self.tag.into(),
        }
    }

    pub fn anchor(&self) -> Anchor {
        AuthenticatedCheckpointAnchor::new(self.service.clone(), self.service.public_key())
    }

    pub fn open(&self, signer: SharedLairSigner) -> Result<Runtime, RuntimeError> {
        OracleRuntime::open(
            &self.journal,
            RuntimePolicy {
                dna: self.dna,
                oracle: self.oracle,
                max_radius_us: MAX_RADIUS,
                radius_us: 250_000,
            },
            signer,
            self.anchor(),
            self.clock.clone(),
            Box::new(DalekVerifier),
        )
    }
}

pub fn nonces(seed: u8, n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| [seed.wrapping_add(i as u8); 32]).collect()
}
