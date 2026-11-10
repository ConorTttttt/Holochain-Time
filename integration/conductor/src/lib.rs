//! Test-only Holochain 0.7 conductor integration harness.
#![forbid(unsafe_code)]
pub mod fixtures;
pub mod fork_recovery;
pub mod resilience;

/// Await native task shutdown before the Tokio test runtime is torn down.
/// SweetConductor's Drop only spawns shutdown and cannot await completion.
pub async fn shutdown_batch(batch: holochain::sweettest::SweetConductorBatch) {
    let mut stopped = 0;
    for mut conductor in batch {
        conductor.shutdown().await;
        assert!(!conductor.is_running());
        stopped += 1;
    }
    println!("CONDUCTOR_SHUTDOWN_COMPLETE={stopped}");
}
