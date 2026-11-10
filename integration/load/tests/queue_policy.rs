//! Deterministic synthetic contention checks. These are NOT conductor seals.
//! The separate queued_seal_load suite exercises real Holochain zome writes.
// This shared test-only module is intentionally only partially exercised by
// each individual integration-test crate; the union covers all public paths.
#[allow(dead_code)]
#[path = "../src/seal_queue.rs"]
mod seal_queue;

use seal_queue::{is_holochain_head_moved, QueueConfig, QueueFailure, SealQueue};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Barrier};

fn config(capacity: usize) -> QueueConfig {
    QueueConfig {
        capacity,
        max_wait: Duration::from_secs(5),
        max_retries: 2,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    }
}

fn observe_peak(max: &AtomicUsize, concurrent: usize) {
    max.fetch_max(concurrent, Ordering::SeqCst);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_competing_requests_never_write_concurrently_on_one_agent_chain() {
    let q = SealQueue::new(3, config(30)).unwrap();
    let active: Vec<_> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
    let peaks: Vec<_> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
    let mut joins = Vec::new();
    for id in 0..30 {
        let lane = id % 3;
        let q = q.clone();
        let active = active[lane].clone();
        let peak = peaks[lane].clone();
        joins.push(tokio::spawn(async move {
            q.submit(
                lane,
                || {
                    let active = active.clone();
                    let peak = peak.clone();
                    async move {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        observe_peak(&peak, now);
                        tokio::task::yield_now().await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok::<usize, &'static str>(id)
                    }
                },
                |_| false,
            )
            .await
        }));
    }
    let mut values = Vec::new();
    for future in joins {
        let outcome = future.await.unwrap();
        assert!(outcome.metrics.admitted);
        assert_eq!(outcome.metrics.attempts, 1);
        values.push(outcome.result.unwrap());
    }
    values.sort_unstable();
    assert_eq!(values, (0..30).collect::<Vec<_>>());
    for peak in peaks {
        assert_eq!(peak.load(Ordering::SeqCst), 1, "overlapping source-chain writes");
    }
    for active in active {
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_independent_source_chains_can_execute_in_parallel() {
    let q = SealQueue::new(3, config(3)).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let futures: Vec<_> = (0..3).map(|id| {
        let queue = q.clone();
        let barrier = barrier.clone();
        let active = active.clone();
        let peak = peak.clone();
        tokio::spawn(async move {
            queue
                .submit(
                    id,
                    || {
                        let barrier = barrier.clone();
                        let active = active.clone();
                        let peak = peak.clone();
                        async move {
                            let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                            observe_peak(&peak, n);
                            barrier.wait().await;
                            active.fetch_sub(1, Ordering::SeqCst);
                            Ok::<usize, &'static str>(id)
                        }
                    },
                    |_| false,
                )
                .await
        })
    }).collect();
    for future in futures {
        assert!(future.await.unwrap().result.is_ok());
    }
    assert_eq!(peak.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_queue_rejects_before_invoking_any_new_call() {
    let q = SealQueue::new(1, config(1)).unwrap();
    let (started, signal) = oneshot::channel::<()>();
    let (release, pending) = oneshot::channel::<()>();
    let first = tokio::spawn({
        let queue = q.clone();
        async move {
            queue
                .submit(
                    0,
                    {
                        let mut start_signal = Some(signal);
                        let mut pending_release = Some(pending);
                        move || {
                            let signal = start_signal.take().expect("single queued invocation");
                            let pending = pending_release.take().expect("single queued invocation");
                            async move {
                                let _ = signal.send(());
                                let _ = pending.await;
                                Ok::<_, &'static str>(1)
                            }
                        }
                    },
                    |_| false,
                )
                .await
        }
    });
    started.await.unwrap();
    let invoked = Arc::new(AtomicUsize::new(0));
    let counted = invoked.clone();
    let rejected = q
        .submit(
            0,
            || {
                counted.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, &'static str>(2) }
            },
            |_| false,
        )
        .await;
    assert!(matches!(rejected.result, Err(QueueFailure::Saturated)));
    assert!(!rejected.metrics.admitted);
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    assert_eq!(first.await.unwrap().result.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_wait_timeout_never_calls_the_zome() {
    let q = SealQueue::new(
        1,
        QueueConfig {
            max_wait: Duration::from_millis(15),
            ..config(2)
        },
    )
    .unwrap();
    let (started, signal) = oneshot::channel::<()>();
    let (release, pending) = oneshot::channel::<()>();
    let first = tokio::spawn({
        let queue = q.clone();
        async move {
            queue
                .submit(
                    0,
                    {
                        let mut start_signal = Some(signal);
                        let mut pending_release = Some(pending);
                        move || {
                            let signal = start_signal.take().expect("single queued invocation");
                            let pending = pending_release.take().expect("single queued invocation");
                            async move {
                                let _ = signal.send(());
                                let _ = pending.await;
                                Ok::<_, &'static str>(1)
                            }
                        }
                    },
                    |_| false,
                )
                .await
        }
    });
    started.await.unwrap();
    let invoked = Arc::new(AtomicUsize::new(0));
    let counted = invoked.clone();
    let refused = q
        .submit(
            0,
            || {
                counted.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, &'static str>(2) }
            },
            |_| false,
        )
        .await;
    assert!(matches!(refused.result, Err(QueueFailure::WaitTimedOut)));
    assert!(refused.metrics.admitted);
    assert_eq!(refused.metrics.attempts, 0);
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    assert_eq!(first.await.unwrap().result.unwrap(), 1);
}

#[tokio::test]
async fn head_moved_retried_exactly_twice_then_success() {
    let q = SealQueue::new(1, config(2)).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let outcome = q
        .submit(
            0,
            || {
                let count = count.clone();
                async move {
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        Err::<u8, _>("SourceChainError(HeadMoved)")
                    } else {
                        Ok(7u8)
                    }
                }
            },
            |error| is_holochain_head_moved(error),
        )
        .await;
    assert_eq!(outcome.result.unwrap(), 7);
    assert_eq!(outcome.metrics.attempts, 3);
    assert_eq!(outcome.metrics.head_moved_retries, 2);
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn retry_exhaustion_never_spins_forever() {
    let q = SealQueue::new(1, config(1)).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let result = q
        .submit(
            0,
            || {
                count.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>("SourceChainError(HeadMoved)") }
            },
            |error| is_holochain_head_moved(error),
        )
        .await;
    assert!(matches!(result.result, Err(QueueFailure::RetryExhausted(_))));
    assert_eq!(result.metrics.attempts, 3);
    assert_eq!(result.metrics.head_moved_retries, 2);
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn ambiguous_or_invalid_call_failure_is_never_replayed() {
    let q = SealQueue::new(1, config(1)).unwrap();
    for error in [
        "InitTimeout",
        "HostError(TransportLost)",
        "invalid cryptographic proof",
        "unknown HeadMoved marker not attributable to sourcechain",
    ] {
        let count = Arc::new(AtomicUsize::new(0));
        let result = q
            .submit(
                0,
                || {
                    count.fetch_add(1, Ordering::SeqCst);
                    async move { Err::<(), _>(error) }
                },
                |diagnostic| is_holochain_head_moved(diagnostic),
            )
            .await;
        assert!(matches!(result.result, Err(QueueFailure::Call(_))));
        assert_eq!(result.metrics.attempts, 1, "replayed ambiguous error");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn invalid_config_and_unrecognized_chain_are_fail_closed() {
    assert!(SealQueue::new(0, config(1)).is_err());
    assert!(SealQueue::new(1, config(0)).is_err());
    assert!(SealQueue::new(1, QueueConfig { max_retries: 9, ..config(1) }).is_err());
    assert!(SealQueue::new(1, QueueConfig { max_wait: Duration::ZERO, ..config(1) }).is_err());
    assert!(is_holochain_head_moved("SourceChainError(HeadMoved(old,new))"));
    assert!(!is_holochain_head_moved("INVALID: HeadMoved"));
}

#[tokio::test]
async fn unknown_author_chain_is_rejected_before_call() {
    let q = SealQueue::new(1, config(2)).unwrap();
    let result = q
        .submit(50, || async { Ok::<_, ()>(()) }, |_| false)
        .await;
    assert!(matches!(result.result, Err(QueueFailure::InvalidLane)));
    assert!(!result.metrics.admitted);
}
