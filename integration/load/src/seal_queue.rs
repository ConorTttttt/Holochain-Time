//! Bounded in-process, per-agent source-chain write admission for seal calls.
//!
//! This queue is deliberately OUTSIDE the DNA/zome: it cannot change consensus,
//! cryptographic verification or global scheduling. Deployments must share one
//! queue per author AgentPubKey across ALL local producers; independent hosts
//! still require HeadMoved-aware retries. There is NO guarantee of durable
//! exactly-once submission, process crash replay protection or fairness across
//! different processes. Unknown/timeout errors are terminal, never replayed.
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

#[derive(Clone, Copy, Debug)]
pub struct QueueConfig {
    /// Maximum admitted requests, including executing and waiting.
    pub capacity: usize,
    /// Upper bound for waiting for a local source-chain lane.
    pub max_wait: Duration,
    /// HeadMoved-only retries, after the initial submission.
    pub max_retries: u8,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 256,
            max_wait: Duration::from_secs(180),
            max_retries: 3,
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(250),
        }
    }
}

impl QueueConfig {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.capacity == 0 || self.capacity > 4096 {
            return Err("queue capacity must be 1..=4096");
        }
        if self.max_wait.is_zero() || self.max_wait > Duration::from_secs(600) {
            return Err("queue wait must be between 1ns and 600s");
        }
        if self.max_retries > 8 {
            return Err("max HeadMoved retries cannot exceed 8");
        }
        if self.initial_backoff.is_zero()
            || self.max_backoff < self.initial_backoff
            || self.max_backoff > Duration::from_secs(5)
        {
            return Err("retry backoff must be bounded and nonzero");
        }
        Ok(self)
    }

    fn backoff(self, retry_number: u8) -> Duration {
        let factor = 1u32 << (retry_number.saturating_sub(1)).min(8);
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum QueueFailure<E> {
    InvalidLane,
    Saturated,
    WaitTimedOut,
    LaneUnavailable,
    Call(E),
    RetryExhausted(E),
}

impl<E> QueueFailure<E> {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidLane => "invalid_lane",
            Self::Saturated => "queue_full",
            Self::WaitTimedOut => "queue_wait_timeout",
            Self::LaneUnavailable => "queue_closed",
            Self::Call(_) => "nonretryable_call_error",
            Self::RetryExhausted(_) => "head_moved_retry_exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QueueMetrics {
    pub admitted: bool,
    pub queue_depth_at_admission: usize,
    pub attempts: u8,
    pub head_moved_retries: u8,
    pub queue_wait_ms: f64,
    pub service_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug)]
pub struct QueueOutcome<T, E> {
    pub result: Result<T, QueueFailure<E>>,
    pub metrics: QueueMetrics,
}

#[derive(Clone)]
pub struct SealQueue {
    slots: Arc<Semaphore>,
    // Each lane represents exactly one Holochain AgentPubKey's source chain.
    lanes: Arc<Vec<Arc<Semaphore>>>,
    config: QueueConfig,
}

impl SealQueue {
    pub fn new(chain_count: usize, config: QueueConfig) -> Result<Self, &'static str> {
        let config = config.validate()?;
        if chain_count == 0 || chain_count > 256 {
            return Err("source-chain lane count must be 1..=256");
        }
        Ok(Self {
            slots: Arc::new(Semaphore::new(config.capacity)),
            lanes: Arc::new(
                (0..chain_count)
                    .map(|_| Arc::new(Semaphore::new(1)))
                    .collect(),
            ),
            config,
        })
    }

    pub fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// The supplied closure is called exactly once unless a completed call
    /// returns an explicitly classified HeadMoved chain CAS failure.
    ///
    /// - Multiple callers may enqueue simultaneously; each author lane writes
    ///   one action at a time using a fair Tokio semaphore.
    /// - A full queue fails immediately before invoking the closure.
    /// - Waiting longer than max_wait fails before any write starts.
    /// - Timeouts/transport errors are NOT retried (success may be ambiguous).
    /// - Retry occurs within the same held author lane, preserving order.
    pub async fn submit<T, E, F, Fut, P>(
        &self,
        lane_index: usize,
        mut call: F,
        is_head_moved: P,
    ) -> QueueOutcome<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        P: Fn(&E) -> bool,
    {
        let start = Instant::now();
        let mut metrics = QueueMetrics::default();
        let Some(lane) = self.lanes.get(lane_index) else {
            return QueueOutcome {
                result: Err(QueueFailure::InvalidLane),
                metrics,
            };
        };
        let Ok(_slot) = self.slots.clone().try_acquire_owned() else {
            metrics.total_ms = start.elapsed().as_secs_f64() * 1000.0;
            return QueueOutcome {
                result: Err(QueueFailure::Saturated),
                metrics,
            };
        };
        metrics.admitted = true;
        metrics.queue_depth_at_admission = self.config.capacity - self.slots.available_permits();
        let guard = timeout(self.config.max_wait, lane.clone().acquire_owned()).await;
        let _lane = match guard {
            Err(_) => {
                metrics.queue_wait_ms = start.elapsed().as_secs_f64() * 1000.0;
                metrics.total_ms = metrics.queue_wait_ms;
                return QueueOutcome {
                    result: Err(QueueFailure::WaitTimedOut),
                    metrics,
                };
            }
            Ok(Err(_)) => {
                return QueueOutcome {
                    result: Err(QueueFailure::LaneUnavailable),
                    metrics,
                };
            }
            Ok(Ok(permit)) => permit,
        };
        metrics.queue_wait_ms = start.elapsed().as_secs_f64() * 1000.0;
        let service_start = Instant::now();
        loop {
            metrics.attempts += 1;
            match call().await {
                Ok(value) => {
                    metrics.service_ms = service_start.elapsed().as_secs_f64() * 1000.0;
                    metrics.total_ms = start.elapsed().as_secs_f64() * 1000.0;
                    return QueueOutcome {
                        result: Ok(value),
                        metrics,
                    };
                }
                Err(error) if is_head_moved(&error) => {
                    if metrics.head_moved_retries >= self.config.max_retries {
                        metrics.service_ms = service_start.elapsed().as_secs_f64() * 1000.0;
                        metrics.total_ms = start.elapsed().as_secs_f64() * 1000.0;
                        return QueueOutcome {
                            result: Err(QueueFailure::RetryExhausted(error)),
                            metrics,
                        };
                    }
                    metrics.head_moved_retries += 1;
                    sleep(self.config.backoff(metrics.head_moved_retries)).await;
                }
                Err(error) => {
                    metrics.service_ms = service_start.elapsed().as_secs_f64() * 1000.0;
                    metrics.total_ms = start.elapsed().as_secs_f64() * 1000.0;
                    return QueueOutcome {
                        result: Err(QueueFailure::Call(error)),
                        metrics,
                    };
                }
            }
        }
    }
}

/// Conservative, exact diagnostic classification for the current Holochain
/// 0.7 SourceChainError Debug output. Do not broadly retry other errors or
/// synthetic substrings such as "unknown HeadMoved". Revisit with a typed
/// upstream error when the conductor interface exposes one.
pub fn is_holochain_head_moved(message: &str) -> bool {
    message.contains("SourceChainError(HeadMoved")
        || message.contains("SourceChainError { source: HeadMoved")
        || message.contains("SourceChainError: HeadMoved")
}
