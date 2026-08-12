use crate::auth::AuthService;
use crate::collector::{CollectorHealth, CollectorHealthState};
use crate::service::ObservationService;
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize)]
pub struct CollectorHealthSnapshot {
        pub enabled: bool,
        pub source: Option<String>,
        pub state: String,
        pub ready: bool,
        pub observed_at_ms: Option<i64>,
        pub last_success_at_ms: Option<i64>,
        pub flows_seen: usize,
        pub flows_emitted: usize,
        pub flows_ingested: usize,
        pub consecutive_failures: u64,
        pub last_error: Option<String>,
}

struct CollectorHealthInner {
        snapshot: CollectorHealthSnapshot,
}

/// Process-local health state shared by collectors and public health endpoints.
pub struct CollectorHealthTracker {
        inner: Mutex<CollectorHealthInner>,
}

impl CollectorHealthTracker {
        pub fn new(source: Option<&'static str>) -> Self {
                let enabled = source.is_some();
                Self {
                        inner: Mutex::new(CollectorHealthInner {
                                snapshot: CollectorHealthSnapshot {
                                        enabled,
                                        source: source.map(str::to_owned),
                                        state: if enabled {
                                                "starting".to_owned()
                                        } else {
                                                "disabled".to_owned()
                                        },
                                        // Enabled collectors stay not-ready until the first successful
                                        // batch; disabled collectors have nothing to wait for.
                                        ready: !enabled,
                                        observed_at_ms: None,
                                        last_success_at_ms: None,
                                        flows_seen: 0,
                                        flows_emitted: 0,
                                        flows_ingested: 0,
                                        consecutive_failures: 0,
                                        last_error: None,
                                },
                        }),
                }
        }

        pub fn snapshot(&self) -> CollectorHealthSnapshot {
                self.inner
                        .lock()
                        .expect("collector health mutex poisoned")
                        .snapshot
                        .clone()
        }

        pub fn record_batch(&self, health: &CollectorHealth, ingested: Result<usize, String>) {
                let mut inner = self.inner.lock().expect("collector health mutex poisoned");
                let snapshot = &mut inner.snapshot;
                snapshot.state = health.state.as_str().to_owned();
                snapshot.observed_at_ms = Some(health.observed_at_ms);
                snapshot.flows_seen = health.flows_seen;
                snapshot.flows_emitted = health.flows_emitted;

                match ingested {
                        Ok(count) => {
                                snapshot.flows_ingested =
                                        snapshot.flows_ingested.saturating_add(count);
                                snapshot.last_success_at_ms = Some(health.observed_at_ms);
                                snapshot.consecutive_failures = 0;
                                snapshot.last_error = health.last_error.clone();
                                snapshot.ready = health.state != CollectorHealthState::Unhealthy;
                        }
                        Err(error) => {
                                // Preserve collector-reported state; storage failures are tracked
                                // via ready/last_error/consecutive_failures instead.
                                snapshot.consecutive_failures =
                                        snapshot.consecutive_failures.saturating_add(1);
                                snapshot.last_error = Some(error);
                                snapshot.ready = false;
                        }
                }
        }

        pub fn record_failure(&self, health: &CollectorHealth) {
                let mut inner = self.inner.lock().expect("collector health mutex poisoned");
                let snapshot = &mut inner.snapshot;
                snapshot.state = health.state.as_str().to_owned();
                snapshot.observed_at_ms = Some(health.observed_at_ms);
                snapshot.flows_seen = health.flows_seen;
                snapshot.flows_emitted = health.flows_emitted;
                snapshot.consecutive_failures = snapshot.consecutive_failures.saturating_add(1);
                snapshot.last_error = health.last_error.clone();
                snapshot.ready = false;
        }
}

/// Axum 共享应用状态：观测服务、认证服务与开发态鉴权开关。
#[derive(Clone)]
pub struct AppState {
        pub observation: Arc<ObservationService>,
        pub auth: Arc<AuthService>,
        pub collector_health: Arc<CollectorHealthTracker>,
        pub dev_bypass_auth: bool,
        pub secure_cookies: bool,
}

#[cfg(test)]
mod tests {
        use super::*;
        use crate::collector::{CollectorHealth, CollectorHealthState};

        #[test]
        fn enabled_collector_starts_not_ready() {
                let tracker = CollectorHealthTracker::new(Some("tc_ebpf"));
                let snapshot = tracker.snapshot();
                assert!(snapshot.enabled);
                assert_eq!(snapshot.state, "starting");
                assert!(!snapshot.ready);
        }

        #[test]
        fn disabled_collector_is_immediately_ready() {
                let tracker = CollectorHealthTracker::new(None);
                let snapshot = tracker.snapshot();
                assert!(!snapshot.enabled);
                assert_eq!(snapshot.state, "disabled");
                assert!(snapshot.ready);
        }

        #[test]
        fn first_successful_batch_marks_ready() {
                let tracker = CollectorHealthTracker::new(Some("simulated"));
                tracker.record_batch(
                        &CollectorHealth {
                                state: CollectorHealthState::Healthy,
                                observed_at_ms: 1_000,
                                flows_seen: 2,
                                flows_emitted: 2,
                                last_error: None,
                        },
                        Ok(2),
                );
                let snapshot = tracker.snapshot();
                assert_eq!(snapshot.state, "healthy");
                assert!(snapshot.ready);
        }

        #[test]
        fn ingest_failure_preserves_collector_state() {
                let tracker = CollectorHealthTracker::new(Some("simulated"));
                tracker.record_batch(
                        &CollectorHealth {
                                state: CollectorHealthState::Healthy,
                                observed_at_ms: 1_000,
                                flows_seen: 2,
                                flows_emitted: 2,
                                last_error: None,
                        },
                        Err("disk full".to_owned()),
                );
                let snapshot = tracker.snapshot();
                assert_eq!(snapshot.state, "healthy");
                assert!(!snapshot.ready);
                assert_eq!(snapshot.consecutive_failures, 1);
                assert_eq!(snapshot.last_error.as_deref(), Some("disk full"));
        }
}
