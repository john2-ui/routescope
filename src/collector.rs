//! Kernel and network data-source boundaries.
//!
//! TODO: Implement the collectors with TC eBPF, conntrack events, and the local DNS proxy.

use crate::domain::{
    ConnectionState, CounterReset, DomainAttribution, DomainConfidence, DomainSource, Flow,
    FlowDirection,
};
use core::fmt;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_SIMULATOR_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CollectorHealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorHealth {
    pub state: CollectorHealthState,
    pub observed_at_ms: i64,
    pub flows_seen: usize,
    pub flows_emitted: usize,
    pub last_error: Option<String>,
}

impl CollectorHealth {
    /// 构造健康状态报告。
    fn healthy(observed_at_ms: i64, flow_count: usize) -> Self {
        Self {
            state: CollectorHealthState::Healthy,
            observed_at_ms,
            flows_seen: flow_count,
            flows_emitted: flow_count,
            last_error: None,
        }
    }

    /// 构造降级状态报告（有数据但校验/处理失败）。
    fn degraded(observed_at_ms: i64, flows_seen: usize, error: &CollectorError) -> Self {
        Self {
            state: CollectorHealthState::Degraded,
            observed_at_ms,
            flows_seen,
            flows_emitted: 0,
            last_error: Some(error.to_string()),
        }
    }

    /// 构造不可用状态报告（数据源不可用）。
    fn unhealthy(observed_at_ms: i64, error: &CollectorError) -> Self {
        Self {
            state: CollectorHealthState::Unhealthy,
            observed_at_ms,
            flows_seen: 0,
            flows_emitted: 0,
            last_error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CollectorError {
    SourceUnavailable {
        source: &'static str,
        message: String,
    },
    InvalidFlow {
        source: &'static str,
        flow_id: String,
        reason: String,
    },
    DuplicateFlowId {
        source: &'static str,
        flow_id: String,
    },
    #[allow(dead_code)]
    CounterReset {
        source: &'static str,
        flow_id: String,
        reset: CounterReset,
    },
}

impl fmt::Display for CollectorError {
    /// 格式化采集错误信息。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnavailable { source, message } => {
                write!(f, "{source} source unavailable: {message}")
            }
            Self::InvalidFlow {
                source,
                flow_id,
                reason,
            } => {
                write!(f, "{source} produced invalid flow {flow_id}: {reason}")
            }
            Self::DuplicateFlowId { source, flow_id } => {
                write!(f, "{source} emitted duplicate flow_id {flow_id}")
            }
            Self::CounterReset {
                source,
                flow_id,
                reset,
            } => {
                write!(f, "{source} counter reset for flow {flow_id}: {reset}")
            }
        }
    }
}

impl std::error::Error for CollectorError {}

#[derive(Debug, Clone)]
pub struct CollectionBatch {
    pub observed_at_ms: i64,
    pub flows: Vec<Flow>,
    pub health: CollectorHealth,
}

#[derive(Debug)]
pub struct CollectorFailure {
    pub error: CollectorError,
    pub health: CollectorHealth,
}

impl fmt::Display for CollectorFailure {
    /// 委托内部 `CollectorError` 格式化失败信息。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for CollectorFailure {}

pub type CollectionResult = Result<CollectionBatch, CollectorFailure>;

/// 流量采集器接口：提供数据源名称与一次采集结果。
pub trait FlowCollector: Send + Sync {
    /// 返回采集器数据源名称。
    fn source_name(&self) -> &'static str;

    /// 执行一次采集，返回 flow 批次或失败信息。
    fn collect(&self) -> CollectionResult;
}

/// 校验批次：禁止重复 flow_id，且每条 flow 必须通过领域校验。
fn validate_batch(source: &'static str, flows: Vec<Flow>) -> CollectionResult {
    let observed_at_ms = now_ms();
    let flows_seen = flows.len();
    let mut flow_ids = HashSet::with_capacity(flows_seen);

    for flow in &flows {
        if !flow_ids.insert(flow.flow_id.as_str()) {
            let error = CollectorError::DuplicateFlowId {
                source,
                flow_id: flow.flow_id.clone(),
            };

            return Err(CollectorFailure {
                health: CollectorHealth::degraded(observed_at_ms, flows_seen, &error),
                error,
            });
        }

        if let Err(reason) = flow.validate() {
            let error = CollectorError::InvalidFlow {
                source,
                flow_id: flow.flow_id.clone(),
                reason: reason.to_owned(),
            };

            return Err(CollectorFailure {
                health: CollectorHealth::degraded(observed_at_ms, flows_seen, &error),
                error,
            });
        }
    }

    Ok(CollectionBatch {
        observed_at_ms,
        flows,
        health: CollectorHealth::healthy(observed_at_ms, flows_seen),
    })
}

/// 构造数据源不可用时的 Unhealthy 失败结果。
#[allow(dead_code)]
fn source_unavailable(source: &'static str, message: &str) -> CollectionResult {
    let error = CollectorError::SourceUnavailable {
        source,
        message: message.to_owned(),
    };

    Err(CollectorFailure {
        health: CollectorHealth::unhealthy(now_ms(), &error),
        error,
    })
}

#[allow(dead_code)]
pub struct TcEbpfCollector;

impl FlowCollector for TcEbpfCollector {
    /// 返回 TC eBPF 数据源名称。
    fn source_name(&self) -> &'static str {
        "tc-ebpf"
    }

    /// TC eBPF 采集占位（尚未实现）。
    fn collect(&self) -> CollectionResult {
        source_unavailable(self.source_name(), "collector is not implemented")
    }
}

#[allow(dead_code)]
pub struct ConntrackCollector;

impl FlowCollector for ConntrackCollector {
    /// 返回 conntrack 数据源名称。
    fn source_name(&self) -> &'static str {
        "conntrack"
    }

    /// conntrack 采集占位（尚未实现）。
    fn collect(&self) -> CollectionResult {
        source_unavailable(self.source_name(), "collector is not implemented")
    }
}

#[allow(dead_code)]
pub struct DnsAttributionCollector;

impl FlowCollector for DnsAttributionCollector {
    /// 返回 DNS 归因数据源名称。
    fn source_name(&self) -> &'static str {
        "dns-attribution"
    }

    /// DNS 归因采集占位（尚未实现）。
    fn collect(&self) -> CollectionResult {
        source_unavailable(self.source_name(), "collector is not implemented")
    }
}

pub struct SimulatedCollector {
    start_ms: i64,
    step_ms: i64,
    session_id: u64,
    tick: AtomicU64,
}

impl SimulatedCollector {
    /// 以默认间隔（5 秒）创建模拟采集器。
    pub fn new() -> Self {
        Self::with_interval_secs(DEFAULT_SIMULATOR_INTERVAL_SECS)
    }

    /// 按指定采集间隔创建模拟采集器。
    pub fn with_interval_secs(interval_secs: u64) -> Self {
        Self::with_start_time_and_interval(now_ms(), interval_secs)
    }

    /// 以固定起点时间创建模拟采集器（仅测试使用）。
    #[cfg(test)]
    fn with_start_time(start_ms: i64) -> Self {
        Self::with_start_time_and_interval(start_ms, DEFAULT_SIMULATOR_INTERVAL_SECS)
    }

    /// 以固定起点与间隔创建模拟采集器。
    fn with_start_time_and_interval(start_ms: i64, interval_secs: u64) -> Self {
        let step_ms = i64::try_from(interval_secs.max(1).saturating_mul(1_000)).unwrap_or(i64::MAX);

        Self {
            start_ms,
            step_ms,
            session_id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            tick: AtomicU64::new(0),
        }
    }

    /// 生成稳定的模拟 flow_id（含 session 前缀）。
    fn flow_id(&self, name: &str) -> String {
        format!("sim:v1:{}:{name}", self.session_id)
    }
}

impl Default for SimulatedCollector {
    /// 同 `new`，使用默认间隔。
    fn default() -> Self {
        Self::new()
    }
}

impl FlowCollector for SimulatedCollector {
    /// 返回模拟器数据源名称。
    fn source_name(&self) -> &'static str {
        "simulator"
    }

    /// 产出两条累计递增的模拟 flow，并做批次校验。
    fn collect(&self) -> CollectionResult {
        let tick = self.tick.fetch_add(1, Ordering::Relaxed).saturating_add(1);

        let elapsed_ticks = i64::try_from(tick.saturating_sub(1)).unwrap_or(i64::MAX);
        let elapsed_ms = self.step_ms.saturating_mul(elapsed_ticks);
        let last_seen = self.start_ms.saturating_add(elapsed_ms);
        let expires_at = Some(last_seen.saturating_add(3_600_000));

        let flows = vec![
            Flow {
                flow_id: self.flow_id("client-a-https"),
                first_seen: self.start_ms,
                last_seen,
                protocol: "tcp".into(),
                direction: FlowDirection::Upload,
                lan_interface: "br-lan".into(),
                wan_interface: "eth0".into(),
                client_mac: "aa:bb:cc:dd:ee:01".into(),
                client_ip: "192.168.1.10".into(),
                client_port: 40_000,
                destination_ip: "93.184.216.34".into(),
                destination_port: 443,
                nat_source_ip: Some("198.51.100.10".into()),
                nat_source_port: Some(50_001),
                nat_destination_ip: Some("93.184.216.34".into()),
                nat_destination_port: Some(443),
                upload_bytes: tick.saturating_mul(1_024),
                download_bytes: tick.saturating_mul(8_192),
                packet_count: tick.saturating_mul(20),
                domain: Some(DomainAttribution {
                    domain: "example.com".into(),
                    source: DomainSource::Dns,
                    confidence: DomainConfidence::High,
                    associated_at: last_seen,
                    expires_at,
                }),
                connection_state: ConnectionState::Established,
            },
            Flow {
                flow_id: self.flow_id("client-b-https"),
                first_seen: self.start_ms,
                last_seen,
                protocol: "tcp".into(),
                direction: FlowDirection::Download,
                lan_interface: "br-lan".into(),
                wan_interface: "eth0".into(),
                client_mac: "aa:bb:cc:dd:ee:02".into(),
                client_ip: "192.168.1.11".into(),
                client_port: 40_001,
                destination_ip: "203.0.113.20".into(),
                destination_port: 443,
                nat_source_ip: Some("198.51.100.10".into()),
                nat_source_port: Some(50_002),
                nat_destination_ip: Some("203.0.113.20".into()),
                nat_destination_port: Some(443),
                upload_bytes: tick.saturating_mul(512),
                download_bytes: tick.saturating_mul(16_384),
                packet_count: tick.saturating_mul(30),
                domain: Some(DomainAttribution {
                    domain: "video.example.net".into(),
                    source: DomainSource::Sni,
                    confidence: DomainConfidence::Low,
                    associated_at: last_seen,
                    expires_at,
                }),
                connection_state: ConnectionState::Established,
            },
        ];

        validate_batch(self.source_name(), flows)
    }
}

/// 返回当前 Unix 毫秒时间戳。
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simulator_keeps_flow_ids_and_increments_counters() {
        let collector = SimulatedCollector::with_start_time(1_700_000_000_000);
        let first = collector.collect().unwrap();
        let second = collector.collect().unwrap();

        assert_eq!(first.flows.len(), 2);
        assert!(first.flows.iter().all(|flow| flow.validate().is_ok()));
        assert_eq!(first.flows[0].flow_id, second.flows[0].flow_id);
        assert!(second.flows[0].upload_bytes > first.flows[0].upload_bytes);
    }

    #[test]
    fn simulator_timestamps_follow_configured_interval() {
        let start_ms = 1_700_000_000_000;
        let collector = SimulatedCollector::with_start_time_and_interval(start_ms, 1);

        let first = collector.collect().unwrap();
        let second = collector.collect().unwrap();

        assert_eq!(first.flows[0].last_seen, start_ms);
        assert_eq!(second.flows[0].last_seen, start_ms + 1_000);
    }

    #[test]
    fn unimplemented_collector_is_unhealthy() {
        let failure = TcEbpfCollector.collect().unwrap_err();

        assert_eq!(failure.health.state, CollectorHealthState::Unhealthy);

        assert!(matches!(
            failure.error,
            CollectorError::SourceUnavailable { .. }
        ));
    }

    #[test]
    fn counter_decrease_is_rejected() {
        use crate::domain::FlowCounters;

        let previous = FlowCounters {
            upload_bytes: 100,
            download_bytes: 200,
            packet_count: 10,
        };

        let current = FlowCounters {
            upload_bytes: 90,
            download_bytes: 250,
            packet_count: 11,
        };

        assert!(current.delta_from(previous).is_err());
    }
}
