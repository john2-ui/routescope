//! Kernel and network data-source boundaries.
//!
//! The TC eBPF collector and conntrack enrichment live here; the local DNS
//! proxy remains a future data source.

use crate::{
    conntrack::{Association, ConntrackReader},
    domain::{
        ConnectionState, CounterReset, DomainAttribution, DomainConfidence, DomainSource, Flow,
        FlowDirection,
    },
};
use aya::{
    Ebpf,
    maps::HashMap as AyaHashMap,
    programs::{
        SchedClassifier, TcAttachType,
        tc::{self, TcError},
    },
};
use core::fmt;
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_SIMULATOR_INTERVAL_SECS: u64 = 5;
const FLOW_IDLE_TIMEOUT_NS: u64 = 5 * 60 * 1_000_000_000;
const TC_EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/routescope_tc.o"));

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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EbpfFlowKey {
    client_mac: [u8; 6],
    protocol: u8,
    _padding: u8,
    client_ip: u32,
    destination_ip: u32,
    client_port: u16,
    destination_port: u16,
}

unsafe impl aya::Pod for EbpfFlowKey {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EbpfFlowValue {
    first_seen_ns: u64,
    last_seen_ns: u64,
    upload_bytes: u64,
    download_bytes: u64,
    packet_count: u64,
}

unsafe impl aya::Pod for EbpfFlowValue {}

/// 流量采集器接口：提供数据源名称与一次采集结果。
pub trait FlowCollector: Send + Sync {
    /// 返回采集器数据源名称。
    fn source_name(&self) -> &'static str;

    /// 执行一次采集，返回 flow 批次或失败信息。
    fn collect(&self) -> CollectionResult;
}

/// 将基础 Flow 快照与 conntrack 只读快照合并。
pub struct ConntrackEnrichedCollector {
    base: Arc<dyn FlowCollector>,
    conntrack: Arc<dyn ConntrackReader>,
}

impl ConntrackEnrichedCollector {
    pub fn new(base: Arc<dyn FlowCollector>, conntrack: Arc<dyn ConntrackReader>) -> Self {
        Self { base, conntrack }
    }
}

impl FlowCollector for ConntrackEnrichedCollector {
    fn source_name(&self) -> &'static str {
        "tc-ebpf+conntrack"
    }

    fn collect(&self) -> CollectionResult {
        let mut batch = self.base.collect()?;

        let snapshot = match self.conntrack.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                batch.health.state = CollectorHealthState::Degraded;
                batch.health.last_error = Some(error);
                batch.health.flows_emitted = batch.flows.len();
                return Ok(batch);
            }
        };

        for flow in &mut batch.flows {
            if let Association::Matched(entry) = snapshot.associate(flow) {
                if let Some(mapping) = entry.nat_mapping() {
                    flow.nat_source_ip = Some(mapping.source_ip.to_string());
                    flow.nat_source_port = Some(mapping.source_port);
                    flow.nat_destination_ip = Some(mapping.destination_ip.to_string());
                    flow.nat_destination_port = Some(mapping.destination_port);
                }
                flow.connection_state = entry.state;
            }
        }

        Ok(batch)
    }
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
    Err(source_failure(source, message))
}

fn source_failure(source: &'static str, message: impl Into<String>) -> CollectorFailure {
    let error = CollectorError::SourceUnavailable {
        source,
        message: message.into(),
    };

    CollectorFailure {
        health: CollectorHealth::unhealthy(now_ms(), &error),
        error,
    }
}

pub struct TcEbpfCollector {
    ebpf: Mutex<Ebpf>,
    lan_interface: String,
    wan_interface: String,
    session_id: u64,
}

impl FlowCollector for TcEbpfCollector {
    fn source_name(&self) -> &'static str {
        "tc-ebpf"
    }

    fn collect(&self) -> CollectionResult {
        let observed_at_ms = now_ms();
        let now_ns = monotonic_ns().map_err(|error| {
            source_failure(
                self.source_name(),
                format!("failed to read monotonic clock: {error}"),
            )
        })?;

        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|_| source_failure(self.source_name(), "eBPF state mutex is poisoned"))?;

        let map = ebpf
            .map_mut("flow_stats")
            .ok_or_else(|| source_failure(self.source_name(), "flow_stats map is missing"))?;
        let mut stats: AyaHashMap<_, EbpfFlowKey, EbpfFlowValue> = AyaHashMap::try_from(map)
            .map_err(|error| {
                source_failure(
                    self.source_name(),
                    format!("failed to open flow_stats map: {error}"),
                )
            })?;

        let entries = stats
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                source_failure(
                    self.source_name(),
                    format!("failed to read flow_stats map: {error}"),
                )
            })?;

        let mut flows = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            if now_ns.saturating_sub(value.last_seen_ns) > FLOW_IDLE_TIMEOUT_NS {
                stats.remove(&key).map_err(|error| {
                    source_failure(
                        self.source_name(),
                        format!("failed to expire idle flow from BPF map: {error}"),
                    )
                })?;
                continue;
            }

            flows.push(self.flow_from_entry(key, value, now_ns, observed_at_ms));
        }

        validate_batch(self.source_name(), flows)
    }
}

impl TcEbpfCollector {
    pub fn new(
        lan_interface: impl Into<String>,
        wan_interface: impl Into<String>,
    ) -> Result<Self, CollectorFailure> {
        let lan_interface = lan_interface.into();
        let wan_interface = wan_interface.into();

        if lan_interface.trim().is_empty() {
            return Err(source_failure("tc-ebpf", "LAN interface must not be empty"));
        }
        if wan_interface.trim().is_empty() {
            return Err(source_failure("tc-ebpf", "WAN interface must not be empty"));
        }

        let mut ebpf = Ebpf::load(TC_EBPF_OBJECT).map_err(|error| {
            source_failure("tc-ebpf", format!("failed to load eBPF object: {error}"))
        })?;

        match tc::qdisc_add_clsact(&lan_interface) {
            Ok(()) | Err(TcError::AlreadyAttached) => {}
            Err(TcError::NetlinkError(error)) if error.raw_os_error() == Some(libc::EEXIST) => {}
            Err(error) => {
                return Err(source_failure(
                    "tc-ebpf",
                    format!("failed to add clsact qdisc on {lan_interface}: {error}"),
                ));
            }
        }

        {
            let program = ebpf
                .program_mut("routescope_tc_ingress")
                .ok_or_else(|| source_failure("tc-ebpf", "ingress program is missing"))?;
            let program: &mut SchedClassifier = program.try_into().map_err(|error| {
                source_failure("tc-ebpf", format!("invalid ingress program type: {error}"))
            })?;
            program.load().map_err(|error| {
                source_failure(
                    "tc-ebpf",
                    format!("failed to load ingress program: {error}"),
                )
            })?;
            program
                .attach(&lan_interface, TcAttachType::Ingress)
                .map_err(|error| {
                    source_failure(
                        "tc-ebpf",
                        format!("failed to attach ingress program to {lan_interface}: {error}"),
                    )
                })?;
        }

        {
            let program = ebpf
                .program_mut("routescope_tc_egress")
                .ok_or_else(|| source_failure("tc-ebpf", "egress program is missing"))?;
            let program: &mut SchedClassifier = program.try_into().map_err(|error| {
                source_failure("tc-ebpf", format!("invalid egress program type: {error}"))
            })?;
            program.load().map_err(|error| {
                source_failure("tc-ebpf", format!("failed to load egress program: {error}"))
            })?;
            program
                .attach(&lan_interface, TcAttachType::Egress)
                .map_err(|error| {
                    source_failure(
                        "tc-ebpf",
                        format!("failed to attach egress program to {lan_interface}: {error}"),
                    )
                })?;
        }

        Ok(Self {
            ebpf: Mutex::new(ebpf),
            lan_interface,
            wan_interface,
            session_id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn flow_from_entry(
        &self,
        key: EbpfFlowKey,
        value: EbpfFlowValue,
        now_ns: u64,
        observed_at_ms: i64,
    ) -> Flow {
        let protocol = match key.protocol {
            6 => "tcp",
            17 => "udp",
            _ => "unknown",
        };
        let client_ip = std::net::Ipv4Addr::from(u32::from_be(key.client_ip));
        let destination_ip = std::net::Ipv4Addr::from(u32::from_be(key.destination_ip));
        let first_seen = monotonic_timestamp_ms(now_ns, value.first_seen_ns, observed_at_ms);
        let last_seen = monotonic_timestamp_ms(now_ns, value.last_seen_ns, observed_at_ms);

        Flow {
            flow_id: self.flow_id(&key, &value),
            first_seen,
            last_seen,
            protocol: protocol.to_owned(),
            direction: FlowDirection::Bidirectional,
            lan_interface: self.lan_interface.clone(),
            wan_interface: self.wan_interface.clone(),
            client_mac: format_mac(key.client_mac),
            client_ip: client_ip.to_string(),
            client_port: u16::from_be(key.client_port),
            destination_ip: destination_ip.to_string(),
            destination_port: u16::from_be(key.destination_port),
            nat_source_ip: None,
            nat_source_port: None,
            nat_destination_ip: None,
            nat_destination_port: None,
            upload_bytes: value.upload_bytes,
            download_bytes: value.download_bytes,
            packet_count: value.packet_count,
            domain: None,
            connection_state: ConnectionState::Unknown,
        }
    }

    fn flow_id(&self, key: &EbpfFlowKey, value: &EbpfFlowValue) -> String {
        format!(
            "tc:v1:{}:{:x}:{}:{}:{}:{}:{}:{}",
            self.session_id,
            value.first_seen_ns,
            format_mac(key.client_mac),
            key.protocol,
            u32::from_be(key.client_ip),
            u16::from_be(key.client_port),
            u32::from_be(key.destination_ip),
            u16::from_be(key.destination_port),
        )
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
                direction: FlowDirection::Bidirectional,
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
                direction: FlowDirection::Bidirectional,
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

fn monotonic_ns() -> Result<u64, String> {
    let mut timespec = MaybeUninit::<libc::timespec>::uninit();
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timespec.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let timespec = unsafe { timespec.assume_init() };
    let seconds =
        u64::try_from(timespec.tv_sec).map_err(|_| "monotonic seconds are negative".to_owned())?;
    let nanoseconds = u64::try_from(timespec.tv_nsec)
        .map_err(|_| "monotonic nanoseconds are negative".to_owned())?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "monotonic timestamp overflowed u64".to_owned())
}

fn monotonic_timestamp_ms(now_ns: u64, event_ns: u64, observed_at_ms: i64) -> i64 {
    let age_ms = now_ns
        .saturating_sub(event_ns)
        .checked_div(1_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(i64::MAX);

    observed_at_ms.saturating_sub(age_ms)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::{ConntrackEntry, ConntrackReader, ConntrackSnapshot, NetworkTuple};

    struct FixedConntrackReader {
        result: Result<ConntrackSnapshot, String>,
    }

    impl ConntrackReader for FixedConntrackReader {
        fn snapshot(&self) -> Result<ConntrackSnapshot, String> {
            self.result.clone()
        }
    }

    fn conntrack_entry_for(flow: &Flow) -> ConntrackEntry {
        let original = NetworkTuple::from_flow(flow).expect("simulated flow has a tuple");
        ConntrackEntry {
            original,
            reply: NetworkTuple {
                protocol: original.protocol,
                source_ip: original.destination_ip,
                source_port: original.destination_port,
                destination_ip: "198.51.100.10".parse().unwrap(),
                destination_port: 50_001,
            },
            state: ConnectionState::Established,
        }
    }

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
    fn invalid_tc_ebpf_configuration_is_unhealthy() {
        let failure = TcEbpfCollector::new("", "eth0")
            .err()
            .expect("empty LAN interface must be rejected");

        assert_eq!(failure.health.state, CollectorHealthState::Unhealthy);

        assert!(matches!(
            failure.error,
            CollectorError::SourceUnavailable { .. }
        ));
    }

    #[test]
    fn conntrack_enrichment_adds_nat_and_state_without_changing_flow_id() {
        let base = Arc::new(SimulatedCollector::with_start_time(1_700_000_000_000));
        let first_batch = base.collect().unwrap();
        let first_flow_id = first_batch.flows[0].flow_id.clone();
        let snapshot =
            ConntrackSnapshot::from_entries(vec![conntrack_entry_for(&first_batch.flows[0])]);
        let collector = ConntrackEnrichedCollector::new(
            base,
            Arc::new(FixedConntrackReader {
                result: Ok(snapshot),
            }),
        );

        let batch = collector.collect().unwrap();
        let flow = batch
            .flows
            .iter()
            .find(|flow| flow.flow_id == first_flow_id)
            .unwrap();
        assert_eq!(flow.nat_source_ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(flow.nat_source_port, Some(50_001));
        assert_eq!(flow.nat_destination_ip.as_deref(), Some("93.184.216.34"));
        assert_eq!(flow.nat_destination_port, Some(443));
        assert_eq!(flow.connection_state, ConnectionState::Established);
    }

    #[test]
    fn conntrack_failure_keeps_tc_flows_and_marks_batch_degraded() {
        let base = Arc::new(SimulatedCollector::with_start_time(1_700_000_000_000));
        let collector = ConntrackEnrichedCollector::new(
            base,
            Arc::new(FixedConntrackReader {
                result: Err("permission denied".into()),
            }),
        );

        let batch = collector.collect().unwrap();
        assert_eq!(batch.flows.len(), 2);
        assert_eq!(batch.health.flows_emitted, 2);
        assert_eq!(batch.health.state, CollectorHealthState::Degraded);
        assert_eq!(
            batch.health.last_error.as_deref(),
            Some("permission denied")
        );
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
