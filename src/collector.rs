//! Kernel and network data-source boundaries.
//!
//! TODO: Implement the collectors with TC eBPF, conntrack events, and the local DNS proxy.

use crate::domain::{
    ConnectionState, DomainAttribution, DomainConfidence, DomainSource, Flow, FlowDirection,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_SIMULATOR_INTERVAL_SECS: u64 = 5;

pub trait FlowCollector: Send + Sync {
    fn source_name(&self) -> &'static str;

    fn collect(&self) -> Vec<Flow> {
        // TODO: Read and normalize data from the underlying source.
        Vec::new()
    }
}

#[allow(dead_code)]
pub struct TcEbpfCollector;

impl FlowCollector for TcEbpfCollector {
    fn source_name(&self) -> &'static str {
        "tc-ebpf"
    }
}

#[allow(dead_code)]
pub struct ConntrackCollector;

impl FlowCollector for ConntrackCollector {
    fn source_name(&self) -> &'static str {
        "conntrack"
    }
}

#[allow(dead_code)]
pub struct DnsAttributionCollector;

impl FlowCollector for DnsAttributionCollector {
    fn source_name(&self) -> &'static str {
        "dns-attribution"
    }
}

pub struct SimulatedCollector {
    start_ms: i64,
    step_ms: i64,
    session_id: u64,
    tick: AtomicU64,
}

impl SimulatedCollector {
    pub fn new() -> Self {
        Self::with_interval_secs(DEFAULT_SIMULATOR_INTERVAL_SECS)
    }

    pub fn with_interval_secs(interval_secs: u64) -> Self {
        Self::with_start_time_and_interval(now_ms(), interval_secs)
    }

    #[cfg(test)]
    fn with_start_time(start_ms: i64) -> Self {
        Self::with_start_time_and_interval(start_ms, DEFAULT_SIMULATOR_INTERVAL_SECS)
    }

    fn with_start_time_and_interval(start_ms: i64, interval_secs: u64) -> Self {
        let step_ms = i64::try_from(interval_secs.max(1).saturating_mul(1_000)).unwrap_or(i64::MAX);

        Self {
            start_ms,
            step_ms,
            session_id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            tick: AtomicU64::new(0),
        }
    }

    fn flow_id(&self, name: &str) -> String {
        format!("sim-{}-{}-{name}", self.start_ms, self.session_id)
    }
}

impl Default for SimulatedCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowCollector for SimulatedCollector {
    fn source_name(&self) -> &'static str {
        "simulator"
    }

    fn collect(&self) -> Vec<Flow> {
        let tick = self.tick.fetch_add(1, Ordering::Relaxed).saturating_add(1);

        let elapsed_ticks = i64::try_from(tick.saturating_sub(1)).unwrap_or(i64::MAX);
        let elapsed_ms = self.step_ms.saturating_mul(elapsed_ticks);
        let last_seen = self.start_ms.saturating_add(elapsed_ms);
        let expires_at = Some(last_seen.saturating_add(3_600_000));

        vec![
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
        ]
    }
}

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
        let first = collector.collect();
        let second = collector.collect();
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|flow| flow.validate().is_ok()));
        assert_eq!(first[0].flow_id, second[0].flow_id);
        assert!(second[0].upload_bytes > first[0].upload_bytes);
        assert!(second[0].last_seen > first[0].last_seen);
    }

    #[test]
    fn simulator_timestamps_follow_configured_interval() {
        let start_ms = 1_700_000_000_000;
        let collector = SimulatedCollector::with_start_time_and_interval(start_ms, 1);

        let first = collector.collect();
        let second = collector.collect();

        assert_eq!(first[0].last_seen, start_ms);
        assert_eq!(second[0].last_seen, start_ms + 1_000);
    }
}
