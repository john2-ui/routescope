use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

pub type TimestampMs = i64;

/// 将时间戳向下取整到其所在 UTC 分钟桶的起点。
pub fn floor_to_minute_ms(ts: TimestampMs) -> TimestampMs {
        ts - ts.rem_euclid(60_000)
}

/// Stable identity for a LAN device. IP addresses are flow-time snapshots only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
        pub mac_address: String,
        pub display_name: Option<String>,
        pub current_ip: Option<String>,
}

/// Normalize a user-provided device name; an empty value clears the name.
pub fn normalize_display_name(value: Option<&str>) -> Result<Option<String>, &'static str> {
        let value = value.unwrap_or("").trim();
        if value.chars().count() > 128 || value.chars().any(char::is_control) {
                return Err("display name must be at most 128 non-control characters");
        }

        Ok((!value.is_empty()).then(|| value.to_owned()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flow {
        pub flow_id: String,
        pub first_seen: TimestampMs,
        pub last_seen: TimestampMs,

        pub protocol: String,
        pub direction: FlowDirection,
        pub lan_interface: String,
        pub wan_interface: String,

        pub client_mac: String,
        pub client_ip: String,
        pub client_port: u16,
        pub destination_ip: String,
        pub destination_port: u16,
        // destination mac address是动态的，没有记录的必要

        // 并非所有流量都会经过nat，所以是可选的
        pub nat_source_ip: Option<String>,
        pub nat_source_port: Option<u16>,
        pub nat_destination_ip: Option<String>,
        pub nat_destination_port: Option<u16>,

        pub upload_bytes: u64,
        pub download_bytes: u64,
        pub packet_count: u64,

        pub domain: Option<DomainAttribution>,
        pub connection_state: ConnectionState,
}

impl Flow {
        /// 校验 flow 必填字段与时间顺序是否合法。
        pub fn validate(&self) -> Result<(), &'static str> {
                if self.flow_id.is_empty() {
                        return Err("flow_id must not be empty");
                }

                if self.client_mac.is_empty() {
                        return Err("client_mac must not be empty");
                }

                if self.client_ip.is_empty() || self.destination_ip.is_empty() {
                        return Err("IP addresses must not be empty");
                }

                if self.protocol.is_empty() {
                        return Err("protocol must not be empty");
                }

                if self.first_seen > self.last_seen {
                        return Err("first_seen must not be after last_seen");
                }

                let nat_fields = [
                        self.nat_source_ip.is_some(),
                        self.nat_source_port.is_some(),
                        self.nat_destination_ip.is_some(),
                        self.nat_destination_port.is_some(),
                ];
                if nat_fields.iter().any(|present| *present)
                        && !nat_fields.iter().all(|present| *present)
                {
                        return Err("NAT mapping fields must be provided together");
                }

                Ok(())
        }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowCounters {
        pub upload_bytes: u64,
        pub download_bytes: u64,
        pub packet_count: u64,
}

impl FlowCounters {
        /// 从 Flow 提取累计计数器快照。
        pub fn from_flow(flow: &Flow) -> Self {
                Self {
                        upload_bytes: flow.upload_bytes,
                        download_bytes: flow.download_bytes,
                        packet_count: flow.packet_count,
                }
        }

        /// 计算相对上次快照的增量；任一计数回退则返回 `CounterReset`。
        pub fn delta_from(self, previous: Self) -> Result<Self, CounterReset> {
                if self.upload_bytes < previous.upload_bytes
                        || self.download_bytes < previous.download_bytes
                        || self.packet_count < previous.packet_count
                {
                        return Err(CounterReset {
                                previous,
                                current: self,
                        });
                }

                Ok(Self {
                        upload_bytes: self.upload_bytes - previous.upload_bytes,
                        download_bytes: self.download_bytes - previous.download_bytes,
                        packet_count: self.packet_count - previous.packet_count,
                })
        }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterReset {
        pub previous: FlowCounters,
        pub current: FlowCounters,
}

impl fmt::Display for CounterReset {
        /// 格式化计数回退错误信息。
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                        f,
                        "flow counter decreased: previous={:?}, current={:?}",
                        self.previous, self.current
                )
        }
}

impl Error for CounterReset {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
        Upload,
        Download,
        Bidirectional,
}

impl FlowDirection {
        /// 转为持久化/序列化用的字符串。
        pub fn as_str(&self) -> &'static str {
                match self {
                        Self::Upload => "upload",
                        Self::Download => "download",
                        Self::Bidirectional => "bidirectional",
                }
        }

        /// 从字符串解析流量方向。
        pub fn parse(value: &str) -> Option<Self> {
                match value {
                        "upload" => Some(Self::Upload),
                        "download" => Some(Self::Download),
                        "bidirectional" => Some(Self::Bidirectional),
                        _ => None,
                }
        }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
        New,
        Established,
        Closing,
        Closed,
        Unknown,
}

impl ConnectionState {
        /// 转为持久化/序列化用的字符串。
        pub fn as_str(&self) -> &'static str {
                match self {
                        Self::New => "new",
                        Self::Established => "established",
                        Self::Closing => "closing",
                        Self::Closed => "closed",
                        Self::Unknown => "unknown",
                }
        }

        /// 从字符串解析连接状态。
        pub fn parse(value: &str) -> Option<Self> {
                match value {
                        "new" => Some(Self::New),
                        "established" => Some(Self::Established),
                        "closing" => Some(Self::Closing),
                        "closed" => Some(Self::Closed),
                        "unknown" => Some(Self::Unknown),
                        _ => None,
                }
        }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAttribution {
        pub domain: String,
        pub source: DomainSource,
        pub confidence: DomainConfidence,
        pub associated_at: TimestampMs,
        pub expires_at: Option<TimestampMs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
        Dns,
        Sni,
        Unknown,
}

impl DomainSource {
        /// 转为持久化/序列化用的字符串。
        pub fn as_str(&self) -> &'static str {
                match self {
                        Self::Dns => "dns",
                        Self::Sni => "sni",
                        Self::Unknown => "unknown",
                }
        }

        /// 从字符串解析域名归因来源。
        pub fn parse(value: &str) -> Option<Self> {
                match value {
                        "dns" => Some(Self::Dns),
                        "sni" => Some(Self::Sni),
                        "unknown" => Some(Self::Unknown),
                        _ => None,
                }
        }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainConfidence {
        High,
        Low,
        Unknown,
}

impl DomainConfidence {
        /// 转为持久化/序列化用的字符串。
        pub fn as_str(&self) -> &'static str {
                match self {
                        Self::High => "high",
                        Self::Low => "low",
                        Self::Unknown => "unknown",
                }
        }

        /// 从字符串解析域名归因置信度。
        pub fn parse(value: &str) -> Option<Self> {
                match value {
                        "high" => Some(Self::High),
                        "low" => Some(Self::Low),
                        "unknown" => Some(Self::Unknown),
                        _ => None,
                }
        }
}

/// Per-device minute traffic bucket (LAN-client perspective).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceMinuteStat {
        pub mac_address: String,
        pub minute_ms: TimestampMs,
        pub upload_bytes: u64,
        pub download_bytes: u64,
}

/// Per-device, per-domain minute traffic bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainMinuteStat {
        pub mac_address: String,
        pub domain: String,
        pub minute_ms: TimestampMs,
        pub upload_bytes: u64,
        pub download_bytes: u64,
        pub source: DomainSource,
        pub confidence: DomainConfidence,
}

/// Per-device domain traffic summary for Top rankings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainTrafficSummary {
        pub domain: String,
        pub upload_bytes: u64,
        pub download_bytes: u64,
        pub total_bytes: u64,
        pub source: DomainSource,
        pub confidence: DomainConfidence,
}

#[cfg(test)]
mod tests {
        use super::*;

        fn valid_flow() -> Flow {
                Flow {
                        flow_id: "flow-1".to_string(),
                        first_seen: 1_000,
                        last_seen: 2_000,
                        protocol: "tcp".to_string(),
                        direction: FlowDirection::Bidirectional,
                        lan_interface: "br-lan".to_string(),
                        wan_interface: "eth0".to_string(),
                        client_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                        client_ip: "192.168.1.10".to_string(),
                        client_port: 51_234,
                        destination_ip: "93.184.216.34".to_string(),
                        destination_port: 443,
                        nat_source_ip: Some("203.0.113.10".to_string()),
                        nat_source_port: Some(40_001),
                        nat_destination_ip: Some("93.184.216.34".to_string()),
                        nat_destination_port: Some(443),
                        upload_bytes: 1_024,
                        download_bytes: 256,
                        packet_count: 12,
                        domain: Some(DomainAttribution {
                                domain: "example.com".to_string(),
                                source: DomainSource::Dns,
                                confidence: DomainConfidence::High,
                                associated_at: 900,
                                expires_at: Some(3_600),
                        }),
                        connection_state: ConnectionState::Established,
                }
        }

        #[test]
        fn valid_flow_passes_validation() {
                assert!(valid_flow().validate().is_ok());
        }

        #[test]
        fn flow_rejects_invalid_time_range() {
                let mut flow = valid_flow();
                flow.first_seen = 3_000;
                flow.last_seen = 2_000;
                assert_eq!(
                        flow.validate(),
                        Err("first_seen must not be after last_seen")
                );
        }

        #[test]
        fn flow_rejects_missing_stable_device_identity() {
                let mut flow = valid_flow();
                flow.client_mac.clear();
                assert_eq!(flow.validate(), Err("client_mac must not be empty"));
        }

        #[test]
        fn bidirectional_flow_uses_lan_client_perspective() {
                let upload = valid_flow();
                assert_eq!(upload.direction, FlowDirection::Bidirectional);
                assert_eq!(upload.upload_bytes, 1_024);
                assert_eq!(upload.download_bytes, 256);
        }

        #[test]
        fn flow_rejects_partial_nat_mapping() {
                let mut flow = valid_flow();
                flow.nat_destination_port = None;
                assert_eq!(
                        flow.validate(),
                        Err("NAT mapping fields must be provided together")
                );
        }
        #[test]
        fn flow_serializes_expected_field_names() {
                let json = serde_json::to_value(valid_flow()).unwrap();
                assert_eq!(json["flow_id"], "flow-1");
                assert_eq!(json["client_mac"], "aa:bb:cc:dd:ee:ff");
                assert_eq!(json["direction"], "bidirectional");
                assert_eq!(json["domain"]["source"], "dns");
                assert_eq!(json["domain"]["confidence"], "high");
                assert_eq!(json["connection_state"], "established");
        }
        #[test]
        fn flow_round_trips_through_json() {
                let original = valid_flow();
                let encoded = serde_json::to_string(&original).unwrap();
                let decoded: Flow = serde_json::from_str(&encoded).unwrap();
                assert_eq!(decoded, original);
        }

        #[test]
        fn floor_to_minute_aligns_to_bucket_start() {
                assert_eq!(floor_to_minute_ms(61_234), 60_000);
                assert_eq!(floor_to_minute_ms(60_000), 60_000);
        }

        #[test]
        fn display_name_normalization_trims_and_allows_clearing() {
                assert_eq!(
                        normalize_display_name(Some("  Living Room TV  ")).unwrap(),
                        Some("Living Room TV".to_owned())
                );
                assert_eq!(normalize_display_name(Some("   ")).unwrap(), None);
                assert!(normalize_display_name(Some("bad\nname")).is_err());
        }

        #[test]
        fn display_name_limit_counts_unicode_characters() {
                let accepted = "测".repeat(128);
                assert_eq!(
                        normalize_display_name(Some(&accepted)).unwrap(),
                        Some(accepted)
                );
                assert!(normalize_display_name(Some(&"测".repeat(129))).is_err());
        }
}
