use serde::{Deserialize, Serialize};

pub type TimestampMs = i64;

/// Floor a timestamp to the start of its UTC minute bucket.
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

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Upload,
    Download,
}

impl FlowDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "upload" => Some(Self::Upload),
            "download" => Some(Self::Download),
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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Established => "established",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Unknown => "unknown",
        }
    }

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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Sni => "sni",
            Self::Unknown => "unknown",
        }
    }
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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
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
            direction: FlowDirection::Upload,
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
    fn direction_uses_lan_client_perspective() {
        let upload = valid_flow();
        assert_eq!(upload.direction, FlowDirection::Upload);
        let mut download = valid_flow();
        download.direction = FlowDirection::Download;
        assert_eq!(download.direction, FlowDirection::Download);
    }
    #[test]
    fn flow_serializes_expected_field_names() {
        let json = serde_json::to_value(valid_flow()).unwrap();
        assert_eq!(json["flow_id"], "flow-1");
        assert_eq!(json["client_mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(json["direction"], "upload");
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
}
