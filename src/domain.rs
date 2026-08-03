use serde::Serialize;

/// Stable identity for a LAN device. IP addresses are flow-time snapshots only.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub mac_address: String,
    pub display_name: Option<String>,
    pub current_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    pub id: String,
    pub client_mac: String,
    pub client_ip: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
    pub direction: FlowDirection,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub domain: Option<DomainAttribution>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainAttribution {
    pub domain: String,
    pub source: DomainSource,
    pub confidence: DomainConfidence,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
    Dns,
    Sni,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainConfidence {
    High,
    Low,
    Unknown,
}
