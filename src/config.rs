use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_path: String,
    pub flow_retention_hours: u32,
    pub aggregate_retention_days: u32,
    pub shutdown_timeout_secs: u64,
    pub dev_bypass_auth: bool,
    pub admin_username: String,
    pub admin_password_hash: Option<String>,
    pub secure_cookies: bool,
    pub simulator_enabled: bool,
    pub simulator_interval_secs: u64,
    pub tc_ebpf_enabled: bool,
    pub lan_interface: String,
    pub wan_interface: String,
    pub collector_interval_secs: u64,
    pub conntrack_enabled: bool,
    pub conntrack_refresh_interval_secs: u64,
    pub dns_proxy_enabled: bool,
    pub dns_listen_addr: SocketAddr,
    pub dns_upstream_addr: SocketAddr,
    pub dns_query_timeout_ms: u64,
}

impl Config {
    /// 从环境变量加载运行配置；未设置项使用默认值。
    pub fn from_env() -> Self {
        let listen_addr = std::env::var("ROUTESCOPE_LISTEN_ADDR")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8080".parse().expect("valid default address"));
        let dev_bypass_requested = std::env::var("ROUTESCOPE_DEV_BYPASS_AUTH")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            listen_addr,
            database_path: std::env::var("ROUTESCOPE_DATABASE_PATH")
                .unwrap_or_else(|_| "data/routescope.db".to_owned()),
            flow_retention_hours: env_u32("ROUTESCOPE_FLOW_RETENTION_HOURS", 24),
            aggregate_retention_days: env_u32("ROUTESCOPE_AGGREGATE_RETENTION_DAYS", 30),
            shutdown_timeout_secs: env_u64("ROUTESCOPE_SHUTDOWN_TIMEOUT_SECS", 10),
            // The bypass is deliberately ignored for LAN/WAN listeners.
            dev_bypass_auth: dev_bypass_requested && listen_addr.ip().is_loopback(),
            admin_username: std::env::var("ROUTESCOPE_ADMIN_USERNAME")
                .unwrap_or_else(|_| "admin".to_owned()),
            admin_password_hash: std::env::var("ROUTESCOPE_ADMIN_PASSWORD_HASH")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            secure_cookies: std::env::var("ROUTESCOPE_SECURE_COOKIES")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            simulator_enabled: std::env::var("ROUTESCOPE_ENABLE_SIMULATOR")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            simulator_interval_secs: std::env::var("ROUTESCOPE_SIMULATOR_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or(5),
            tc_ebpf_enabled: std::env::var("ROUTESCOPE_ENABLE_TC_EBPF")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            lan_interface: std::env::var("ROUTESCOPE_LAN_INTERFACE")
                .unwrap_or_else(|_| "br-lan".to_owned()),
            wan_interface: std::env::var("ROUTESCOPE_WAN_INTERFACE")
                .unwrap_or_else(|_| "eth0".to_owned()),
            collector_interval_secs: std::env::var("ROUTESCOPE_COLLECT_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or(5),
            conntrack_enabled: std::env::var("ROUTESCOPE_ENABLE_CONNTRACK")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            conntrack_refresh_interval_secs: std::env::var(
                "ROUTESCOPE_CONNTRACK_REFRESH_INTERVAL_SECS",
            )
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5),
            dns_proxy_enabled: std::env::var("ROUTESCOPE_ENABLE_DNS_PROXY")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            dns_listen_addr: std::env::var("ROUTESCOPE_DNS_LISTEN_ADDR")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| "127.0.0.1:5353".parse().expect("valid default DNS address")),
            dns_upstream_addr: std::env::var("ROUTESCOPE_DNS_UPSTREAM_ADDR")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| "1.1.1.1:53".parse().expect("valid default DNS upstream")),
            dns_query_timeout_ms: std::env::var("ROUTESCOPE_DNS_QUERY_TIMEOUT_MS")
                .ok()
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or(2_000),
        }
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
