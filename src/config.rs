use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_path: String,
    pub flow_retention_hours: u32,
    pub aggregate_retention_days: u32,
    pub dev_bypass_auth: bool,
    pub simulator_enabled: bool,
    pub simulator_interval_secs: u64,
}

impl Config {
    /// 从环境变量加载运行配置；未设置项使用默认值。
    pub fn from_env() -> Self {
        let listen_addr = std::env::var("ROUTESCOPE_LISTEN_ADDR")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8080".parse().expect("valid default address"));

        Self {
            listen_addr,
            database_path: std::env::var("ROUTESCOPE_DATABASE_PATH")
                .unwrap_or_else(|_| "data/routescope.db".to_owned()),
            flow_retention_hours: 24,
            aggregate_retention_days: 30,
            dev_bypass_auth: std::env::var("ROUTESCOPE_DEV_BYPASS_AUTH")
                .map(|value| value == "1")
                .unwrap_or(false),
            simulator_enabled: std::env::var("ROUTESCOPE_ENABLE_SIMULATOR")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            simulator_interval_secs: std::env::var("ROUTESCOPE_SIMULATOR_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or(5),
        }
    }
}
