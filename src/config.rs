use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_path: String,
    pub flow_retention_hours: u32,
    pub aggregate_retention_days: u32,
    pub dev_bypass_auth: bool,
}

impl Config {
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
        }
    }
}
