//! Application use cases over the persistence layer.

use crate::domain::{Device, DeviceMinuteStat, DomainTrafficSummary, Flow};
use crate::storage::{RouteScopeRepository, SqliteRepository};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_DOMAIN_TOP_LIMIT: usize = 20;

#[derive(Clone)]
pub struct ObservationService {
    repo: Arc<SqliteRepository>,
    flow_retention_hours: u32,
    aggregate_retention_days: u32,
}

impl ObservationService {
    pub fn new(
        repo: Arc<SqliteRepository>,
        flow_retention_hours: u32,
        aggregate_retention_days: u32,
    ) -> Self {
        Self {
            repo,
            flow_retention_hours,
            aggregate_retention_days,
        }
    }

    pub fn devices(&self) -> Result<Vec<Device>, rusqlite::Error> {
        self.repo.list_devices()
    }

    pub fn device(&self, mac_address: &str) -> Result<Option<Device>, rusqlite::Error> {
        self.repo.find_device(mac_address)
    }

    pub fn recent_flows(&self, mac_address: &str) -> Result<Vec<Flow>, rusqlite::Error> {
        let flows = self.repo.list_recent_flows(mac_address)?;
        let cutoff = now_ms() - i64::from(self.flow_retention_hours) * 3_600_000;
        Ok(flows
            .into_iter()
            .filter(|flow| flow.last_seen >= cutoff)
            .collect())
    }

    pub fn device_traffic(
        &self,
        mac_address: &str,
    ) -> Result<Vec<DeviceMinuteStat>, rusqlite::Error> {
        let cutoff = now_ms() - i64::from(self.aggregate_retention_days) * 86_400_000;
        self.repo.list_device_minute_stats(mac_address, cutoff)
    }

    pub fn device_domain_top(
        &self,
        mac_address: &str,
    ) -> Result<Vec<DomainTrafficSummary>, rusqlite::Error> {
        // Domain Top uses the recent flow window so it matches the 24h connection view.
        let cutoff = now_ms() - i64::from(self.flow_retention_hours) * 3_600_000;
        self.repo
            .list_domain_traffic_top(mac_address, cutoff, DEFAULT_DOMAIN_TOP_LIMIT)
    }

    pub fn ingest_flows(&self, flows: &[Flow]) -> Result<usize, rusqlite::Error> {
        for flow in flows {
            self.repo.upsert_flow(flow)?;
        }

        Ok(flows.len())
    }

    pub fn cleanup_expired_data(&self) -> Result<(usize, usize), rusqlite::Error> {
        self.repo.delete_expired_data(
            now_ms(),
            self.flow_retention_hours,
            self.aggregate_retention_days,
        )
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}
