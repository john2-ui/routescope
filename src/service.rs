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
    /// 注入仓储与数据保留策略，创建观测服务。
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

    /// 列出全部设备。
    pub fn devices(&self) -> Result<Vec<Device>, rusqlite::Error> {
        self.repo.list_devices()
    }

    /// 按 MAC 查询单个设备。
    pub fn device(&self, mac_address: &str) -> Result<Option<Device>, rusqlite::Error> {
        self.repo.find_device(mac_address)
    }

    /// 查询某设备近期 flow，并按 flow 保留窗口再过滤。
    pub fn recent_flows(&self, mac_address: &str) -> Result<Vec<Flow>, rusqlite::Error> {
        let flows = self.repo.list_recent_flows(mac_address)?;
        let cutoff = now_ms() - i64::from(self.flow_retention_hours) * 3_600_000;
        Ok(flows
            .into_iter()
            .filter(|flow| flow.last_seen >= cutoff)
            .collect())
    }

    /// 查询某设备在聚合保留窗口内的分钟流量序列。
    pub fn device_traffic(
        &self,
        mac_address: &str,
    ) -> Result<Vec<DeviceMinuteStat>, rusqlite::Error> {
        let cutoff = now_ms() - i64::from(self.aggregate_retention_days) * 86_400_000;
        self.repo.list_device_minute_stats(mac_address, cutoff)
    }

    /// 查询某设备域名流量 Top（使用 flow 保留窗口，与近期连接视图对齐）。
    pub fn device_domain_top(
        &self,
        mac_address: &str,
    ) -> Result<Vec<DomainTrafficSummary>, rusqlite::Error> {
        // Domain Top uses the recent flow window so it matches the 24h connection view.
        let cutoff = now_ms() - i64::from(self.flow_retention_hours) * 3_600_000;
        self.repo
            .list_domain_traffic_top(mac_address, cutoff, DEFAULT_DOMAIN_TOP_LIMIT)
    }

    /// Update a device's manual display name without changing its MAC identity.
    pub fn rename_device(
        &self,
        mac_address: &str,
        display_name: Option<&str>,
    ) -> Result<bool, rusqlite::Error> {
        self.repo
            .update_device_display_name(mac_address, display_name)
    }

    /// 批量写入 flow，返回成功写入条数。
    pub fn ingest_flows(&self, flows: &[Flow]) -> Result<usize, rusqlite::Error> {
        self.repo.upsert_flows(flows)
    }

    /// 按当前时间与保留策略清理过期 flow 与聚合数据。
    pub fn cleanup_expired_data(&self) -> Result<(usize, usize), rusqlite::Error> {
        self.repo.delete_expired_data(
            now_ms(),
            self.flow_retention_hours,
            self.aggregate_retention_days,
        )
    }
}

/// 返回当前 Unix 毫秒时间戳。
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}
