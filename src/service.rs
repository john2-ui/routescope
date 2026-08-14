//! Application use cases over the persistence layer.

use crate::domain::{
        DataDeletionResult, DataTimeRange, Device, DeviceFlowSummary, DeviceMinuteStat,
        DomainMinuteStat, DomainTrafficSummary, Flow, FlowPageAnchor, FlowPageDirection,
        ResolvedDomainBinding,
};
use crate::storage::{RouteScopeRepository, SqliteRepository};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_DOMAIN_TOP_LIMIT: usize = 20;
pub const DEFAULT_FLOW_PAGE_LIMIT: usize = 50;
pub const MAX_FLOW_PAGE_LIMIT: usize = 500;
const FLOW_CURSOR_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowWindow {
        Hours1,
        Hours6,
        Hours24,
}

impl FlowWindow {
        pub fn parse(value: Option<&str>) -> Result<Self, FlowQueryError> {
                match value.unwrap_or("24h") {
                        "1h" => Ok(Self::Hours1),
                        "6h" => Ok(Self::Hours6),
                        "24h" => Ok(Self::Hours24),
                        _ => Err(FlowQueryError::InvalidWindow),
                }
        }

        pub fn as_str(self) -> &'static str {
                match self {
                        Self::Hours1 => "1h",
                        Self::Hours6 => "6h",
                        Self::Hours24 => "24h",
                }
        }

        fn duration_ms(self) -> i64 {
                match self {
                        Self::Hours1 => 3_600_000,
                        Self::Hours6 => 6 * 3_600_000,
                        Self::Hours24 => 24 * 3_600_000,
                }
        }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowPage {
        pub items: Vec<Flow>,
        pub next_cursor: Option<String>,
        pub previous_cursor: Option<String>,
        pub window: String,
        pub since_ms: i64,
        pub limit: usize,
}

#[derive(Debug)]
pub enum FlowQueryError {
        InvalidWindow,
        InvalidLimit,
        InvalidCursor,
        CursorDeviceMismatch,
        Database(rusqlite::Error),
}

impl FlowQueryError {
        pub fn is_bad_request(&self) -> bool {
                !matches!(self, Self::Database(_))
        }
}

impl fmt::Display for FlowQueryError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                        Self::InvalidWindow => formatter.write_str("window must be 1h, 6h, or 24h"),
                        Self::InvalidLimit => {
                                formatter.write_str("limit must be between 1 and 500")
                        }
                        Self::InvalidCursor => formatter.write_str("invalid flow cursor"),
                        Self::CursorDeviceMismatch => {
                                formatter.write_str("flow cursor belongs to another device")
                        }
                        Self::Database(error) => write!(formatter, "flow query failed: {error}"),
                }
        }
}

impl Error for FlowQueryError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
                match self {
                        Self::Database(error) => Some(error),
                        _ => None,
                }
        }
}

impl From<rusqlite::Error> for FlowQueryError {
        fn from(error: rusqlite::Error) -> Self {
                Self::Database(error)
        }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CursorDirection {
        Older,
        Newer,
}

impl From<CursorDirection> for FlowPageDirection {
        fn from(direction: CursorDirection) -> Self {
                match direction {
                        CursorDirection::Older => Self::Older,
                        CursorDirection::Newer => Self::Newer,
                }
        }
}

#[derive(Debug, Serialize, Deserialize)]
struct FlowCursorPayload {
        version: u8,
        device_key: String,
        window: FlowWindow,
        since_ms: i64,
        limit: usize,
        direction: CursorDirection,
        last_seen: i64,
        flow_id: String,
}

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

        /// Query a bounded Flow page. Initial requests provide window/limit; continuations only a cursor.
        pub fn flow_page(
                &self,
                mac_address: &str,
                window: Option<&str>,
                limit: Option<usize>,
                cursor: Option<&str>,
        ) -> Result<FlowPage, FlowQueryError> {
                let now = now_ms();
                let retention_cutoff = now.saturating_sub(
                        i64::from(self.flow_retention_hours).saturating_mul(3_600_000),
                );

                let (window, since_ms, limit, direction, anchor, continuation) =
                        if let Some(cursor) = cursor {
                                if window.is_some() || limit.is_some() {
                                        return Err(FlowQueryError::InvalidCursor);
                                }
                                let payload = decode_flow_cursor(cursor)?;
                                let expected_device_key = device_key(mac_address);
                                if payload.device_key != expected_device_key {
                                        return Err(FlowQueryError::CursorDeviceMismatch);
                                }
                                if payload.version != FLOW_CURSOR_VERSION {
                                        return Err(FlowQueryError::InvalidCursor);
                                }
                                validate_flow_limit(payload.limit)?;
                                if payload.flow_id.is_empty()
                                        || payload.since_ms > now
                                        || payload.last_seen > now
                                        || payload.last_seen < payload.since_ms
                                {
                                        return Err(FlowQueryError::InvalidCursor);
                                }
                                let window_cutoff =
                                        now.saturating_sub(payload.window.duration_ms());
                                (
                                        payload.window,
                                        payload.since_ms.max(retention_cutoff).max(window_cutoff),
                                        payload.limit,
                                        FlowPageDirection::from(payload.direction),
                                        Some(FlowPageAnchor {
                                                last_seen: payload.last_seen,
                                                flow_id: payload.flow_id,
                                        }),
                                        true,
                                )
                        } else {
                                let window = FlowWindow::parse(window)?;
                                let limit = limit.unwrap_or(DEFAULT_FLOW_PAGE_LIMIT);
                                validate_flow_limit(limit)?;
                                (
                                        window,
                                        now.saturating_sub(window.duration_ms())
                                                .max(retention_cutoff),
                                        limit,
                                        FlowPageDirection::Older,
                                        None,
                                        false,
                                )
                        };

                let mut items = self.repo.list_flow_page(
                        mac_address,
                        since_ms,
                        anchor.as_ref(),
                        direction,
                        limit.saturating_add(1),
                )?;
                let has_more = items.len() > limit;
                if has_more {
                        items.truncate(limit);
                }
                if direction == FlowPageDirection::Newer {
                        items.reverse();
                }

                let next_cursor = if !items.is_empty()
                        && (has_more || direction == FlowPageDirection::Newer)
                {
                        items.last().map(|flow| {
                                encode_flow_cursor(
                                        mac_address,
                                        window,
                                        since_ms,
                                        limit,
                                        CursorDirection::Older,
                                        flow,
                                )
                        })
                } else {
                        None
                }
                .transpose()?;
                let previous_cursor = if !items.is_empty()
                        && ((continuation && direction == FlowPageDirection::Older)
                                || (direction == FlowPageDirection::Newer && has_more))
                {
                        items.first().map(|flow| {
                                encode_flow_cursor(
                                        mac_address,
                                        window,
                                        since_ms,
                                        limit,
                                        CursorDirection::Newer,
                                        flow,
                                )
                        })
                } else {
                        None
                }
                .transpose()?;

                Ok(FlowPage {
                        items,
                        next_cursor,
                        previous_cursor,
                        window: window.as_str().to_owned(),
                        since_ms,
                        limit,
                })
        }

        /// Aggregate recent Flow data without loading connection rows.
        pub fn recent_flow_summary(
                &self,
                mac_address: &str,
        ) -> Result<DeviceFlowSummary, rusqlite::Error> {
                let now = now_ms();
                let cutoff = now
                        .saturating_sub(
                                i64::from(self.flow_retention_hours).saturating_mul(3_600_000),
                        )
                        .max(now.saturating_sub(FlowWindow::Hours24.duration_ms()));
                self.repo.summarize_recent_flows(mac_address, cutoff)
        }

        /// 查询某设备在聚合保留窗口内的分钟流量序列。
        pub fn device_traffic(
                &self,
                mac_address: &str,
        ) -> Result<Vec<DeviceMinuteStat>, rusqlite::Error> {
                let cutoff = now_ms() - i64::from(self.aggregate_retention_days) * 86_400_000;
                self.repo.list_device_minute_stats(mac_address, cutoff)
        }

        /// 查询某设备、某域名在聚合保留窗口内的原始分钟流量序列。
        pub fn domain_traffic(
                &self,
                mac_address: &str,
                domain: &str,
        ) -> Result<Vec<DomainMinuteStat>, rusqlite::Error> {
                let cutoff = now_ms() - i64::from(self.aggregate_retention_days) * 86_400_000;
                self.repo
                        .list_domain_minute_stats(mac_address, domain, cutoff)
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

        /// 将新解析出的稳定 DNS binding 回填到此前已写入的 Flow 和域名聚合。
        pub fn backfill_domain_bindings(
                &self,
                bindings: &[ResolvedDomainBinding],
        ) -> Result<usize, rusqlite::Error> {
                self.repo.backfill_domain_bindings(bindings)
        }

        /// Hard-delete one device and all persisted observations associated with it.
        pub fn delete_device_data(
                &self,
                mac_address: &str,
        ) -> Result<Option<DataDeletionResult>, rusqlite::Error> {
                self.repo.delete_device_data(mac_address)
        }

        /// Remove a canonical domain attribution from one device or every device.
        pub fn delete_domain_data(
                &self,
                mac_address: Option<&str>,
                domain: &str,
        ) -> Result<DataDeletionResult, rusqlite::Error> {
                self.repo.delete_domain_data(mac_address, domain)
        }

        /// Delete observations falling in a validated half-open time range.
        pub fn delete_data_range(
                &self,
                range: DataTimeRange,
        ) -> Result<DataDeletionResult, rusqlite::Error> {
                self.repo.delete_data_range(range.from_ms, range.to_ms)
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

fn validate_flow_limit(limit: usize) -> Result<(), FlowQueryError> {
        if (1..=MAX_FLOW_PAGE_LIMIT).contains(&limit) {
                Ok(())
        } else {
                Err(FlowQueryError::InvalidLimit)
        }
}

fn device_key(mac_address: &str) -> String {
        let normalized = mac_address.trim().to_ascii_lowercase();
        URL_SAFE_NO_PAD.encode(Sha256::digest(normalized.as_bytes()))
}

fn encode_flow_cursor(
        mac_address: &str,
        window: FlowWindow,
        since_ms: i64,
        limit: usize,
        direction: CursorDirection,
        flow: &Flow,
) -> Result<String, FlowQueryError> {
        let payload = FlowCursorPayload {
                version: FLOW_CURSOR_VERSION,
                device_key: device_key(mac_address),
                window,
                since_ms,
                limit,
                direction,
                last_seen: flow.last_seen,
                flow_id: flow.flow_id.clone(),
        };
        serde_json::to_vec(&payload)
                .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
                .map_err(|_| FlowQueryError::InvalidCursor)
}

fn decode_flow_cursor(cursor: &str) -> Result<FlowCursorPayload, FlowQueryError> {
        let bytes = URL_SAFE_NO_PAD
                .decode(cursor)
                .map_err(|_| FlowQueryError::InvalidCursor)?;
        serde_json::from_slice(&bytes).map_err(|_| FlowQueryError::InvalidCursor)
}

#[cfg(test)]
mod tests {
        use super::*;
        use crate::domain::{ConnectionState, FlowDirection};

        fn flow(flow_id: &str, mac_address: &str, last_seen: i64) -> Flow {
                Flow {
                        flow_id: flow_id.to_owned(),
                        first_seen: last_seen.saturating_sub(1_000),
                        last_seen,
                        protocol: "tcp".to_owned(),
                        direction: FlowDirection::Bidirectional,
                        lan_interface: "br-lan".to_owned(),
                        wan_interface: "eth0".to_owned(),
                        client_mac: mac_address.to_owned(),
                        client_ip: "192.168.1.10".to_owned(),
                        client_port: 50_000,
                        destination_ip: "93.184.216.34".to_owned(),
                        destination_port: 443,
                        nat_source_ip: None,
                        nat_source_port: None,
                        nat_destination_ip: None,
                        nat_destination_port: None,
                        upload_bytes: 100,
                        download_bytes: 200,
                        packet_count: 3,
                        domain: None,
                        connection_state: ConnectionState::Established,
                }
        }

        #[test]
        fn flow_cursor_pages_round_trip_in_both_directions() {
                let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
                let service = ObservationService::new(Arc::clone(&repo), 24, 30);
                let mac = "aa:bb:cc:dd:ee:ff";
                let now = now_ms();
                for index in 0..5 {
                        repo.upsert_flow(&flow(
                                &format!("flow-{index}"),
                                mac,
                                now.saturating_sub(index * 1_000),
                        ))
                        .unwrap();
                }

                let first = service.flow_page(mac, Some("24h"), Some(2), None).unwrap();
                assert_eq!(
                        first.items
                                .iter()
                                .map(|flow| flow.flow_id.as_str())
                                .collect::<Vec<_>>(),
                        ["flow-0", "flow-1"]
                );
                assert!(first.previous_cursor.is_none());

                let second = service
                        .flow_page(mac, None, None, first.next_cursor.as_deref())
                        .unwrap();
                assert_eq!(
                        second.items
                                .iter()
                                .map(|flow| flow.flow_id.as_str())
                                .collect::<Vec<_>>(),
                        ["flow-2", "flow-3"]
                );
                assert!(second.next_cursor.is_some());
                assert!(second.previous_cursor.is_some());

                let returned = service
                        .flow_page(mac, None, None, second.previous_cursor.as_deref())
                        .unwrap();
                assert_eq!(returned.items, first.items);
                assert!(returned.previous_cursor.is_none());
        }

        #[test]
        fn flow_windows_limits_and_cursor_device_are_validated() {
                let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
                let service = ObservationService::new(Arc::clone(&repo), 24, 30);
                let mac = "aa:bb:cc:dd:ee:ff";
                let now = now_ms();
                repo.upsert_flow(&flow("recent", mac, now.saturating_sub(30 * 60 * 1_000)))
                        .unwrap();
                repo.upsert_flow(&flow("two-hours", mac, now.saturating_sub(2 * 3_600_000)))
                        .unwrap();

                let hour = service.flow_page(mac, Some("1h"), None, None).unwrap();
                assert_eq!(hour.items.len(), 1);
                let six_hours = service.flow_page(mac, Some("6h"), None, None).unwrap();
                assert_eq!(six_hours.items.len(), 2);
                let day = service.flow_page(mac, Some("24h"), None, None).unwrap();
                assert_eq!(day.items.len(), 2);
                let defaults = service.flow_page(mac, None, None, None).unwrap();
                assert_eq!(defaults.window, "24h");
                assert_eq!(defaults.limit, DEFAULT_FLOW_PAGE_LIMIT);
                assert!(matches!(
                        service.flow_page(mac, Some("week"), None, None),
                        Err(FlowQueryError::InvalidWindow)
                ));
                assert!(matches!(
                        service.flow_page(mac, None, Some(0), None),
                        Err(FlowQueryError::InvalidLimit)
                ));
                assert!(matches!(
                        service.flow_page(mac, None, Some(MAX_FLOW_PAGE_LIMIT + 1), None),
                        Err(FlowQueryError::InvalidLimit)
                ));

                let limited = service.flow_page(mac, None, Some(1), None).unwrap();
                let cursor = limited.next_cursor.unwrap();
                assert!(matches!(
                        service.flow_page("00:00:00:00:00:01", None, None, Some(&cursor)),
                        Err(FlowQueryError::CursorDeviceMismatch)
                ));
                assert!(matches!(
                        service.flow_page(mac, Some("24h"), None, Some(&cursor)),
                        Err(FlowQueryError::InvalidCursor)
                ));
                assert!(matches!(
                        service.flow_page(mac, None, None, Some("not-base64!")),
                        Err(FlowQueryError::InvalidCursor)
                ));
        }
}
