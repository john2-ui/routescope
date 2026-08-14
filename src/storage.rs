//! SQLite persistence: schema, repository, and retention cleanup.

use crate::domain::{
        ConnectionState, DataDeletionResult, Device, DeviceFlowSummary, DeviceMinuteStat,
        DomainAttribution, DomainConfidence, DomainMinuteStat, DomainSource, DomainTrafficSummary,
        Flow, FlowCounters, FlowDirection, FlowPageAnchor, FlowPageDirection,
        ResolvedDomainBinding, floor_to_minute_ms,
};
use rusqlite::{
        Connection, OptionalExtension, Params, Result as SqliteResult, Row, Statement, Transaction,
        params,
};
use std::{io, sync::Mutex, time::Duration};

const CURRENT_SCHEMA_VERSION: i32 = 3;

const FLOW_SELECT: &str = r#"
        SELECT
            flow_id, first_seen, last_seen, protocol, direction,
            lan_interface, wan_interface,
            client_mac, client_ip, client_port,
            destination_ip, destination_port,
            nat_source_ip, nat_source_port,
            nat_destination_ip, nat_destination_port,
            upload_bytes, download_bytes, packet_count,
            domain, domain_source, domain_confidence,
            domain_associated_at, domain_expires_at,
            connection_state
        FROM flows
"#;

/// RouteScope 持久化仓储接口。
pub trait RouteScopeRepository: Send + Sync {
        /// 按 MAC 插入或更新设备。
        #[allow(dead_code)]
        fn upsert_device(&self, device: &Device) -> SqliteResult<()>;
        /// 写入/更新 flow，并按计数增量更新分钟聚合。
        #[allow(dead_code)]
        fn upsert_flow(&self, flow: &Flow) -> SqliteResult<()>;
        /// 在一个 SQLite 事务中批量写入/更新 flow。
        fn upsert_flows(&self, flows: &[Flow]) -> SqliteResult<usize>;
        /// Apply newly resolved MAC-scoped DNS bindings to already persisted flows.
        fn backfill_domain_bindings(
                &self,
                bindings: &[ResolvedDomainBinding],
        ) -> SqliteResult<usize>;
        /// Hard-delete a device and all of its persisted observation data.
        fn delete_device_data(&self, mac_address: &str)
        -> SqliteResult<Option<DataDeletionResult>>;
        /// Remove one domain attribution globally or from a single device.
        fn delete_domain_data(
                &self,
                mac_address: Option<&str>,
                domain: &str,
        ) -> SqliteResult<DataDeletionResult>;
        /// Delete persisted observations in the half-open range `[from_ms, to_ms)`.
        fn delete_data_range(&self, from_ms: i64, to_ms: i64) -> SqliteResult<DataDeletionResult>;
        /// 列出全部设备。
        fn list_devices(&self) -> SqliteResult<Vec<Device>>;
        /// 按 MAC 查询单个设备。
        fn find_device(&self, mac_address: &str) -> SqliteResult<Option<Device>>;
        /// 更新设备手动显示名称；返回设备是否存在。
        fn update_device_display_name(
                &self,
                mac_address: &str,
                display_name: Option<&str>,
        ) -> SqliteResult<bool>;
        /// 按时间窗和稳定 keyset 边界查询某设备 Flow。
        fn list_flow_page(
                &self,
                mac_address: &str,
                since_ms: i64,
                anchor: Option<&FlowPageAnchor>,
                direction: FlowPageDirection,
                limit: usize,
        ) -> SqliteResult<Vec<Flow>>;
        /// 聚合某设备时间窗内的 Flow，用于概览而不读取明细。
        fn summarize_recent_flows(
                &self,
                mac_address: &str,
                since_ms: i64,
        ) -> SqliteResult<DeviceFlowSummary>;
        /// 查询某设备自 `since_ms` 起的分钟流量序列。
        fn list_device_minute_stats(
                &self,
                mac_address: &str,
                since_ms: i64,
        ) -> SqliteResult<Vec<DeviceMinuteStat>>;
        /// 查询某设备、某域名自 `since_ms` 起的分钟流量序列。
        fn list_domain_minute_stats(
                &self,
                mac_address: &str,
                domain: &str,
                since_ms: i64,
        ) -> SqliteResult<Vec<DomainMinuteStat>>;
        /// 聚合某设备域名流量 Top N。
        fn list_domain_traffic_top(
                &self,
                mac_address: &str,
                since_ms: i64,
                limit: usize,
        ) -> SqliteResult<Vec<DomainTrafficSummary>>;
        /// 按保留窗口删除过期 flow 与分钟聚合，返回删除行数。
        fn delete_expired_data(
                &self,
                now_ms: i64,
                flow_retention_hours: u32,
                aggregate_retention_days: u32,
        ) -> SqliteResult<(usize, usize)>;
}

pub struct SqliteRepository {
        conn: Mutex<Connection>,
}

impl SqliteRepository {
        /// 打开文件数据库并执行 schema 迁移。
        pub fn open(path: &str) -> SqliteResult<Self> {
                let conn = Connection::open(path)?;
                configure_connection(&conn, true)?;
                let repo = Self {
                        conn: Mutex::new(conn),
                };
                repo.migrate()?;
                Ok(repo)
        }

        /// 打开内存数据库（测试与离线性能基准使用）。
        pub fn open_in_memory() -> SqliteResult<Self> {
                let conn = Connection::open_in_memory()?;
                configure_connection(&conn, false)?;
                let repo = Self {
                        conn: Mutex::new(conn),
                };
                repo.migrate()?;
                Ok(repo)
        }

        /// 创建/升级 schema，并记录 SQLite `user_version`。
        fn migrate(&self) -> SqliteResult<()> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let version: i32 =
                        conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
                if version > CURRENT_SCHEMA_VERSION {
                        return Err(unsupported_schema_error(version));
                }

                let tx = conn.unchecked_transaction()?;
                if version < 1 {
                        tx.execute_batch(
                                r#"
            CREATE TABLE IF NOT EXISTS devices (
                mac_address   TEXT PRIMARY KEY NOT NULL,
                display_name  TEXT,
                current_ip    TEXT,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS flows (
                flow_id                TEXT PRIMARY KEY NOT NULL,
                first_seen             INTEGER NOT NULL,
                last_seen              INTEGER NOT NULL,
                protocol               TEXT NOT NULL,
                direction              TEXT NOT NULL,
                lan_interface          TEXT NOT NULL,
                wan_interface          TEXT NOT NULL,
                client_mac             TEXT NOT NULL,
                client_ip              TEXT NOT NULL,
                client_port            INTEGER NOT NULL,
                destination_ip         TEXT NOT NULL,
                destination_port       INTEGER NOT NULL,
                nat_source_ip          TEXT,
                nat_source_port        INTEGER,
                nat_destination_ip     TEXT,
                nat_destination_port   INTEGER,
                upload_bytes           INTEGER NOT NULL,
                download_bytes         INTEGER NOT NULL,
                packet_count           INTEGER NOT NULL,
                domain                 TEXT,
                domain_source          TEXT,
                domain_confidence      TEXT,
                domain_associated_at   INTEGER,
                domain_expires_at      INTEGER,
                connection_state       TEXT NOT NULL,
                FOREIGN KEY (client_mac) REFERENCES devices(mac_address)
            );
            CREATE INDEX IF NOT EXISTS idx_flows_client_mac_last_seen
                ON flows(client_mac, last_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_flows_last_seen
                ON flows(last_seen);
            CREATE TABLE IF NOT EXISTS device_minute_stats (
                mac_address    TEXT NOT NULL,
                minute_ms      INTEGER NOT NULL,
                upload_bytes   INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                PRIMARY KEY (mac_address, minute_ms)
            );
            CREATE TABLE IF NOT EXISTS domain_minute_stats (
                mac_address    TEXT NOT NULL,
                domain         TEXT NOT NULL,
                minute_ms      INTEGER NOT NULL,
                upload_bytes   INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL,
                domain_source  TEXT NOT NULL,
                confidence     TEXT NOT NULL,
                PRIMARY KEY (mac_address, domain, minute_ms)
            );
            CREATE INDEX IF NOT EXISTS idx_device_minute_stats_minute
                ON device_minute_stats(minute_ms);
            CREATE INDEX IF NOT EXISTS idx_domain_minute_stats_minute
                ON domain_minute_stats(minute_ms);
            CREATE TABLE IF NOT EXISTS local_accounts (
                username      TEXT PRIMARY KEY NOT NULL,
                password_hash TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            "#,
                        )?;
                }
                if version < 2 {
                        tx.execute_batch(
                                r#"
            DROP INDEX IF EXISTS idx_flows_client_mac_last_seen;
            CREATE INDEX IF NOT EXISTS idx_flows_client_mac_last_seen_flow_id
                ON flows(client_mac, last_seen DESC, flow_id DESC);
            "#,
                        )?;
                }
                if version < 3 {
                        tx.execute_batch(
                                r#"
            CREATE TABLE IF NOT EXISTS flow_minute_contributions (
                flow_id          TEXT NOT NULL,
                mac_address      TEXT NOT NULL,
                minute_ms        INTEGER NOT NULL,
                upload_bytes     INTEGER NOT NULL,
                download_bytes   INTEGER NOT NULL,
                domain           TEXT,
                domain_source    TEXT,
                confidence       TEXT,
                associated_at    INTEGER,
                expires_at       INTEGER,
                PRIMARY KEY (flow_id, minute_ms),
                FOREIGN KEY (flow_id) REFERENCES flows(flow_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_flow_minute_contributions_minute
                ON flow_minute_contributions(minute_ms);
            "#,
                        )?;
                }
                // Keep schema changes and user_version in the same transaction so a
                // failed migration cannot leave the database marked as upgraded.
                tx.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
                tx.commit()?;
                Ok(())
        }

        /// 返回最早创建的本地管理账户；首版只使用一个管理员账户。
        pub fn first_local_account(&self) -> SqliteResult<Option<(String, String)>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                conn.query_row(
                        r#"
            SELECT username, password_hash
            FROM local_accounts
            ORDER BY created_at_ms ASC, username ASC
            LIMIT 1
            "#,
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
        }

        /// 在尚未配置本地账户时写入首个管理员账户。
        pub fn insert_local_account_if_missing(
                &self,
                username: &str,
                password_hash: &str,
        ) -> SqliteResult<bool> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let inserted = conn.execute(
                        r#"
            INSERT INTO local_accounts (username, password_hash, created_at_ms)
            VALUES (?1, ?2, strftime('%s','now') * 1000)
            ON CONFLICT(username) DO NOTHING
            "#,
                        params![username, password_hash],
                )?;
                Ok(inserted == 1)
        }
}

fn configure_connection(conn: &Connection, enable_wal: bool) -> SqliteResult<()> {
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        if enable_wal {
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.pragma_update(None, "synchronous", "NORMAL")?;
        }
        Ok(())
}

fn collect_flow_rows<P: Params>(stmt: &mut Statement<'_>, params: P) -> SqliteResult<Vec<Flow>> {
        stmt.query_map(params, flow_from_row)?.collect()
}

fn flow_from_row(row: &Row<'_>) -> SqliteResult<Flow> {
        let direction_raw: String = row.get(4)?;
        let state_raw: String = row.get(24)?;
        let domain: Option<String> = row.get(19)?;
        let domain = match domain {
                Some(name) => {
                        let source_raw: String = row.get(20)?;
                        let confidence_raw: String = row.get(21)?;
                        Some(DomainAttribution {
                                domain: name,
                                source: DomainSource::parse(&source_raw)
                                        .unwrap_or(DomainSource::Unknown),
                                confidence: DomainConfidence::parse(&confidence_raw)
                                        .unwrap_or(DomainConfidence::Unknown),
                                associated_at: row.get(22)?,
                                expires_at: row.get(23)?,
                        })
                }
                None => None,
        };
        Ok(Flow {
                flow_id: row.get(0)?,
                first_seen: row.get(1)?,
                last_seen: row.get(2)?,
                protocol: row.get(3)?,
                direction: FlowDirection::parse(&direction_raw).unwrap_or(FlowDirection::Upload),
                lan_interface: row.get(5)?,
                wan_interface: row.get(6)?,
                client_mac: row.get(7)?,
                client_ip: row.get(8)?,
                client_port: row.get::<_, i64>(9)? as u16,
                destination_ip: row.get(10)?,
                destination_port: row.get::<_, i64>(11)? as u16,
                nat_source_ip: row.get(12)?,
                nat_source_port: row.get::<_, Option<i64>>(13)?.map(|value| value as u16),
                nat_destination_ip: row.get(14)?,
                nat_destination_port: row.get::<_, Option<i64>>(15)?.map(|value| value as u16),
                upload_bytes: row.get::<_, i64>(16)? as u64,
                download_bytes: row.get::<_, i64>(17)? as u64,
                packet_count: row.get::<_, i64>(18)? as u64,
                domain,
                connection_state: ConnectionState::parse(&state_raw)
                        .unwrap_or(ConnectionState::Unknown),
        })
}

fn unsupported_schema_error(version: i32) -> rusqlite::Error {
        rusqlite::Error::ToSqlConversionFailure(Box::new(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                        "database schema version {version} is newer than supported version \
             {CURRENT_SCHEMA_VERSION}"
                ),
        )))
}

/// 向设备分钟表累加上下行字节。
fn add_device_minute_bytes(
        tx: &Transaction<'_>,
        mac_address: &str,
        minute_ms: i64,
        upload_bytes: u64,
        download_bytes: u64,
) -> SqliteResult<()> {
        let upload_bytes = counter_to_sqlite_integer(upload_bytes, "upload_bytes")?;
        let download_bytes = counter_to_sqlite_integer(download_bytes, "download_bytes")?;

        tx.execute(
                r#"
        INSERT INTO device_minute_stats
            (mac_address, minute_ms, upload_bytes, download_bytes)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(mac_address, minute_ms) DO UPDATE SET
            upload_bytes = upload_bytes + excluded.upload_bytes,
            download_bytes = download_bytes + excluded.download_bytes
        "#,
                params![mac_address, minute_ms, upload_bytes, download_bytes],
        )?;
        Ok(())
}

/// 向域名分钟表累加字节，并更新 source/confidence。
fn add_domain_minute_bytes(
        tx: &Transaction<'_>,
        mac_address: &str,
        attribution: &DomainAttribution,
        minute_ms: i64,
        upload_bytes: u64,
        download_bytes: u64,
) -> SqliteResult<()> {
        let upload_bytes = counter_to_sqlite_integer(upload_bytes, "upload_bytes")?;
        let download_bytes = counter_to_sqlite_integer(download_bytes, "download_bytes")?;

        tx.execute(
                r#"
        INSERT INTO domain_minute_stats
            (mac_address, domain, minute_ms, upload_bytes, download_bytes,
             domain_source, confidence)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(mac_address, domain, minute_ms) DO UPDATE SET
            upload_bytes = upload_bytes + excluded.upload_bytes,
            download_bytes = download_bytes + excluded.download_bytes,
            domain_source = excluded.domain_source,
            confidence = excluded.confidence
        "#,
                params![
                        mac_address,
                        attribution.domain,
                        minute_ms,
                        upload_bytes,
                        download_bytes,
                        attribution.source.as_str(),
                        attribution.confidence.as_str(),
                ],
        )?;
        Ok(())
}

/// Remove a contribution previously charged to a domain minute bucket.
fn subtract_domain_minute_bytes(
        tx: &Transaction<'_>,
        mac_address: &str,
        domain: &str,
        minute_ms: i64,
        upload_bytes: u64,
        download_bytes: u64,
) -> SqliteResult<()> {
        let upload_bytes = counter_to_sqlite_integer(upload_bytes, "upload_bytes")?;
        let download_bytes = counter_to_sqlite_integer(download_bytes, "download_bytes")?;
        let updated = tx.execute(
                r#"
        UPDATE domain_minute_stats
        SET upload_bytes = upload_bytes - ?4,
            download_bytes = download_bytes - ?5
        WHERE mac_address = ?1 AND domain = ?2 AND minute_ms = ?3
          AND upload_bytes >= ?4 AND download_bytes >= ?5
        "#,
                params![mac_address, domain, minute_ms, upload_bytes, download_bytes],
        )?;
        if updated != 1 {
                return Err(invalid_counter_error(format!(
                        "domain contribution exceeds aggregate for {mac_address}/{domain}/{minute_ms}"
                )));
        }
        tx.execute(
                r#"
        DELETE FROM domain_minute_stats
        WHERE mac_address = ?1 AND domain = ?2 AND minute_ms = ?3
          AND upload_bytes = 0 AND download_bytes = 0
        "#,
                params![mac_address, domain, minute_ms],
        )?;
        Ok(())
}

#[derive(Debug, Clone)]
struct StoredFlowState {
        counters: FlowCounters,
        last_seen: i64,
        domain: Option<DomainAttribution>,
}

fn attribution_from_columns(
        domain: Option<String>,
        source: Option<String>,
        confidence: Option<String>,
        associated_at: Option<i64>,
        expires_at: Option<i64>,
) -> Option<DomainAttribution> {
        Some(DomainAttribution {
                domain: domain?,
                source: DomainSource::parse(source.as_deref().unwrap_or("unknown"))
                        .unwrap_or(DomainSource::Unknown),
                confidence: DomainConfidence::parse(confidence.as_deref().unwrap_or("unknown"))
                        .unwrap_or(DomainConfidence::Unknown),
                associated_at: associated_at.unwrap_or(0),
                expires_at,
        })
}

fn confidence_rank(confidence: &DomainConfidence) -> u8 {
        match confidence {
                DomainConfidence::High => 2,
                DomainConfidence::Low => 1,
                DomainConfidence::Unknown => 0,
        }
}

fn source_rank(source: &DomainSource) -> u8 {
        match source {
                DomainSource::Dns => 2,
                DomainSource::Sni => 1,
                DomainSource::Unknown => 0,
        }
}

/// Keep a persisted high-confidence attribution when a later collector snapshot
/// has no domain or only a weaker hint.
fn effective_attribution(
        stored: Option<&DomainAttribution>,
        incoming: Option<&DomainAttribution>,
) -> Option<DomainAttribution> {
        match (stored, incoming) {
                (None, None) => None,
                (Some(stored), None) => Some(stored.clone()),
                (None, Some(incoming)) => Some(incoming.clone()),
                (Some(stored), Some(incoming)) => {
                        let stored_rank = (
                                confidence_rank(&stored.confidence),
                                source_rank(&stored.source),
                        );
                        let incoming_rank = (
                                confidence_rank(&incoming.confidence),
                                source_rank(&incoming.source),
                        );
                        if incoming_rank > stored_rank
                                || (incoming_rank == stored_rank
                                        && incoming.associated_at >= stored.associated_at)
                        {
                                Some(incoming.clone())
                        } else {
                                Some(stored.clone())
                        }
                }
        }
}

fn load_stored_flow_state(
        tx: &Transaction<'_>,
        flow_id: &str,
) -> SqliteResult<Option<StoredFlowState>> {
        tx.query_row(
                r#"
        SELECT upload_bytes, download_bytes, packet_count, last_seen,
               domain, domain_source, domain_confidence,
               domain_associated_at, domain_expires_at
        FROM flows WHERE flow_id = ?1
        "#,
                params![flow_id],
                |row| {
                        Ok(StoredFlowState {
                                counters: FlowCounters {
                                        upload_bytes: counter_from_sqlite_integer(
                                                row.get(0)?,
                                                "upload_bytes",
                                        )?,
                                        download_bytes: counter_from_sqlite_integer(
                                                row.get(1)?,
                                                "download_bytes",
                                        )?,
                                        packet_count: counter_from_sqlite_integer(
                                                row.get(2)?,
                                                "packet_count",
                                        )?,
                                },
                                last_seen: row.get(3)?,
                                domain: attribution_from_columns(
                                        row.get(4)?,
                                        row.get(5)?,
                                        row.get(6)?,
                                        row.get(7)?,
                                        row.get(8)?,
                                ),
                        })
                },
        )
        .optional()
}

fn add_flow_minute_contribution(
        tx: &Transaction<'_>,
        flow_id: &str,
        mac_address: &str,
        minute_ms: i64,
        upload_bytes: u64,
        download_bytes: u64,
        attribution: Option<&DomainAttribution>,
) -> SqliteResult<()> {
        let upload_bytes = counter_to_sqlite_integer(upload_bytes, "upload_bytes")?;
        let download_bytes = counter_to_sqlite_integer(download_bytes, "download_bytes")?;
        let (domain, source, confidence, associated_at, expires_at) = match attribution {
                Some(attribution) => (
                        Some(attribution.domain.as_str()),
                        Some(attribution.source.as_str()),
                        Some(attribution.confidence.as_str()),
                        Some(attribution.associated_at),
                        attribution.expires_at,
                ),
                None => (None, None, None, None, None),
        };
        tx.execute(
                r#"
        INSERT INTO flow_minute_contributions
            (flow_id, mac_address, minute_ms, upload_bytes, download_bytes,
             domain, domain_source, confidence, associated_at, expires_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(flow_id, minute_ms) DO UPDATE SET
            upload_bytes = upload_bytes + excluded.upload_bytes,
            download_bytes = download_bytes + excluded.download_bytes,
            domain = excluded.domain,
            domain_source = excluded.domain_source,
            confidence = excluded.confidence,
            associated_at = excluded.associated_at,
            expires_at = excluded.expires_at
        "#,
                params![
                        flow_id,
                        mac_address,
                        minute_ms,
                        upload_bytes,
                        download_bytes,
                        domain,
                        source,
                        confidence,
                        associated_at,
                        expires_at
                ],
        )?;
        Ok(())
}

/// v2 did not have a contribution ledger. Lazily create a baseline only for an
/// unattributed legacy flow; this enables useful backfill without rewriting old
/// attributed trend buckets.
fn ensure_legacy_unattributed_baseline(
        tx: &Transaction<'_>,
        flow_id: &str,
        mac_address: &str,
        state: &StoredFlowState,
) -> SqliteResult<()> {
        if state.domain.is_some()
                || (state.counters.upload_bytes == 0 && state.counters.download_bytes == 0)
        {
                return Ok(());
        }
        let exists = tx
                .prepare("SELECT 1 FROM flow_minute_contributions WHERE flow_id = ?1 LIMIT 1")?
                .exists(params![flow_id])?;
        if !exists {
                add_flow_minute_contribution(
                        tx,
                        flow_id,
                        mac_address,
                        floor_to_minute_ms(state.last_seen),
                        state.counters.upload_bytes,
                        state.counters.download_bytes,
                        None,
                )?;
        }
        Ok(())
}

fn reconcile_flow_contributions(
        tx: &Transaction<'_>,
        flow_id: &str,
        mac_address: &str,
        attribution: &DomainAttribution,
) -> SqliteResult<()> {
        let contributions = {
                let mut stmt = tx.prepare(
                        r#"
            SELECT minute_ms, upload_bytes, download_bytes,
                   domain, domain_source, confidence, associated_at, expires_at
            FROM flow_minute_contributions
            WHERE flow_id = ?1
            "#,
                )?;
                stmt.query_map(params![flow_id], |row| {
                        Ok((
                                row.get::<_, i64>(0)?,
                                counter_from_sqlite_integer(row.get(1)?, "upload_bytes")?,
                                counter_from_sqlite_integer(row.get(2)?, "download_bytes")?,
                                attribution_from_columns(
                                        row.get(3)?,
                                        row.get(4)?,
                                        row.get(5)?,
                                        row.get(6)?,
                                        row.get(7)?,
                                ),
                        ))
                })?
                .collect::<SqliteResult<Vec<_>>>()?
        };

        for (minute_ms, upload_bytes, download_bytes, previous) in contributions {
                if previous.as_ref().map(|value| value.domain.as_str())
                        != Some(attribution.domain.as_str())
                {
                        if let Some(previous) = previous {
                                subtract_domain_minute_bytes(
                                        tx,
                                        mac_address,
                                        &previous.domain,
                                        minute_ms,
                                        upload_bytes,
                                        download_bytes,
                                )?;
                        }
                        add_domain_minute_bytes(
                                tx,
                                mac_address,
                                attribution,
                                minute_ms,
                                upload_bytes,
                                download_bytes,
                        )?;
                } else {
                        tx.execute(
                                r#"
                    UPDATE domain_minute_stats
                    SET domain_source = ?4, confidence = ?5
                    WHERE mac_address = ?1 AND domain = ?2 AND minute_ms = ?3
                    "#,
                                params![
                                        mac_address,
                                        attribution.domain,
                                        minute_ms,
                                        attribution.source.as_str(),
                                        attribution.confidence.as_str()
                                ],
                        )?;
                }
        }
        tx.execute(
                r#"
        UPDATE flow_minute_contributions
        SET domain = ?2, domain_source = ?3, confidence = ?4,
            associated_at = ?5, expires_at = ?6
        WHERE flow_id = ?1
        "#,
                params![
                        flow_id,
                        attribution.domain,
                        attribution.source.as_str(),
                        attribution.confidence.as_str(),
                        attribution.associated_at,
                        attribution.expires_at
                ],
        )?;
        Ok(())
}

/// 构造计数非法相关的 rusqlite 错误。
fn invalid_counter_error(message: impl Into<String>) -> rusqlite::Error {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message.into(),
        )))
}

/// 将 `u64` 计数转为 SQLite INTEGER；越界则报错。
fn counter_to_sqlite_integer(value: u64, field: &str) -> SqliteResult<i64> {
        i64::try_from(value)
                .map_err(|_| invalid_counter_error(format!("{field} exceeds SQLite INTEGER range")))
}

/// 将 SQLite INTEGER 读回 `u64`；负值则报错。
fn counter_from_sqlite_integer(value: i64, field: &str) -> SqliteResult<u64> {
        u64::try_from(value)
                .map_err(|_| invalid_counter_error(format!("stored {field} must not be negative")))
}

fn upsert_device_tx(tx: &Transaction<'_>, device: &Device) -> SqliteResult<()> {
        tx.execute(
                r#"
        INSERT INTO devices (mac_address, display_name, current_ip, updated_at_ms)
        VALUES (?1, ?2, ?3, strftime('%s','now') * 1000)
        ON CONFLICT(mac_address) DO UPDATE SET
            display_name = COALESCE(excluded.display_name, devices.display_name),
            current_ip   = excluded.current_ip,
            updated_at_ms = excluded.updated_at_ms
        "#,
                params![device.mac_address, device.display_name, device.current_ip],
        )?;
        Ok(())
}

fn upsert_flow_tx(tx: &Transaction<'_>, flow: &Flow) -> SqliteResult<()> {
        let current_counters = FlowCounters::from_flow(flow);
        let current_upload_bytes =
                counter_to_sqlite_integer(current_counters.upload_bytes, "upload_bytes")?;
        let current_download_bytes =
                counter_to_sqlite_integer(current_counters.download_bytes, "download_bytes")?;
        let current_packet_count =
                counter_to_sqlite_integer(current_counters.packet_count, "packet_count")?;

        upsert_device_tx(
                tx,
                &Device {
                        mac_address: flow.client_mac.clone(),
                        display_name: None,
                        current_ip: Some(flow.client_ip.clone()),
                },
        )?;

        let previous = load_stored_flow_state(tx, &flow.flow_id)?;
        let attribution = effective_attribution(
                previous.as_ref().and_then(|state| state.domain.as_ref()),
                flow.domain.as_ref(),
        );
        let (domain, domain_source, domain_confidence, domain_associated_at, domain_expires_at) =
                match attribution.as_ref() {
                        Some(d) => (
                                Some(d.domain.as_str()),
                                Some(d.source.as_str()),
                                Some(d.confidence.as_str()),
                                Some(d.associated_at),
                                d.expires_at,
                        ),
                        None => (None, None, None, None, None),
                };

        let delta = match previous.as_ref() {
                Some(previous) => current_counters
                        .clone()
                        .delta_from(previous.counters.clone())
                        .map_err(|reset| {
                                invalid_counter_error(format!("flow {}: {reset}", flow.flow_id))
                        })?,
                None => current_counters.clone(),
        };

        if let (Some(previous), Some(attribution)) = (previous.as_ref(), attribution.as_ref())
                && previous.domain.as_ref() != Some(attribution)
        {
                ensure_legacy_unattributed_baseline(tx, &flow.flow_id, &flow.client_mac, previous)?;
                reconcile_flow_contributions(tx, &flow.flow_id, &flow.client_mac, attribution)?;
        }

        tx.execute(
                r#"
            INSERT INTO flows (
                flow_id, first_seen, last_seen, protocol, direction,
                lan_interface, wan_interface,
                client_mac, client_ip, client_port,
                destination_ip, destination_port,
                nat_source_ip, nat_source_port,
                nat_destination_ip, nat_destination_port,
                upload_bytes, download_bytes, packet_count,
                domain, domain_source, domain_confidence,
                domain_associated_at, domain_expires_at,
                connection_state
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7,
                ?8, ?9, ?10,
                ?11, ?12,
                ?13, ?14,
                ?15, ?16,
                ?17, ?18, ?19,
                ?20, ?21, ?22,
                ?23, ?24,
                ?25
            )
            ON CONFLICT(flow_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                upload_bytes = excluded.upload_bytes,
                download_bytes = excluded.download_bytes,
                packet_count = excluded.packet_count,
                nat_source_ip = COALESCE(excluded.nat_source_ip, flows.nat_source_ip),
                nat_source_port = COALESCE(excluded.nat_source_port, flows.nat_source_port),
                nat_destination_ip = COALESCE(
                    excluded.nat_destination_ip,
                    flows.nat_destination_ip
                ),
                nat_destination_port = COALESCE(
                    excluded.nat_destination_port,
                    flows.nat_destination_port
                ),
                domain = excluded.domain,
                domain_source = excluded.domain_source,
                domain_confidence = excluded.domain_confidence,
                domain_associated_at = excluded.domain_associated_at,
                domain_expires_at = excluded.domain_expires_at,
                connection_state = excluded.connection_state
            "#,
                params![
                        flow.flow_id,
                        flow.first_seen,
                        flow.last_seen,
                        flow.protocol,
                        flow.direction.as_str(),
                        flow.lan_interface,
                        flow.wan_interface,
                        flow.client_mac,
                        flow.client_ip,
                        flow.client_port as i64,
                        flow.destination_ip,
                        flow.destination_port as i64,
                        flow.nat_source_ip,
                        flow.nat_source_port.map(|v| v as i64),
                        flow.nat_destination_ip,
                        flow.nat_destination_port.map(|v| v as i64),
                        current_upload_bytes,
                        current_download_bytes,
                        current_packet_count,
                        domain,
                        domain_source,
                        domain_confidence,
                        domain_associated_at,
                        domain_expires_at,
                        flow.connection_state.as_str(),
                ],
        )?;

        if delta.upload_bytes > 0 || delta.download_bytes > 0 {
                let minute_ms = floor_to_minute_ms(flow.last_seen);
                add_device_minute_bytes(
                        tx,
                        &flow.client_mac,
                        minute_ms,
                        delta.upload_bytes,
                        delta.download_bytes,
                )?;
                add_flow_minute_contribution(
                        tx,
                        &flow.flow_id,
                        &flow.client_mac,
                        minute_ms,
                        delta.upload_bytes,
                        delta.download_bytes,
                        attribution.as_ref(),
                )?;
                if let Some(attribution) = attribution.as_ref() {
                        add_domain_minute_bytes(
                                tx,
                                &flow.client_mac,
                                attribution,
                                minute_ms,
                                delta.upload_bytes,
                                delta.download_bytes,
                        )?;
                }
        }

        Ok(())
}

fn backfill_domain_binding_tx(
        tx: &Transaction<'_>,
        binding: &ResolvedDomainBinding,
) -> SqliteResult<usize> {
        let expires_at = binding.attribution.expires_at.unwrap_or(i64::MAX);
        let flow_ids = {
                let mut stmt = tx.prepare(
                        r#"
            SELECT flow_id
            FROM flows
            WHERE client_mac = ?1 AND destination_ip = ?2
              AND last_seen >= ?3 AND first_seen < ?4
            "#,
                )?;
                stmt.query_map(
                        params![
                                binding.client_mac,
                                binding.target_ip,
                                binding.attribution.associated_at,
                                expires_at
                        ],
                        |row| row.get::<_, String>(0),
                )?
                .collect::<SqliteResult<Vec<_>>>()?
        };

        let mut updated = 0;
        for flow_id in flow_ids {
                let Some(state) = load_stored_flow_state(tx, &flow_id)? else {
                        continue;
                };
                let effective =
                        effective_attribution(state.domain.as_ref(), Some(&binding.attribution));
                if effective.as_ref() == state.domain.as_ref() {
                        continue;
                }
                let Some(effective) = effective else {
                        continue;
                };

                ensure_legacy_unattributed_baseline(tx, &flow_id, &binding.client_mac, &state)?;
                reconcile_flow_contributions(tx, &flow_id, &binding.client_mac, &effective)?;
                tx.execute(
                        r#"
            UPDATE flows
            SET domain = ?2, domain_source = ?3, domain_confidence = ?4,
                domain_associated_at = ?5, domain_expires_at = ?6
            WHERE flow_id = ?1
            "#,
                        params![
                                flow_id,
                                effective.domain,
                                effective.source.as_str(),
                                effective.confidence.as_str(),
                                effective.associated_at,
                                effective.expires_at
                        ],
                )?;
                updated += 1;
        }
        Ok(updated)
}

fn count_rows<P: Params>(tx: &Transaction<'_>, sql: &str, params: P) -> SqliteResult<usize> {
        let count = tx.query_row(sql, params, |row| row.get::<_, i64>(0))?;
        usize::try_from(count).map_err(|_| invalid_counter_error("row count must be non-negative"))
}

fn delete_device_data_tx(
        tx: &Transaction<'_>,
        mac_address: &str,
) -> SqliteResult<Option<DataDeletionResult>> {
        let exists = tx
                .prepare("SELECT 1 FROM devices WHERE mac_address = ?1")?
                .exists(params![mac_address])?;
        if !exists {
                return Ok(None);
        }

        let mut result = DataDeletionResult {
                devices_deleted: 1,
                flows_deleted: count_rows(
                        tx,
                        "SELECT COUNT(*) FROM flows WHERE client_mac = ?1",
                        params![mac_address],
                )?,
                contributions_deleted: count_rows(
                        tx,
                        "SELECT COUNT(*) FROM flow_minute_contributions WHERE mac_address = ?1",
                        params![mac_address],
                )?,
                ..DataDeletionResult::default()
        };
        result.device_minutes_deleted = tx.execute(
                "DELETE FROM device_minute_stats WHERE mac_address = ?1",
                params![mac_address],
        )?;
        result.domain_minutes_deleted = tx.execute(
                "DELETE FROM domain_minute_stats WHERE mac_address = ?1",
                params![mac_address],
        )?;
        tx.execute(
                "DELETE FROM flows WHERE client_mac = ?1",
                params![mac_address],
        )?;
        tx.execute(
                "DELETE FROM devices WHERE mac_address = ?1",
                params![mac_address],
        )?;
        Ok(Some(result))
}

fn delete_domain_data_tx(
        tx: &Transaction<'_>,
        mac_address: Option<&str>,
        domain: &str,
) -> SqliteResult<DataDeletionResult> {
        let mut result = DataDeletionResult::default();
        match mac_address {
                Some(mac_address) => {
                        result.contributions_deleted = tx.execute(
                                r#"
                    DELETE FROM flow_minute_contributions
                    WHERE mac_address = ?1 AND domain = ?2
                    "#,
                                params![mac_address, domain],
                        )?;
                        result.domain_minutes_deleted = tx.execute(
                                r#"
                    DELETE FROM domain_minute_stats
                    WHERE mac_address = ?1 AND domain = ?2
                    "#,
                                params![mac_address, domain],
                        )?;
                        result.flows_redacted = tx.execute(
                                r#"
                    UPDATE flows
                    SET domain = NULL, domain_source = NULL, domain_confidence = NULL,
                        domain_associated_at = NULL, domain_expires_at = NULL
                    WHERE client_mac = ?1 AND domain = ?2
                    "#,
                                params![mac_address, domain],
                        )?;
                }
                None => {
                        result.contributions_deleted = tx.execute(
                                "DELETE FROM flow_minute_contributions WHERE domain = ?1",
                                params![domain],
                        )?;
                        result.domain_minutes_deleted = tx.execute(
                                "DELETE FROM domain_minute_stats WHERE domain = ?1",
                                params![domain],
                        )?;
                        result.flows_redacted = tx.execute(
                                r#"
                    UPDATE flows
                    SET domain = NULL, domain_source = NULL, domain_confidence = NULL,
                        domain_associated_at = NULL, domain_expires_at = NULL
                    WHERE domain = ?1
                    "#,
                                params![domain],
                        )?;
                }
        }
        Ok(result)
}

fn delete_data_range_tx(
        tx: &Transaction<'_>,
        from_ms: i64,
        to_ms: i64,
) -> SqliteResult<DataDeletionResult> {
        let flow_overlap = "first_seen < ?2 AND last_seen >= ?1";
        let contributions_deleted = count_rows(
                tx,
                &format!(r#"
            SELECT COUNT(*)
            FROM flow_minute_contributions c
            WHERE (c.minute_ms >= ?1 AND c.minute_ms < ?2)
               OR EXISTS (
                    SELECT 1 FROM flows f
                    WHERE f.flow_id = c.flow_id AND {flow_overlap}
               )
            "#),
                params![from_ms, to_ms],
        )?;
        let flows_deleted = count_rows(
                tx,
                &format!("SELECT COUNT(*) FROM flows WHERE {flow_overlap}"),
                params![from_ms, to_ms],
        )?;

        let device_minutes_deleted = tx.execute(
                r#"
            DELETE FROM device_minute_stats
            WHERE minute_ms >= ?1 AND minute_ms < ?2
            "#,
                params![from_ms, to_ms],
        )?;
        let domain_minutes_deleted = tx.execute(
                r#"
            DELETE FROM domain_minute_stats
            WHERE minute_ms >= ?1 AND minute_ms < ?2
            "#,
                params![from_ms, to_ms],
        )?;
        tx.execute(
                r#"
            DELETE FROM flow_minute_contributions
            WHERE minute_ms >= ?1 AND minute_ms < ?2
            "#,
                params![from_ms, to_ms],
        )?;
        tx.execute(
                &format!("DELETE FROM flows WHERE {flow_overlap}"),
                params![from_ms, to_ms],
        )?;

        Ok(DataDeletionResult {
                flows_deleted,
                device_minutes_deleted,
                domain_minutes_deleted,
                contributions_deleted,
                ..DataDeletionResult::default()
        })
}

impl RouteScopeRepository for SqliteRepository {
        /// 按 MAC 插入或更新设备；保留已有 display_name，更新 current_ip。
        fn upsert_device(&self, device: &Device) -> SqliteResult<()> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                conn.execute(
                        r#"
            INSERT INTO devices (mac_address, display_name, current_ip, updated_at_ms)
            VALUES (?1, ?2, ?3, strftime('%s','now') * 1000)
            ON CONFLICT(mac_address) DO UPDATE SET
                display_name = COALESCE(excluded.display_name, devices.display_name),
                current_ip = excluded.current_ip,
                updated_at_ms = excluded.updated_at_ms
            "#,
                        params![device.mac_address, device.display_name, device.current_ip],
                )?;
                Ok(())
        }

        /// 校验并 upsert flow；按计数增量更新设备/域名分钟聚合。
        fn upsert_flow(&self, flow: &Flow) -> SqliteResult<()> {
                self.upsert_flows(std::slice::from_ref(flow))?;
                Ok(())
        }

        /// Batch flow writes in a single transaction to avoid one lock/commit per flow.
        fn upsert_flows(&self, flows: &[Flow]) -> SqliteResult<usize> {
                for flow in flows {
                        flow.validate().map_err(|msg| {
                                rusqlite::Error::ToSqlConversionFailure(msg.into())
                        })?;
                }
                if flows.is_empty() {
                        return Ok(0);
                }

                let mut conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let tx = conn.transaction()?;
                for flow in flows {
                        upsert_flow_tx(&tx, flow)?;
                }
                tx.commit()?;
                Ok(flows.len())
        }

        fn backfill_domain_bindings(
                &self,
                bindings: &[ResolvedDomainBinding],
        ) -> SqliteResult<usize> {
                if bindings.is_empty() {
                        return Ok(0);
                }
                let mut conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let tx = conn.transaction()?;
                let mut updated = 0;
                for binding in bindings {
                        updated += backfill_domain_binding_tx(&tx, binding)?;
                }
                tx.commit()?;
                Ok(updated)
        }

        fn delete_device_data(
                &self,
                mac_address: &str,
        ) -> SqliteResult<Option<DataDeletionResult>> {
                let mut conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let tx = conn.transaction()?;
                let result = delete_device_data_tx(&tx, mac_address)?;
                tx.commit()?;
                Ok(result)
        }

        fn delete_domain_data(
                &self,
                mac_address: Option<&str>,
                domain: &str,
        ) -> SqliteResult<DataDeletionResult> {
                let mut conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let tx = conn.transaction()?;
                let result = delete_domain_data_tx(&tx, mac_address, domain)?;
                tx.commit()?;
                Ok(result)
        }

        fn delete_data_range(&self, from_ms: i64, to_ms: i64) -> SqliteResult<DataDeletionResult> {
                let mut conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let tx = conn.transaction()?;
                let result = delete_data_range_tx(&tx, from_ms, to_ms)?;
                tx.commit()?;
                Ok(result)
        }

        /// 列出全部设备（按 MAC 排序）。
        fn list_devices(&self) -> SqliteResult<Vec<Device>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let mut stmt = conn.prepare(
                        r#"
            SELECT mac_address, display_name, current_ip
            FROM devices
            ORDER BY mac_address
            "#,
                )?;
                let rows = stmt.query_map([], |row| {
                        Ok(Device {
                                mac_address: row.get(0)?,
                                display_name: row.get(1)?,
                                current_ip: row.get(2)?,
                        })
                })?;
                rows.collect()
        }

        /// 按 MAC 查询单个设备。
        fn find_device(&self, mac_address: &str) -> SqliteResult<Option<Device>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                conn.query_row(
                        r#"
                SELECT mac_address, display_name, current_ip
                FROM devices
                WHERE mac_address = ?1
                "#,
                        params![mac_address],
                        |row| {
                                Ok(Device {
                                        mac_address: row.get(0)?,
                                        display_name: row.get(1)?,
                                        current_ip: row.get(2)?,
                                })
                        },
                )
                .optional()
        }

        /// Update a manual device name without creating an unknown device.
        fn update_device_display_name(
                &self,
                mac_address: &str,
                display_name: Option<&str>,
        ) -> SqliteResult<bool> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let updated = conn.execute(
                        r#"
            UPDATE devices
            SET display_name = ?1, updated_at_ms = strftime('%s','now') * 1000
            WHERE mac_address = ?2
            "#,
                        params![display_name, mac_address],
                )?;
                Ok(updated == 1)
        }

        /// 按时间窗与 `(last_seen, flow_id)` keyset 查询某设备 Flow。
        fn list_flow_page(
                &self,
                mac_address: &str,
                since_ms: i64,
                anchor: Option<&FlowPageAnchor>,
                direction: FlowPageDirection,
                limit: usize,
        ) -> SqliteResult<Vec<Flow>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let limit = i64::try_from(limit).unwrap_or(i64::MAX);

                match (anchor, direction) {
                        (None, _) => {
                                let sql = format!(
                                        "{FLOW_SELECT} WHERE client_mac = ?1 AND last_seen >= ?2 \
                                         ORDER BY last_seen DESC, flow_id DESC LIMIT ?3"
                                );
                                let mut stmt = conn.prepare(&sql)?;
                                collect_flow_rows(&mut stmt, params![mac_address, since_ms, limit])
                        }
                        (Some(anchor), FlowPageDirection::Older) => {
                                let sql = format!(
                                        "{FLOW_SELECT} WHERE client_mac = ?1 AND last_seen >= ?2 \
                                         AND (last_seen < ?3 OR (last_seen = ?3 AND flow_id < ?4)) \
                                         ORDER BY last_seen DESC, flow_id DESC LIMIT ?5"
                                );
                                let mut stmt = conn.prepare(&sql)?;
                                collect_flow_rows(
                                        &mut stmt,
                                        params![
                                                mac_address,
                                                since_ms,
                                                anchor.last_seen,
                                                anchor.flow_id,
                                                limit
                                        ],
                                )
                        }
                        (Some(anchor), FlowPageDirection::Newer) => {
                                let sql = format!(
                                        "{FLOW_SELECT} WHERE client_mac = ?1 AND last_seen >= ?2 \
                                         AND (last_seen > ?3 OR (last_seen = ?3 AND flow_id > ?4)) \
                                         ORDER BY last_seen ASC, flow_id ASC LIMIT ?5"
                                );
                                let mut stmt = conn.prepare(&sql)?;
                                collect_flow_rows(
                                        &mut stmt,
                                        params![
                                                mac_address,
                                                since_ms,
                                                anchor.last_seen,
                                                anchor.flow_id,
                                                limit
                                        ],
                                )
                        }
                }
        }

        fn summarize_recent_flows(
                &self,
                mac_address: &str,
                since_ms: i64,
        ) -> SqliteResult<DeviceFlowSummary> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                conn.query_row(
                        r#"
                SELECT
                    COALESCE(SUM(upload_bytes), 0),
                    COALESCE(SUM(download_bytes), 0),
                    COUNT(*),
                    MAX(last_seen)
                FROM flows
                WHERE client_mac = ?1 AND last_seen >= ?2
                "#,
                        params![mac_address, since_ms],
                        |row| {
                                Ok(DeviceFlowSummary {
                                        upload_bytes: row.get::<_, i64>(0)? as u64,
                                        download_bytes: row.get::<_, i64>(1)? as u64,
                                        flow_count: row.get::<_, i64>(2)? as usize,
                                        last_seen: row.get(3)?,
                                })
                        },
                )
        }

        /// 查询某设备自 `since_ms` 起的分钟流量序列。
        fn list_device_minute_stats(
                &self,
                mac_address: &str,
                since_ms: i64,
        ) -> SqliteResult<Vec<DeviceMinuteStat>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let mut stmt = conn.prepare(
                        r#"
            SELECT mac_address, minute_ms, upload_bytes, download_bytes
            FROM device_minute_stats
            WHERE mac_address = ?1 AND minute_ms >= ?2
            ORDER BY minute_ms ASC
            "#,
                )?;
                let rows = stmt.query_map(params![mac_address, since_ms], |row| {
                        Ok(DeviceMinuteStat {
                                mac_address: row.get(0)?,
                                minute_ms: row.get(1)?,
                                upload_bytes: row.get::<_, i64>(2)? as u64,
                                download_bytes: row.get::<_, i64>(3)? as u64,
                        })
                })?;
                rows.collect()
        }

        /// 查询某设备、某域名的分钟流量，按时间升序返回。
        fn list_domain_minute_stats(
                &self,
                mac_address: &str,
                domain: &str,
                since_ms: i64,
        ) -> SqliteResult<Vec<DomainMinuteStat>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let mut stmt = conn.prepare(
                        r#"
            SELECT mac_address, domain, minute_ms, upload_bytes, download_bytes,
                   domain_source, confidence
            FROM domain_minute_stats
            WHERE mac_address = ?1 AND domain = ?2 AND minute_ms >= ?3
            ORDER BY minute_ms ASC
            "#,
                )?;
                let rows = stmt.query_map(params![mac_address, domain, since_ms], |row| {
                        let source_raw: String = row.get(5)?;
                        let confidence_raw: String = row.get(6)?;
                        Ok(DomainMinuteStat {
                                mac_address: row.get(0)?,
                                domain: row.get(1)?,
                                minute_ms: row.get(2)?,
                                upload_bytes: row.get::<_, i64>(3)? as u64,
                                download_bytes: row.get::<_, i64>(4)? as u64,
                                source: DomainSource::parse(&source_raw)
                                        .unwrap_or(DomainSource::Unknown),
                                confidence: DomainConfidence::parse(&confidence_raw)
                                        .unwrap_or(DomainConfidence::Unknown),
                        })
                })?;
                rows.collect()
        }

        /// 聚合某设备域名流量 Top N（按总字节排序，附带置信度与来源）。
        fn list_domain_traffic_top(
                &self,
                mac_address: &str,
                since_ms: i64,
                limit: usize,
        ) -> SqliteResult<Vec<DomainTrafficSummary>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let mut stmt = conn.prepare(
                        r#"
            SELECT
                domain,
                SUM(upload_bytes) AS upload_bytes,
                SUM(download_bytes) AS download_bytes,
                SUM(upload_bytes + download_bytes) AS total_bytes,
                CASE MIN(
                    CASE confidence
                        WHEN 'high' THEN 0
                        WHEN 'low' THEN 1
                        ELSE 2
                    END
                )
                    WHEN 0 THEN 'high'
                    WHEN 1 THEN 'low'
                    ELSE 'unknown'
                END AS confidence,
                (
                    SELECT s.domain_source
                    FROM domain_minute_stats s
                    WHERE s.mac_address = domain_minute_stats.mac_address
                      AND s.domain = domain_minute_stats.domain
                      AND s.minute_ms >= ?2
                    ORDER BY
                        CASE s.confidence
                            WHEN 'high' THEN 0
                            WHEN 'low' THEN 1
                            ELSE 2
                        END ASC,
                        s.minute_ms DESC
                    LIMIT 1
                ) AS domain_source
            FROM domain_minute_stats
            WHERE mac_address = ?1 AND minute_ms >= ?2
            GROUP BY domain
            ORDER BY total_bytes DESC
            LIMIT ?3
            "#,
                )?;
                let rows = stmt.query_map(params![mac_address, since_ms, limit as i64], |row| {
                        let confidence_raw: String = row.get(4)?;
                        let source_raw: String = row.get(5)?;
                        let upload_bytes = row.get::<_, i64>(1)? as u64;
                        let download_bytes = row.get::<_, i64>(2)? as u64;
                        Ok(DomainTrafficSummary {
                                domain: row.get(0)?,
                                upload_bytes,
                                download_bytes,
                                total_bytes: row.get::<_, i64>(3)? as u64,
                                source: DomainSource::parse(&source_raw)
                                        .unwrap_or(DomainSource::Unknown),
                                confidence: DomainConfidence::parse(&confidence_raw)
                                        .unwrap_or(DomainConfidence::Unknown),
                        })
                })?;
                rows.collect()
        }

        /// 按保留窗口删除过期 flow 与分钟聚合，返回 `(删除 flow 数, 删除聚合行数)`。
        fn delete_expired_data(
                &self,
                now_ms: i64,
                flow_retention_hours: u32,
                aggregate_retention_days: u32,
        ) -> SqliteResult<(usize, usize)> {
                let flow_cutoff = now_ms - i64::from(flow_retention_hours) * 3_600_000;
                let agg_cutoff = now_ms - i64::from(aggregate_retention_days) * 86_400_000;
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let deleted_flows = conn.execute(
                        "DELETE FROM flows WHERE last_seen < ?1",
                        params![flow_cutoff],
                )?;
                let deleted_device_stats = conn.execute(
                        "DELETE FROM device_minute_stats WHERE minute_ms < ?1",
                        params![agg_cutoff],
                )?;
                conn.execute(
                        "DELETE FROM flow_minute_contributions WHERE minute_ms < ?1",
                        params![agg_cutoff],
                )?;
                let deleted_domain_stats = conn.execute(
                        "DELETE FROM domain_minute_stats WHERE minute_ms < ?1",
                        params![agg_cutoff],
                )?;
                Ok((deleted_flows, deleted_device_stats + deleted_domain_stats))
        }
}

#[cfg(test)]
mod tests {
        use super::*;
        use crate::domain::{
                ConnectionState, DomainAttribution, DomainConfidence, DomainSource, FlowDirection,
        };

        fn sample_flow(flow_id: &str, mac: &str, last_seen: i64) -> Flow {
                Flow {
                        flow_id: flow_id.to_string(),
                        first_seen: last_seen - 1_000,
                        last_seen,
                        protocol: "tcp".to_string(),
                        direction: FlowDirection::Bidirectional,
                        lan_interface: "br-lan".to_string(),
                        wan_interface: "eth0".to_string(),
                        client_mac: mac.to_string(),
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
                                associated_at: last_seen - 2_000,
                                expires_at: Some(last_seen + 60_000),
                        }),
                        connection_state: ConnectionState::Established,
                }
        }

        fn all_flows(repo: &SqliteRepository, mac: &str) -> Vec<Flow> {
                repo.list_flow_page(mac, i64::MIN, None, FlowPageDirection::Older, usize::MAX)
                        .unwrap()
        }

        #[test]
        fn upsert_and_find_device_by_mac() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let device = Device {
                        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                        display_name: Some("Laptop".to_string()),
                        current_ip: Some("192.168.1.10".to_string()),
                };

                repo.upsert_device(&device).unwrap();

                let found = repo.find_device("aa:bb:cc:dd:ee:ff").unwrap().unwrap();
                assert_eq!(found, device);
                assert_eq!(repo.list_devices().unwrap().len(), 1);
        }

        #[test]
        fn migration_records_supported_schema_version() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let version: i32 = {
                        let conn = repo.conn.lock().unwrap();
                        conn.pragma_query_value(None, "user_version", |row| row.get(0))
                                .unwrap()
                };
                assert_eq!(version, CURRENT_SCHEMA_VERSION);
        }

        #[test]
        fn version_one_database_migrates_to_composite_flow_index() {
                let conn = Connection::open_in_memory().unwrap();
                configure_connection(&conn, false).unwrap();
                conn.execute_batch(
                        r#"
                CREATE TABLE flows (
                    flow_id TEXT PRIMARY KEY NOT NULL,
                    client_mac TEXT NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                CREATE INDEX idx_flows_client_mac_last_seen
                    ON flows(client_mac, last_seen DESC);
                PRAGMA user_version = 1;
                "#,
                )
                .unwrap();
                let repo = SqliteRepository {
                        conn: Mutex::new(conn),
                };

                repo.migrate().unwrap();

                let conn = repo.conn.lock().unwrap();
                let version: i32 = conn
                        .pragma_query_value(None, "user_version", |row| row.get(0))
                        .unwrap();
                assert_eq!(version, CURRENT_SCHEMA_VERSION);
                let old_exists = conn
                        .prepare(
                                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = \
                                 'idx_flows_client_mac_last_seen'",
                        )
                        .unwrap()
                        .exists([])
                        .unwrap();
                let new_sql: String = conn
                        .query_row(
                                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = \
                                 'idx_flows_client_mac_last_seen_flow_id'",
                                [],
                                |row| row.get(0),
                        )
                        .unwrap();
                assert!(!old_exists);
                assert!(new_sql.contains("client_mac, last_seen DESC, flow_id DESC"));
                let contributions_exist = conn
                        .prepare(
                                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = \
                                 'flow_minute_contributions'",
                        )
                        .unwrap()
                        .exists([])
                        .unwrap();
                assert!(contributions_exist);
        }

        #[test]
        fn flow_pages_use_stable_time_and_id_boundaries() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                for (id, last_seen) in [
                        ("same-a", 100_000),
                        ("same-c", 100_000),
                        ("same-b", 100_000),
                        ("older-b", 90_000),
                        ("older-a", 90_000),
                        ("expired", 70_000),
                ] {
                        repo.upsert_flow(&sample_flow(id, mac, last_seen)).unwrap();
                }
                repo.upsert_flow(&sample_flow("other-device", "00:00:00:00:00:01", 110_000))
                        .unwrap();

                let first = repo
                        .list_flow_page(mac, 80_000, None, FlowPageDirection::Older, 2)
                        .unwrap();
                assert_eq!(
                        first.iter()
                                .map(|flow| flow.flow_id.as_str())
                                .collect::<Vec<_>>(),
                        ["same-c", "same-b"]
                );

                let older = repo
                        .list_flow_page(
                                mac,
                                80_000,
                                Some(&FlowPageAnchor {
                                        last_seen: first[1].last_seen,
                                        flow_id: first[1].flow_id.clone(),
                                }),
                                FlowPageDirection::Older,
                                3,
                        )
                        .unwrap();
                assert_eq!(
                        older.iter()
                                .map(|flow| flow.flow_id.as_str())
                                .collect::<Vec<_>>(),
                        ["same-a", "older-b", "older-a"]
                );

                let newer = repo
                        .list_flow_page(
                                mac,
                                80_000,
                                Some(&FlowPageAnchor {
                                        last_seen: older[0].last_seen,
                                        flow_id: older[0].flow_id.clone(),
                                }),
                                FlowPageDirection::Newer,
                                2,
                        )
                        .unwrap();
                assert_eq!(
                        newer.iter()
                                .map(|flow| flow.flow_id.as_str())
                                .collect::<Vec<_>>(),
                        ["same-b", "same-c"]
                );
        }

        #[test]
        fn recent_flow_summary_is_computed_in_sql_with_cutoff() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut first = sample_flow("summary-first", mac, 100_000);
                first.upload_bytes = 10;
                first.download_bytes = 20;
                let mut second = sample_flow("summary-second", mac, 110_000);
                second.upload_bytes = 30;
                second.download_bytes = 40;
                repo.upsert_flows(&[first, second]).unwrap();
                repo.upsert_flow(&sample_flow("summary-old", mac, 80_000))
                        .unwrap();

                assert_eq!(
                        repo.summarize_recent_flows(mac, 90_000).unwrap(),
                        DeviceFlowSummary {
                                upload_bytes: 40,
                                download_bytes: 60,
                                flow_count: 2,
                                last_seen: Some(110_000),
                        }
                );
        }

        #[test]
        fn failed_migration_transaction_does_not_bump_schema_version() {
                let conn = Connection::open_in_memory().unwrap();
                configure_connection(&conn, false).unwrap();
                {
                        let tx = conn.unchecked_transaction().unwrap();
                        tx.execute_batch(
                                r#"
                CREATE TABLE devices (
                    mac_address TEXT PRIMARY KEY NOT NULL,
                    display_name TEXT,
                    current_ip TEXT,
                    updated_at_ms INTEGER NOT NULL
                );
                "#,
                        )
                        .unwrap();
                        tx.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)
                                .unwrap();
                        // Simulate a later DDL statement failing before commit.
                        assert!(
                tx.execute_batch("CREATE TABLE devices (mac_address TEXT PRIMARY KEY NOT NULL);")
                    .is_err()
            );
                }

                let version: i32 = conn
                        .pragma_query_value(None, "user_version", |row| row.get(0))
                        .unwrap();
                assert_eq!(version, 0);
                let devices_exists: bool = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'devices'")
            .unwrap()
            .exists([])
            .unwrap();
                assert!(!devices_exists);
        }

        #[test]
        fn batch_upsert_is_atomic_when_one_flow_is_invalid() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let valid = sample_flow("batch-valid", "aa:bb:cc:dd:ee:01", 10_000);
                let mut invalid = sample_flow("batch-invalid", "aa:bb:cc:dd:ee:02", 10_000);
                invalid.client_mac.clear();

                assert!(repo.upsert_flows(&[valid, invalid]).is_err());
                assert!(repo.list_devices().unwrap().is_empty());
        }

        #[test]
        fn manual_device_name_can_be_updated_and_cleared() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                repo.upsert_device(&Device {
                        mac_address: mac.to_owned(),
                        display_name: None,
                        current_ip: Some("192.168.1.10".to_owned()),
                })
                .unwrap();

                assert!(repo
                        .update_device_display_name(mac, Some("Living Room TV"))
                        .unwrap());
                assert_eq!(
                        repo.find_device(mac)
                                .unwrap()
                                .unwrap()
                                .display_name
                                .as_deref(),
                        Some("Living Room TV")
                );
                assert!(repo.update_device_display_name(mac, None).unwrap());
                assert_eq!(repo.find_device(mac).unwrap().unwrap().display_name, None);
                assert!(!repo
                        .update_device_display_name("ff:ff:ff:ff:ff:ff", Some("missing"))
                        .unwrap());
        }

        #[test]
        fn device_identity_is_stable_when_ip_changes() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";

                repo.upsert_device(&Device {
                        mac_address: mac.to_string(),
                        display_name: Some("Phone".to_string()),
                        current_ip: Some("192.168.1.20".to_string()),
                })
                .unwrap();

                repo.upsert_device(&Device {
                        mac_address: mac.to_string(),
                        display_name: Some("Phone".to_string()),
                        current_ip: Some("192.168.1.21".to_string()),
                })
                .unwrap();

                let devices = repo.list_devices().unwrap();
                assert_eq!(devices.len(), 1);
                assert_eq!(devices[0].current_ip.as_deref(), Some("192.168.1.21"));
        }

        #[test]
        fn flow_ingestion_preserves_manual_device_name() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";

                repo.upsert_device(&Device {
                        mac_address: mac.to_string(),
                        display_name: Some("Living Room TV".to_string()),
                        current_ip: Some("192.168.1.20".to_string()),
                })
                .unwrap();

                repo.upsert_flow(&sample_flow("flow-1", mac, 10_000))
                        .unwrap();

                let device = repo.find_device(mac).unwrap().unwrap();
                assert_eq!(device.display_name.as_deref(), Some("Living Room TV"));
                assert_eq!(device.current_ip.as_deref(), Some("192.168.1.10"));
        }

        #[test]
        fn upsert_flow_round_trips_with_domain_attribution() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let flow = sample_flow("flow-1", "aa:bb:cc:dd:ee:ff", 10_000);

                repo.upsert_flow(&flow).unwrap();
                let loaded = all_flows(&repo, "aa:bb:cc:dd:ee:ff");

                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0], flow);
        }

        #[test]
        fn delete_expired_flows_keeps_recent_window() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let now = 100_000_000i64;

                repo.upsert_flow(&sample_flow("old", mac, now - 25 * 3_600_000))
                        .unwrap();
                repo.upsert_flow(&sample_flow("new", mac, now - 3_600_000))
                        .unwrap();

                let (deleted_flows, _) = repo.delete_expired_data(now, 24, 30).unwrap();
                assert_eq!(deleted_flows, 1);

                let remaining = all_flows(&repo, mac);
                assert_eq!(remaining.len(), 1);
                assert_eq!(remaining[0].flow_id, "new");
        }

        #[test]
        fn delete_expired_aggregates_by_day_window() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let now = 100_000_000i64;
                let old_minute = now - 31 * 86_400_000;
                let new_minute = now - 86_400_000;

                {
                        let conn = repo.conn.lock().unwrap();
                        conn.execute(
                                r#"
                INSERT INTO device_minute_stats
                (mac_address, minute_ms, upload_bytes, download_bytes)
                VALUES ('aa:bb:cc:dd:ee:ff', ?1, 10, 20)
                "#,
                                params![old_minute],
                        )
                        .unwrap();
                        conn.execute(
                                r#"
                INSERT INTO device_minute_stats
                (mac_address, minute_ms, upload_bytes, download_bytes)
                VALUES ('aa:bb:cc:dd:ee:ff', ?1, 30, 40)
                "#,
                                params![new_minute],
                        )
                        .unwrap();
                }

                let (_, deleted_aggs) = repo.delete_expired_data(now, 24, 30).unwrap();
                assert_eq!(deleted_aggs, 1);

                let count: i64 = {
                        let conn = repo.conn.lock().unwrap();
                        conn.query_row("SELECT COUNT(*) FROM device_minute_stats", [], |r| r.get(0))
                                .unwrap()
                };
                assert_eq!(count, 1);
        }

        #[test]
        fn upsert_flow_accumulates_minute_stats_by_delta() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let last_seen = 125_000i64; // minute bucket 120_000
                let mut flow = sample_flow("flow-1", mac, last_seen);
                flow.upload_bytes = 1_000;
                flow.download_bytes = 2_000;

                repo.upsert_flow(&flow).unwrap();

                flow.upload_bytes = 1_500;
                flow.download_bytes = 2_500;
                repo.upsert_flow(&flow).unwrap();

                let stats = repo.list_device_minute_stats(mac, 0).unwrap();
                assert_eq!(stats.len(), 1);
                assert_eq!(stats[0].minute_ms, 120_000);
                assert_eq!(stats[0].upload_bytes, 1_500);
                assert_eq!(stats[0].download_bytes, 2_500);

                let domains = repo.list_domain_traffic_top(mac, 0, 10).unwrap();
                assert_eq!(domains.len(), 1);
                assert_eq!(domains[0].domain, "example.com");
                assert_eq!(domains[0].total_bytes, 4_000);
                assert_eq!(domains[0].confidence, DomainConfidence::High);
                assert_eq!(domains[0].source, DomainSource::Dns);
        }

        #[test]
        fn domain_minute_query_filters_domain_and_orders_by_minute() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";

                let mut later = sample_flow("trend-later", mac, 185_000);
                later.upload_bytes = 300;
                later.download_bytes = 700;
                repo.upsert_flow(&later).unwrap();

                let mut other = sample_flow("trend-other", mac, 155_000);
                other.domain = Some(DomainAttribution {
                        domain: "other.example".to_owned(),
                        source: DomainSource::Sni,
                        confidence: DomainConfidence::Low,
                        associated_at: 154_000,
                        expires_at: Some(300_000),
                });
                repo.upsert_flow(&other).unwrap();

                let mut earlier = sample_flow("trend-earlier", mac, 125_000);
                earlier.upload_bytes = 100;
                earlier.download_bytes = 200;
                repo.upsert_flow(&earlier).unwrap();

                let stats = repo
                        .list_domain_minute_stats(mac, "example.com", 120_000)
                        .unwrap();
                assert_eq!(stats.len(), 2);
                assert_eq!(stats[0].minute_ms, 120_000);
                assert_eq!(stats[0].upload_bytes, 100);
                assert_eq!(stats[0].download_bytes, 200);
                assert_eq!(stats[1].minute_ms, 180_000);
                assert_eq!(stats[1].upload_bytes, 300);
                assert_eq!(stats[1].download_bytes, 700);
                assert!(stats.iter().all(|stat| stat.mac_address == mac));
                assert!(stats.iter().all(|stat| stat.domain == "example.com"));
                assert!(stats.iter().all(|stat| stat.source == DomainSource::Dns));
                assert!(stats
                        .iter()
                        .all(|stat| stat.confidence == DomainConfidence::High));
        }

        #[test]
        fn duplicate_flow_snapshot_is_idempotent() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let flow = sample_flow("flow-duplicate", mac, 125_000);

                repo.upsert_flow(&flow).unwrap();
                repo.upsert_flow(&flow).unwrap();

                let stats = repo.list_device_minute_stats(mac, 0).unwrap();
                assert_eq!(stats.len(), 1);
                assert_eq!(stats[0].upload_bytes, flow.upload_bytes);
                assert_eq!(stats[0].download_bytes, flow.download_bytes);
        }

        #[test]
        fn delayed_dns_binding_backfills_each_recorded_minute_once() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut flow = sample_flow("flow-delayed-domain", mac, 65_000);
                flow.first_seen = 60_000;
                flow.upload_bytes = 100;
                flow.download_bytes = 200;
                flow.packet_count = 3;
                flow.domain = None;
                repo.upsert_flow(&flow).unwrap();

                flow.last_seen = 125_000;
                flow.upload_bytes = 150;
                flow.download_bytes = 260;
                flow.packet_count = 5;
                repo.upsert_flow(&flow).unwrap();

                let binding = ResolvedDomainBinding {
                        client_mac: mac.to_owned(),
                        target_ip: flow.destination_ip.clone(),
                        attribution: DomainAttribution {
                                domain: "late.example".to_owned(),
                                source: DomainSource::Dns,
                                confidence: DomainConfidence::High,
                                associated_at: 62_000,
                                expires_at: Some(180_000),
                        },
                };

                assert_eq!(
                        repo.backfill_domain_bindings(std::slice::from_ref(&binding))
                                .unwrap(),
                        1
                );
                assert_eq!(
                        repo.backfill_domain_bindings(std::slice::from_ref(&binding))
                                .unwrap(),
                        0
                );

                let stats = repo
                        .list_domain_minute_stats(mac, "late.example", 0)
                        .unwrap();
                assert_eq!(stats.len(), 2);
                assert_eq!(
                        (
                                stats[0].minute_ms,
                                stats[0].upload_bytes,
                                stats[0].download_bytes
                        ),
                        (60_000, 100, 200)
                );
                assert_eq!(
                        (
                                stats[1].minute_ms,
                                stats[1].upload_bytes,
                                stats[1].download_bytes
                        ),
                        (120_000, 50, 60)
                );
                let stored = all_flows(&repo, mac);
                assert_eq!(stored[0].domain.as_ref().unwrap().domain, "late.example");

                let device_stats = repo.list_device_minute_stats(mac, 0).unwrap();
                assert_eq!(device_stats[0].upload_bytes, 100);
                assert_eq!(device_stats[1].upload_bytes, 50);
        }

        #[test]
        fn delayed_dns_binding_reassigns_low_confidence_sni_aggregate() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut flow = sample_flow("flow-sni-backfill", mac, 125_000);
                flow.first_seen = 120_000;
                flow.upload_bytes = 400;
                flow.download_bytes = 600;
                flow.domain = Some(DomainAttribution {
                        domain: "cdn-guess.example".to_owned(),
                        source: DomainSource::Sni,
                        confidence: DomainConfidence::Low,
                        associated_at: 120_000,
                        expires_at: None,
                });
                repo.upsert_flow(&flow).unwrap();

                let binding = ResolvedDomainBinding {
                        client_mac: mac.to_owned(),
                        target_ip: flow.destination_ip.clone(),
                        attribution: DomainAttribution {
                                domain: "exact.example".to_owned(),
                                source: DomainSource::Dns,
                                confidence: DomainConfidence::High,
                                associated_at: 121_000,
                                expires_at: Some(180_000),
                        },
                };
                assert_eq!(repo.backfill_domain_bindings(&[binding]).unwrap(), 1);

                assert!(repo
                        .list_domain_minute_stats(mac, "cdn-guess.example", 0)
                        .unwrap()
                        .is_empty());
                let exact = repo
                        .list_domain_minute_stats(mac, "exact.example", 0)
                        .unwrap();
                assert_eq!(exact.len(), 1);
                assert_eq!(exact[0].upload_bytes, 400);
                assert_eq!(exact[0].download_bytes, 600);
                assert_eq!(exact[0].source, DomainSource::Dns);
                assert_eq!(exact[0].confidence, DomainConfidence::High);
        }

        #[test]
        fn delayed_dns_binding_respects_device_target_and_time_interval() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut matching = sample_flow("matching", mac, 125_000);
                matching.first_seen = 120_000;
                matching.domain = None;
                let mut old = sample_flow("old", mac, 100_000);
                old.first_seen = 90_000;
                old.domain = None;
                let mut other_device = sample_flow("other-device", "00:00:00:00:00:01", 125_000);
                other_device.first_seen = 120_000;
                other_device.domain = None;
                let mut other_target = sample_flow("other-target", mac, 125_000);
                other_target.first_seen = 120_000;
                other_target.destination_ip = "203.0.113.99".to_owned();
                other_target.domain = None;
                repo.upsert_flows(&[matching, old, other_device, other_target])
                        .unwrap();

                let binding = ResolvedDomainBinding {
                        client_mac: mac.to_owned(),
                        target_ip: "93.184.216.34".to_owned(),
                        attribution: DomainAttribution {
                                domain: "isolated.example".to_owned(),
                                source: DomainSource::Dns,
                                confidence: DomainConfidence::High,
                                associated_at: 110_000,
                                expires_at: Some(180_000),
                        },
                };
                assert_eq!(repo.backfill_domain_bindings(&[binding]).unwrap(), 1);

                let attributed = all_flows(&repo, mac)
                        .into_iter()
                        .filter(|flow| flow.domain.is_some())
                        .map(|flow| flow.flow_id)
                        .collect::<Vec<_>>();
                assert_eq!(attributed, ["matching"]);
                assert!(all_flows(&repo, "00:00:00:00:00:01")[0].domain.is_none());
        }

        #[test]
        fn repeated_snapshot_without_domain_preserves_persisted_dns_attribution() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut flow = sample_flow("flow-domain-preserved", mac, 125_000);
                repo.upsert_flow(&flow).unwrap();

                flow.domain = None;
                flow.upload_bytes += 10;
                flow.download_bytes += 20;
                repo.upsert_flow(&flow).unwrap();

                let stored = all_flows(&repo, mac);
                assert_eq!(stored[0].domain.as_ref().unwrap().domain, "example.com");
                let stats = repo
                        .list_domain_minute_stats(mac, "example.com", 0)
                        .unwrap();
                assert_eq!(stats[0].upload_bytes, flow.upload_bytes);
                assert_eq!(stats[0].download_bytes, flow.download_bytes);
        }

        #[test]
        fn device_data_deletion_is_isolated_and_keeps_admin_account() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let selected = "aa:bb:cc:dd:ee:ff";
                let other = "00:00:00:00:00:01";
                repo.insert_local_account_if_missing("admin", "hash")
                        .unwrap();
                repo.upsert_flow(&sample_flow("delete-device", selected, 125_000))
                        .unwrap();
                repo.upsert_flow(&sample_flow("keep-device", other, 125_000))
                        .unwrap();

                let result = repo.delete_device_data(selected).unwrap().unwrap();
                assert_eq!(result.devices_deleted, 1);
                assert_eq!(result.flows_deleted, 1);
                assert_eq!(result.device_minutes_deleted, 1);
                assert_eq!(result.domain_minutes_deleted, 1);
                assert_eq!(result.contributions_deleted, 1);
                assert!(repo.find_device(selected).unwrap().is_none());
                assert!(all_flows(&repo, selected).is_empty());
                assert!(repo.find_device(other).unwrap().is_some());
                assert_eq!(all_flows(&repo, other).len(), 1);
                assert_eq!(
                        repo.first_local_account().unwrap(),
                        Some(("admin".to_owned(), "hash".to_owned()))
                );
                assert!(repo.delete_device_data(selected).unwrap().is_none());
        }

        #[test]
        fn domain_deletion_redacts_attribution_without_changing_device_totals() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let selected = "aa:bb:cc:dd:ee:ff";
                let other = "00:00:00:00:00:01";
                let selected_flow = sample_flow("selected-domain", selected, 125_000);
                let other_device_flow = sample_flow("other-device-domain", other, 125_000);
                let mut other_domain_flow = sample_flow("other-domain", selected, 185_000);
                other_domain_flow.domain.as_mut().unwrap().domain = "other.example".to_owned();
                repo.upsert_flows(&[selected_flow, other_device_flow, other_domain_flow])
                        .unwrap();
                let device_totals = repo.list_device_minute_stats(selected, 0).unwrap();

                let result = repo
                        .delete_domain_data(Some(selected), "example.com")
                        .unwrap();
                assert_eq!(result.flows_redacted, 1);
                assert_eq!(result.domain_minutes_deleted, 1);
                assert_eq!(result.contributions_deleted, 1);
                assert_eq!(
                        repo.list_device_minute_stats(selected, 0).unwrap(),
                        device_totals
                );
                assert!(repo
                        .list_domain_minute_stats(selected, "example.com", 0)
                        .unwrap()
                        .is_empty());
                assert_eq!(
                        all_flows(&repo, selected)
                                .iter()
                                .find(|flow| flow.flow_id == "selected-domain")
                                .unwrap()
                                .domain,
                        None
                );
                assert!(all_flows(&repo, other)[0].domain.is_some());
                assert!(all_flows(&repo, selected)
                        .iter()
                        .find(|flow| flow.flow_id == "other-domain")
                        .unwrap()
                        .domain
                        .is_some());

                assert_eq!(
                        repo.delete_domain_data(Some(selected), "example.com")
                                .unwrap(),
                        DataDeletionResult::default()
                );
                let global = repo.delete_domain_data(None, "example.com").unwrap();
                assert_eq!(global.flows_redacted, 1);
                assert!(all_flows(&repo, other)[0].domain.is_none());
        }

        #[test]
        fn time_range_deletion_uses_half_open_flow_and_minute_boundaries() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut before = sample_flow("range-before", mac, 119_999);
                before.first_seen = 110_000;
                let mut at_start = sample_flow("range-start", mac, 120_000);
                at_start.first_seen = 119_000;
                let mut inside = sample_flow("range-inside", mac, 150_000);
                inside.first_seen = 140_000;
                let mut at_end = sample_flow("range-end", mac, 190_000);
                at_end.first_seen = 180_000;
                repo.upsert_flows(&[before, at_start, inside, at_end])
                        .unwrap();

                let result = repo.delete_data_range(120_000, 180_000).unwrap();
                assert_eq!(result.flows_deleted, 2);
                assert_eq!(result.device_minutes_deleted, 1);
                assert_eq!(result.domain_minutes_deleted, 1);
                assert_eq!(result.contributions_deleted, 2);
                let remaining = all_flows(&repo, mac)
                        .into_iter()
                        .map(|flow| flow.flow_id)
                        .collect::<Vec<_>>();
                assert_eq!(remaining, ["range-end", "range-before"]);
                assert!(repo.find_device(mac).unwrap().is_some());
                assert_eq!(
                        repo.delete_data_range(120_000, 180_000).unwrap(),
                        DataDeletionResult::default()
                );
        }

        #[test]
        fn destructive_deletion_rolls_back_when_a_statement_fails() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                repo.upsert_flow(&sample_flow("rollback-delete", mac, 125_000))
                        .unwrap();
                {
                        let conn = repo.conn.lock().unwrap();
                        conn.execute_batch(
                                r#"
                    CREATE TRIGGER reject_domain_delete
                    BEFORE DELETE ON domain_minute_stats
                    BEGIN
                        SELECT RAISE(ABORT, 'test deletion failure');
                    END;
                    "#,
                        )
                        .unwrap();
                }

                assert!(repo.delete_device_data(mac).is_err());
                assert!(repo.find_device(mac).unwrap().is_some());
                assert_eq!(all_flows(&repo, mac).len(), 1);
                assert_eq!(repo.list_device_minute_stats(mac, 0).unwrap().len(), 1);
                assert_eq!(
                        repo.list_domain_minute_stats(mac, "example.com", 0)
                                .unwrap()
                                .len(),
                        1
                );
        }

        #[test]
        fn delayed_nat_enrichment_preserves_counters_and_fills_mapping() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut flow = sample_flow("flow-nat-delay", mac, 125_000);
                flow.nat_source_ip = None;
                flow.nat_source_port = None;
                flow.nat_destination_ip = None;
                flow.nat_destination_port = None;
                flow.upload_bytes = 1_000;
                flow.download_bytes = 2_000;

                repo.upsert_flow(&flow).unwrap();
                let stats_before = repo.list_device_minute_stats(mac, 0).unwrap();

                flow.nat_source_ip = Some("203.0.113.10".into());
                flow.nat_source_port = Some(40_001);
                flow.nat_destination_ip = Some("93.184.216.34".into());
                flow.nat_destination_port = Some(443);
                repo.upsert_flow(&flow).unwrap();

                let loaded = all_flows(&repo, mac);
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].nat_source_port, Some(40_001));
                assert_eq!(loaded[0].nat_destination_port, Some(443));
                assert_eq!(repo.list_device_minute_stats(mac, 0).unwrap(), stats_before);
        }

        #[test]
        fn counter_reset_is_rejected_without_overwriting_existing_snapshot() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let mut flow = sample_flow("flow-reset", mac, 125_000);
                flow.upload_bytes = 1_000;
                flow.download_bytes = 2_000;
                flow.packet_count = 30;

                repo.upsert_flow(&flow).unwrap();

                flow.upload_bytes = 900;
                flow.download_bytes = 2_100;
                flow.packet_count = 31;

                assert!(repo.upsert_flow(&flow).is_err());

                let stored = all_flows(&repo, mac);
                assert_eq!(stored.len(), 1);
                assert_eq!(stored[0].upload_bytes, 1_000);
                assert_eq!(stored[0].download_bytes, 2_000);
                assert_eq!(stored[0].packet_count, 30);
        }

        #[test]
        fn domain_traffic_top_orders_by_total_bytes() {
                let repo = SqliteRepository::open_in_memory().unwrap();
                let mac = "aa:bb:cc:dd:ee:ff";
                let now = 180_000i64;

                let mut big = sample_flow("flow-big", mac, now);
                big.domain = Some(DomainAttribution {
                        domain: "big.example".to_string(),
                        source: DomainSource::Dns,
                        confidence: DomainConfidence::High,
                        associated_at: now - 1_000,
                        expires_at: Some(now + 60_000),
                });
                big.upload_bytes = 9_000;
                big.download_bytes = 1_000;
                repo.upsert_flow(&big).unwrap();

                let mut small = sample_flow("flow-small", mac, now);
                small.client_port = 51_235;
                small.domain = Some(DomainAttribution {
                        domain: "small.example".to_string(),
                        source: DomainSource::Sni,
                        confidence: DomainConfidence::Low,
                        associated_at: now - 1_000,
                        expires_at: Some(now + 60_000),
                });
                small.upload_bytes = 100;
                small.download_bytes = 50;
                repo.upsert_flow(&small).unwrap();

                let top = repo.list_domain_traffic_top(mac, 0, 10).unwrap();
                assert_eq!(top.len(), 2);
                assert_eq!(top[0].domain, "big.example");
                assert_eq!(top[1].domain, "small.example");
                assert_eq!(top[1].confidence, DomainConfidence::Low);
        }

        #[test]
        fn sqlite_repository_is_sync() {
                fn assert_sync<T: Sync>() {}
                assert_sync::<SqliteRepository>();
        }
}
