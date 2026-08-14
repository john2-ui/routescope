//! SQLite persistence: schema, repository, and retention cleanup.

use crate::domain::{
        ConnectionState, Device, DeviceMinuteStat, DomainAttribution, DomainConfidence,
        DomainMinuteStat, DomainSource, DomainTrafficSummary, Flow, FlowCounters, FlowDirection,
        floor_to_minute_ms,
};
use rusqlite::{Connection, OptionalExtension, Result as SqliteResult, Transaction, params};
use std::{io, sync::Mutex, time::Duration};

const CURRENT_SCHEMA_VERSION: i32 = 1;

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
        /// 查询某设备全部 flow（按 last_seen 降序）。
        fn list_recent_flows(&self, mac_address: &str) -> SqliteResult<Vec<Flow>>;
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

        let (domain, domain_source, domain_confidence, domain_associated_at, domain_expires_at) =
                match &flow.domain {
                        Some(d) => (
                                Some(d.domain.as_str()),
                                Some(d.source.as_str()),
                                Some(d.confidence.as_str()),
                                Some(d.associated_at),
                                d.expires_at,
                        ),
                        None => (None, None, None, None, None),
                };

        let previous: Option<FlowCounters> = tx
                .query_row(
                        "SELECT upload_bytes, download_bytes, packet_count
             FROM flows WHERE flow_id = ?1",
                        params![flow.flow_id],
                        |row| {
                                Ok(FlowCounters {
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
                                })
                        },
                )
                .optional()?;

        let delta = match previous {
                Some(previous) => current_counters.delta_from(previous).map_err(|reset| {
                        invalid_counter_error(format!("flow {}: {reset}", flow.flow_id))
                })?,
                None => current_counters,
        };

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
                if let Some(attribution) = &flow.domain {
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

        /// 查询某设备全部 flow（含域名归因），按 last_seen 降序。
        fn list_recent_flows(&self, mac_address: &str) -> SqliteResult<Vec<Flow>> {
                let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
                let mut stmt = conn.prepare(
                        r#"
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
                WHERE client_mac = ?1
                ORDER BY last_seen DESC
                "#,
                )?;
                let rows = stmt.query_map(params![mac_address], |row| {
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
                                                confidence: DomainConfidence::parse(
                                                        &confidence_raw,
                                                )
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
                                direction: FlowDirection::parse(&direction_raw)
                                        .unwrap_or(FlowDirection::Upload),
                                lan_interface: row.get(5)?,
                                wan_interface: row.get(6)?,
                                client_mac: row.get(7)?,
                                client_ip: row.get(8)?,
                                client_port: row.get::<_, i64>(9)? as u16,
                                destination_ip: row.get(10)?,
                                destination_port: row.get::<_, i64>(11)? as u16,
                                nat_source_ip: row.get(12)?,
                                nat_source_port: row.get::<_, Option<i64>>(13)?.map(|v| v as u16),
                                nat_destination_ip: row.get(14)?,
                                nat_destination_port: row
                                        .get::<_, Option<i64>>(15)?
                                        .map(|v| v as u16),
                                upload_bytes: row.get::<_, i64>(16)? as u64,
                                download_bytes: row.get::<_, i64>(17)? as u64,
                                packet_count: row.get::<_, i64>(18)? as u64,
                                domain,
                                connection_state: ConnectionState::parse(&state_raw)
                                        .unwrap_or(ConnectionState::Unknown),
                        })
                })?;
                rows.collect()
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
                let loaded = repo.list_recent_flows("aa:bb:cc:dd:ee:ff").unwrap();

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

                let remaining = repo.list_recent_flows(mac).unwrap();
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

                let loaded = repo.list_recent_flows(mac).unwrap();
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

                let stored = repo.list_recent_flows(mac).unwrap();
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
