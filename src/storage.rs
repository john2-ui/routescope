//! SQLite persistence: schema, repository, and retention cleanup.

use crate::domain::{
    ConnectionState, Device, DomainAttribution, DomainConfidence, DomainSource, Flow, FlowDirection,
};
use rusqlite::{Connection, OptionalExtension, Result as SqliteResult, params};
use std::sync::Mutex;

pub trait RouteScopeRepository: Send + Sync {
    fn upsert_device(&self, device: &Device) -> SqliteResult<()>;
    fn upsert_flow(&self, flow: &Flow) -> SqliteResult<()>;
    fn list_devices(&self) -> SqliteResult<Vec<Device>>;
    fn find_device(&self, mac_address: &str) -> SqliteResult<Option<Device>>;
    fn list_recent_flows(&self, mac_address: &str) -> SqliteResult<Vec<Flow>>;
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
    pub fn open(path: &str) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        let repo = Self {
            conn: Mutex::new(conn),
        };
        repo.migrate()?;
        Ok(repo)
    }

    pub fn open_in_memory() -> SqliteResult<Self> {
        let conn = Connection::open_in_memory()?;
        let repo = Self {
            conn: Mutex::new(conn),
        };
        repo.migrate()?;
        Ok(repo)
    }

    fn migrate(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
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
            "#,
        )?;
        Ok(())
    }
}

impl RouteScopeRepository for SqliteRepository {
    fn upsert_device(&self, device: &Device) -> SqliteResult<()> {
        let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
        conn.execute(
            r#"
        INSERT INTO devices (mac_address, display_name, current_ip, updated_at_ms)
        VALUES (?1, ?2, ?3, strftime('%s','now') * 1000)
        ON CONFLICT(mac_address) DO UPDATE SET
            display_name = excluded.display_name,
            current_ip   = excluded.current_ip,
            updated_at_ms = excluded.updated_at_ms
        "#,
            params![device.mac_address, device.display_name, device.current_ip],
        )?;
        Ok(())
    }

    fn upsert_flow(&self, flow: &Flow) -> SqliteResult<()> {
        flow.validate()
            .map_err(|msg| rusqlite::Error::ToSqlConversionFailure(msg.into()))?;

        self.upsert_device(&Device {
            mac_address: flow.client_mac.clone(),
            display_name: None,
            current_ip: Some(flow.client_ip.clone()),
        })?;

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

        let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
        conn.execute(
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
                flow.upload_bytes as i64,
                flow.download_bytes as i64,
                flow.packet_count as i64,
                domain,
                domain_source,
                domain_confidence,
                domain_associated_at,
                domain_expires_at,
                flow.connection_state.as_str(),
            ],
        )?;
        Ok(())
    }

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
                        source: DomainSource::parse(&source_raw).unwrap_or(DomainSource::Unknown),
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
                nat_source_port: row.get::<_, Option<i64>>(13)?.map(|v| v as u16),
                nat_destination_ip: row.get(14)?,
                nat_destination_port: row.get::<_, Option<i64>>(15)?.map(|v| v as u16),
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
            direction: FlowDirection::Upload,
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
        repo.upsert_flow(&sample_flow("new", mac, now - 1 * 3_600_000))
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
        let new_minute = now - 1 * 86_400_000;

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
    fn sqlite_repository_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SqliteRepository>();
    }
}
