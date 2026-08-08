#!/usr/bin/env python3
"""Seed local SQLite with sample devices and flows for API smoke tests."""

from __future__ import annotations

import argparse
import os
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = os.environ.get("ROUTESCOPE_DATABASE_PATH", "data/routescope.db")

SCHEMA = """
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
"""


def now_ms() -> int:
    return int(time.time() * 1000)


def floor_to_minute_ms(ts: int) -> int:
    return ts - (ts % 60_000)


def upsert_device(conn: sqlite3.Connection, mac: str, name: str, ip: str, updated_at: int) -> None:
    conn.execute(
        """
        INSERT INTO devices (mac_address, display_name, current_ip, updated_at_ms)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            display_name = excluded.display_name,
            current_ip = excluded.current_ip,
            updated_at_ms = excluded.updated_at_ms
        """,
        (mac, name, ip, updated_at),
    )


def upsert_flow(conn: sqlite3.Connection, row: dict) -> None:
    conn.execute(
        """
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
            :flow_id, :first_seen, :last_seen, :protocol, :direction,
            :lan_interface, :wan_interface,
            :client_mac, :client_ip, :client_port,
            :destination_ip, :destination_port,
            :nat_source_ip, :nat_source_port,
            :nat_destination_ip, :nat_destination_port,
            :upload_bytes, :download_bytes, :packet_count,
            :domain, :domain_source, :domain_confidence,
            :domain_associated_at, :domain_expires_at,
            :connection_state
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
        """,
        row,
    )


def add_device_minute(
    conn: sqlite3.Connection,
    mac: str,
    minute_ms: int,
    upload_bytes: int,
    download_bytes: int,
) -> None:
    conn.execute(
        """
        INSERT INTO device_minute_stats
            (mac_address, minute_ms, upload_bytes, download_bytes)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(mac_address, minute_ms) DO UPDATE SET
            upload_bytes = excluded.upload_bytes,
            download_bytes = excluded.download_bytes
        """,
        (mac, minute_ms, upload_bytes, download_bytes),
    )


def add_domain_minute(
    conn: sqlite3.Connection,
    mac: str,
    domain: str,
    minute_ms: int,
    upload_bytes: int,
    download_bytes: int,
    source: str,
    confidence: str,
) -> None:
    conn.execute(
        """
        INSERT INTO domain_minute_stats
            (mac_address, domain, minute_ms, upload_bytes, download_bytes,
             domain_source, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac_address, domain, minute_ms) DO UPDATE SET
            upload_bytes = excluded.upload_bytes,
            download_bytes = excluded.download_bytes,
            domain_source = excluded.domain_source,
            confidence = excluded.confidence
        """,
        (mac, domain, minute_ms, upload_bytes, download_bytes, source, confidence),
    )


def seed(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        ts = now_ms()
        minute = floor_to_minute_ms(ts - 5_000)
        earlier_minute = minute - 60_000

        upsert_device(conn, "aa:bb:cc:dd:ee:01", "Laptop", "192.168.1.10", ts)
        upsert_device(conn, "aa:bb:cc:dd:ee:02", "Phone", "192.168.1.20", ts)

        upsert_flow(
            conn,
            {
                "flow_id": "seed-flow-laptop-1",
                "first_seen": ts - 60_000,
                "last_seen": ts - 5_000,
                "protocol": "tcp",
                "direction": "upload",
                "lan_interface": "br-lan",
                "wan_interface": "eth0",
                "client_mac": "aa:bb:cc:dd:ee:01",
                "client_ip": "192.168.1.10",
                "client_port": 51234,
                "destination_ip": "93.184.216.34",
                "destination_port": 443,
                "nat_source_ip": "203.0.113.10",
                "nat_source_port": 40001,
                "nat_destination_ip": "93.184.216.34",
                "nat_destination_port": 443,
                "upload_bytes": 4096,
                "download_bytes": 8192,
                "packet_count": 42,
                "domain": "example.com",
                "domain_source": "dns",
                "domain_confidence": "high",
                "domain_associated_at": ts - 90_000,
                "domain_expires_at": ts + 3_600_000,
                "connection_state": "established",
            },
        )
        upsert_flow(
            conn,
            {
                "flow_id": "seed-flow-laptop-2",
                "first_seen": ts - 90_000,
                "last_seen": ts - 70_000,
                "protocol": "tcp",
                "direction": "download",
                "lan_interface": "br-lan",
                "wan_interface": "eth0",
                "client_mac": "aa:bb:cc:dd:ee:01",
                "client_ip": "192.168.1.10",
                "client_port": 51235,
                "destination_ip": "1.1.1.1",
                "destination_port": 443,
                "nat_source_ip": "203.0.113.10",
                "nat_source_port": 40003,
                "nat_destination_ip": "1.1.1.1",
                "nat_destination_port": 443,
                "upload_bytes": 512,
                "download_bytes": 256,
                "packet_count": 8,
                "domain": "cdn.example",
                "domain_source": "sni",
                "domain_confidence": "low",
                "domain_associated_at": ts - 100_000,
                "domain_expires_at": ts + 3_600_000,
                "connection_state": "closed",
            },
        )
        upsert_flow(
            conn,
            {
                "flow_id": "seed-flow-phone-1",
                "first_seen": ts - 120_000,
                "last_seen": ts - 10_000,
                "protocol": "udp",
                "direction": "download",
                "lan_interface": "br-lan",
                "wan_interface": "eth0",
                "client_mac": "aa:bb:cc:dd:ee:02",
                "client_ip": "192.168.1.20",
                "client_port": 5353,
                "destination_ip": "8.8.8.8",
                "destination_port": 53,
                "nat_source_ip": "203.0.113.10",
                "nat_source_port": 40002,
                "nat_destination_ip": "8.8.8.8",
                "nat_destination_port": 53,
                "upload_bytes": 128,
                "download_bytes": 256,
                "packet_count": 4,
                "domain": None,
                "domain_source": None,
                "domain_confidence": None,
                "domain_associated_at": None,
                "domain_expires_at": None,
                "connection_state": "closed",
            },
        )

        add_device_minute(conn, "aa:bb:cc:dd:ee:01", earlier_minute, 512, 256)
        add_device_minute(conn, "aa:bb:cc:dd:ee:01", minute, 4096, 8192)
        add_device_minute(conn, "aa:bb:cc:dd:ee:02", minute, 128, 256)
        add_domain_minute(
            conn,
            "aa:bb:cc:dd:ee:01",
            "example.com",
            minute,
            4096,
            8192,
            "dns",
            "high",
        )
        add_domain_minute(
            conn,
            "aa:bb:cc:dd:ee:01",
            "cdn.example",
            earlier_minute,
            512,
            256,
            "sni",
            "low",
        )

        conn.commit()
        devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        device_stats = conn.execute("SELECT COUNT(*) FROM device_minute_stats").fetchone()[0]
        domain_stats = conn.execute("SELECT COUNT(*) FROM domain_minute_stats").fetchone()[0]
        print(
            f"Seeded {db_path}: {devices} devices, {flows} flows, "
            f"{device_stats} device-minute rows, {domain_stats} domain-minute rows"
        )
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        help=f"SQLite path (default: {DEFAULT_DB})",
    )
    args = parser.parse_args()
    db_path = Path(args.db)
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    seed(db_path)


if __name__ == "__main__":
    main()
