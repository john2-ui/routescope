#!/usr/bin/env python3
"""Seed a dedicated RouteScope database with deterministic pagination demo data."""

from __future__ import annotations

import argparse
import sqlite3
import time
from collections import defaultdict
from pathlib import Path

from seed_dev_data import (
    ROOT,
    SCHEMA,
    add_device_minute,
    add_domain_minute,
    floor_to_minute_ms,
    upsert_device,
    upsert_flow,
)

DEFAULT_DB = "data/routescope-flow-demo.db"
DEFAULT_FLOW_COUNT = 1_500
DEMO_MAC = "de:ad:be:ef:00:01"
DEMO_IP = "10.10.0.50"
DEMO_FLOW_PREFIX = "flow-demo:"

DESTINATIONS = (
    ("93.184.216.34", 443, "example.com", "dns", "high"),
    ("142.250.72.14", 443, "video.example", "dns", "high"),
    ("151.101.1.69", 443, "packages.example", "dns", "high"),
    ("104.16.132.229", 443, "cdn.example", "sni", "low"),
    ("1.1.1.1", 53, "resolver.example", "dns", "high"),
    ("8.8.8.8", 53, None, None, None),
    ("203.0.113.20", 8080, "download.example", "dns", "high"),
    ("198.51.100.40", 22, None, None, None),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=DEFAULT_DB, help=f"SQLite path (default: {DEFAULT_DB})")
    parser.add_argument(
        "--flows",
        type=int,
        default=DEFAULT_FLOW_COUNT,
        help=f"number of Flow rows (default: {DEFAULT_FLOW_COUNT})",
    )
    return parser.parse_args()


def resolve_db_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def seed(db_path: Path, flow_count: int) -> None:
    if flow_count < 100:
        raise SystemExit("--flows must be at least 100 so pagination is visible")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time() * 1_000)
    # Leave ten minutes of headroom so every row stays inside 24h while the demo starts.
    span_ms = 24 * 60 * 60 * 1_000 - 10 * 60 * 1_000
    step_ms = max(1, span_ms // max(flow_count - 1, 1))
    device_minutes: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    domain_minutes: dict[tuple[str, int, str, str], list[int]] = defaultdict(
        lambda: [0, 0]
    )

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.execute(
            "DELETE FROM flows WHERE client_mac = ? AND flow_id LIKE ?",
            (DEMO_MAC, f"{DEMO_FLOW_PREFIX}%"),
        )
        conn.execute("DELETE FROM device_minute_stats WHERE mac_address = ?", (DEMO_MAC,))
        conn.execute("DELETE FROM domain_minute_stats WHERE mac_address = ?", (DEMO_MAC,))
        upsert_device(conn, DEMO_MAC, "Flow Pagination Demo", DEMO_IP, now)

        for index in range(flow_count):
            destination_ip, destination_port, domain, source, confidence = DESTINATIONS[
                index % len(DESTINATIONS)
            ]
            last_seen = now - index * step_ms
            first_seen = last_seen - 500 - (index % 30) * 1_000
            protocol = "udp" if destination_port == 53 or index % 7 == 0 else "tcp"
            upload_bytes = 512 + (index % 97) * 1_337
            download_bytes = 1_024 + (index % 211) * 4_099
            packet_count = 4 + (index % 500)
            has_nat = index % 5 != 0
            nat_port = 30_000 + index % 30_000
            associated_at = last_seen - 2_000 if domain else None

            upsert_flow(
                conn,
                {
                    "flow_id": f"{DEMO_FLOW_PREFIX}{index:06d}",
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "protocol": protocol,
                    "direction": "bidirectional",
                    "lan_interface": "br-lan",
                    "wan_interface": "eth0",
                    "client_mac": DEMO_MAC,
                    "client_ip": DEMO_IP,
                    "client_port": 10_000 + index % 50_000,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "nat_source_ip": "203.0.113.10" if has_nat else None,
                    "nat_source_port": nat_port if has_nat else None,
                    "nat_destination_ip": destination_ip if has_nat else None,
                    "nat_destination_port": destination_port if has_nat else None,
                    "upload_bytes": upload_bytes,
                    "download_bytes": download_bytes,
                    "packet_count": packet_count,
                    "domain": domain,
                    "domain_source": source,
                    "domain_confidence": confidence,
                    "domain_associated_at": associated_at,
                    "domain_expires_at": last_seen + 60 * 60 * 1_000 if domain else None,
                    "connection_state": "established" if index % 4 else "closed",
                },
            )

            minute = floor_to_minute_ms(last_seen)
            device_minutes[minute][0] += upload_bytes
            device_minutes[minute][1] += download_bytes
            if domain and source and confidence:
                key = (domain, minute, source, confidence)
                domain_minutes[key][0] += upload_bytes
                domain_minutes[key][1] += download_bytes

        for minute, (upload_bytes, download_bytes) in device_minutes.items():
            add_device_minute(
                conn, DEMO_MAC, minute, upload_bytes, download_bytes
            )
        for (domain, minute, source, confidence), totals in domain_minutes.items():
            add_domain_minute(
                conn,
                DEMO_MAC,
                domain,
                minute,
                totals[0],
                totals[1],
                source,
                confidence,
            )

        conn.commit()
        print(
            f"Seeded {flow_count} demo flows across 24h into {db_path}\n"
            f"Device: Flow Pagination Demo ({DEMO_MAC})"
        )
    finally:
        conn.close()


def main() -> None:
    args = parse_args()
    seed(resolve_db_path(args.db), args.flows)


if __name__ == "__main__":
    main()
