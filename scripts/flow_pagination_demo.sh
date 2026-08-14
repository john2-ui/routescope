#!/usr/bin/env bash
# Seed many Flow rows, verify cursor pagination, then keep a local web demo running.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mode="${1:-serve}"
if [[ "$mode" != "serve" && "$mode" != "--check" ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

demo_db="${ROUTESCOPE_FLOW_DEMO_DB:-data/routescope-flow-demo.db}"
flow_count="${ROUTESCOPE_FLOW_DEMO_COUNT:-1500}"
listen_addr="${ROUTESCOPE_FLOW_DEMO_LISTEN_ADDR:-127.0.0.1:8081}"
base_url="http://${listen_addr}"
demo_mac="de:ad:be:ef:00:01"

PYTHONDONTWRITEBYTECODE=1 python3 scripts/seed_flow_demo.py --db "$demo_db" --flows "$flow_count"
cargo build --quiet

server_log="$(mktemp)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$server_log"
}
trap cleanup EXIT INT TERM

ROUTESCOPE_LISTEN_ADDR="$listen_addr" \
ROUTESCOPE_DATABASE_PATH="$demo_db" \
ROUTESCOPE_DEV_BYPASS_AUTH=1 \
ROUTESCOPE_ENABLE_SIMULATOR=0 \
ROUTESCOPE_ENABLE_TC_EBPF=0 \
ROUTESCOPE_ENABLE_DNS_PROXY=0 \
target/debug/routescope >"$server_log" 2>&1 &
server_pid=$!

for _ in $(seq 1 40); do
  if curl --fail --silent "$base_url/readyz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "RouteScope exited early:" >&2
    cat "$server_log" >&2
    exit 1
  fi
  sleep 0.25
done

if ! curl --fail --silent "$base_url/readyz" >/dev/null; then
  echo "RouteScope did not become ready:" >&2
  cat "$server_log" >&2
  exit 1
fi

python3 - "$base_url" "$demo_mac" "$flow_count" <<'PY'
import json
import sys
import urllib.parse
import urllib.request

base_url, mac, expected_count = sys.argv[1], sys.argv[2], int(sys.argv[3])


def get_json(path):
    with urllib.request.urlopen(base_url + path, timeout=3) as response:
        return json.load(response)


def collect(window):
    page = get_json(f"/api/v1/devices/{mac}/flows?window={window}&limit=500")
    rows = list(page["items"])
    seen = {row["flow_id"] for row in rows}
    while page["next_cursor"]:
        cursor = urllib.parse.quote(page["next_cursor"], safe="")
        page = get_json(f"/api/v1/devices/{mac}/flows?cursor={cursor}")
        for row in page["items"]:
            assert row["flow_id"] not in seen, row["flow_id"]
            seen.add(row["flow_id"])
            rows.append(row)
    assert all(
        (left["last_seen"], left["flow_id"])
        > (right["last_seen"], right["flow_id"])
        for left, right in zip(rows, rows[1:])
    )
    return rows


one_hour = collect("1h")
six_hours = collect("6h")
day = collect("24h")
assert 0 < len(one_hour) < len(six_hours) < len(day), (
    len(one_hour), len(six_hours), len(day)
)
assert len(day) == expected_count, (len(day), expected_count)

first = get_json(f"/api/v1/devices/{mac}/flows?window=24h&limit=50")
assert len(first["items"]) == 50 and first["next_cursor"], first
second_cursor = urllib.parse.quote(first["next_cursor"], safe="")
second = get_json(f"/api/v1/devices/{mac}/flows?cursor={second_cursor}")
assert len(second["items"]) == 50 and second["previous_cursor"], second
back_cursor = urllib.parse.quote(second["previous_cursor"], safe="")
back = get_json(f"/api/v1/devices/{mac}/flows?cursor={back_cursor}")
assert [row["flow_id"] for row in back["items"]] == [
    row["flow_id"] for row in first["items"]
]

with urllib.request.urlopen(base_url + f"/devices/{mac}", timeout=3) as response:
    html = response.read().decode()
assert "Flow Pagination Demo" in html
assert "[FIRST]" in html and "[OLDER]" in html and "flow_cursor=" in html

print(
    "Pagination checks passed: "
    f"1h={len(one_hour)}, 6h={len(six_hours)}, 24h={len(day)}, "
    "forward/backward cursor round-trip=ok"
)
PY

echo
echo "Flow pagination demo is ready:"
echo "  $base_url/devices/$demo_mac"
echo "  database: $demo_db"
echo "  flows: $flow_count"

if [[ "$mode" == "--check" ]]; then
  echo "Check mode complete; stopping demo server."
  exit 0
fi

echo "Press Ctrl-C to stop the demo server."
wait "$server_pid"
