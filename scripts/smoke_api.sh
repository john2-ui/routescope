#!/usr/bin/env bash
# Seed SQLite, start RouteScope, and smoke-test the wired read APIs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

listen_override="${ROUTESCOPE_LISTEN_ADDR-}"
database_override="${ROUTESCOPE_DATABASE_PATH-}"
dev_bypass_override="${ROUTESCOPE_DEV_BYPASS_AUTH-}"
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi
[[ -n "$listen_override" ]] && ROUTESCOPE_LISTEN_ADDR="$listen_override"
[[ -n "$database_override" ]] && ROUTESCOPE_DATABASE_PATH="$database_override"
[[ -n "$dev_bypass_override" ]] && ROUTESCOPE_DEV_BYPASS_AUTH="$dev_bypass_override"

export ROUTESCOPE_LISTEN_ADDR="${ROUTESCOPE_LISTEN_ADDR:-127.0.0.1:8080}"
export ROUTESCOPE_DATABASE_PATH="${ROUTESCOPE_DATABASE_PATH:-data/routescope.db}"
export ROUTESCOPE_DEV_BYPASS_AUTH="${ROUTESCOPE_DEV_BYPASS_AUTH:-1}"

BASE_URL="http://${ROUTESCOPE_LISTEN_ADDR}"
MAC_LAPTOP="aa:bb:cc:dd:ee:01"
MAC_PHONE="aa:bb:cc:dd:ee:02"

python3 scripts/seed_dev_data.py --db "$ROUTESCOPE_DATABASE_PATH"

cargo build -q

server_log="$(mktemp)"
cookie_jar="$(mktemp)"
cargo run -q >"$server_log" 2>&1 &
server_pid=$!

cleanup() {
  if kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$server_log"
  rm -f "$cookie_jar"
}
trap cleanup EXIT

for _ in $(seq 1 40); do
  if curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "Server exited early. Log:" >&2
    cat "$server_log" >&2
    exit 1
  fi
  sleep 0.25
done

if ! curl -sf "$BASE_URL/healthz" >/dev/null; then
  echo "Server did not become ready. Log:" >&2
  cat "$server_log" >&2
  exit 1
fi
if ! curl -sf "$BASE_URL/readyz" >/dev/null; then
  echo "Server did not become ready. Log:" >&2
  cat "$server_log" >&2
  exit 1
fi

echo "== GET /healthz =="
curl -sf "$BASE_URL/healthz"
echo

echo "== GET /api/v1/devices =="
devices_json="$(curl -sf "$BASE_URL/api/v1/devices")"
echo "$devices_json"
echo "$devices_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
macs = {d["mac_address"] for d in data}
assert "aa:bb:cc:dd:ee:01" in macs and "aa:bb:cc:dd:ee:02" in macs, data
print("ok: devices list contains seeded MACs")
'

echo "== GET /api/v1/devices/${MAC_LAPTOP} =="
detail_json="$(curl -sf "$BASE_URL/api/v1/devices/${MAC_LAPTOP}")"
echo "$detail_json"
echo "$detail_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data["display_name"] == "Laptop", data
print("ok: laptop detail")
'

echo "== GET /api/v1/devices/${MAC_LAPTOP}/flows =="
flows_json="$(curl -sf "$BASE_URL/api/v1/devices/${MAC_LAPTOP}/flows")"
echo "$flows_json"
echo "$flows_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert len(data) >= 1, data
assert data[0]["domain"]["domain"] == "example.com", data
print("ok: laptop flows with domain attribution")
'

echo "== GET /api/v1/devices/${MAC_PHONE}/flows =="
phone_flows="$(curl -sf "$BASE_URL/api/v1/devices/${MAC_PHONE}/flows")"
echo "$phone_flows"
echo "$phone_flows" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert len(data) >= 1, data
assert data[0]["domain"] is None, data
print("ok: phone flow without domain")
'

echo "== GET /api/v1/devices/${MAC_LAPTOP}/traffic =="
traffic_json="$(curl -sf "$BASE_URL/api/v1/devices/${MAC_LAPTOP}/traffic")"
echo "$traffic_json"
echo "$traffic_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert len(data) >= 2, data
assert data[0]["minute_ms"] <= data[-1]["minute_ms"], data
total_up = sum(row["upload_bytes"] for row in data)
assert total_up >= 4096, data
print("ok: laptop minute traffic trend")
'

echo "== GET /api/v1/devices/${MAC_LAPTOP}/domains =="
domains_json="$(curl -sf "$BASE_URL/api/v1/devices/${MAC_LAPTOP}/domains")"
echo "$domains_json"
echo "$domains_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert len(data) >= 2, data
assert data[0]["domain"] == "example.com", data
assert data[0]["confidence"] == "high", data
assert data[0]["total_bytes"] >= data[1]["total_bytes"], data
assert data[1]["domain"] == "cdn.example", data
assert data[1]["confidence"] == "low", data
print("ok: laptop domain top ordered by traffic")
'

echo "== GET management pages =="
dashboard_html="$(curl -sf "$BASE_URL/")"
devices_html="$(curl -sf -c "$cookie_jar" "$BASE_URL/devices")"
detail_html="$(curl -sf -b "$cookie_jar" "$BASE_URL/devices/${MAC_LAPTOP}")"
python3 - "$dashboard_html" "$devices_html" "$detail_html" <<'PY'
import sys

dashboard, devices, detail = sys.argv[1:]
assert "设备实时概览" in dashboard, dashboard
assert "手动命名" in devices, devices
assert "最近 24 小时 Flow" in detail, detail
assert "example.com" in detail, detail
print("ok: management pages render live observations")
PY

csrf_token="$(awk '$6 == "routescope_csrf" { print $7 }' "$cookie_jar")"
[[ -n "$csrf_token" ]]
echo "== POST device name management API =="
renamed_json="$(curl -sf \
  -b "$cookie_jar" \
  -H "x-csrf-token: $csrf_token" \
  -H "content-type: application/json" \
  -d '{"display_name":"Study Laptop"}' \
  "$BASE_URL/api/v1/devices/${MAC_LAPTOP}/name")"
echo "$renamed_json"
echo "$renamed_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data["display_name"] == "Study Laptop", data
print("ok: device manual name update")
'

echo "== GET unknown device (expect 404) =="
status="$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/v1/devices/ff:ff:ff:ff:ff:ff")"
echo "status=$status"
[[ "$status" == "404" ]]

echo
echo "Smoke test passed."
