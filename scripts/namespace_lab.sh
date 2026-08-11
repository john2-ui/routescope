#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLIENT_A_NS="routescope-client-a"
CLIENT_B_NS="routescope-client-b"
ROUTER_NS="routescope-router"
WAN_NS="routescope-wan"

CLIENT_A_MAC="02:00:00:00:00:0a"
CLIENT_B_MAC="02:00:00:00:00:0b"

CLIENT_A_IP="10.0.0.10"
CLIENT_B_IP="10.0.0.11"
LAN_ROUTER_IP="10.0.0.1"
WAN_ROUTER_IP="10.0.2.1"
WAN_SERVER_IP="10.0.2.2"
UDP_SERVER_PORT="9090"

HTTP_SERVER_PID=""
HTTP_SERVER_LOG=""
UDP_SERVER_PID=""
UDP_SERVER_LOG=""
ROUTESCOPE_PID=""
ROUTESCOPE_LOG=""
ROUTESCOPE_DB=""

# Topology (namespaces + addressing):
#
#   ┌─────────────────────┐         ┌──────────────────────────────────┐         ┌─────────────────────┐
#   │ routescope-client-a │         │       routescope-router          │         │  routescope-wan     │
#   │                     │  veth   │                                  │  veth   │                     │
#   │ eth0                ├─────────┤ lan-a ──┐                        │         │                     │
#   │ 10.0.0.10/24        │         │         │                        │         │ eth0                │
#   │ MAC ..:0a           │         │      br-lan  10.0.0.1/24         │         │ 10.0.2.2/24         │
#   └─────────────────────┘         │         │                        │         │ HTTP :8080 (test)   │
#                                   │ lan-b ──┘                        │         └──────────▲──────────┘
#   ┌─────────────────────┐         │                                  │                    │
#   │ routescope-client-b │  veth   │ wan0  10.0.2.1/24  ──────────────┼────────────────────┘
#   │                     ├─────────┤                                  │   10.0.2.0/24
#   │ eth0                │         │ ip_forward=1                     │
#   │ 10.0.0.11/24        │         │ nft: forward + MASQUERADE→wan0   │
#   │ MAC ..:0b           │         └──────────────────────────────────┘
#   └─────────────────────┘
#
#   LAN 10.0.0.0/24: clients default via 10.0.0.1
#   WAN 10.0.2.0/24: wan default via 10.0.2.1; LAN egress SNAT to 10.0.2.1

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/namespace_lab.sh up
  sudo scripts/namespace_lab.sh down
  sudo scripts/namespace_lab.sh status
  sudo scripts/namespace_lab.sh test
  sudo scripts/namespace_lab.sh collector-test

The test topology is:
  client-a/client-b -- br-lan -- router -- wan0 -- wan
EOF
}

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "error: this command must run as root (try sudo)" >&2
        exit 1
    fi
}

require_commands() {
    local command

    for command in "$@"; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "error: required command not found: $command" >&2
            exit 1
        fi
    done
}

ns_exec() {
    local namespace=$1
    shift
    ip netns exec "$namespace" "$@"
}

namespace_exists() {
    ip netns list | awk '{print $1}' | awk -v target="$1" '$0 == target { found = 1 } END { exit !found }'
}

delete_namespaces() {
    local namespace

    for namespace in "$CLIENT_A_NS" "$CLIENT_B_NS" "$ROUTER_NS" "$WAN_NS"; do
        ip netns del "$namespace" 2>/dev/null || true
    done
}

create_veth_pair() {
    local left_name=$1
    local right_name=$2
    local left_namespace=$3
    local right_namespace=$4
    local left_final_name=$5
    local right_final_name=$6

    ip link add "$left_name" type veth peer name "$right_name"
    ip link set "$left_name" netns "$left_namespace"
    ip link set "$right_name" netns "$right_namespace"
    ns_exec "$left_namespace" ip link set "$left_name" name "$left_final_name"
    ns_exec "$right_namespace" ip link set "$right_name" name "$right_final_name"
}

configure_router_firewall() {
    ns_exec "$ROUTER_NS" nft -f - <<'EOF'
flush ruleset

table inet routescope_filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "br-lan" oifname "wan0" accept
        iifname "wan0" oifname "br-lan" accept
    }
}

table ip routescope_nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "wan0" ip saddr 10.0.0.0/24 masquerade
    }
}
EOF
}

setup_topology() {
    require_root
    require_commands ip nft sysctl

    delete_namespaces
    ip netns add "$CLIENT_A_NS"
    ip netns add "$CLIENT_B_NS"
    ip netns add "$ROUTER_NS"
    ip netns add "$WAN_NS"

    create_veth_pair \
        rs-a-client rs-a-router \
        "$CLIENT_A_NS" "$ROUTER_NS" \
        eth0 lan-a
    create_veth_pair \
        rs-b-client rs-b-router \
        "$CLIENT_B_NS" "$ROUTER_NS" \
        eth0 lan-b
    create_veth_pair \
        rs-wan-router rs-wan \
        "$ROUTER_NS" "$WAN_NS" \
        wan0 eth0

    ns_exec "$CLIENT_A_NS" ip link set lo up
    ns_exec "$CLIENT_B_NS" ip link set lo up
    ns_exec "$ROUTER_NS" ip link set lo up
    ns_exec "$WAN_NS" ip link set lo up

    ns_exec "$ROUTER_NS" ip link add br-lan type bridge
    ns_exec "$ROUTER_NS" ip link set lan-a master br-lan
    ns_exec "$ROUTER_NS" ip link set lan-b master br-lan

    ns_exec "$CLIENT_A_NS" ip link set eth0 address "$CLIENT_A_MAC"
    ns_exec "$CLIENT_B_NS" ip link set eth0 address "$CLIENT_B_MAC"

    ns_exec "$CLIENT_A_NS" ip addr add "$CLIENT_A_IP/24" dev eth0
    ns_exec "$CLIENT_B_NS" ip addr add "$CLIENT_B_IP/24" dev eth0
    ns_exec "$ROUTER_NS" ip addr add "$LAN_ROUTER_IP/24" dev br-lan
    ns_exec "$ROUTER_NS" ip addr add "$WAN_ROUTER_IP/24" dev wan0
    ns_exec "$WAN_NS" ip addr add "$WAN_SERVER_IP/24" dev eth0

    ns_exec "$CLIENT_A_NS" ip link set eth0 up
    ns_exec "$CLIENT_B_NS" ip link set eth0 up
    ns_exec "$ROUTER_NS" ip link set br-lan up
    ns_exec "$ROUTER_NS" ip link set lan-a up
    ns_exec "$ROUTER_NS" ip link set lan-b up
    ns_exec "$ROUTER_NS" ip link set wan0 up
    ns_exec "$WAN_NS" ip link set eth0 up

    ns_exec "$CLIENT_A_NS" ip route add default via "$LAN_ROUTER_IP"
    ns_exec "$CLIENT_B_NS" ip route add default via "$LAN_ROUTER_IP"
    ns_exec "$WAN_NS" ip route add default via "$WAN_ROUTER_IP"

    ns_exec "$ROUTER_NS" sysctl -q -w net.ipv4.ip_forward=1
    configure_router_firewall

    echo "namespace topology is ready"
    show_status
}

show_status() {
    local namespace

    for namespace in "$CLIENT_A_NS" "$CLIENT_B_NS" "$ROUTER_NS" "$WAN_NS"; do
        if namespace_exists "$namespace"; then
            echo "== $namespace =="
            ip netns exec "$namespace" ip -br addr
        else
            echo "$namespace: absent"
        fi
    done
}

stop_wan_http_processes() {
    if ! namespace_exists "$WAN_NS"; then
        return 0
    fi

    ns_exec "$WAN_NS" pkill -TERM -f 'python3.*http.server 8080' 2>/dev/null || true
    sleep 0.1
    ns_exec "$WAN_NS" pkill -KILL -f 'python3.*http.server 8080' 2>/dev/null || true
}

stop_wan_udp_processes() {
    if ! namespace_exists "$WAN_NS"; then
        return 0
    fi

    ns_exec "$WAN_NS" pkill -TERM -f 'routescope-udp-server' 2>/dev/null || true
    sleep 0.1
    ns_exec "$WAN_NS" pkill -KILL -f 'routescope-udp-server' 2>/dev/null || true
}

stop_routescope_processes() {
    if ! namespace_exists "$ROUTER_NS"; then
        return 0
    fi

    ns_exec "$ROUTER_NS" pkill -TERM -f '/target/debug/routescope' 2>/dev/null || true
    sleep 0.1
    ns_exec "$ROUTER_NS" pkill -KILL -f '/target/debug/routescope' 2>/dev/null || true
}

reset_routescope_tc() {
    if ! namespace_exists "$ROUTER_NS"; then
        return 0
    fi

    ns_exec "$ROUTER_NS" tc qdisc del dev br-lan clsact 2>/dev/null || true
}

cleanup_http_server() {
    if [[ -n "$HTTP_SERVER_PID" ]]; then
        kill "$HTTP_SERVER_PID" 2>/dev/null || true
        wait "$HTTP_SERVER_PID" 2>/dev/null || true
        HTTP_SERVER_PID=""
    fi

    if [[ -n "$UDP_SERVER_PID" ]]; then
        kill "$UDP_SERVER_PID" 2>/dev/null || true
        wait "$UDP_SERVER_PID" 2>/dev/null || true
        UDP_SERVER_PID=""
    fi

    stop_wan_http_processes
    stop_wan_udp_processes

    if [[ -n "$HTTP_SERVER_LOG" ]]; then
        rm -f "$HTTP_SERVER_LOG"
        HTTP_SERVER_LOG=""
    fi

    if [[ -n "$UDP_SERVER_LOG" ]]; then
        rm -f "$UDP_SERVER_LOG"
        UDP_SERVER_LOG=""
    fi
}

cleanup_routescope() {
    if [[ -n "$ROUTESCOPE_PID" ]]; then
        kill "$ROUTESCOPE_PID" 2>/dev/null || true
        wait "$ROUTESCOPE_PID" 2>/dev/null || true
        ROUTESCOPE_PID=""
    fi

    stop_routescope_processes
    reset_routescope_tc

    if [[ -n "$ROUTESCOPE_LOG" ]]; then
        rm -f "$ROUTESCOPE_LOG"
        ROUTESCOPE_LOG=""
    fi

    if [[ -n "$ROUTESCOPE_DB" ]]; then
        rm -f "$ROUTESCOPE_DB"
        ROUTESCOPE_DB=""
    fi
}

start_routescope_collector() {
    if [[ ! -x "$ROOT/target/debug/routescope" ]]; then
        echo "error: build RouteScope first with 'cargo build'" >&2
        return 1
    fi

    stop_routescope_processes
    reset_routescope_tc

    ROUTESCOPE_LOG="${TMPDIR:-/tmp}/routescope-collector.$$.log"
    ROUTESCOPE_DB="${TMPDIR:-/tmp}/routescope-collector.$$.db"
    : >"$ROUTESCOPE_LOG"
    rm -f "$ROUTESCOPE_DB"

    ns_exec "$ROUTER_NS" env \
        ROUTESCOPE_LISTEN_ADDR=127.0.0.1:8080 \
        ROUTESCOPE_DATABASE_PATH="$ROUTESCOPE_DB" \
        ROUTESCOPE_DEV_BYPASS_AUTH=1 \
        ROUTESCOPE_ENABLE_SIMULATOR=0 \
        ROUTESCOPE_ENABLE_TC_EBPF=1 \
        ROUTESCOPE_ENABLE_CONNTRACK=1 \
        ROUTESCOPE_LAN_INTERFACE=br-lan \
        ROUTESCOPE_WAN_INTERFACE=wan0 \
        ROUTESCOPE_COLLECT_INTERVAL_SECS=1 \
        ROUTESCOPE_CONNTRACK_REFRESH_INTERVAL_SECS=1 \
        "$ROOT/target/debug/routescope" \
        >"$ROUTESCOPE_LOG" 2>&1 &
    ROUTESCOPE_PID=$!

    for _ in {1..50}; do
        if ns_exec "$ROUTER_NS" curl \
            --fail --silent --max-time 1 \
            "http://127.0.0.1:8080/healthz" >/dev/null \
            && ns_exec "$ROUTER_NS" curl \
                --fail --silent --max-time 1 \
                "http://127.0.0.1:8080/readyz" >/dev/null; then
            return 0
        fi

        if ! kill -0 "$ROUTESCOPE_PID" 2>/dev/null; then
            echo "error: RouteScope exited before becoming ready. Log:" >&2
            cat "$ROUTESCOPE_LOG" >&2
            return 1
        fi
        sleep 0.1
    done

    echo "error: RouteScope did not become ready. Log:" >&2
    cat "$ROUTESCOPE_LOG" >&2
    return 1
}

assert_collector_devices() {
    local devices_json=$1

    printf '%s\n' "$devices_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
macs = {device["mac_address"] for device in data}
expected = {"02:00:00:00:00:0a", "02:00:00:00:00:0b"}
missing = expected - macs
if missing:
    raise SystemExit(f"missing devices: {sorted(missing)}; got {sorted(macs)}")
print("ok: collector observed both namespace clients")
'
}

assert_collector_flow() {
    local mac_address=$1
    local protocol=$2
    local destination_port=$3
    local flows_json=$4

    python3 -c '
import json
import sys

mac, protocol, destination_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = json.load(sys.stdin)
matches = [
    flow for flow in data
    if flow["client_mac"] == mac
    and flow["protocol"] == protocol
    and flow["destination_port"] == destination_port
]
if len(matches) != 1:
    raise SystemExit(
        f"expected one {protocol}:{destination_port} flow for {mac}, "
        f"got {len(matches)}: {data}"
    )

flow = matches[0]
if flow["direction"] != "bidirectional":
    raise SystemExit(f"flow is not bidirectional: {flow}")
if flow["packet_count"] <= 0 or flow["upload_bytes"] <= 0 or flow["download_bytes"] <= 0:
    raise SystemExit(f"flow does not contain both directions: {flow}")
if flow["nat_source_ip"] != "10.0.2.1" or not flow["nat_source_port"]:
    raise SystemExit(f"missing or invalid SNAT mapping: {flow}")
if flow["nat_destination_ip"] != "10.0.2.2":
    raise SystemExit(f"unexpected translated destination: {flow}")
if flow["nat_destination_port"] != destination_port:
    raise SystemExit(f"unexpected translated destination port: {flow}")
if flow["connection_state"] == "unknown":
    raise SystemExit(f"conntrack state was not associated: {flow}")
print(f"ok: bidirectional {protocol}:{destination_port} flow with NAT for {mac}")
' "$mac_address" "$protocol" "$destination_port" <<<"$flows_json"
}

test_collector_api() {
    local devices_json=""
    local laptop_flows=""
    local phone_flows=""

    for _ in {1..30}; do
        devices_json=$(ns_exec "$ROUTER_NS" curl \
            --fail --silent --max-time 1 \
            "http://127.0.0.1:8080/api/v1/devices") || true
        if [[ -n "$devices_json" ]] && assert_collector_devices "$devices_json" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done

    if [[ -z "$devices_json" ]] || ! assert_collector_devices "$devices_json"; then
        echo "error: collector did not observe namespace devices. Log:" >&2
        cat "$ROUTESCOPE_LOG" >&2
        return 1
    fi

    for _ in {1..30}; do
        laptop_flows=$(ns_exec "$ROUTER_NS" curl \
            --fail --silent --max-time 1 \
            "http://127.0.0.1:8080/api/v1/devices/${CLIENT_A_MAC}/flows") || true
        phone_flows=$(ns_exec "$ROUTER_NS" curl \
            --fail --silent --max-time 1 \
            "http://127.0.0.1:8080/api/v1/devices/${CLIENT_B_MAC}/flows") || true

        if [[ -n "$laptop_flows" ]] \
            && [[ -n "$phone_flows" ]] \
            && assert_collector_flow "$CLIENT_A_MAC" tcp 8080 "$laptop_flows" >/dev/null 2>&1 \
            && assert_collector_flow "$CLIENT_B_MAC" tcp 8080 "$phone_flows" >/dev/null 2>&1 \
            && assert_collector_flow "$CLIENT_A_MAC" udp "$UDP_SERVER_PORT" "$laptop_flows" >/dev/null 2>&1 \
            && assert_collector_flow "$CLIENT_B_MAC" udp "$UDP_SERVER_PORT" "$phone_flows" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done

    assert_collector_flow "$CLIENT_A_MAC" tcp 8080 "$laptop_flows"
    assert_collector_flow "$CLIENT_B_MAC" tcp 8080 "$phone_flows"
    assert_collector_flow "$CLIENT_A_MAC" udp "$UDP_SERVER_PORT" "$laptop_flows"
    assert_collector_flow "$CLIENT_B_MAC" udp "$UDP_SERVER_PORT" "$phone_flows"
}

test_client_http() {
    local namespace=$1
    local client_name=$2
    local ready=0
    local nat_seen=0
    local log_lines_before
    local attempt

    log_lines_before=$(awk 'END { print NR }' "$HTTP_SERVER_LOG")

    for attempt in {1..20}; do
        if ns_exec "$namespace" curl \
            --fail --silent --max-time 2 \
            "http://${WAN_SERVER_IP}:8080/" >/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done

    if [[ "$ready" -ne 1 ]]; then
        echo "error: $client_name could not reach the WAN HTTP service" >&2
        return 1
    fi

    for attempt in {1..20}; do
        if awk -v start="$log_lines_before" \
            'NR > start && $0 ~ /10[.]0[.]2[.]1/ { found = 1 } END { exit !found }' \
            "$HTTP_SERVER_LOG"; then
            nat_seen=1
            break
        fi
        sleep 0.1
    done

    if [[ "$nat_seen" -ne 1 ]]; then
        echo "error: WAN service did not observe the router WAN address for $client_name" >&2
        echo "== WAN HTTP server log ==" >&2
        cat "$HTTP_SERVER_LOG" >&2 || true
        echo "== router nftables ruleset ==" >&2
        ns_exec "$ROUTER_NS" nft list ruleset >&2 || true
        return 1
    fi

    echo "ok: $client_name reached WAN through NAT"
}

start_wan_udp_server() {
    UDP_SERVER_LOG="${TMPDIR:-/tmp}/routescope-wan-udp.$$.log"
    : >"$UDP_SERVER_LOG"

    ns_exec "$WAN_NS" python3 -u -c '
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("10.0.2.2", 9090))
print("routescope-udp-server-ready", flush=True)
while True:
    payload, address = server.recvfrom(65535)
    server.sendto(b"routescope-udp-response:" + payload, address)
' >"$UDP_SERVER_LOG" 2>&1 &
    UDP_SERVER_PID=$!

    for _ in {1..20}; do
        if awk '/routescope-udp-server-ready/ { found = 1 } END { exit !found }' \
            "$UDP_SERVER_LOG"; then
            return 0
        fi
        if ! kill -0 "$UDP_SERVER_PID" 2>/dev/null; then
            echo "error: UDP server exited before becoming ready. Log:" >&2
            cat "$UDP_SERVER_LOG" >&2
            return 1
        fi
        sleep 0.1
    done

    echo "error: UDP server did not become ready. Log:" >&2
    cat "$UDP_SERVER_LOG" >&2
    return 1
}

test_client_udp() {
    local namespace=$1
    local client_name=$2

    ns_exec "$namespace" python3 - "$WAN_SERVER_IP" "$UDP_SERVER_PORT" <<'PY'
import socket
import sys

server_ip = sys.argv[1]
server_port = int(sys.argv[2])
payload = b"routescope-udp-request"

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(2)
client.sendto(payload, (server_ip, server_port))
response, _ = client.recvfrom(65535)
if response != b"routescope-udp-response:" + payload:
    raise SystemExit(f"unexpected UDP response: {response!r}")
PY

    echo "ok: $client_name exchanged UDP traffic through NAT"
}

test_topology() {
    require_root
    require_commands ip curl python3 awk pkill

    for namespace in "$CLIENT_A_NS" "$CLIENT_B_NS" "$ROUTER_NS" "$WAN_NS"; do
        if ! namespace_exists "$namespace"; then
            echo "error: namespace topology is not ready; run '$0 up' first" >&2
            exit 1
        fi
    done

    stop_wan_http_processes

    HTTP_SERVER_LOG="${TMPDIR:-/tmp}/routescope-wan-http.$$.log"
    : >"$HTTP_SERVER_LOG"
    trap cleanup_http_server EXIT

    ns_exec "$WAN_NS" python3 -u -m http.server 8080 --bind "$WAN_SERVER_IP" \
        >"$HTTP_SERVER_LOG" 2>&1 &
    HTTP_SERVER_PID=$!

    test_client_http "$CLIENT_A_NS" "client-a"
    test_client_http "$CLIENT_B_NS" "client-b"

    echo "namespace smoke test passed"
}

test_collector() {
    require_root
    require_commands ip curl python3 awk pkill tc

    for namespace in "$CLIENT_A_NS" "$CLIENT_B_NS" "$ROUTER_NS" "$WAN_NS"; do
        if ! namespace_exists "$namespace"; then
            echo "error: namespace topology is not ready; run '$0 up' first" >&2
            exit 1
        fi
    done

    stop_wan_http_processes
    trap 'cleanup_routescope; cleanup_http_server' EXIT
    start_routescope_collector

    HTTP_SERVER_LOG="${TMPDIR:-/tmp}/routescope-wan-http.$$.log"
    : >"$HTTP_SERVER_LOG"
    ns_exec "$WAN_NS" python3 -u -m http.server 8080 --bind "$WAN_SERVER_IP" \
        >"$HTTP_SERVER_LOG" 2>&1 &
    HTTP_SERVER_PID=$!

    start_wan_udp_server

    test_client_http "$CLIENT_A_NS" "client-a" &
    local client_a_http_pid=$!
    test_client_http "$CLIENT_B_NS" "client-b" &
    local client_b_http_pid=$!
    wait "$client_a_http_pid"
    wait "$client_b_http_pid"

    test_client_udp "$CLIENT_A_NS" "client-a"
    test_client_udp "$CLIENT_B_NS" "client-b"
    test_collector_api

    echo "namespace TC eBPF collector test passed"
}

main() {
    local action=${1:-}

    case "$action" in
        up)
            setup_topology
            ;;
        down)
            require_root
            require_commands ip
            delete_namespaces
            echo "namespace topology removed"
            ;;
        status)
            require_root
            require_commands ip
            show_status
            ;;
        test)
            test_topology
            ;;
        collector-test)
            test_collector
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"
