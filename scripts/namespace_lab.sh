#!/usr/bin/env bash
set -euo pipefail

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

HTTP_SERVER_PID=""
HTTP_SERVER_LOG=""

usage() {
    cat <<'EOF'
Usage:
  sudo scripts/namespace_lab.sh up
  sudo scripts/namespace_lab.sh down
  sudo scripts/namespace_lab.sh status
  sudo scripts/namespace_lab.sh test

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

cleanup_http_server() {
    if [[ -n "$HTTP_SERVER_PID" ]]; then
        kill "$HTTP_SERVER_PID" 2>/dev/null || true
        wait "$HTTP_SERVER_PID" 2>/dev/null || true
        HTTP_SERVER_PID=""
    fi

    if [[ -n "$HTTP_SERVER_LOG" ]]; then
        rm -f "$HTTP_SERVER_LOG"
        HTTP_SERVER_LOG=""
    fi
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
        return 1
    fi

    echo "ok: $client_name reached WAN through NAT"
}

test_topology() {
    require_root
    require_commands ip curl python3 awk

    for namespace in "$CLIENT_A_NS" "$CLIENT_B_NS" "$ROUTER_NS" "$WAN_NS"; do
        if ! namespace_exists "$namespace"; then
            echo "error: namespace topology is not ready; run '$0 up' first" >&2
            exit 1
        fi
    done

    HTTP_SERVER_LOG="${TMPDIR:-/tmp}/routescope-wan-http.$$.log"
    : >"$HTTP_SERVER_LOG"
    trap cleanup_http_server EXIT

    ns_exec "$WAN_NS" python3 -m http.server 8080 --bind "$WAN_SERVER_IP" \
        >"$HTTP_SERVER_LOG" 2>&1 &
    HTTP_SERVER_PID=$!

    test_client_http "$CLIENT_A_NS" "client-a"
    test_client_http "$CLIENT_B_NS" "client-b"

    echo "namespace smoke test passed"
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
        *)
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"
