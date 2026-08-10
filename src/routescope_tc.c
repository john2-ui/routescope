#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define BPF_ANY 0
#define BPF_MAP_TYPE_LRU_HASH 9

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(
    void *map,
    const void *key,
    const void *value,
    __u64 flags
) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_idx;
    __u32 numa_node;
};

struct flow_key {
    __u8 client_mac[6];
    __u8 protocol;
    __u8 padding;
    __u32 client_ip;
    __u32 destination_ip;
    __u16 client_port;
    __u16 destination_port;
};

struct flow_value {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 upload_bytes;
    __u64 download_bytes;
    __u64 packet_count;
};

struct bpf_map_def SEC("maps") flow_stats = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_value),
    .max_entries = 16384,
};

static __inline __attribute__((always_inline))
int parse_transport_ports(
    void *data,
    void *data_end,
    __u8 protocol,
    __u16 *source_port,
    __u16 *destination_port
) {
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data;
        if ((void *)(tcp + 1) > data_end) {
            return -1;
        }
        *source_port = tcp->source;
        *destination_port = tcp->dest;
        return 0;
    }

    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = data;
        if ((void *)(udp + 1) > data_end) {
            return -1;
        }
        *source_port = udp->source;
        *destination_port = udp->dest;
        return 0;
    }

    return -1;
}

static __inline __attribute__((always_inline))
int record_packet(struct __sk_buff *skb, __u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *ethernet = data;

    if ((void *)(ethernet + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (ethernet->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(ethernet + 1);
    if ((void *)(ip + 1) > data_end || ip->ihl != 5) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    __u16 source_port = 0;
    __u16 destination_port = 0;
    void *transport = (void *)(ip + 1);
    if (parse_transport_ports(
            transport,
            data_end,
            ip->protocol,
            &source_port,
            &destination_port
        ) < 0) {
        return TC_ACT_OK;
    }

    struct flow_key key = {};
    int i;

    #pragma unroll
    for (i = 0; i < 6; i++) {
        key.client_mac[i] = direction == 0
            ? ethernet->h_source[i]
            : ethernet->h_dest[i];
    }

    key.protocol = ip->protocol;

    if (direction == 0) {
        key.client_ip = ip->saddr;
        key.destination_ip = ip->daddr;
        key.client_port = source_port;
        key.destination_port = destination_port;
    } else {
        key.client_ip = ip->daddr;
        key.destination_ip = ip->saddr;
        key.client_port = destination_port;
        key.destination_port = source_port;
    }

    __u64 now_ns = bpf_ktime_get_ns();
    struct flow_value *value = bpf_map_lookup_elem(&flow_stats, &key);

    if (value == 0) {
        struct flow_value initial = {
            .first_seen_ns = now_ns,
            .last_seen_ns = now_ns,
            .packet_count = 1,
        };

        if (direction == 0) {
            initial.upload_bytes = skb->len;
        } else {
            initial.download_bytes = skb->len;
        }

        bpf_map_update_elem(&flow_stats, &key, &initial, BPF_ANY);
        return TC_ACT_OK;
    }

    value->last_seen_ns = now_ns;
    value->packet_count += 1;

    if (direction == 0) {
        value->upload_bytes += skb->len;
    } else {
        value->download_bytes += skb->len;
    }

    return TC_ACT_OK;
}

SEC("classifier/ingress")
int routescope_tc_ingress(struct __sk_buff *skb) {
    return record_packet(skb, 0);
}

SEC("classifier/egress")
int routescope_tc_egress(struct __sk_buff *skb) {
    return record_packet(skb, 1);
}

char _license[] SEC("license") = "GPL";
