#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>  // Contains IPPROTO_TCP definition

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct conn_value {
    __u8 state; // 0: NEW, 1: ESTABLISHED, 2: CLOSED
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
} conntrack_map SEC(".maps");

SEC("tc")
int tc_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    struct conn_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
        .protocol = ip->protocol,
    };

    struct conn_value *entry = bpf_map_lookup_elem(&conntrack_map, &key);

    if (!entry || entry->state == 2) {
        return TC_ACT_SHOT; // Drop invalid connections
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
