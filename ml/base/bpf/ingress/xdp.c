#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h> // For TC_ACT_OK and TC_ACT_SHOT

#define IP_UDP 17        // UDP protocol identifier

// Define a map for stats (shared between XDP and TC programs)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} stats_map SEC(".maps");

// Function to print protocol
static inline void print_protocol(__u8 protocol) {
    bpf_trace_printk("Protocol: %u\\n", protocol);
}

// XDP program
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check for IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Filter UDP packets
    if (ip->protocol == IP_UDP) {
        __u32 key = 0;
        __u64 init_val = 1;
        __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        } else {
            bpf_map_update_elem(&stats_map, &key, &init_val, BPF_ANY);
        }
    }
    bpf_printk("Incoming packet");
    return XDP_PASS;
}

// TC egress program
SEC("tc")
int tc_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Check for IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Filter UDP packets
    if (ip->protocol == IP_UDP) {
        __u32 key = 1;
        __u64 init_val = 1;
        __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        } else {
            bpf_map_update_elem(&stats_map, &key, &init_val, BPF_ANY);
        }
    }
    bpf_printk("Outgoing packet..");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
