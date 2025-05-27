#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h> // For TC_ACT_OK and TC_ACT_SHOT

#define IP_UDP 17        // UDP protocol identifier

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

    bpf_printk("Outgoing packet..");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

