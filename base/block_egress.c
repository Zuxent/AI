#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

SEC("tc/egress")
int block_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

        // Block outgoing UDP packets to a specific port
        if (ip->protocol == IP_UDP) {
            struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4);
            if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

            if (ntohs(udp->dest) == 30120) { // Example port
                return TC_ACT_SHOT; // Drop the packet
            }
        }
    }

    return TC_ACT_OK; // Allow other packets
}

char _license[] SEC("license") = "GPL";
