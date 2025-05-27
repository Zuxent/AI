///////////////////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------------------//
//                                          Libraries                                            //
//-----------------------------------------------------------------------------------------------//
///////////////////////////////////////////////////////////////////////////////////////////////////
#include "bpf_helpers.h"
#include <linux/tcp.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>       // For ip_fast_csum
#include <linux/icmp.h>     // For checksum-related macros
#include <linux/tcp.h>      // For TCP header related functions
#include <linux/udp.h>      // For UDP header related functions
#include <stdbool.h>
///////////////////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------------------//
//                                        Define Values                                          //
//-----------------------------------------------------------------------------------------------//
///////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 3)
#endif
#define IP_TCP 6         // TCP protocol identifier
#define IP_UDP 17        // UDP protocol identifier
#define IP_ICMP 1        // ICMP protocol identifier
#define RATE_LIMIT_THRESHOLD 100  // Max packets allowed per time window
#define RATE_LIMIT_TIME_WINDOW 1000000000ULL  // 1 second (in nanoseconds)
// Define Syn Cookie settings
#define CONN_INIT 0
#define CONN_SYN_SENT 1
#define CONN_ESTABLISHED 2
#define CONN_FINISHED 3
#define COOKIE_EXPIRATION_TIME 10 * 1 // 1 minute expiration for SYN cookie
#define SYN_COOKIES_ENABLED 1 // Enable/Disable SYN Cookies
#define debug 1 // Enable/Disable Debug print
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------------------//
//                                       Define Structs                                          //
//-----------------------------------------------------------------------------------------------//
///////////////////////////////////////////////////////////////////////////////////////////////////
struct custom_ethhdr {
    __u8 h_dest[6];        // Destination MAC address
    __u8 h_source[6];      // Source MAC address
    __u16 h_proto;         // Protocol type (e.g., IPv4, IPv6)
} __attribute__((packed));

struct my_iphdr {
    __u8 ihl : 4;          // Internet Header Length
    __u8 version : 4;      // IP version (IPv4)
    __u8 tos;              // Type of Service
    __u16 tot_len;         // Total length of the IP packet
    __u16 id;              // Identification
    __u16 frag_off;        // Fragment offset
    __u8 ttl;              // Time to Live
    __u8 protocol;         // Protocol (e.g., TCP, UDP, ICMP)
    __u16 check;           // Header checksum
    __u32 saddr;           // Source IP address
    __u32 daddr;           // Destination IP address
} __attribute__((packed));

struct pseudohdr {
    __be32 saddr;   // Source address
    __be32 daddr;   // Destination address
    __u8 zero;      // Padding for alignment
    __u8 protocol;  // Protocol type (TCP, UDP, etc.)
    __be16 length;  // Length of the TCP/UDP data
};


#define MAX_HASHKEY_LENGTH 256  // Define a reasonable max length for the hash key
#define MAX_BYTE_OFFSETS 40      // Maximum number of byte offsets in a pattern
#define MAX_PATTERNS 18          // Maximum number of patterns

// Define a structure to hold pattern data
struct udp_pattern {
    __u16 length;                 // Expected UDP payload length
    __u8 byte_offsets[MAX_BYTE_OFFSETS]; // Offsets to check in the payload
    __u8 byte_values[MAX_BYTE_OFFSETS];  // Corresponding values to match at these offsets
    __u8 num_bytes;               // Number of bytes to check
    char description[32];         // Description for debugging/logging
};

// Define the map to store patterns
BPF_MAP_DEF(pattern_map) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),         // Key is the pattern index
    .value_size = sizeof(struct udp_pattern), // Value is the pattern structure
    .max_entries = MAX_PATTERNS,       // Maximum number of patterns
};
BPF_MAP_ADD(pattern_map);

struct syn_cookie {
    __u32 cookie_value;
    __u64 timestamp; // Timestamp when the SYN cookie was issued
};
BPF_MAP_DEF(syn_cookies_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),  // 5-tuple hash key
    .value_size = sizeof(struct syn_cookie),
    .max_entries = 10000000, // Limit number of stored SYN cookies
};
BPF_MAP_ADD(syn_cookies_map);




///////////////////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------------------//
//                                            Maps                                               //
//-----------------------------------------------------------------------------------------------//
///////////////////////////////////////////////////////////////////////////////////////////////////
BPF_MAP_DEF(protocols) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 255,
};
BPF_MAP_ADD(protocols);

BPF_MAP_DEF(totalPktStats) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 5,
};
BPF_MAP_ADD(totalPktStats);
















// Define the program array map correctly
BPF_MAP_DEF(prog_array_map) = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,  // Adjust the size according to your requirements
};
BPF_MAP_ADD(prog_array_map);

// Update packet statistics
__attribute__((always_inline)) void update_packet_stats(__u32 map_key) {
    __u64 *packet_counter = bpf_map_lookup_elem(&totalPktStats, &map_key);
    if (packet_counter) {
        (*packet_counter)++;
    }
}
// Rate limit information structure
struct rate_limit_info {
    __u64 last_received_timestamp;
    __u64 packet_count;
};
// Rate limit map for source IP addresses
BPF_MAP_DEF(rate_limit_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct rate_limit_info),
    .max_entries = 1024,
};
BPF_MAP_ADD(rate_limit_map);

// Check and update the rate limit for a given source IP
static __always_inline int check_rate_limit(__u32 src_ip) {
    __u64 now = bpf_ktime_get_ns();
    
    // Look up the rate limit data for this source IP
    struct rate_limit_info *info = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (!info) {
        // No data found, initialize with packet count 1
        struct rate_limit_info new_info = {
            .last_received_timestamp = now,
            .packet_count = 1
        };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_info, BPF_ANY);
        return XDP_PASS;
    }

    // If the packet count exceeds the threshold within the time window
    if (now - info->last_received_timestamp < RATE_LIMIT_TIME_WINDOW) {
        if (info->packet_count >= RATE_LIMIT_THRESHOLD) {
            return XDP_DROP;
        } else {
            info->packet_count++;
        }
    } else {
        // Time window exceeded, reset packet count and timestamp
        info->last_received_timestamp = now;
        info->packet_count = 1;
    }

    bpf_map_update_elem(&rate_limit_map, &src_ip, info, BPF_ANY);
    return XDP_PASS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------------------//
//                                      Helper Functions                                         //
//-----------------------------------------------------------------------------------------------//
///////////////////////////////////////////////////////////////////////////////////////////////////


// Generate a 5-tuple hash key for the connection
static __always_inline __u64 generate_5tuple_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    __u64 key = saddr;
    key = (key << 32) | daddr;
    key ^= (__u64)sport << 16;
    key ^= (__u64)dport;
    return key;
}


// Check if IP is the specific local IP to drop (7a08a8c0 = 122.8.168.192)
static __always_inline bool is_specific_local_ip(__u32 ip) {
    __u32 DROP_IP = 0xdd08a8c0; // 122.8.168.192 (in hex)
    return ip == DROP_IP;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------------------//
//                                       Packet handler                                          //
//-----------------------------------------------------------------------------------------------//
///////////////////////////////////////////////////////////////////////////////////////////////////
SEC("xdp")
int handler(struct xdp_md *ctx) {
    __u32 key_packets_dropped = 2;
    __u32 key_packets_passed = 1;
    __u32 syn_secret = 98056;
    __u64 current_time = bpf_ktime_get_ns();
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct custom_ethhdr *ether = data;
    if ((void *)ether + sizeof(*ether) > data_end) {
        update_packet_stats(key_packets_dropped);
        return XDP_ABORTED;
    }

    struct my_iphdr *ip = (void *)(ether + 1);
    if ((void *)ip + sizeof(*ip) > data_end) {
        update_packet_stats(key_packets_dropped);
        return XDP_ABORTED;
    }
    // Check rate limit for the source IP address
    if (check_rate_limit(ip->saddr) == XDP_DROP) {
        return XDP_DROP;  // Drop the packet if it exceeds the rate limit
    }
    // Protocol handling
    __u32 proto_index = ip->protocol;
    __u64 *counter = bpf_map_lookup_elem(&protocols, &proto_index);
    if (counter) {
        (*counter)++;
    }

    __u16 total_length = ntohs(ip->tot_len);
    __u8 ip_header_length = ip->ihl * 4;
    
    if (ether->h_proto == htons(ETH_P_IP)) {
        void *trans_proto_hdr = (void *)ip + ip->ihl * 4;
        if (trans_proto_hdr > data_end) {
            update_packet_stats(key_packets_dropped);
            return XDP_ABORTED;
        }

        // Handle TCP packets
        if (ip->protocol == IP_TCP) {
            struct tcphdr *tcp = trans_proto_hdr;
            if ((void *)tcp + sizeof(*tcp) > data_end) {
                update_packet_stats(key_packets_dropped);
                return XDP_ABORTED;
            }
            bpf_tail_call(ctx, &prog_array_map, 1);

        // Handle UDP packets
        } else if (ip->protocol == IP_UDP) {
            bpf_printk("UDP | packet from IP: %x", ip->saddr);
            struct udphdr *udp = (void *)ip + ip_header_length;
            if ((void *)udp + sizeof(*udp) > data_end) {
                update_packet_stats(key_packets_dropped);
                return XDP_ABORTED;
            }
            return XDP_PASS; // Allow UDP packets

        // Handle ICMP packets
        } else if (ip->protocol == IP_ICMP) {
            bpf_printk("icmp | packet from IP: %x", ip->saddr);
            struct icmphdr *icmp = trans_proto_hdr;
            if ((void *)icmp + sizeof(*icmp) > data_end) {
                update_packet_stats(key_packets_dropped);
                return XDP_ABORTED;
            }
        }
    }

    // If no specific action was taken, pass the packet
    update_packet_stats(key_packets_passed);
    return XDP_PASS;
}

SEC("xdp")
int syn_challenge(struct xdp_md *ctx) {
    __u32 key_packets_dropped = 2;
    __u32 key_packets_passed = 1;
    __u32 syn_secret = 98056;
    __u64 current_time = bpf_ktime_get_ns();
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct custom_ethhdr *ether = data;
    if ((void *)ether + sizeof(*ether) > data_end) {
        update_packet_stats(key_packets_dropped);
        return XDP_ABORTED;
    }

    struct my_iphdr *ip = (void *)(ether + 1);
    if ((void *)ip + sizeof(*ip) > data_end) {
        update_packet_stats(key_packets_dropped);
        return XDP_ABORTED;
    }

    // Check rate limit for the source IP address
    if (check_rate_limit(ip->saddr) == XDP_DROP) {
        return XDP_DROP;  // Drop the packet if it exceeds the rate limit
    }

    __u16 total_length = ntohs(ip->tot_len);
    __u8 ip_header_length = ip->ihl * 4;

    if (ether->h_proto == htons(ETH_P_IP)) {
        void *trans_proto_hdr = (void *)ip + ip_header_length;
        if (trans_proto_hdr > data_end) {
            update_packet_stats(key_packets_dropped);
            return XDP_ABORTED;
        }

        // Handle TCP packets
        if (ip->protocol == IP_TCP) {
            struct tcphdr *tcp = trans_proto_hdr;
            // Check if TCP header is within bounds
            if ((void *)tcp + sizeof(*tcp) > data_end) {
                update_packet_stats(key_packets_dropped);
                return XDP_ABORTED;
            }

            #define TARGET_IP 0xdd08a8c0  // 221.8.168.192
            // LOCAL MACHINE PASS THROUGH
            if (ip->saddr == TARGET_IP) {
                update_packet_stats(key_packets_passed);
                return XDP_PASS;
            }

            __u64 key_5tuple = generate_5tuple_hash(ip->saddr, ip->daddr, tcp->source, tcp->dest);

            if (SYN_COOKIES_ENABLED) {
                bpf_printk("Matched Source IP: %x", ip->saddr);
                if (tcp->syn && !tcp->ack) {
                    __u32 src_ip = ip->saddr;
                    __u32 dst_ip = ip->daddr;
                    __u16 src_port = tcp->source;
                    __u16 dst_port = tcp->dest;

                    __u64 timestamp = current_time / 1000000000ULL;
                    __u64 hash = (__u64)src_ip ^ dst_ip ^ src_port ^ dst_port ^ syn_secret ^ timestamp;
                    hash ^= (hash >> 32);
                    hash *= 0xc6a4a7935bd1e995ULL;
                    hash ^= (hash >> 32);
                    __u32 cookie = (__u32)hash;

                    struct syn_cookie syn_cookie_data = {
                        .cookie_value = cookie,
                        .timestamp = timestamp
                    };

                    bpf_map_update_elem(&syn_cookies_map, &key_5tuple, &syn_cookie_data, BPF_ANY);

                }

                // Handle incoming ACK packets (ACK flag set, SYN flag not set)
                if (tcp->ack) {
                    struct syn_cookie *stored_cookie = bpf_map_lookup_elem(&syn_cookies_map, &key_5tuple);
                    if (stored_cookie) {
                        __u32 src_ip = ip->saddr;  // Initialize src_ip here
                        __u32 dst_ip = ip->daddr;   // Initialize dst_ip here
                        __u16 src_port = tcp->source; // Initialize src_port here
                        __u16 dst_port = tcp->dest;   // Initialize dst_port here
                        // Check if the stored SYN cookie is still valid (not expired)
                        __u64 current_time = bpf_ktime_get_ns() / 1000000000ULL;
                        if (current_time - stored_cookie->timestamp < COOKIE_EXPIRATION_TIME) {
                            __u64 hash = (__u64)src_ip ^ dst_ip ^ src_port ^ dst_port ^ syn_secret ^ stored_cookie->timestamp;
                            hash ^= (hash >> 32);
                            hash *= 0xc6a4a7935bd1e995ULL;
                            hash ^= (hash >> 32);
                            __u32 expected_cookie = (__u32)hash;

                            // Validate the SYN cookie with the ACK sequence number
                            if (expected_cookie == tcp->ack_seq) {
                                bpf_printk("SYN cookie validated successfully, allowing connection.");
                                return XDP_PASS;  // Allow packet (valid ACK)
                            } else {
                                bpf_printk("SYN cookie validation failed.");
                            }
                        } else {
                            bpf_printk("SYN cookie expired.");
                        }
                    } else {
                        bpf_printk("No matching SYN cookie found.");
                    }

                    // Drop packets with invalid or expired SYN cookies
                    return XDP_DROP;
                }
            }
        } else {
            bpf_printk("Non-TCP packet hit challenge: %x", ip->saddr);
            bpf_tail_call(ctx, &prog_array_map, 0);
        }
    }

    // If no specific action was taken, pass the packet
    update_packet_stats(key_packets_passed);
    return XDP_PASS;
}



char _license[] SEC("license") = "GPL"; 
