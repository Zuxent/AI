#include "../ingress/bpf_helpers.h"
#include <linux/tcp.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <stdbool.h>
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
#define COOKIE_EXPIRATION_TIME 60 * 1 // 1 minute expiration for SYN cookie
#define SYN_COOKIES_ENABLED 0 // Enable/Disable SYN Cookies

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

//-------------------//
//        Maps       //
//-------------------//
// Map to store packet count and timestamp per IP address for rate limiting
BPF_MAP_DEF(rate_limit_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),    // Key is the source IP address
    .value_size = sizeof(struct rate_limit_info),
    .max_entries = 1024,          // Max number of IPs to track
};
BPF_MAP_ADD(rate_limit_map);

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

BPF_MAP_DEF(syn_cookies_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),  // 5-tuple hash key
    .value_size = sizeof(struct syn_cookie),
    .max_entries = 1024, // Limit number of stored SYN cookies
};
BPF_MAP_ADD(syn_cookies_map);

//-------------------//
//   Define Structs  //
//-------------------//
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

struct syn_cookie {
    __u32 cookie_value;
    __u64 timestamp; // Timestamp when the SYN cookie was issued
};

// Define a structure to hold rate limit data
struct rate_limit_info {
    __u64 packet_count;
    __u64 last_reset_time;
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