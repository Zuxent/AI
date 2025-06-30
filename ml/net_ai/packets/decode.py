## Program calls
from utilities.logging import *
from config.config import *
from packets.decode import *
## Lib calls
import time
import signal
import os
import json
import threading
import socket
import datetime
import subprocess
import csv
from collections import Counter
import numpy as np
import os
import subprocess
import pandas as pd
import numpy as np
import concurrent.futures
from collections import Counter
import shutil, math
import tempfile
import binascii
import sys, struct
from concurrent.futures import ThreadPoolExecutor
dir = os.getcwd()
from scapy.all import rdpcap
from collections import defaultdict, Counter
import shutil

# Get terminal size
size = shutil.get_terminal_size()
width = size.columns



csv.field_size_limit(sys.maxsize)
attack_types = {
    "[UDP]": "17\t\t",
    "[ICMP]": "1\t\t",
    "[ICMP Dest Unreachable]": "1,17\t\t",
    "[ICMP Dest Time To Live Expired]": "1,1\t\t",
    "[IPv4/Fragmented]": "4\t\t",
    "[GRE]": "47\t\t",
    "[IPX]": "111\t\t",
    "[AH]": "51\t\t",
    "[ESP]": "50\t\t",
    "[OpenVPN Reflection]": "17\t\t1194",
    "[VSE Flood/1]": "17\t\t27015",
    "[RRSIG DNS Query Reflection]": "002e0001",
    "[ANY DNS Query Reflection]": "00ff0001",
    "[NTP Reflection]": "17\t\t123",
    "[Chargen Reflection]": "17\t\t19",
    "[MDNS Reflection]": "17\t\t5353",
    "[BitTorrent Reflection]": "17\t\t6881",
    "[CLDAP Reflection]": "17\t\t389",
    "[STUN Reflection]": "17\t\t3478",
    "[MSSQL Reflection]": "17\t\t1434",
    "[SNMP Reflection]": "17\t\t161",
    "[WSD Reflection]": "17\t\t3702",
    "[DTLS Reflection]": "17\t\t443\t\t40",
    "[OpenAFS Reflection]": "17\t\t7001",
    "[ARD Reflection]": "17\t\t3283",
    "[BFD Reflection]": "17\t\t3784",
    "[SSDP Reflection]": "17\t\t1900",
    "[ArmA Reflection/1]": "17\t\t2302",
    "[ArmA Reflection/2]": "17\t\t2303",
    "[vxWorks Reflection]": "17\t\t17185",
    "[Plex Reflection]": "17\t\t32414",
    "[TeamSpeak Reflection]": "17\t\t9987",
    "[Lantronix Reflection]": "17\t\t30718",
    "[DVR IP Reflection]": "17\t\t37810",
    "[Jenkins Reflection]": "17\t\t33848",
    "[Citrix Reflection]": "17\t\t1604",
    "[NAT-PMP Reflection]": "008000",
    "[Memcache Reflection]": "17\t\t11211",
    "[NetBIOS Reflection]": "17\t\t137",
    "[SIP Reflection]": "17\t\t5060",
    "[Digiman Reflection]": "17\t\t2362",
    "[Crestron Reflection]": "17\t\t41794",
    "[CoAP Reflection]": "17\t\t5683",
    "[BACnet Reflection]": "17\t\t47808",
    "[FiveM Reflection]": "17\t\t30120",
    "[Modbus Reflection]": "17\t\t502",
    "[QOTD Reflection]": "17\t\t17",
    "[ISAKMP Reflection]": "17\t\t500",
    "[XDMCP Reflection]": "17\t\t177",
    "[IPMI Reflection]": "17\t\t623",
    "[Apple serialnumberd Reflection]": "17\t\t626",
    "[UDPMIX DNS Flood]": "7065616365636f7270",
    "[Hex UDP Flood]": " ",
    "[Flood of 0x00]": "0000000000000000000",
    "[TSource Engine Query]": "54536f75726365",
    "[Known Botnet UDP Flood/1]": "52794d47616e67",
    "[Known Botnet UDP Flood/2]": "a6c300",
    "[OVH-RAPE/1]": "fefefefe",
    "[OVH-RAPE/2]": "4a4a4a4a",
    "[TeamSpeak Status Flood]": "545333494e49",
    "[Flood of 0xFF]": "fffffffffff",
    "[UDP getstatus Flood]": "676574737461747573",
    "[Speed Test]": "0x00000010\t\t8080",
    "[TCP Reflection from HTTPS/1]": "0x00000012\t\t443",
    "[TCP Reflection from HTTPS/2]": "0x00000010\t\t443",
    "[TCP Reflection from HTTP/1]": "0x00000012\t\t80",
    "[TCP Reflection from HTTP/2]": "0x00000010\t\t80",
    "[TCP Reflection from BGP/1]": "0x00000012\t\t179",
    "[TCP Reflection from BGP/2]": "0x00000010\t\t179",
    "[TCP Reflection from SMTP/1]": "0x00000012\t\t465",
    "[TCP Reflection from SMTP/2]": "0x00000010\t\t465",
    "[TCP SYN-ACK]": "0x00000012",
    "[TCP PSH-ACK]": "0x00000018",
    "[TCP RST-ACK]": "0x00000014",
    "[TCP FIN]": "0x00000001",
    "[TCP SYN]": "0x00000002",
    "[TCP PSH]": "0x00000008",
    "[TCP URG]": "0x00000020",
    "[TCP RST]": "0x00000004",
    "[TCP ACK]": "0x00000010",
    "[Unset TCP Flags]": "0x00000000",
    "[TCP SYN-ECN-CWR]": "0x000000c2",
    "[TCP SYN-ECN]": "0x00000042",
    "[TCP SYN-CWR]": "0x00000082",
    "[TCP SYN-PSH-ACK-URG]": "0x0000003a",
    "[TCP SYN-ACK-ECN-CWR]": "0x000000d2",
    "[TCP PSH-ACK-URG]": "0x00000038",
    "[TCP FIN-SYN-RST-PSH-ACK-URG]": "0x0000003f",
    "[TCP RST-ACK-URG-CWR-Reserved]": "0x000004b4",
    "[TCP SYN-PSH-URG-ECN-CWR-Reserved]": "0x000004ea",
    "[TCP FIN-RST-PSH-ECN-CWR-Reserved]": "0x00000ccd",
    "[TCP FIN-RST-PSH-ACK-URG-ECN-CWR-Reserved]": "0x00000cfd"
  }
class SimpleRawPCAP:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.protocol_counts = Counter()
        self.udp_sport_counts = Counter()
        self.tcp_sport_counts = Counter()
        self.src_ip_counts = Counter()

        self.anomalies = 0
        self.total_packets = 0
        self.start_time = None
        self.end_time = None

        self.time_windows = defaultdict(lambda: defaultdict(int))  # For time-based analysis
        self.src_ip_list = []  # For entropy analysis

        ## Initialize entropy and time window variables
        self.entropy = None
        self.entropy2 = None
        self.time_window = 0  # For time-based analysis
        self.time_window_size = 60  # Time window size in seconds
        self.time_window_threshold = 100  # Threshold for time window spikes

        self.packet_lengths = []
        self.inter_arrival_times = []
        self.last_timestamp = None
        self.ttl_values = Counter()

        self.flow_stats = defaultdict(lambda: {'count': 0, 'total_bytes': 0})
        self.window_packet_counts = defaultdict(int)
        self.window_unique_src_ips = defaultdict(set)

        self.tcp_flags = Counter()



        # UDP
        self.udp_packets = defaultdict(list)  # Store UDP packets by source port
        self.udp_payloads_by_length = defaultdict(list)  # Store UDP payloads by length
        self.udp_payloads_entropy = defaultdict(Counter)
        


        ## DDos
        self.suspected_ips_count = None

        self.ip_profile = defaultdict(lambda: {
            'macs': set(),
            'ttls': [],
        })


        ## Ip spoofing results (mac, ip, port, total packets, total bytes, entropy,)


    def calculate_entropy(self, counter_dict):
        total = sum(counter_dict.values())
        if total == 0:
            return 0.0
        return -sum((count / total) * math.log2(count / total) for count in counter_dict.values())

    def parse(self):
        with open(self.pcap_file, 'rb') as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                raise ValueError("Incomplete global header")
            magic = struct.unpack('I', global_header[:4])[0]
            if magic not in [0xa1b2c3d4, 0xd4c3b2a1]:
                raise ValueError("Invalid PCAP file")
    
            while True:
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', pkt_header)
    
                timestamp = ts_sec + ts_usec / 1_000_000
                if self.start_time is None:
                    self.start_time = timestamp
                self.end_time = timestamp
    
                if self.last_timestamp is not None:
                    self.inter_arrival_times.append(timestamp - self.last_timestamp)
                self.last_timestamp = timestamp
    
                pkt_results = f.read(incl_len)
                if len(pkt_results) < 34:
                    continue
                
                # === Layer 2: Ethernet Header ===
                dest_mac = ':'.join(f"{b:02x}" for b in pkt_results[0:6])
                source_mac = ':'.join(f"{b:02x}" for b in pkt_results[6:12])
                eth_type = struct.unpack('!H', pkt_results[12:14])[0]
    
                if eth_type != 0x0800:
                    continue  # Only IPv4
                
                self.src_ip_counts[source_mac] += 1
                self.src_ip_counts[dest_mac] += 1
    
                # === Layer 3: IPv4 Header ===
                version_ihl = pkt_results[14]
                version = (version_ihl >> 4) & 0x0F
                ihl = version_ihl & 0x0F
                ip_header_len = ihl * 4
                if version != 4:
                    continue
                
                tos = pkt_results[15]
                total_length = struct.unpack('!H', pkt_results[16:18])[0]
                identification = struct.unpack('!H', pkt_results[18:20])[0]
                flags_fragment = struct.unpack('!H', pkt_results[20:22])[0]
                flags = (flags_fragment >> 13) & 0x07
                fragment_offset = flags_fragment & 0x1FFF
                ttl = pkt_results[22]
                proto = pkt_results[23]
                header_checksum = struct.unpack('!H', pkt_results[24:26])[0]
                src_ip = '.'.join(map(str, pkt_results[26:30]))
                dest_ip = '.'.join(map(str, pkt_results[30:34]))
    
                ip_header = pkt_results[14:14 + ip_header_len]
    
                self.protocol_counts[str(proto)] += 1
                self.src_ip_counts[src_ip] += 1
                self.total_packets += 1
                self.packet_lengths.append(incl_len)
                self.ttl_values[ttl] += 1
    
                if total_length > 1500 or total_length < 60:
                    self.anomalies += 1
    
                window = int(timestamp)
                self.time_windows[window][src_ip] += 1
                self.window_packet_counts[window] += 1
                self.window_unique_src_ips[window].add(src_ip)
                self.src_ip_list.append(src_ip)
    

                # Log IP and MAC addresses
                #logp(f"Packet {self.total_packets}: {src_ip} ({source_mac}) -> {dest_ip} ({dest_mac})")
                # Get source IP, MAC, and TTL
                src_ip = '.'.join(map(str, pkt_results[26:30]))
                src_mac = ':'.join(f"{b:02x}" for b in pkt_results[6:12])
                ttl = pkt_results[22]

                # Update tracking
                profile = self.ip_profile[src_ip]
                profile['macs'].add(src_mac)
                profile['ttls'].append(ttl)



                # === Layer 4: TCP ===
                if proto == 6 and len(pkt_results) >= 14 + ip_header_len + 20:
                    tcp_start = 14 + ip_header_len
                    if len(pkt_results) < tcp_start + 20:
                        continue
                    
                    src_port = struct.unpack('!H', pkt_results[tcp_start:tcp_start + 2])[0]
                    dst_port = struct.unpack('!H', pkt_results[tcp_start + 2:tcp_start + 4])[0]
                    tcp_seq_num = struct.unpack('!I', pkt_results[tcp_start + 4:tcp_start + 8])[0]
                    tcp_ack_num = struct.unpack('!I', pkt_results[tcp_start + 8:tcp_start + 12])[0]
                    tcp_data_offset = (pkt_results[tcp_start + 12] >> 4) & 0x0F
                    tcp_header_len = tcp_data_offset * 4
                    flags_byte = pkt_results[tcp_start + 13]
                    tcp_window = struct.unpack('!H', pkt_results[tcp_start + 14:tcp_start + 16])[0]
    
                    tcp_payload_len = total_length - ip_header_len - tcp_header_len
    
                    self.tcp_sport_counts[str(src_port)] += 1
                    self.tcp_flags[flags_byte] += 1
    
                    flow_key = f"{src_ip}:{src_port}"
                    self.flow_stats[flow_key]['count'] += 1
                    self.flow_stats[flow_key]['total_bytes'] += incl_len
    
                    tcp_header = {
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'seq_num': tcp_seq_num,
                        'ack_num': tcp_ack_num,
                        'header_len': tcp_header_len,
                        'flags': {
                            'URG': bool(flags_byte & 0x20),
                            'ACK': bool(flags_byte & 0x10),
                            'PSH': bool(flags_byte & 0x08),
                            'RST': bool(flags_byte & 0x04),
                            'SYN': bool(flags_byte & 0x02),
                            'FIN': bool(flags_byte & 0x01),
                            'ECN': bool(flags_byte & 0x40),
                            'CWR': bool(flags_byte & 0x80)
                        },
                        'window': tcp_window,
                        'payload_len': tcp_payload_len
                    }
    
                    logp(f"TCP Packet {self.total_packets}: {src_ip}:{src_port} -> {dest_ip}:{dst_port}, Flags: {tcp_header['flags']}")
    
                # === Layer 4: UDP ===
                elif proto == 17 and len(pkt_results) >= 14 + ip_header_len + 8:
                    udp_start = 14 + ip_header_len
                    src_port = struct.unpack('!H', pkt_results[udp_start:udp_start + 2])[0]
                    dst_port = struct.unpack('!H', pkt_results[udp_start + 2:udp_start + 4])[0]
                    udp_len = struct.unpack('!H', pkt_results[udp_start + 4:udp_start + 6])[0]
    
                    udp_payload_len = total_length - ip_header_len - 8
                    udp_payload_offset = udp_start + 8
                    udp_payload = pkt_results[udp_payload_offset : udp_payload_offset + udp_payload_len]
    
                    self.udp_sport_counts[str(src_port)] += 1
                    self.udp_payloads_by_length[udp_payload_len].append(udp_payload)
    
                    flow_key = f"{src_ip}:{src_port}"
                    self.flow_stats[flow_key]['count'] += 1
                    self.flow_stats[flow_key]['total_bytes'] += incl_len
    
            self.entropy2 = {
                'src_ip_entropy': self.calculate_entropy(self.src_ip_counts),
                'src_port_entropy_udp': self.calculate_entropy(self.udp_sport_counts),
                'src_port_entropy_tcp': self.calculate_entropy(self.tcp_sport_counts),
                'ttl_entropy': self.calculate_entropy(self.ttl_values)
            }

    def post_analysis(self, window_threshold=100, entropy_threshold=7.0):
        suspected_ips = set()

        # Time-based detection
        print("=== Time Window Spike Detection ===")
        for window, ip_counts in self.time_windows.items():
            packet_count = self.window_packet_counts[window]
            unique_ips = self.window_unique_src_ips[window]

            if packet_count > window_threshold:
                print(f"[!] High traffic in window {datetime.datetime.fromtimestamp(window)}: {packet_count} packets")
                for ip in unique_ips:
                    suspected_ips.add(ip)
                    print(f"    - IP {ip} contributed with {ip_counts[ip]} packets")

        # Entropy-based detection
        print("\n=== Entropy Analysis ===")
        for key, value in self.entropy2.items():
            print(f"{key}: {value:.3f}")
            if value < entropy_threshold:
                print(f"  [!] Low entropy detected for {key} (possible spoofing or concentration)")
        
        # Summarize flow stats for suspected IPs
        print("\n=== Suspected IP Flow Stats ===")
        for ip in suspected_ips:
            print(f"\n>> {ip}")
            for flow_key, stats in self.flow_stats.items():
                if flow_key.startswith(ip + ":"):
                    print(f"  Flow {flow_key} - Packets: {stats['count']}, Bytes: {stats['total_bytes']}")

        print(f"\nTotal suspected IPs: {len(suspected_ips)}")
        self.suspected_ips_count = len(suspected_ips)
        return suspected_ips



    from collections import Counter

    def analyze_udp_payload_patterns(self, dominance_threshold=1, min_payloads=10):
        results = []

        for length, payloads in self.udp_payloads_by_length.items():
            if len(payloads) < min_payloads:
                continue  # Not enough samples to be meaningful

            position_counts = [Counter() for _ in range(length)]
            for payload in payloads:
                for i, byte in enumerate(payload):
                    position_counts[i][byte] += 1

            pattern = {
                "length": length,
                "sample_count": len(payloads),
                "dominant_bytes": []
            }

            for i, counter in enumerate(position_counts):
                total = sum(counter.values())
                if not total:
                    continue
                most_common_byte, count = counter.most_common(1)[0]
                dominance = count / total
                if dominance >= dominance_threshold:
                    pattern["dominant_bytes"].append({
                        "position": i,
                        "byte": f"0x{most_common_byte:02X}",
                    })

            if pattern["dominant_bytes"]:
                results.append(pattern)

        return results




    def protocol(self):
        if not self.protocol_counts:
            return "Unknown"
        proto = self.protocol_counts.most_common(1)[0][0]
        return {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(proto, "Unknown")

    def common_sport(self):
        result = {}
        if self.udp_sport_counts:
            result['udp.srcport'] = self.udp_sport_counts.most_common(1)[0][0]
        if self.tcp_sport_counts:
            result['tcp.srcport'] = self.tcp_sport_counts.most_common(1)[0][0]
        return result or "No common ports found"

    def top_src_ips(self, n=5):
        return self.src_ip_counts.most_common(n)

    def anomaly_score(self):
        if self.total_packets == 0:
            return 0.0
        return round(self.anomalies / self.total_packets, 3)
    
    def total_ip(self):
      return len(self.src_ip_counts)
    
    def avg_packets_per_ip(self):
        if not self.src_ip_counts:
            return 0.0
        return round(self.total_packets / len(self.src_ip_counts), 2)
    

    def ips_above_avg_packets(self):
        if not self.src_ip_counts:
            return []

        avg = self.avg_packets_per_ip()
        return [ip for ip, count in self.src_ip_counts.items() if count > avg]

    def get_feature_vector(self):
        return {
            'total_packets': self.total_packets,
            'avg_packet_length': np.mean(self.packet_lengths) if self.packet_lengths else 0,
            'packet_length_variance': np.var(self.packet_lengths) if self.packet_lengths else 0,
            'avg_interarrival_time': np.mean(self.inter_arrival_times) if self.inter_arrival_times else 0,
            'src_ip_entropy': self.entropy2.get('src_ip_entropy', 0),
            'udp_port_entropy': self.entropy2.get('src_port_entropy_udp', 0),
            'tcp_port_entropy': self.entropy2.get('src_port_entropy_tcp', 0),
            'ttl_entropy': self.entropy2.get('ttl_entropy', 0),
            'top_src_ip': self.src_ip_counts.most_common(1)[0][0] if self.src_ip_counts else None,
            'tcp_syn_count': self.tcp_flags[0x02],
            'tcp_rst_count': self.tcp_flags[0x04],
            'anomalies': self.anomalies,
            'flows_over_100': sum(1 for f in self.flow_stats.values() if f['count'] > 100),
            'spike_windows': sum(1 for c in self.window_packet_counts.values() if c > self.time_window_threshold)
        }
    
    def analyze_all(self):
        #post_analysis = self.post_analysis(self.time_window_threshold, 7.0)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                "protocol": executor.submit(self.protocol),
                "common_sport": executor.submit(self.common_sport),
                "top_ips": executor.submit(self.top_src_ips),
                "anomaly_score": executor.submit(self.anomaly_score),
                "total_ip": executor.submit(self.total_ip),
                "avg_packets_per_ip": executor.submit(self.avg_packets_per_ip),
                "ips_above_avg_packets": executor.submit(self.ips_above_avg_packets),
                "analyze_udp_payload_patterns": executor.submit(self.analyze_udp_payload_patterns)

            }
            return {key: future.result() for key, future in futures.items()}
        
def tshark(pcap, pcap_path):
    width = shutil.get_terminal_size(fallback=(80, 20)).columns
    line = "-" * (width - 11)


    logp(line)
    logp("Starting tshark analysis...")
    start_time = time.time()
    analyzer = SimpleRawPCAP(pcap_path)
    analyzer.parse()  # Required to populate results before analysis
    user = "developer"
    results = analyzer.analyze_all()
    logp(results["protocol"])
    
    #log_to_discord(user ,results, analyzer.entropy)
    logp(results["common_sport"])
    protocol = results["protocol"]
    udp_srcport = results.get("common_sport", {}).get("udp.srcport", 0)
    tcp_srcport = results.get("common_sport", {}).get("tcp.srcport", 0)
    top_ips = results["top_ips"]
    # Extract just the IP addresses
    ip_list = [ip[0] for ip in top_ips]
    # Join into a comma-separated string
    comma_separated_ips = ", ".join(ip_list)
    anomaly_score = results["anomaly_score"]
    total_ip = results["total_ip"]
    avg_packets_per_ip = results["avg_packets_per_ip"]
    ips_above_avg = len(results["ips_above_avg_packets"])
    logp(f"udp_srcport: {udp_srcport}, tcp_srcport: {tcp_srcport}")
    logp(f"top_ips: {comma_separated_ips}")
    logp(f"anomaly_score: {anomaly_score}")
    logp(f"total_ip: {total_ip}")
    logp(f"avg_packets_per_ip: {avg_packets_per_ip}")
    logp(f"ips_above_avg: {ips_above_avg}")



    #analyzer.post_analysis()
    #print(f"{analyzer.entropy} entropy")
    total_time = round(time.time() - start_time, 3)
    logp(f"✅ Time to Analysis → {total_time}s")
    logp(line)
    return results
    