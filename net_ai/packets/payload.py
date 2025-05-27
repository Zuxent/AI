
## Program calls
from utilities.logging import *
from config.config import *
from packets.decode import *


class payload:
    def __init__(self):
        self.tcp_payloads_by_length = {}
        self.udp_payloads_by_length = {}
        self.src_ip_counts = Counter()
        self.suspected_ips_count = 0
        self.entropy = 0

    def add_tcp_payload(self, length, payload):
        if length not in self.tcp_payloads_by_length:
            self.tcp_payloads_by_length[length] = []
        self.tcp_payloads_by_length[length].append(payload)

    def add_udp_payload(self, length, payload):
        if length not in self.udp_payloads_by_length:
            self.udp_payloads_by_length[length] = []
        self.udp_payloads_by_length[length].append(payload)

    def analyze_tcp_payload_patterns(self, dominance_threshold=1, min_payloads=10):
        results = []

        for length, payloads in self.tcp_payloads_by_length.items():
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

    def analyze_payload_patterns(payloads_by_length, dominance_threshold=1, min_payloads=10):
        results = []

        for length, payloads in payloads_by_length.items():
            if len(payloads) < min_payloads:
                continue

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
