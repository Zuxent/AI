class DDoSDetector:
    def __init__(self):
        self.packet_data = []

    def load_pcap(self, pcap_file):
        """Load packets from a pcap file."""
        with open(pcap_file, 'r') as file:
            for line in file:
                self.packet_data.append(self.parse_packet(line.strip()))

    def parse_packet(self, packet_line):
        """Parse a single packet line into a dictionary."""
        parts = packet_line.split(',')
        return {
            'timestamp': float(parts[0]),
            'source_ip': parts[1],
            'destination_ip': parts[2],
            'protocol': parts[3],
            'size': int(parts[4])
        }

    def detect_high_traffic(self, threshold, time_window):
        """Detect high traffic within a time window."""
        traffic_count = {}
        for packet in self.packet_data:
            time_key = int(packet['timestamp'] // time_window)
            traffic_count[time_key] = traffic_count.get(time_key, 0) + 1

        for time_key, count in traffic_count.items():
            if count > threshold:
                print(f"High traffic detected at time window {time_key * time_window}-{(time_key + 1) * time_window}")

    def detect_ip_flood(self, threshold):
        """Detect IP flood attacks by counting packets per source IP."""
        ip_count = {}
        for packet in self.packet_data:
            ip_count[packet['source_ip']] = ip_count.get(packet['source_ip'], 0) + 1

        for ip, count in ip_count.items():
            if count > threshold:
                print(f"IP flood detected from {ip} with {count} packets")

    def detect_protocol_anomalies(self, protocol_threshold):
        """Detect anomalies in protocol usage."""
        protocol_count = {}
        for packet in self.packet_data:
            protocol_count[packet['protocol']] = protocol_count.get(packet['protocol'], 0) + 1

        for protocol, count in protocol_count.items():
            if count > protocol_threshold:
                print(f"Protocol anomaly detected: {protocol} with {count} packets")

    def detect_packet_size_anomalies(self, size_threshold):
        """Detect anomalies in packet sizes."""
        for packet in self.packet_data:
            if packet['size'] > size_threshold:
                print(f"Large packet detected: {packet['size']} bytes from {packet['source_ip']}")

# Example usage:
# detector = DDoSDetector()
# detector.load_pcap('packets.pcap')
# detector.detect_high_traffic(threshold=1000, time_window=60)
# detector.detect_ip_flood(threshold=500)
# detector.detect_protocol_anomalies(protocol_threshold=300)
# detector.detect_packet_size_anomalies(size_threshold=1500)