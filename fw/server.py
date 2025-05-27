import socket
import threading
import time

# Configuration
UDP_IP = "0.0.0.0"  # Listen on all available interfaces
UDP_PORT = 30120

# Global variables
packet_count = 0
lock = threading.Lock()

# Function to count packets per second
def count_pps():
    global packet_count
    while True:
        time.sleep(1)
        with lock:
            print(f"PPS: {packet_count}")
            packet_count = 0  # Reset the count for the next second

# Function to handle incoming UDP packets
def udp_server():
    global packet_count
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(1024)  # Receive up to 1024 bytes
        with lock:
            packet_count += 1  # Increase packet count

# Start the PPS counter in a separate thread
pps_thread = threading.Thread(target=count_pps, daemon=True)
pps_thread.start()

# Start the UDP server
udp_server()
