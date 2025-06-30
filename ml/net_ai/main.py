import socket
import os
import struct
import json
#from packets.decode import *
from utilities.logging import *
import subprocess
import signal
import threading
from utilities.ui import *
from packets.decode import tshark


HOST = '0.0.0.0'
PORT = 8080
RAMDISK = "/dev/shm/"

def kill_port_process(port, protocol="tcp"):
    """
    Kill any process listening on the specified TCP or UDP port.
    
    :param port: Port number to check.
    :param protocol: 'tcp' or 'udp'
    """
    try:
        # Use correct lsof syntax
        result = subprocess.check_output(
            f"lsof -i {protocol}:{port} -t",
            shell=True
        ).decode().strip().splitlines()

        if not result:
            logp(f"✅ No process using port {port}/{protocol}.")
            return

        for pid in result:
            os.kill(int(pid), signal.SIGKILL)
            logp(f"🛑 Killed process {pid} using port {port}/{protocol}.")

    except subprocess.CalledProcessError:
        logp(f"✅ No process found using port {port}/{protocol}.")
    except Exception as e:
        logp(f"❌ Error killing process on port {port}/{protocol}: {e}")

def handle_client(conn):
    try:
        # Read filename length (2 bytes)
        filename_len = struct.unpack('H', conn.recv(2))[0]

        # Read filename
        filename = conn.recv(filename_len).decode()

        # Read file size (8 bytes)
        filesize = struct.unpack('Q', conn.recv(8))[0]

        # Build full path
        pcap_path = os.path.join(RAMDISK, filename)

        # Receive file data
        with open(pcap_path, 'wb') as f:
            received = 0
            while received < filesize:
                chunk = conn.recv(min(4096, filesize - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

        logp(f"✅ Received file: {filename} ({filesize} bytes)")

        # Process with tshark
        result = tshark(os.path.splitext(filename)[0], pcap_path)

        # Send result back
        conn.sendall(json.dumps(result).encode())

    except Exception as e:
        err = {'error': str(e)}
        conn.sendall(json.dumps(err).encode())

    finally:
        conn.close()
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
            logp(f"🗑️ Deleted file from RAM: {pcap_path}")


def main():
    logp("Zuxent AI Socket Server Started")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow address reuse
        s.bind((HOST, PORT))
        s.listen(5)
        logp(f"🚪 Listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            logp(f"📡 Connection from {addr}")
            handle_client(conn)

if __name__ == '__main__':
    kill_port_process(8080, "tcp")  # Kill TCP port 8080
    window = "off"
    live = "off"
    # Start main() in a thread
    main_thread = threading.Thread(target=main)
    main_thread.start()

    if live == "off": 
        pass
    else:
        discord_thread = threading.Thread(target=live_discord)
        discord_thread.start()
    if window == "off": 
        pass
    else:
        ui = threading.Thread(target=startup)
        ui.start()
    
    main_thread.join()
    if live == "off": 
        pass
    else:
        discord_thread.join()
    if window == "off": 
        pass
    else:
        ui.join()


