import socket
import os
import struct
import json

HOST = '127.0.0.1'
PORT = 8080

pcap = "smp"
file_path = f'{pcap}.pcap'
filename = os.path.basename(file_path)

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    filesize = len(data)
    filename_bytes = filename.encode()
    filename_len = len(filename_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Send filename length (2 bytes), filename, then filesize (8 bytes)
        s.sendall(struct.pack('H', filename_len))
        s.sendall(filename_bytes)
        s.sendall(struct.pack('Q', filesize))
        s.sendall(data)

        # Receive response
        response = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk

        # Parse JSON
        print(json.dumps(json.loads(response.decode()), indent=4))

except Exception as e:
    print(f"Error: {e}")
