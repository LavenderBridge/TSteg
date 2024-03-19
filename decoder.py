import socket
import struct

# Define the listening IP and port
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 12345

# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the listening IP and port
sock.bind((LISTEN_IP, LISTEN_PORT))

# Listen for incoming connections
sock.listen(1)

# Accept the incoming connection
conn, addr = sock.accept()

print('Connection from:', addr)

# Receive and process data
while True:
    data = conn.recv(5)
    if not data:
        break
    tsval, tsecr, overflow = struct.unpack('!HHB', data)
    print(f"Timestamp Value: {tsval}, Timestamp Echo Reply: {tsecr}, Overflow: {bin(overflow)[2:]:>04}")

# Close the connection
conn.close()

# Close the socket
sock.close()

