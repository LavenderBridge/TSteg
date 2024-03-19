import socket
import struct

# Define the destination IP and port
DEST_IP = '127.0.0.1'
DEST_PORT = 12345

# Input data (20 bits)
input_data = "10110100111100000110"

# Function to split input data into groups of 4 bits
def split_into_groups(data, group_size):
    return [data[i:i+group_size] for i in range(0, len(data), group_size)]

# Split input data into groups of 4 bits each
data_groups = split_into_groups(input_data, 4)

# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the destination
sock.connect((DEST_IP, DEST_PORT))

# Pack and send data
for group in data_groups:
    group=group.zfill(8)
    data = struct.pack('!HHB', 0, 0, int(group, 2))  # tsval, tsecr, overflow
    sock.send(data)

# Close the socket
sock.close()

