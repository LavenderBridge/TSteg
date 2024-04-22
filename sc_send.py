from scapy.all import *
from scapy.layers.inet import TCP, IP
import time

print("Running sender script")
# Define the target IP address and port
target_ip = "127.0.0.1"
target_port = 12345

# Craft a TCP SYN packet
packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

# Send the packet
while True:
    send(packet)
    time.sleep(3)
print("Packet sent successfully.")
