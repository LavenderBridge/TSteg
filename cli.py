from scapy.all import *
from scapy.layers.inet import IP, TCP

# Define client IP and port
client_ip = "192.168.106.44"
client_port = 54321
server_ip = "172.29.94.202"
server_port = 12345

# Send SYN packet to initiate connection
syn_packet = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S")
syn_ack_response = sr1(syn_packet, timeout=2, verbose=False)

if syn_ack_response and TCP in syn_ack_response and syn_ack_response[TCP].flags & 0x12 == 0x12:
    # Received SYN-ACK response, send ACK to establish connection
    seq_num = syn_ack_response[TCP].ack
    ack_num = syn_ack_response[TCP].seq + 1
    ack_packet = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=seq_num, ack=ack_num)
    send(ack_packet, verbose=False)
    print("Connection established.")
else:
    print("Failed to establish connection.")
