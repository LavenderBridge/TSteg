from scapy.all import *
from scapy.layers.inet import IP, TCP

# Define server IP and port
server_ip = "192.168.106.44"
server_port = 12345

# Define a function to handle incoming connections
def handle_connection(packet):
    if TCP in packet and packet[TCP].dport == server_port and packet[TCP].flags & 0x02:
        # Received SYN packet, send SYN-ACK response
        seq_num = 1000
        ack_num = packet[TCP].seq + 1
        ip_response = IP(src=server_ip, dst=packet[IP].src)
        tcp_response = TCP(sport=server_port, dport=packet[TCP].sport, flags="SA", seq=seq_num, ack=ack_num)
        send(ip_response/tcp_response, verbose=False)

# Start sniffing for incoming packets
sniff(filter="tcp and dst port {}".format(server_port), prn=handle_connection)
