from scapy.all import *
from scapy.layers.inet import TCP, IP

print("Running reciever scriptt")

# # Define the port to listen on
listening_port = 12345

# # Define a function to handle received packets
# def handle_packet(packet):
#     if packet.haslayer(TCP) and packet[TCP].dport == listening_port:
#         print("Received TCP packet:")
#         print(packet.show())

# # Start sniffing for packets
# sniff(filter="tcp", prn=handle_packet, store=0)

def handle_packet(packet):
    try:
        if (packet.haslayer(TCP) and packet[TCP].dport == 12345):
            print("Received packet:")
            packet.show()
    except:
        print("IDK WHAT TO DO")

# Start sniffing for packets
sniff(prn=handle_packet)