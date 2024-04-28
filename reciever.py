from scapy.all import *

mainstr = ""

def process_packet(packet):
    if TCP in packet and packet[TCP].dport == 12345:
        print(packet.show())
        #timestamps = []
        global mainstr
        bstring = ""
        options = packet[TCP].options
        for option in options:
            if option[0] == "Timestamp":
                print(option[1]);
                timestamp_data, _ = option[1]
                #timestamps.append(timestamp_data)
                tempstr=bin(timestamp_data)[2:]
                tempstr = "0" * (4-len(tempstr)) + tempstr;
                print(tempstr)
                if tempstr != "0000":
                    bstring += tempstr
                #print(bstring) 
                #message = ''.join(chr(byte) for byte in timestamp_data)
                #print("recieved", message)
        mainstr+=bstring
        

def decode(mainstr):
    if len(mainstr) % 8 != 0:
        print("ERROR")
        #exit(0)
    alphabet = ""
    for i in range(0, len(mainstr), 8):
        byte = mainstr[i:i+8]
        dec = int(byte, 2)
        char = chr(dec)
        alphabet += char

    return alphabet

sniff(filter="tcp port 12345", prn=process_packet, store=0, timeout=10)
print (mainstr)

ans = decode(mainstr)
print(ans)
