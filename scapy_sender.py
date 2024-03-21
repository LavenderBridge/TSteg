from scapy.all import *

# Define your custom TCP options with an editable overflow field
class TCPTimestampOption(Packet):
    name = "Timestamp"
    fields_desc = [FieldLenField("length", None, length_of="overflow", adjust=lambda pkt, x:x//4), 
                   ShortField("tsval", 0), 
                   ShortField("tsecr", 0), 
                   BitField("overflow", 0, 4)]

# Function to craft TCP options with timestamp and overflow fields
def craft_timestamp_options(data_groups):
    options = []
    for group in data_groups:
        options.append(TCPTimestampOption(tsval=0, tsecr=0, overflow=group))
    return options

# Function to break input data into groups of 4 bits
def split_into_groups(data, group_size):
    return [data[i:i+group_size] for i in range(0, len(data), group_size)]

def string_to_binary(string):
    binary_str = ''.join(format(ord(char), '08b') for char in string)
    return binary_str

def split_binary(binary_str):
    # Check if the binary string is less than or equal to 20 bits
    if len(binary_str) <= 20:
        return [binary_str], 0
    else:
        # Calculate the number of 20-bit groups
        num_groups = len(binary_str) // 20
        if len(binary_str) % 20 != 0:
            num_groups += 1
        
        # Split the binary string into groups of 20 bits each
        binary_groups = [binary_str[i:i+20] for i in range(0, len(binary_str), 20)]
        return binary_groups, num_groups

# Input data (20 bits)
input_data = input("Enter string to encode: ")
print(f"String entered: {input_data}");

input_data_binary = string_to_binary(input_data)
print(f'Binary representation of input string: {input_data_binary}')

#Check if binary > 20 bits
input_data_binary_groups, num_groups = split_binary(input_data_binary)

print("\n-------groups-------")
for i in (input_data_binary_groups):
    print(i)
print("--------------------\n")
#print(num_groups)

# Split input data into groups of 4 bits each
data_groups = []
for i in range (num_groups):
        data_groups.append( split_into_groups(input_data_binary_groups[i], 4))

print("--------------data groups---------------")
for i in range (num_groups):
    print(data_groups[i])
print("----------------------------------------")
# Craft TCP options with timestamp and overflow fields
options = []
for i in range (num_groups):
    options.append(craft_timestamp_options(data_groups[i]))

print("------------------tcp packets-----------------")
ip_packet = []
for i in range (num_groups):
    # Craft the IPv4 packet
    ip_packet.append(IP(dst="127.0.0.1")/TCP(options=options[i]))

for i in range (num_groups):
    print(ip_packet[i])
    # Display the packet
    print(ip_packet[i].show())

# Send the packet
for i in range (num_groups): 
    send(ip_packet[i])

