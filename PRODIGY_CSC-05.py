from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        proto = packet['IP'].proto
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")

        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print("Payload:", payload.hex())  # Display payload in hexadecimal format

# Sniff packets on the network
print("Packet Sniffer started...")
sniff(prn=packet_callback, store=0)
