import socket
import struct
import textwrap

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'dest_mac': get_mac_addr(dest_mac),
        'rc_mac': get_mac_addr(src_mac),
        'proto': socket.htons(proto),
        'data': data[14:]
    }

def ipv4_packet(data):
    version_header_len = data[0]
    header_len = (version_header_len & 0xF) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return {
        'rc': ipv4_addr(src),
        'dst': ipv4_addr(target),
        'proto': proto,
        'ttl': ttl,
        'data': data[header_len:]
    }

def ipv4_addr(addr):
    return '.'.join(map(str, addr))

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        eth_frame = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print("Destination MAC: {}, Source MAC: {}, Protocol: {}".format(eth_frame['dest_mac'], eth_frame['src_mac'], eth_frame['proto']))
        if eth_frame['proto'] == 8:
            ipv4_packet_info = ipv4_packet(eth_frame['data'])
            print("IPv4 Packet:")
            print("Source IP: {}, Destination IP: {}, Protocol: {}, TTL: {}".format(ipv4_packet_info['src'], ipv4_packet_info['dst'], ipv4_packet_info['proto'], ipv4_packet_info['ttl']))
            print("Payload:")
            print(format_multi_line('', ipv4_packet_info['data']))

if __name__ == "__main__":
    main()
