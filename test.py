from scapy.all import sniff

def process_packet(packet):
    print(packet)

sniff(prn = process_packet)